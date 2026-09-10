package session

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// The session crypto is a Noise_NNpsk-style construction built from
// audited primitives only:
//
//	ephemeral X25519 DH  ->  forward secrecy
//	PSK mixed into HKDF  ->  mutual authentication (both ends must know it)
//	ChaCha20-Poly1305    ->  AEAD for every frame after the handshake
//
// Wire format of an encrypted carrier message: [12-byte random nonce]
// [ciphertext]. Explicit random nonces make the scheme robust against
// carriers that occasionally drop a message (a dropped message would
// desync a counter-based nonce forever).

const (
	nonceSize = chacha20poly1305.NonceSize
	keySize   = chacha20poly1305.KeySize
	// aeadOverhead = 8-byte sequence + AEAD tag. The nonce is
	// deterministically derived from the sequence and is NOT
	// transmitted.
	aeadOverhead = 8 + chacha20poly1305.Overhead

	// keyConfirmTagLen = len("OPENFLUX-KC") + 64 pub bytes + AEAD tag.
	keyConfirmTagLen = 11 + 64 + chacha20poly1305.Overhead
)

// ErrCryptoMismatch indicates the peer failed to decrypt repeatedly —
// almost always a PSK mismatch.
var ErrCryptoMismatch = errors.New("session: repeated decryption failures (PSK mismatch?)")

// maxDecryptFailures closes the session after this many consecutive
// decryption failures.
const maxDecryptFailures = 3

type sessionCrypto struct {
	send cipher.AEAD
	recv cipher.AEAD
	// kc is a dedicated AEAD key used ONLY for handshake key
	// confirmation: it lives in its own key/nonce space, so the
	// all-zero confirmation nonce can never collide with transport
	// nonces (RFC 8439 key/nonce uniqueness).
	kc cipher.AEAD

	// Strict per-direction sequence numbers: carriers are
	// reliable+ordered by contract, so a gap or replay means the
	// contract is broken (or an attack) and the session must die.
	sendSeq  atomic.Uint64
	recvMu   sync.Mutex
	nextRecv uint64

	consecutiveFailures atomic.Int32
}

var (
	errReplayedMessage = errors.New("session: replayed message")
	errOutOfOrder      = errors.New("session: message gap (carrier lost a frame)")
)

// checkSeq enforces strict in-order delivery. Caller must hold recvMu.
func (c *sessionCrypto) checkSeq(seq uint64) error {
	if seq < c.nextRecv {
		return errReplayedMessage
	}
	if seq > c.nextRecv {
		return errOutOfOrder
	}
	c.nextRecv++
	return nil
}

// generateEphemeralKey creates an X25519 keypair for the handshake.
func generateEphemeralKey() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// deriveSession builds the AEAD pair. isClient selects the direction
// assignment; both sides must agree on the same PSK.
func deriveSession(psk []byte, priv *ecdh.PrivateKey, peerPubBytes []byte, isClient bool) (*sessionCrypto, error) {
	if len(peerPubBytes) != 32 {
		return nil, fmt.Errorf("session: bad peer key length %d", len(peerPubBytes))
	}
	peerPub, err := ecdh.X25519().NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("session: bad peer key: %w", err)
	}
	shared, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("session: DH: %w", err)
	}

	// Transcript binding: keys depend on both public keys, so a MITM
	// substituting a key gets different session keys.
	salt := append(append([]byte{}, priv.PublicKey().Bytes()...), peerPubBytes...)
	if !isClient {
		salt = append(append([]byte{}, peerPubBytes...), priv.PublicKey().Bytes()...)
	}
	ikm := append(append([]byte{}, shared...), psk...)

	readKey := func(info string) ([]byte, error) {
		k := make([]byte, keySize)
		if _, err := io.ReadFull(hkdf.New(sha256.New, ikm, salt, []byte(info)), k); err != nil {
			return nil, err
		}
		return k, nil
	}

	c2s, err := readKey("openflux-v2-c2s")
	if err != nil {
		return nil, err
	}
	s2c, err := readKey("openflux-v2-s2c")
	if err != nil {
		return nil, err
	}
	kcKey, err := readKey("openflux-v2-keyconfirm")
	if err != nil {
		return nil, err
	}

	// Client sends with c2s, receives with s2c; server mirrors.
	sendKey, recvKey := c2s, s2c
	if !isClient {
		sendKey, recvKey = s2c, c2s
	}

	sc := &sessionCrypto{nextRecv: 1}
	if sc.send, err = chacha20poly1305.New(sendKey); err != nil {
		return nil, err
	}
	if sc.recv, err = chacha20poly1305.New(recvKey); err != nil {
		return nil, err
	}
	if sc.kc, err = chacha20poly1305.New(kcKey); err != nil {
		return nil, err
	}
	return sc, nil
}

// seqNonce derives the deterministic AEAD nonce from the sequence
// number: unique per message under the session key, no randomness
// needed (RFC 8439 counter nonce, same as Noise CipherState).
func seqNonce(seq uint64) [nonceSize]byte {
	var n [nonceSize]byte
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

// encrypt wraps plaintext as [8-byte seq][ciphertext]. The sequence is
// sent in plaintext (it is not secret) and authenticated implicitly:
// tampering with it changes the derived nonce and fails the AEAD tag.
func (c *sessionCrypto) encrypt(plaintext []byte) ([]byte, error) {
	seq := c.sendSeq.Add(1)
	nonce := seqNonce(seq)
	out := make([]byte, 0, 8+len(plaintext)+chacha20poly1305.Overhead)
	var hdr [8]byte
	binary.BigEndian.PutUint64(hdr[:], seq)
	out = append(out, hdr[:]...)
	out = c.send.Seal(out, nonce[:], plaintext, nil)
	return out, nil
}

// decrypt unwraps [8-byte seq][ciphertext], verifies integrity and
// enforces strict in-order delivery: replays and gaps (a lost frame)
// are fatal errors, because a reliable ordered carrier must not
// exhibit either.
func (c *sessionCrypto) decrypt(data []byte) ([]byte, error) {
	if len(data) < 8+chacha20poly1305.Overhead {
		return nil, errors.New("session: ciphertext too short")
	}
	seq := binary.BigEndian.Uint64(data[:8])
	// Ordering first: cheaply rejects replays/gaps before AEAD work.
	c.recvMu.Lock()
	err := c.checkSeq(seq)
	c.recvMu.Unlock()
	if err != nil {
		return nil, err
	}
	nonce := seqNonce(seq)
	return c.recv.Open(nil, nonce[:], data[8:], nil)
}

// --- Key confirmation ---
//
// HELLO_ACK carries an AEAD tag over a constant bound to both ephemeral
// public keys. Verifying it proves the peer derived the same keys, i.e.
// knows the PSK. The tag uses the DEDICATED kc key (own key space), so
// the fixed zero nonce is trivially unique and can never collide with
// transport nonces.

var keyConfirmNonce = make([]byte, nonceSize)

func keyConfirmMessage(clientPub, serverPub []byte) []byte {
	msg := make([]byte, 0, len("OPENFLUX-KC")+64)
	msg = append(msg, "OPENFLUX-KC"...)
	msg = append(msg, clientPub...)
	msg = append(msg, serverPub...)
	return msg
}

// computeKeyConfirm produces the confirmation tag (caller: the side
// answering HELLO).
func (c *sessionCrypto) computeKeyConfirm(clientPub, serverPub []byte) []byte {
	return c.kc.Seal(nil, keyConfirmNonce, keyConfirmMessage(clientPub, serverPub), nil)
}

// verifyKeyConfirm checks the tag (caller: the side that sent HELLO).
func (c *sessionCrypto) verifyKeyConfirm(clientPub, serverPub, tag []byte) bool {
	plain, err := c.kc.Open(nil, keyConfirmNonce, tag, nil)
	if err != nil {
		return false
	}
	return bytes.Equal(plain, keyConfirmMessage(clientPub, serverPub))
}
