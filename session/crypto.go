package session

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
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
	nonceSize    = chacha20poly1305.NonceSize
	keySize      = chacha20poly1305.KeySize
	aeadOverhead = nonceSize + chacha20poly1305.Overhead

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

	consecutiveFailures atomic.Int32
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

	// Client sends with c2s, receives with s2c; server mirrors.
	sendKey, recvKey := c2s, s2c
	if !isClient {
		sendKey, recvKey = s2c, c2s
	}

	sc := &sessionCrypto{}
	if sc.send, err = chacha20poly1305.New(sendKey); err != nil {
		return nil, err
	}
	if sc.recv, err = chacha20poly1305.New(recvKey); err != nil {
		return nil, err
	}
	return sc, nil
}

// encrypt wraps plaintext as [nonce][ciphertext].
func (c *sessionCrypto) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, nonceSize+len(plaintext)+chacha20poly1305.Overhead)
	out = append(out, nonce...)
	out = c.send.Seal(out, nonce, plaintext, nil)
	return out, nil
}

// decrypt unwraps [nonce][ciphertext].
func (c *sessionCrypto) decrypt(data []byte) ([]byte, error) {
	if len(data) < nonceSize+chacha20poly1305.Overhead {
		return nil, errors.New("session: ciphertext too short")
	}
	return c.recv.Open(nil, data[:nonceSize], data[nonceSize:], nil)
}

// --- Key confirmation ---
//
// HELLO_ACK carries an AEAD tag over a constant bound to both ephemeral
// public keys. Verifying it proves the peer derived the same keys, i.e.
// knows the PSK. A fixed zero nonce is safe here: the tag is computed
// exactly once per session key (random stream nonces are 96-bit, so an
// accidental collision with the all-zero nonce is negligible).

var keyConfirmNonce = make([]byte, nonceSize)

func keyConfirmMessage(clientPub, serverPub []byte) []byte {
	msg := make([]byte, 0, len("OPENFLUX-KC")+64)
	msg = append(msg, "OPENFLUX-KC"...)
	msg = append(msg, clientPub...)
	msg = append(msg, serverPub...)
	return msg
}

// computeKeyConfirm produces the tag with the SEND key (caller: the side
// answering HELLO).
func (c *sessionCrypto) computeKeyConfirm(clientPub, serverPub []byte) []byte {
	return c.send.Seal(nil, keyConfirmNonce, keyConfirmMessage(clientPub, serverPub), nil)
}

// verifyKeyConfirm checks the tag with the RECV key (caller: the side
// that sent HELLO).
func (c *sessionCrypto) verifyKeyConfirm(clientPub, serverPub, tag []byte) bool {
	plain, err := c.recv.Open(nil, keyConfirmNonce, tag, nil)
	if err != nil {
		return false
	}
	return bytes.Equal(plain, keyConfirmMessage(clientPub, serverPub))
}
