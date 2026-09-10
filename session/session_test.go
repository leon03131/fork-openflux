package session

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/wire"
)

// newSessionPair builds two sessions over memory transports and handshakes.
func newSessionPair(t *testing.T, pskA, pskB []byte) (*Session, *Session) {
	t.Helper()
	ta, tb := transport.NewMemoryTransportPair(transport.DefaultConfig())
	if err := ta.Start(); err != nil {
		t.Fatal(err)
	}
	if err := tb.Start(); err != nil {
		t.Fatal(err)
	}
	sa, err := New(ta, pskA, true)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := New(tb, pskB, false)
	if err != nil {
		t.Fatal(err)
	}
	sa.Start()
	sb.Start()
	return sa, sb
}

func handshakeBoth(t *testing.T, sa, sb *Session) {
	t.Helper()
	done := make(chan error, 2)
	go func() { done <- sa.Handshake() }()
	go func() { done <- sb.Handshake() }()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}
}

func TestEncryptedSession(t *testing.T) {
	sa, sb := newSessionPair(t, []byte("secret-key"), []byte("secret-key"))
	handshakeBoth(t, sa, sb)

	// Both sides must have crypto enabled.
	if sa.crypto.Load() == nil || sb.crypto.Load() == nil {
		t.Fatal("crypto not enabled after handshake")
	}

	// Frames must flow.
	got := make(chan wire.Frame, 1)
	sb.OnFrame(func(f wire.Frame) { got <- f })
	if err := sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 1, Payload: []byte("encrypted hello")}); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-got:
		if string(f.Payload) != "encrypted hello" {
			t.Fatalf("payload %q", f.Payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for frame")
	}
}

func TestEncryptedSessionWireIsCiphertext(t *testing.T) {
	// Intercept what actually crosses the transport boundary.
	ta, tb := transport.NewMemoryTransportPair(transport.DefaultConfig())
	ta.Start()
	tb.Start()

	raw := make(chan []byte, 4)
	tb.Receive(func(d []byte) { raw <- d }) // raw listener BEFORE session hooks

	sa, err := New(ta, []byte("secret-key"), true)
	if err != nil {
		t.Fatal(err)
	}
	// Handshake-less shortcut: install crypto directly to observe the wire.
	priv, _ := generateEphemeralKey()
	c, err := deriveSession([]byte("secret-key"), priv, priv.PublicKey().Bytes(), true)
	if err != nil {
		t.Fatal(err)
	}
	sa.crypto.Store(c)
	sa.Start() // note: replaces tb's raw callback; send only a->b

	if err := sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 1, Payload: []byte("TOP SECRET")}); err != nil {
		t.Fatal(err)
	}

	select {
	case blob := <-raw:
		if bytes.Contains(blob, []byte("TOP SECRET")) {
			t.Fatal("plaintext leaked onto the wire")
		}
	case <-time.After(time.Second):
		t.Fatal("no wire message observed")
	}
}

func TestWrongPSKFailsHandshake(t *testing.T) {
	sa, sb := newSessionPair(t, []byte("key-A"), []byte("key-B"))

	// The client must fail fast at key confirmation.
	serverDone := make(chan error, 1)
	go func() { serverDone <- sb.Handshake() }()

	err := sa.Handshake()
	if err == nil {
		t.Fatal("client handshake succeeded with wrong PSK")
	}
	if !strings.Contains(err.Error(), "key confirmation") {
		t.Fatalf("unexpected handshake error: %v", err)
	}

	// The server waits for the client's encrypted confirmation, which
	// never comes (wrong PSK). Close it and expect a clean shutdown.
	sb.Close()
	select {
	case err := <-serverDone:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("server handshake: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server handshake stuck after Close")
	}
	sa.Close()
}

func TestUndecryptableFramesKillSession(t *testing.T) {
	sa, sb := newSessionPair(t, []byte("key-A"), []byte("key-A"))
	handshakeBoth(t, sa, sb)

	// Forge ciphertext with a WRONG key set (simulates a carrier-level
	// attacker or a corrupted peer) and inject it via the carrier.
	priv, _ := generateEphemeralKey()
	evil, err := deriveSession([]byte("wrong"), priv, priv.PublicKey().Bytes(), true)
	if err != nil {
		t.Fatal(err)
	}
	// ta is sa's transport; sending raw bytes reaches sb's session.
	ta := sa.trans
	for i := 0; i < maxDecryptFailures; i++ {
		blob, err := evil.encrypt([]byte("garbage"))
		if err != nil {
			t.Fatal(err)
		}
		if err := ta.Send(blob); err != nil {
			t.Fatal(err)
		}
	}

	select {
	case <-sb.Closed():
		// With strict ordering, foreign ciphertext is killed by the
		// sequence check (replay/gap) or by AEAD failure accumulation:
		// either way the session must die.
		if sb.Err() == nil {
			t.Fatal("session closed without a reason")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session survived undecryptable frames")
	}
}

func TestPlaintextSessionStillWorks(t *testing.T) {
	sa, sb := newSessionPair(t, nil, nil)
	handshakeBoth(t, sa, sb)
	if sa.crypto.Load() != nil {
		t.Fatal("crypto unexpectedly enabled")
	}
	got := make(chan wire.Frame, 1)
	sb.OnFrame(func(f wire.Frame) { got <- f })
	if err := sa.SendFrame(wire.Frame{Type: wire.TypePing, Payload: []byte("12345678")}); err != nil {
		t.Fatal(err)
	}
	// PING is handled by the session itself (PONG), so send a DATA-ish
	// frame type that reaches the handler.
	if err := sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 3, Payload: []byte("plain")}); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-got:
		if string(f.Payload) != "plain" {
			t.Fatalf("payload %q", f.Payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

func TestTamperedCiphertextRejected(t *testing.T) {
	priv, _ := generateEphemeralKey()
	c, err := deriveSession([]byte("k"), priv, priv.PublicKey().Bytes(), true)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := c.encrypt([]byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	blob[len(blob)-1] ^= 0xFF // flip a bit
	if _, err := c.decrypt(blob); err == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
}

// cryptoPair returns client and server sessionCrypto with matching keys.
func cryptoPair(t *testing.T) (*sessionCrypto, *sessionCrypto) {
	t.Helper()
	privC, _ := generateEphemeralKey()
	privS, _ := generateEphemeralKey()
	client, err := deriveSession([]byte("k"), privC, privS.PublicKey().Bytes(), true)
	if err != nil {
		t.Fatal(err)
	}
	server, err := deriveSession([]byte("k"), privS, privC.PublicKey().Bytes(), false)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestReplayRejected(t *testing.T) {
	client, server := cryptoPair(t)

	// Receive several messages.
	blobs := make([][]byte, 5)
	for i := range blobs {
		var err error
		blobs[i], err = client.encrypt([]byte{byte(i)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := server.decrypt(blobs[i]); err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
	}
	// Replay the middle one: must be rejected.
	if _, err := server.decrypt(blobs[2]); !errors.Is(err, errReplayedMessage) {
		t.Fatalf("replay accepted: %v", err)
	}
	// Replay the newest: rejected.
	if _, err := server.decrypt(blobs[4]); !errors.Is(err, errReplayedMessage) {
		t.Fatalf("replay accepted: %v", err)
	}
	// A brand new message still passes.
	fresh, _ := client.encrypt([]byte{99})
	if _, err := server.decrypt(fresh); err != nil {
		t.Fatalf("fresh message rejected: %v", err)
	}
}

func TestGapKillsOrdering(t *testing.T) {
	client, server := cryptoPair(t)
	// Strict in-order delivery: a lost message must be fatal, because
	// the carrier contract is reliable+ordered.
	first, _ := client.encrypt([]byte{1})
	client.encrypt([]byte{2}) // seq 2: never delivered
	third, _ := client.encrypt([]byte{3})
	if _, err := server.decrypt(first); err != nil {
		t.Fatal(err)
	}
	if _, err := server.decrypt(third); !errors.Is(err, errOutOfOrder) {
		t.Fatalf("gap not detected: %v", err)
	}
}

func TestBothDirectionsIndependent(t *testing.T) {
	client, server := cryptoPair(t)
	// Interleave directions; each direction has its own counter/window.
	for i := 0; i < 4; i++ {
		c2s, _ := client.encrypt([]byte{byte(i)})
		if _, err := server.decrypt(c2s); err != nil {
			t.Fatalf("c2s %d: %v", i, err)
		}
		s2c, _ := server.encrypt([]byte{byte(i)})
		if _, err := client.decrypt(s2c); err != nil {
			t.Fatalf("s2c %d: %v", i, err)
		}
	}
}
