package session

import (
	"bytes"
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

func TestWrongPSKDies(t *testing.T) {
	sa, sb := newSessionPair(t, []byte("key-A"), []byte("key-B"))
	handshakeBoth(t, sa, sb) // handshake itself is plaintext, succeeds

	// Encrypted frames are undecryptable for the peer: after
	// maxDecryptFailures the session must close.
	for i := 0; i < maxDecryptFailures; i++ {
		if err := sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 1, Payload: []byte("x")}); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-sb.Closed():
		if sb.Err() != ErrCryptoMismatch {
			t.Fatalf("close reason = %v, want ErrCryptoMismatch", sb.Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session survived wrong PSK")
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
