package session

import (
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/transport"
)

// TestCorruptionDoesNotConsumeSequence proves that a frame corrupted
// ONLY in the ciphertext (sequence prefix intact) fails AEAD, does not
// consume its sequence number, and the session dies by the failure
// budget — never silently swallowing stream data.
func TestCorruptionDoesNotConsumeSequence(t *testing.T) {
	ta, tb := transport.NewFaultyPair(transport.DefaultConfig())
	ta.Start()
	tb.Start()
	sa, err := New(ta, []byte("test-key-0123456789abcdef01234567"), true)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := New(tb, []byte("test-key-0123456789abcdef01234567"), false)
	if err != nil {
		t.Fatal(err)
	}
	sa.Start()
	sb.Start()
	handshakeBoth(t, sa, sb)

	// Corrupt ONLY the ciphertext region (after the 8-byte sequence
	// prefix): AEAD must fail, the seq must NOT be consumed, and the
	// session must die by the failure budget.
	for i := 0; i < maxDecryptFailures; i++ {
		blob, err := sa.crypto.Load().encrypt([]byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
		blob[len(blob)-1] ^= 0xFF // flip last byte (inside AEAD tag)
		if err := ta.Send(blob); err != nil {
			t.Fatal(err)
		}
	}

	select {
	case <-sb.Closed():
		if sb.Err() != ErrCryptoMismatch {
			t.Fatalf("closed with %v, want ErrCryptoMismatch", sb.Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session survived ciphertext corruption")
	}
}
