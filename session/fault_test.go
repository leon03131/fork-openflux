package session

import (
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/wire"
)

// newFaultySessionPair builds an encrypted session pair over a
// fault-injecting carrier.
func newFaultySessionPair(t *testing.T) (*Session, *Session, *transport.FaultyTransport, *transport.FaultyTransport) {
	t.Helper()
	ta, tb := transport.NewFaultyPair(transport.DefaultConfig())
	if err := ta.Start(); err != nil {
		t.Fatal(err)
	}
	if err := tb.Start(); err != nil {
		t.Fatal(err)
	}
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
	return sa, sb, ta, tb
}

func TestSessionSurvivesCleanFaultyCarrier(t *testing.T) {
	sa, sb, _, _ := newFaultySessionPair(t)
	got := make(chan wire.Frame, 1)
	sb.OnFrame(func(f wire.Frame) { got <- f })
	if err := sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 1, Payload: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("no frame")
	}
}

func TestSessionDiesOnDrops(t *testing.T) {
	sa, sb, ta, _ := newFaultySessionPair(t)
	_ = sa
	sb.OnFrame(func(wire.Frame) {})

	ta.DropProb = 1.0 // 100% packet loss c->s

	for i := 0; i < 3; i++ {
		sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 1, Payload: []byte("x")})
	}
	// Wait until the dropped frames were actually written by the async
	// writerLoop (HELLO + confirmation PING already count).
	deadline := time.Now().Add(3 * time.Second)
	for ta.Stats().PacketsSent < 5 {
		if time.Now().After(deadline) {
			t.Fatal("writerLoop did not flush dropped frames")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Restore delivery: the next frame has a sequence gap -> fatal.
	ta.DropProb = 0
	sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 1, Payload: []byte("x")})

	select {
	case <-sb.Closed():
		if sb.Err() != errOutOfOrder {
			t.Fatalf("closed with %v, want gap error", sb.Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session survived a sequence gap")
	}
}

func TestSessionDiesOnDuplicates(t *testing.T) {
	sa, sb, ta, _ := newFaultySessionPair(t)
	sb.OnFrame(func(wire.Frame) {})

	ta.DupProb = 1.0
	sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 1, Payload: []byte("x")})

	select {
	case <-sb.Closed():
		if sb.Err() != errReplayedMessage {
			t.Fatalf("closed with %v, want replay error", sb.Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session survived a duplicated frame")
	}
}

func TestSessionDiesOnCorruption(t *testing.T) {
	sa, sb, ta, _ := newFaultySessionPair(t)
	sb.OnFrame(func(wire.Frame) {})

	ta.CorruptProb = 1.0
	for i := 0; i < maxDecryptFailures; i++ {
		sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 1, Payload: []byte("x")})
	}

	select {
	case <-sb.Closed():
	case <-time.After(3 * time.Second):
		t.Fatal("session survived corrupted frames")
	}
}
