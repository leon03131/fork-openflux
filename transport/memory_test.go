package transport

import (
	"bytes"
	"testing"
	"time"
)

// RunConformance exercises the Transport contract against any
// implementation pair. It is used by MemoryTransport tests and can be
// reused by future carriers.
func RunConformance(t *testing.T, a, b Transport) {
	t.Helper()

	if err := a.Start(); err != nil {
		t.Fatalf("start a: %v", err)
	}
	if err := b.Start(); err != nil {
		t.Fatalf("start b: %v", err)
	}

	if !a.IsConnected() || !b.IsConnected() {
		t.Fatal("expected both endpoints connected after Start")
	}

	recvA := make(chan []byte, 16)
	recvB := make(chan []byte, 16)
	a.Receive(func(d []byte) { recvA <- d })
	b.Receive(func(d []byte) { recvB <- d })

	// a -> b
	msg := []byte("hello")
	if err := a.Send(msg); err != nil {
		t.Fatalf("send a->b: %v", err)
	}
	select {
	case got := <-recvB:
		if !bytes.Equal(got, msg) {
			t.Fatalf("b got %q, want %q", got, msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting a->b")
	}

	// b -> a
	msg2 := bytes.Repeat([]byte("x"), 4096)
	if err := b.Send(msg2); err != nil {
		t.Fatalf("send b->a: %v", err)
	}
	select {
	case got := <-recvA:
		if !bytes.Equal(got, msg2) {
			t.Fatalf("a got %d bytes, want %d", len(got), len(msg2))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting b->a")
	}

	// Stats must reflect the traffic.
	sa, sb := a.Stats(), b.Stats()
	if sa.PacketsSent != 1 || sa.PacketsRecv != 1 {
		t.Fatalf("a stats: sent=%d recv=%d, want 1/1", sa.PacketsSent, sa.PacketsRecv)
	}
	if sb.PacketsSent != 1 || sb.PacketsRecv != 1 {
		t.Fatalf("b stats: sent=%d recv=%d, want 1/1", sb.PacketsSent, sb.PacketsRecv)
	}

	// After Stop, Send must fail.
	a.Stop()
	b.Stop()
	if err := a.Send([]byte("x")); err == nil {
		t.Fatal("send after Stop must fail")
	}
}

func TestMemoryTransportConformance(t *testing.T) {
	a, b := NewMemoryTransportPair(DefaultConfig())
	RunConformance(t, a, b)
}

func TestMemoryTransportConformanceCompressed(t *testing.T) {
	a, b := NewMemoryTransportPair(DefaultConfig())
	RunConformance(t, NewCompressedTransport(a), NewCompressedTransport(b))
}
