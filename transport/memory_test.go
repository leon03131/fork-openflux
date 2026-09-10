package transport

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func waitConnected(t *testing.T, tr Transport) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !tr.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("transport did not become connected in 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

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

	// Some carriers connect asynchronously (direct dials with retries).
	waitConnected(t, a)
	waitConnected(t, b)

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

	// Ordering: 200 numbered messages must arrive strictly in order.
	const ordered = 200
	for i := 0; i < ordered; i++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(i))
		if err := a.Send(buf[:]); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	for i := 0; i < ordered; i++ {
		select {
		case got := <-recvB:
			if len(got) != 4 || int(binary.BigEndian.Uint32(got)) != i {
				t.Fatalf("message %d out of order: %v", i, got)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for message %d", i)
		}
	}

	// Stats must reflect the traffic (1 + 1 + ordered messages).
	sa, sb := a.Stats(), b.Stats()
	if sa.PacketsSent != 1+ordered || sa.PacketsRecv != 1 {
		t.Fatalf("a stats: sent=%d recv=%d", sa.PacketsSent, sa.PacketsRecv)
	}
	if sb.PacketsSent != 1 || sb.PacketsRecv != 1+ordered {
		t.Fatalf("b stats: sent=%d recv=%d", sb.PacketsSent, sb.PacketsRecv)
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
