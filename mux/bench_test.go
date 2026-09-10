package mux

import (
	"io"
	"testing"

	"github.com/leon03131/fork-openflux/session"
	"github.com/leon03131/fork-openflux/transport"
)

// BenchmarkStreamThroughput measures end-to-end stream throughput over an
// in-process memory carrier pair (no network, no disk).
func BenchmarkStreamThroughput(b *testing.B) {
	ta, tb := transport.NewMemoryTransportPair(transport.DefaultConfig())
	ta.Start()
	tb.Start()
	sa, _ := session.New(ta, nil, true)
	sb, _ := session.New(tb, nil, false)
	sa.Start()
	sb.Start()
	done := make(chan error, 2)
	go func() { done <- sa.Handshake() }()
	go func() { done <- sb.Handshake() }()
	<-done
	<-done

	cm := NewClientMux(sa)
	sm := NewServerMux(sb)
	defer cm.Close()
	defer sm.Close()

	go func() {
		for {
			st, err := sm.Accept()
			if err != nil {
				return
			}
			go func() {
				st.AcceptOpen()
				io.Copy(io.Discard, st) // sink
			}()
		}
	}()

	st, err := cm.Open("bench", 1)
	if err != nil {
		b.Fatal(err)
	}

	chunk := make([]byte, 64*1024)
	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
}
