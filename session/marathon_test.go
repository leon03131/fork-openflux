package session_test

// Marathon tests: many full connect/handshake/exchange/teardown cycles,
// watching runtime.NumGoroutine for linear growth (leaked writerLoop,
// watchdog, keepaliveLoop, transport dispatch or mux goroutines).
//
// This file lives in the external test package because it also exercises
// the mux layer (mux imports session — an internal test file would be an
// import cycle).

import (
	"bytes"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/mux"
	"github.com/leon03131/fork-openflux/session"
	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/wire"
)

var marathonPSK = []byte("0123456789abcdef0123456789abcdef")

// frameWaitTimeout bounds every frame/echo wait so a protocol bug fails
// the test instead of hanging it forever.
const frameWaitTimeout = 3 * time.Second

// goroutineWatch compares NumGoroutine against a post-warmup baseline.
type goroutineWatch struct{ baseline int }

// setBaseline records the reference count. The short sleep lets the last
// iteration's goroutines actually exit (GC/scheduler slack).
func (w *goroutineWatch) setBaseline(t *testing.T, iter int) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	w.baseline = runtime.NumGoroutine()
	t.Logf("iter %d: baseline goroutines = %d", iter, w.baseline)
}

// checkpoint sleeps for shutdown slack, then fails on suspicious drift.
func (w *goroutineWatch) checkpoint(t *testing.T, iter, maxDrift int) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	now := runtime.NumGoroutine()
	drift := now - w.baseline
	t.Logf("iter %d: goroutines = %d (baseline %d, drift %+d)", iter, now, w.baseline, drift)
	if drift >= maxDrift {
		t.Fatalf("goroutine leak suspected at iter %d: baseline=%d now=%d drift=%+d (max %d)",
			iter, w.baseline, now, drift, maxDrift)
	}
}

// marathonSessionPair builds two PSK sessions over a memory transport
// pair, both started (transport first, then session).
func marathonSessionPair(t *testing.T) (ta, tb *transport.MemoryTransport, sa, sb *session.Session) {
	t.Helper()
	ta, tb = transport.NewMemoryTransportPair(transport.DefaultConfig())
	if err := ta.Start(); err != nil {
		t.Fatalf("transport A start: %v", err)
	}
	if err := tb.Start(); err != nil {
		t.Fatalf("transport B start: %v", err)
	}
	sa, err := session.New(ta, marathonPSK, true)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	sb, err = session.New(tb, marathonPSK, false)
	if err != nil {
		t.Fatalf("server session: %v", err)
	}
	if err := sa.Start(); err != nil {
		t.Fatalf("client session start: %v", err)
	}
	if err := sb.Start(); err != nil {
		t.Fatalf("server session start: %v", err)
	}
	return ta, tb, sa, sb
}

// marathonHandshake runs both Handshake calls concurrently (each side
// blocks waiting for the peer) and fails on any error.
func marathonHandshake(t *testing.T, sa, sb *session.Session) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = sa.Handshake() }()
	go func() { defer wg.Done(); errs[1] = sb.Handshake() }()
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("handshake: client=%v server=%v", errs[0], errs[1])
	}
}

func TestSessionReconnectMarathon(t *testing.T) {
	const N = 200
	t.Logf("goroutines at start = %d", runtime.NumGoroutine())
	var w goroutineWatch

	for i := 1; i <= N; i++ {
		// A closure per iteration keeps defers scoped: a t.Fatalf still
		// runs the teardown instead of leaking 200 iterations of it.
		func() {
			ta, tb, sa, sb := marathonSessionPair(t)
			defer ta.Stop()
			defer tb.Stop()
			defer sa.Close()
			defer sb.Close()

			marathonHandshake(t, sa, sb)

			// One DATA frame each way; handlers buffer exactly one frame
			// so the dispatch loop never blocks on us.
			gotA := make(chan wire.Frame, 1) // client receives s2c
			gotB := make(chan wire.Frame, 1) // server receives c2s
			sa.OnFrame(func(f wire.Frame) {
				if f.Type == wire.TypeData {
					gotA <- f
				}
			})
			sb.OnFrame(func(f wire.Frame) {
				if f.Type == wire.TypeData {
					gotB <- f
				}
			})

			c2s := []byte("client-to-server")
			s2c := []byte("server-to-client")
			if err := sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 1, Payload: c2s}); err != nil {
				t.Fatalf("iter %d: send c2s: %v", i, err)
			}
			if err := sb.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 2, Payload: s2c}); err != nil {
				t.Fatalf("iter %d: send s2c: %v", i, err)
			}

			select {
			case f := <-gotB:
				if !bytes.Equal(f.Payload, c2s) {
					t.Fatalf("iter %d: server got %q, want %q", i, f.Payload, c2s)
				}
			case <-time.After(frameWaitTimeout):
				t.Fatalf("iter %d: timeout waiting for c2s frame", i)
			}
			select {
			case f := <-gotA:
				if !bytes.Equal(f.Payload, s2c) {
					t.Fatalf("iter %d: client got %q, want %q", i, f.Payload, s2c)
				}
			case <-time.After(frameWaitTimeout):
				t.Fatalf("iter %d: timeout waiting for s2c frame", i)
			}
		}()

		if i == 10 {
			w.setBaseline(t, i)
		}
		if i%50 == 0 {
			w.checkpoint(t, i, 30)
		}
	}
	t.Logf("goroutines at end = %d", runtime.NumGoroutine())
}

func TestMuxReconnectMarathon(t *testing.T) {
	const N = 50
	t.Logf("goroutines at start = %d", runtime.NumGoroutine())
	var w goroutineWatch

	for i := 1; i <= N; i++ {
		func() {
			ta, tb, sa, sb := marathonSessionPair(t)
			defer ta.Stop()
			defer tb.Stop()
			// mux.Close also closes the underlying session.
			marathonHandshake(t, sa, sb)

			cm := mux.NewClientMux(sa)
			sm := mux.NewServerMux(sb)
			defer cm.Close()
			defer sm.Close()

			// Server side: accept one stream and echo it back.
			echoDone := make(chan struct{})
			go func() {
				defer close(echoDone)
				st, err := sm.Accept()
				if err != nil {
					return
				}
				defer st.Close()
				if err := st.AcceptOpen(); err != nil {
					return
				}
				st.SetDeadline(time.Now().Add(frameWaitTimeout))
				io.Copy(st, st)
			}()

			st, err := cm.Open("x", 80)
			if err != nil {
				t.Fatalf("iter %d: Open: %v", i, err)
			}
			st.SetDeadline(time.Now().Add(frameWaitTimeout))

			msg := []byte("marathon echo")
			if _, err := st.Write(msg); err != nil {
				t.Fatalf("iter %d: Write: %v", i, err)
			}
			buf := make([]byte, len(msg))
			if _, err := io.ReadFull(st, buf); err != nil {
				t.Fatalf("iter %d: echo read: %v", i, err)
			}
			if !bytes.Equal(buf, msg) {
				t.Fatalf("iter %d: echo %q, want %q", i, buf, msg)
			}
			st.Close()

			cm.Close()
			sm.Close()
			// The echo goroutine must die with the mux, not linger.
			select {
			case <-echoDone:
			case <-time.After(frameWaitTimeout):
				t.Fatalf("iter %d: echo goroutine stuck after mux close", i)
			}
		}()

		if i == 10 {
			w.setBaseline(t, i)
		}
		if i%25 == 0 {
			w.checkpoint(t, i, 30)
		}
	}
	t.Logf("goroutines at end = %d", runtime.NumGoroutine())
}
