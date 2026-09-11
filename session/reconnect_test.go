package session_test

// True-reconnect tests: unlike marathon_test.go (a fresh transport pair
// per cycle), here ONE FaultyTransport pair lives for the whole test,
// playing the role of a long-lived carrier (yandex/oneme style). The
// test itself plays the supervisor from main.go runV2: after a carrier
// break kills the session pair, it restores link connectivity and builds
// a FRESH session pair over the SAME transports (session.Start simply
// re-registers the Receive callback).
//
// Note on the break step: BOTH endpoints are severed. A one-sided
// SetConnected(false) is noticed only by that side's watchdog; the peer
// would linger until the 45s keepalive timeout. A real carrier drop is
// visible at both ends, so both are flipped.

import (
	"bytes"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/session"
	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/wire"
)

// reconnectHandshake runs both Handshake calls concurrently with a hard
// 10s deadline (session.Handshake itself allows up to HelloTimeout=15s,
// so the test deadline always fires first on a stall).
func reconnectHandshake(t *testing.T, iter int, sa, sb *session.Session) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = sa.Handshake() }()
	go func() { defer wg.Done(); errs[1] = sb.Handshake() }()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("iter %d: handshake did not finish within 10s", iter)
	}
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("iter %d: handshake: client=%v server=%v", iter, errs[0], errs[1])
	}
}

// reconnectExchange pushes 3 DATA frames each way and verifies ordered,
// uncorrupted delivery via OnFrame on the peer side.
func reconnectExchange(t *testing.T, iter int, sa, sb *session.Session) {
	t.Helper()
	gotA := make(chan wire.Frame, 8) // client inbox (s2c)
	gotB := make(chan wire.Frame, 8) // server inbox (c2s)
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

	for k := 0; k < 3; k++ {
		c2s := []byte(fmt.Sprintf("iter-%d-c2s-%d", iter, k))
		s2c := []byte(fmt.Sprintf("iter-%d-s2c-%d", iter, k))
		if err := sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 1, Payload: c2s}); err != nil {
			t.Fatalf("iter %d: send c2s #%d: %v", iter, k, err)
		}
		if err := sb.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 2, Payload: s2c}); err != nil {
			t.Fatalf("iter %d: send s2c #%d: %v", iter, k, err)
		}
	}
	// Strict ordering: frame #k must arrive exactly as the k-th send.
	for k := 0; k < 3; k++ {
		want := []byte(fmt.Sprintf("iter-%d-c2s-%d", iter, k))
		select {
		case f := <-gotB:
			if !bytes.Equal(f.Payload, want) {
				t.Fatalf("iter %d: server frame #%d = %q, want %q", iter, k, f.Payload, want)
			}
		case <-time.After(frameWaitTimeout):
			t.Fatalf("iter %d: timeout waiting for c2s frame #%d", iter, k)
		}
	}
	for k := 0; k < 3; k++ {
		want := []byte(fmt.Sprintf("iter-%d-s2c-%d", iter, k))
		select {
		case f := <-gotA:
			if !bytes.Equal(f.Payload, want) {
				t.Fatalf("iter %d: client frame #%d = %q, want %q", iter, k, f.Payload, want)
			}
		case <-time.After(frameWaitTimeout):
			t.Fatalf("iter %d: timeout waiting for s2c frame #%d", iter, k)
		}
	}
}

// reconnectAwaitDeath waits for the session to die after the carrier
// break. The watchdog ticks once per second, so 5s is generous.
func reconnectAwaitDeath(t *testing.T, iter int, name string, s *session.Session) {
	t.Helper()
	select {
	case <-s.Closed():
		t.Logf("iter %d: %s session died: %v", iter, name, s.Err())
	case <-time.After(5 * time.Second):
		t.Fatalf("iter %d: %s session still alive 5s after carrier loss", iter, name)
	}
}

func TestTrueReconnectMarathon(t *testing.T) {
	const N = 50
	// One long-lived carrier pair for the whole marathon. The session
	// layer never stops transports, so these stay up across iterations.
	ta, tb := transport.NewFaultyPair(transport.DefaultConfig())
	if err := ta.Start(); err != nil {
		t.Fatalf("transport A start: %v", err)
	}
	if err := tb.Start(); err != nil {
		t.Fatalf("transport B start: %v", err)
	}
	defer ta.Stop()
	defer tb.Stop()

	t.Logf("goroutines at start = %d", runtime.NumGoroutine())
	var w goroutineWatch

	for i := 1; i <= N; i++ {
		// A closure per iteration keeps defers scoped: a t.Fatalf still
		// runs the teardown instead of leaking 50 iterations of it.
		func() {
			// Supervisor role: a FRESH session pair over the SAME
			// (already reconnected) carrier.
			sa, err := session.New(ta, marathonPSK, true)
			if err != nil {
				t.Fatalf("iter %d: client session: %v", i, err)
			}
			sb, err := session.New(tb, marathonPSK, false)
			if err != nil {
				t.Fatalf("iter %d: server session: %v", i, err)
			}
			if err := sa.Start(); err != nil {
				t.Fatalf("iter %d: client start: %v", i, err)
			}
			if err := sb.Start(); err != nil {
				t.Fatalf("iter %d: server start: %v", i, err)
			}
			defer sa.Close() // idempotent: already dead after the break
			defer sb.Close()

			reconnectHandshake(t, i, sa, sb)
			reconnectExchange(t, i, sa, sb)

			// Link break: both ends of the carrier lose connectivity.
			ta.SetConnected(false)
			tb.SetConnected(false)

			reconnectAwaitDeath(t, i, "client", sa)
			reconnectAwaitDeath(t, i, "server", sb)

			// Supervisor: carrier reconnects; the fresh session pair is
			// built at the top of the next iteration.
			ta.SetConnected(true)
			tb.SetConnected(true)
		}()

		if i == 5 {
			w.setBaseline(t, i)
		}
		if i%10 == 0 {
			if i == N {
				w.checkpoint(t, i, 10) // strict: drift must be < 10
			} else {
				time.Sleep(100 * time.Millisecond)
				t.Logf("iter %d: goroutines = %d (baseline %d)", i, runtime.NumGoroutine(), w.baseline)
			}
		}
	}
	t.Logf("goroutines at end = %d (baseline %d)", runtime.NumGoroutine(), w.baseline)
}

func TestQueueSaturationDies(t *testing.T) {
	// Tiny peer queue: 8 carrier messages. The exit side never consumes
	// DATA, so the queue must fill after ~9 client frames and the
	// session must react loudly instead of stalling.
	cfg := transport.DefaultConfig()
	cfg.MaxQueueSize = 8
	ta, tb := transport.NewFaultyPair(cfg)
	if err := ta.Start(); err != nil {
		t.Fatalf("transport A start: %v", err)
	}
	if err := tb.Start(); err != nil {
		t.Fatalf("transport B start: %v", err)
	}
	defer ta.Stop() // cleanup runs LIFO: transports stop last
	defer tb.Stop()

	sa, err := session.New(ta, marathonPSK, true)
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	sb, err := session.New(tb, marathonPSK, false)
	if err != nil {
		t.Fatalf("server session: %v", err)
	}
	if err := sa.Start(); err != nil {
		t.Fatalf("client start: %v", err)
	}
	if err := sb.Start(); err != nil {
		t.Fatalf("server start: %v", err)
	}
	defer sa.Close()
	defer sb.Close()

	// The exit side accepts the session but never consumes DATA: the
	// handler parks on block until test cleanup. This stalls tb's
	// dispatchLoop on the first DATA frame, modelling a peer whose
	// reader is stuck (e.g. a mux stream with a full window).
	block := make(chan struct{})
	defer close(block) // runs first (LIFO), unblocking tb.dispatchLoop
	sb.OnFrame(func(f wire.Frame) {
		if f.Type == wire.TypeData {
			<-block
		}
	})

	reconnectHandshake(t, 0, sa, sb)

	// Max legal frame: wire.MaxPayload is 64 KiB and wire.Encode rejects
	// anything larger, so 64 KiB is the biggest payload that actually
	// reaches the queues (a 200KB payload would fail inside Encode and
	// turn this into an Encode test, not a saturation test).
	payload := make([]byte, wire.MaxPayload)
	var sent atomic.Int64
	sendErr := make(chan error, 1)
	go func() {
		for {
			if err := sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 1, Payload: payload}); err != nil {
				sendErr <- err
				return
			}
			sent.Add(1)
		}
	}()

	// Saturation must be LOUD: either a session dies (writerLoop kills
	// the session when the carrier Send fails) or SendFrame starts
	// returning errors. A silent stall is a bug.
	select {
	case err := <-sendErr:
		t.Logf("SendFrame failed after %d frames (as expected): %v", sent.Load(), err)
	case <-sa.Closed():
		t.Logf("client session died after %d frames (as expected): %v", sent.Load(), sa.Err())
	case <-sb.Closed():
		t.Logf("server session died after %d frames (as expected): %v", sent.Load(), sb.Err())
	case <-time.After(10 * time.Second):
		t.Fatalf("queue saturation: %d frames sent, but no session death and no SendFrame error within 10s (silent hang)", sent.Load())
	}

	// Cross-check the sibling signals for the report.
	select {
	case <-sa.Closed():
		t.Logf("final: client session closed, err=%v", sa.Err())
	default:
		t.Logf("final: client session still open")
	}
	select {
	case <-sb.Closed():
		t.Logf("final: server session closed, err=%v", sb.Err())
	default:
		t.Logf("final: server session still open")
	}
}
