// Package soak runs a long-lived end-to-end stress test of the v2 stack:
// mux streams over encrypted sessions over a fault-injecting carrier.
//
// Unlike the unit-style fault tests (session/fault_test.go), which verify
// that a session DIES LOUDLY on a specific fault, this test verifies that
// the supervisor pattern from main.go runV2 keeps the tunnel usable
// indefinitely: sessions die on faults, get rebuilt over the same
// transports, and streams keep flowing.
//
// Duration is controlled by OPENFLUX_SOAK (e.g. "60s"); default 45s.
// Run with: go test -v ./soak/ -timeout <duration+60s>
package soak

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/mux"
	"github.com/leon03131/fork-openflux/session"
	"github.com/leon03131/fork-openflux/transport"
)

var soakPSK = []byte("0123456789abcdef0123456789abcdef")

// errTeardown closes old-generation sessions with a FATAL error so their
// writerLoop exits immediately instead of draining dead-generation frames
// into the next session's receive callback (see writerLoop's drain path:
// it only drains on a graceful close).
var errTeardown = errors.New("soak: supervisor teardown")

// errDataMismatch marks echo payload corruption — never a tolerated error.
var errDataMismatch = errors.New("soak: echo payload mismatch")

const (
	soakWorkers       = 8
	streamDeadline    = 30 * time.Second // deadlock guard per stream
	disconnectEvery   = 5 * time.Second
	maxGoroutineDrift = 20
	settleTime        = 2 * time.Second
)

type soakStats struct {
	success    atomic.Int64 // full echo round-trips verified byte-for-byte
	errors     atomic.Int64 // stream attempts killed by faults/rebuilds
	mismatches atomic.Int64 // data corruption — always a bug
	rebuilds   atomic.Int64 // session pairs successfully established
}

func TestSoak(t *testing.T) {
	duration := 45 * time.Second
	if v := os.Getenv("OPENFLUX_SOAK"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("bad OPENFLUX_SOAK %q: %v", v, err)
		}
		duration = d
	}
	t.Logf("soak duration: %v", duration)

	goroutinesBefore := runtime.NumGoroutine()

	ta, tb := transport.NewFaultyPair(transport.DefaultConfig())
	// Soft random faults in both directions: every one of them breaks the
	// reliable+ordered carrier contract eventually, killing the session.
	ta.DropProb, tb.DropProb = 0.01, 0.01
	ta.DupProb, tb.DupProb = 0.01, 0.01
	ta.CorruptProb, tb.CorruptProb = 0.005, 0.005
	if err := ta.Start(); err != nil {
		t.Fatal(err)
	}
	if err := tb.Start(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var st soakStats
	var curMux atomic.Pointer[mux.Mux]

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); supervise(ctx, t, ta, tb, &curMux, &st) }()
	wg.Add(1)
	go func() { defer wg.Done(); faultInjector(ctx, ta, tb) }()
	for i := 0; i < soakWorkers; i++ {
		wg.Add(1)
		go func(id int) { defer wg.Done(); worker(ctx, id, &curMux, &st) }(i)
	}
	wg.Wait() // returns once ctx expired and every goroutine above exited

	ta.Stop()
	tb.Stop()

	// Settle: session writerLoops (graceful drain <= 2s), echo goroutines
	// and transport dispatchLoops all need slack to actually exit.
	time.Sleep(settleTime)
	goroutinesAfter := runtime.NumGoroutine()

	t.Logf("streams ok=%d errors=%d mismatches=%d session (re)builds=%d",
		st.success.Load(), st.errors.Load(), st.mismatches.Load(), st.rebuilds.Load())
	t.Logf("goroutines: before=%d after=%d drift=%+d",
		goroutinesBefore, goroutinesAfter, goroutinesAfter-goroutinesBefore)

	if st.mismatches.Load() > 0 {
		t.Errorf("data corruption: %d echo mismatches", st.mismatches.Load())
	}
	if st.success.Load() == 0 {
		t.Error("no successful echo stream in the whole soak run")
	}
	if drift := goroutinesAfter - goroutinesBefore; drift >= maxGoroutineDrift {
		t.Errorf("goroutine leak suspected: before=%d after=%d drift=%+d (max %d)",
			goroutinesBefore, goroutinesAfter, drift, maxGoroutineDrift)
	}
}

// supervise mirrors main.go runV2: build a session pair over the (already
// started) transports, handshake, publish a fresh client mux, run until
// either session dies, then tear everything down and rebuild.
func supervise(ctx context.Context, t *testing.T, ta, tb *transport.FaultyTransport, curMux *atomic.Pointer[mux.Mux], st *soakStats) {
	t.Helper()
	for ctx.Err() == nil {
		sa, err := session.New(ta, soakPSK, true)
		if err != nil {
			t.Logf("supervisor: session.New client: %v", err)
			return
		}
		sb, err := session.New(tb, soakPSK, false)
		if err != nil {
			t.Logf("supervisor: session.New server: %v", err)
			sa.CloseWithError(errTeardown)
			return
		}
		sa.Start()
		sb.Start()

		// Both Handshake calls block on each other — run concurrently.
		hs := make(chan error, 2)
		go func() { hs <- sa.Handshake() }()
		go func() { hs <- sb.Handshake() }()
		var herr error
		for i := 0; i < 2; i++ {
			select {
			case e := <-hs:
				if e != nil && herr == nil {
					herr = e
				}
			case <-ctx.Done():
				sa.CloseWithError(errTeardown)
				sb.CloseWithError(errTeardown)
				<-hs
				<-hs
				return
			}
		}
		if herr != nil {
			sa.CloseWithError(errTeardown)
			sb.CloseWithError(errTeardown)
			t.Logf("supervisor: handshake: %v (retrying)", herr)
			if !sleepCtx(ctx, 200*time.Millisecond) {
				return
			}
			continue
		}

		cm := mux.NewClientMux(sa)
		sm := mux.NewServerMux(sb)
		curMux.Store(cm)
		n := st.rebuilds.Add(1)
		go echoAcceptor(sm)

		var reason error
		select {
		case <-ctx.Done():
			reason = ctx.Err()
		case <-sa.Closed():
			reason = fmt.Errorf("client session: %w", sa.Err())
		case <-sb.Closed():
			reason = fmt.Errorf("server session: %w", sb.Err())
		}
		t.Logf("supervisor: session #%d down (%v), rebuilding", n, reason)

		curMux.Store(nil)
		// Fatal teardown first: skips the graceful writerLoop drain, so
		// no dead-generation frames leak into the next session pair.
		sa.CloseWithError(errTeardown)
		sb.CloseWithError(errTeardown)
		cm.Close()
		sm.Close()
		if !sleepCtx(ctx, 150*time.Millisecond) {
			return
		}
	}
}

// echoAcceptor is the exit-side echo server for one mux generation: accept
// streams until the mux dies, echo every accepted stream back to itself.
func echoAcceptor(m *mux.Mux) {
	for {
		s, err := m.Accept()
		if err != nil {
			return
		}
		go func() {
			defer s.Close()
			if err := s.AcceptOpen(); err != nil {
				return
			}
			io.Copy(s, s) // exits on EOF (half-close) or stream death
		}()
	}
}

// faultInjector severs both transports every few seconds, then restores
// them after a short random outage. The session watchdog must notice and
// the supervisor must rebuild.
func faultInjector(ctx context.Context, ta, tb *transport.FaultyTransport) {
	rng := rand.New(rand.NewSource(1))
	ticker := time.NewTicker(disconnectEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		ta.SetConnected(false)
		tb.SetConnected(false)
		outage := time.Duration(100+rng.Intn(400)) * time.Millisecond
		select {
		case <-ctx.Done():
			ta.SetConnected(true)
			tb.SetConnected(true)
			return
		case <-time.After(outage):
		}
		ta.SetConnected(true)
		tb.SetConnected(true)
	}
}

// worker loops echo round-trips over the current client mux until ctx
// ends. Stream-level errors are EXPECTED (sessions die on injected faults)
// and counted; only a payload mismatch is a correctness failure.
func worker(ctx context.Context, id int, curMux *atomic.Pointer[mux.Mux], st *soakStats) {
	rng := rand.New(rand.NewSource(int64(id+1) * 7919))
	for ctx.Err() == nil {
		m := curMux.Load()
		if m == nil {
			// Session is being rebuilt.
			if !sleepCtx(ctx, 50*time.Millisecond) {
				return
			}
			continue
		}
		err := echoRoundtrip(m, rng)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err == nil:
			st.success.Add(1)
		case errors.Is(err, errDataMismatch):
			st.mismatches.Add(1)
		default:
			st.errors.Add(1)
			// The session may be mid-rebuild: brief backoff before retry.
			if !sleepCtx(ctx, 50+time.Duration(rng.Intn(150))*time.Millisecond) {
				return
			}
		}
	}
}

// echoRoundtrip opens one stream, writes a random payload (100B-50KB),
// reads the echo back and verifies it byte-for-byte. Every fourth stream
// uses CloseWrite (half-close) and reads to EOF instead of ReadFull.
func echoRoundtrip(m *mux.Mux, rng *rand.Rand) error {
	n := 100 + rng.Intn(50*1024-100)
	payload := make([]byte, n)
	rng.Read(payload)

	s, err := m.Open("soak.echo", 443)
	if err != nil {
		return err
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(streamDeadline))

	if rng.Intn(4) == 0 {
		// Half-close path: the echo server drains to EOF, then closes.
		if _, err := s.Write(payload); err != nil {
			return err
		}
		if err := s.CloseWrite(); err != nil {
			return err
		}
		got, err := io.ReadAll(s)
		if err != nil {
			return err
		}
		if len(got) != n {
			// NOT data corruption: mux closeNoSend marks a killed
			// stream readEOF, so a session death mid-round-trip
			// surfaces here as a clean EOF with a truncated echo.
			return fmt.Errorf("short echo: %d of %d bytes (stream died)", len(got), n)
		}
		if !bytes.Equal(got, payload) {
			return fmt.Errorf("%w: half-close %s", errDataMismatch, firstDiff(got, payload))
		}
		return nil
	}

	if _, err := s.Write(payload); err != nil {
		return err
	}
	got := make([]byte, n)
	if _, err := io.ReadFull(s, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("%w: %s", errDataMismatch, firstDiff(got, payload))
	}
	return nil
}

// firstDiff describes the first byte offset where got and want diverge.
func firstDiff(got, want []byte) string {
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	off := 0
	for off < n && got[off] == want[off] {
		off++
	}
	return fmt.Sprintf("first diff at byte %d of %d", off, len(want))
}

// sleepCtx sleeps for d or until ctx ends; reports whether it slept fully.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
