package mux

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/session"
	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/wire"
)

// newMuxPair builds a client/server mux pair over in-process sessions.
func newMuxPair(t *testing.T) (*Mux, *Mux) {
	t.Helper()
	return newMuxPairPSK(t, nil)
}

// newMuxPairPSK is newMuxPair with an optional PSK (nil = plaintext).
func newMuxPairPSK(t *testing.T, psk []byte) (*Mux, *Mux) {
	t.Helper()
	cm, sm, _, _ := newMuxPairSessions(t, psk)
	return cm, sm
}

// newMuxPairSessions is newMuxPairPSK that also returns the underlying
// sessions (client, server) for tests that kill a session directly.
func newMuxPairSessions(t *testing.T, psk []byte) (*Mux, *Mux, *session.Session, *session.Session) {
	t.Helper()
	ta, tb := transport.NewMemoryTransportPair(transport.DefaultConfig())
	if err := ta.Start(); err != nil {
		t.Fatal(err)
	}
	if err := tb.Start(); err != nil {
		t.Fatal(err)
	}
	sa, err := session.New(ta, psk, true)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := session.New(tb, psk, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.Start(); err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var errA, errB error
	wg.Add(2)
	go func() { defer wg.Done(); errA = sa.Handshake() }()
	go func() { defer wg.Done(); errB = sb.Handshake() }()
	wg.Wait()
	if errA != nil || errB != nil {
		t.Fatalf("handshake: %v / %v", errA, errB)
	}

	cm := NewClientMux(sa)
	sm := NewServerMux(sb)
	t.Cleanup(func() {
		cm.Close()
		sm.Close()
	})
	return cm, sm, sa, sb
}

// echoAcceptor accepts streams and echoes everything back.
func echoAcceptor(t *testing.T, m *Mux) {
	for {
		st, err := m.Accept()
		if err != nil {
			return
		}
		go func() {
			if err := st.AcceptOpen(); err != nil {
				return
			}
			io.Copy(st, st)
			st.Close()
		}()
	}
}

func TestOpenEcho(t *testing.T) {
	cm, sm := newMuxPair(t)
	go echoAcceptor(t, sm)

	st, err := cm.Open("example.com", 443)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	msg := []byte("hello mux")
	if _, err := st.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

func TestOpenRejected(t *testing.T) {
	cm, sm := newMuxPair(t)

	// Server rejects every OPEN.
	go func() {
		for {
			st, err := sm.Accept()
			if err != nil {
				return
			}
			st.RejectOpen("connection refused")
		}
	}()

	_, err := cm.Open("10.255.255.1", 1)
	if err == nil {
		t.Fatal("Open must fail")
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("error should carry peer reason, got: %v", err)
	}
}

func TestHalfClose(t *testing.T) {
	cm, sm := newMuxPair(t)

	// Server: read until EOF, then reply.
	go func() {
		for {
			st, err := sm.Accept()
			if err != nil {
				return
			}
			go func() {
				st.AcceptOpen()
				data, _ := io.ReadAll(st) // ends on client half-close
				st.Write(append([]byte("got:"), data...))
				// Graceful finish = CloseWrite (FIN semantics); Close
				// alone would be an abortive reset.
				st.CloseWrite()
				defer st.Close()
			}()
		}
	}()

	st, err := cm.Open("example.com", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := st.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "got:ping" {
		t.Fatalf("got %q", got)
	}
}

func TestFlowControlBlocksUntilRead(t *testing.T) {
	cm, sm := newMuxPair(t)

	accepted := make(chan *Stream, 1)
	go func() {
		st, err := sm.Accept()
		if err != nil {
			return
		}
		st.AcceptOpen()
		accepted <- st
	}()

	cst, err := cm.Open("example.com", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer cst.Close()
	sst := <-accepted

	// Write 2x the window without the server reading.
	total := DefaultWindowSize * 2
	writeDone := make(chan error, 1)
	go func() {
		data := bytes.Repeat([]byte("d"), total)
		_, err := cst.Write(data)
		writeDone <- err
	}()

	// The writer must block: window is 512 KiB, nobody reads.
	select {
	case <-writeDone:
		t.Fatal("write completed without the peer reading - flow control broken")
	case <-time.After(300 * time.Millisecond):
	}

	// Now drain on the server; the writer must complete.
	received := make([]byte, 0, total)
	sst.SetReadDeadline(time.Now().Add(10 * time.Second))
	for len(received) < total {
		buf := make([]byte, 64*1024)
		n, err := sst.Read(buf)
		if err != nil {
			t.Fatalf("server read: %v", err)
		}
		received = append(received, buf[:n]...)
	}

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writer never unblocked")
	}
	if len(received) != total {
		t.Fatalf("received %d, want %d", len(received), total)
	}
}

func TestConcurrentStreams(t *testing.T) {
	cm, sm := newMuxPair(t)
	go echoAcceptor(t, sm)

	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := cm.Open("example.com", 443)
			if err != nil {
				errs <- err
				return
			}
			defer st.Close()
			msg := bytes.Repeat([]byte{byte('a' + i%26)}, 10000+i)
			if _, err := st.Write(msg); err != nil {
				errs <- err
				return
			}
			buf := make([]byte, len(msg))
			st.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(st, buf); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(buf, msg) {
				errs <- errors.New("data mismatch")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent stream: %v", err)
	}
}

func TestDeadlineWakesBlockedRead(t *testing.T) {
	cm, sm := newMuxPair(t)
	go echoAcceptor(t, sm)

	st, err := cm.Open("example.com", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	// Start a Read with NO data available; it blocks. Then set a
	// deadline while blocked: the Read must wake and time out.
	readDone := make(chan error, 1)
	go func() {
		_, err := st.Read(make([]byte, 1))
		readDone <- err
	}()

	time.Sleep(100 * time.Millisecond) // let Read block
	st.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

	select {
	case err := <-readDone:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expected os.ErrDeadlineExceeded, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked Read ignored SetReadDeadline")
	}
}

func TestSetReadDeadlineWakesAllReaders(t *testing.T) {
	cm, sm := newMuxPair(t)
	go func() {
		for {
			st, err := sm.Accept()
			if err != nil {
				return
			}
			st.AcceptOpen() // never sends
		}
	}()

	st, err := cm.Open("example.com", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	// net.Conn allows concurrent Reads from multiple goroutines; one
	// SetReadDeadline must wake ALL of them.
	const readers = 3
	var wg sync.WaitGroup
	wg.Add(readers)
	errs := make([]error, readers)
	for i := 0; i < readers; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = st.Read(make([]byte, 1))
		}(i)
	}

	time.Sleep(100 * time.Millisecond)
	st.SetReadDeadline(time.Now().Add(150 * time.Millisecond))

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		for i := range errs {
			if !errors.Is(errs[i], os.ErrDeadlineExceeded) {
				t.Fatalf("reader %d: %v", i, errs[i])
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("not all readers woke up")
	}
}

func TestSetDeadlineWakesBothDirections(t *testing.T) {
	cm, sm := newMuxPair(t)

	// Server accepts but never sends anything (client Read will block)
	// and never reads (client Write will block on zero window).
	go func() {
		for {
			st, err := sm.Accept()
			if err != nil {
				return
			}
			st.AcceptOpen()
		}
	}()

	st, err := cm.Open("example.com", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	// Exhaust the send window so Write blocks.
	st.mu.Lock()
	st.sendWindow = 0
	st.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		st.Read(make([]byte, 1)) // blocks: no data
	}()
	go func() {
		defer wg.Done()
		st.Write([]byte("x")) // blocks: no window
	}()

	time.Sleep(100 * time.Millisecond) // let both block
	st.SetDeadline(time.Now().Add(200 * time.Millisecond))

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("SetDeadline did not wake both Read and Write")
	}
}

// TestConcurrentStreamsEncrypted hammers an ENCRYPTED session with 64
// concurrent streams doing simultaneous writes: the strict in-order
// sequence check must not fire on a healthy carrier, and all data must
// arrive intact. Regression test for the seq-allocation vs queue-order
// race.
func TestConcurrentStreamsEncrypted(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	cm, sm := newMuxPairPSK(t, psk)
	go echoAcceptor(t, sm)

	const n = 64
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := cm.Open("example.com", 443)
			if err != nil {
				errs <- err
				return
			}
			defer st.Close()
			// Several writes per stream to maximize interleaving.
			var expect []byte
			for j := 0; j < 4; j++ {
				expect = append(expect, bytes.Repeat([]byte{byte(i), byte(j)}, 5000)...)
			}
			if _, err := st.Write(expect); err != nil {
				errs <- err
				return
			}
			buf := make([]byte, len(expect))
			st.SetReadDeadline(time.Now().Add(15 * time.Second))
			if _, err := io.ReadFull(st, buf); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(buf, expect) {
				errs <- errors.New("data mismatch")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent encrypted stream: %v", err)
	}
}

// TestOpenRateLimit fires 300 OPENs in a row (burst is 256): the
// limiter must reject the excess with "rate limited" and nothing must
// panic or wedge.
func TestOpenRateLimit(t *testing.T) {
	cm, sm := newMuxPair(t)

	// Accept and hold every stream that passes the limiter.
	go func() {
		for {
			st, err := sm.Accept()
			if err != nil {
				return
			}
			st.AcceptOpen()
		}
	}()

	const total = 300
	var succeeded, rateLimited int
	for i := 0; i < total; i++ {
		st, err := cm.Open("example.com", 80)
		if err != nil {
			if strings.Contains(err.Error(), "rate limited") {
				rateLimited++
				continue
			}
			t.Fatalf("unexpected Open error: %v", err)
		}
		succeeded++
		defer st.Close()
	}

	if rateLimited == 0 {
		t.Fatalf("%d rapid OPENs did not trigger the rate limiter (burst %d)", total, openRateBurst)
	}
	// Upper bound with generous slack for refill on slow machines
	// (up to ~1s of refill on top of the burst).
	if succeeded > openRateBurst+openRateLimit {
		t.Fatalf("limiter let %d/%d OPENs through (burst %d)", succeeded, total, openRateBurst)
	}
	t.Logf("rate limiter: %d accepted, %d rejected", succeeded, rateLimited)
}

// TestConcurrentWritesWithDeadlines: several writers with different
// deadlines on a window-exhausted stream; each must finish by its own
// deadline, not hang behind another's.
func TestConcurrentWritesWithDeadlines(t *testing.T) {
	cm, sm := newMuxPair(t)
	go func() {
		for {
			st, err := sm.Accept()
			if err != nil {
				return
			}
			st.AcceptOpen() // never reads: window exhausts
		}
	}()

	st, err := cm.Open("example.com", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	// Exhaust the window.
	st.mu.Lock()
	st.sendWindow = 0
	st.mu.Unlock()

	var wg sync.WaitGroup
	// Writer 1: long deadline. Writer 2: short deadline — must fire first.
	start := time.Now()
	wg.Add(2)
	var e1, e2 error
	go func() { defer wg.Done(); _, e1 = st.Write([]byte("aaaa")) }()
	go func() { defer wg.Done(); _, e2 = st.Write([]byte("bb")) }()

	time.Sleep(50 * time.Millisecond) // both blocked
	st.SetWriteDeadline(start.Add(300 * time.Millisecond))

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("writers stuck behind each other's deadline")
	}
	for _, e := range []error{e1, e2} {
		if !errors.Is(e, os.ErrDeadlineExceeded) {
			t.Fatalf("want deadline exceeded, got %v", e)
		}
	}
}

// TestCloseWriteWakesBlockedWriters: writers blocked on an exhausted
// window must wake when the write side is closed.
func TestCloseWriteWakesBlockedWriters(t *testing.T) {
	cm, sm := newMuxPair(t)
	go func() {
		for {
			st, err := sm.Accept()
			if err != nil {
				return
			}
			st.AcceptOpen()
		}
	}()

	st, err := cm.Open("example.com", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	st.mu.Lock()
	st.sendWindow = 0
	st.mu.Unlock()

	const writers = 3
	var wg sync.WaitGroup
	wg.Add(writers)
	errs := make([]error, writers)
	for i := 0; i < writers; i++ {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = st.Write([]byte("x"))
		}(i)
	}

	time.Sleep(100 * time.Millisecond)
	st.CloseWrite()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		for i := range errs {
			if !errors.Is(errs[i], ErrWriteClosed) && !errors.Is(errs[i], ErrStreamClosed) {
				t.Fatalf("writer %d: unexpected error %v", i, errs[i])
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CloseWrite did not wake blocked writers")
	}
}

func TestDialTCPAdapter(t *testing.T) {
	cm, sm := newMuxPair(t)
	go echoAcceptor(t, sm)

	conn, err := cm.DialTCP("example.com:443")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
}

// TestSessionDeathPropagatesReason: when the session dies with a cause,
// that cause (not a generic ErrStreamClosed / io.EOF) must surface from
// stream Reads.
func TestSessionDeathPropagatesReason(t *testing.T) {
	cm, sm, csess, _ := newMuxPairSessions(t, nil)
	go echoAcceptor(t, sm)

	st, err := cm.Open("example.com", 443)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	// Sanity: the stream works before the kill.
	if _, err := st.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := io.ReadFull(st, make([]byte, 1)); err != nil {
		t.Fatalf("Read before kill: %v", err)
	}

	csess.CloseWithError(errors.New("boom-test"))

	// The next Read blocks until the session-death teardown lands, then
	// must return the cause (the deadline is only an anti-hang guard).
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = st.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("Read must fail after session death")
	}
	if !strings.Contains(err.Error(), "boom-test") {
		t.Fatalf("Read error must carry the session cause, got: %v", err)
	}
	if errors.Is(err, ErrStreamClosed) || errors.Is(err, io.EOF) {
		t.Fatalf("Read returned a generic error instead of the cause: %v", err)
	}
}

// TestWindowUpdateCoalescing pushes 4 MiB through an echo stream and
// counts WINDOW_UPDATE frames received by each session (counting
// wrappers around the mux frame handlers). Coalescing must keep WU
// frames far below the number of Read calls — the pre-coalescing
// behavior sent exactly one WU per Read.
func TestWindowUpdateCoalescing(t *testing.T) {
	cm, sm, csess, ssess := newMuxPairSessions(t, nil)

	// Count WINDOW_UPDATE frames flowing in each direction. No streams
	// exist yet, so re-registering the handlers loses nothing.
	var wuToClient, wuToServer atomic.Int64
	csess.OnFrame(func(f wire.Frame) {
		if f.Type == wire.TypeWindowUpdate {
			wuToClient.Add(1)
		}
		cm.handleFrame(f)
	})
	ssess.OnFrame(func(f wire.Frame) {
		if f.Type == wire.TypeWindowUpdate {
			wuToServer.Add(1)
		}
		sm.handleFrame(f)
	})

	// Echo server with a small read buffer: Read count is measurable
	// and comparable to the client's.
	var serverReads atomic.Int64
	go func() {
		st, err := sm.Accept()
		if err != nil {
			return
		}
		if err := st.AcceptOpen(); err != nil {
			return
		}
		buf := make([]byte, 8192)
		for {
			n, err := st.Read(buf)
			if n > 0 {
				serverReads.Add(1)
				if _, werr := st.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	st, err := cm.Open("example.com", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	const total = 4 << 20 // 4 MiB
	data := make([]byte, total)
	for i := range data {
		data[i] = byte(i)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := st.Write(data)
		writeDone <- err
	}()

	var clientReads int64
	received := 0
	buf := make([]byte, 8192)
	st.SetReadDeadline(time.Now().Add(60 * time.Second))
	for received < total {
		n, err := st.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if !bytes.Equal(buf[:n], data[received:received+n]) {
			t.Fatal("echo data mismatch")
		}
		received += n
		clientReads++
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Let in-flight frames and the final timer-driven flush land.
	time.Sleep(300 * time.Millisecond)

	wu := wuToClient.Load() + wuToServer.Load()
	reads := clientReads + serverReads.Load()
	// Threshold-driven minimum is ~2*(4MiB/64KiB) = 128 WU total; the
	// old code would have sent exactly `reads`.
	t.Logf("4 MiB echo: %d reads, %d WINDOW_UPDATE frames (pre-coalescing: %d)", reads, wu, reads)
	if wu == 0 {
		t.Fatal("no WINDOW_UPDATE frames observed")
	}
	if wu*4 > reads {
		t.Fatalf("WINDOW_UPDATE not coalesced: %d WU for %d reads", wu, reads)
	}
	// Absolute bound with generous slack for timer flushes on stalls.
	if wu > 512 {
		t.Fatalf("too many WINDOW_UPDATE frames: %d", wu)
	}
}

// TestHalfCloseThenDeathReturnsError: a graceful half-close followed by
// session death must NOT report a clean EOF after the drain — the tail
// of the data may have died with the carrier.
func TestHalfCloseThenDeathReturnsError(t *testing.T) {
	cm, sm, csess, _ := newMuxPairSessions(t, nil)

	accepted := make(chan *Stream, 1)
	go func() {
		st, err := sm.Accept()
		if err != nil {
			return
		}
		st.AcceptOpen()
		accepted <- st
	}()

	st, err := cm.Open("example.com", 80)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	sst := <-accepted

	// The peer sends data, then gracefully half-closes (FIN).
	if _, err := sst.Write([]byte("partial")); err != nil {
		t.Fatalf("peer Write: %v", err)
	}
	if err := sst.CloseWrite(); err != nil {
		t.Fatalf("peer CloseWrite: %v", err)
	}

	// Drain the data...
	buf := make([]byte, 64)
	n, err := st.Read(buf)
	if err != nil || string(buf[:n]) != "partial" {
		t.Fatalf("drain Read: n=%d err=%v", n, err)
	}
	// ...and wait for the half-close to actually arrive.
	wait := time.Now().Add(5 * time.Second)
	for {
		st.mu.Lock()
		eof := st.readEOF
		st.mu.Unlock()
		if eof {
			break
		}
		if time.Now().After(wait) {
			t.Fatal("half-close never arrived")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Now the session dies before any further data.
	csess.CloseWithError(errors.New("boom-test"))

	// Wait for the teardown to land on the stream: closedCh closes
	// after resetErr is set (happens-before via the channel close).
	// A Read issued earlier would race the mux's death goroutine and
	// could legitimately still see the clean EOF.
	select {
	case <-st.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("stream was not torn down after session death")
	}

	_, err = st.Read(buf)
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("Read after half-close + session death must be an error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "boom-test") {
		t.Fatalf("Read error must carry the session cause, got: %v", err)
	}
}
