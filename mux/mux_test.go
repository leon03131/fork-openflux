package mux

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/session"
	"github.com/leon03131/fork-openflux/transport"
)

// newMuxPair builds a client/server mux pair over in-process sessions.
func newMuxPair(t *testing.T) (*Mux, *Mux) {
	t.Helper()
	return newMuxPairPSK(t, nil)
}

// newMuxPairPSK is newMuxPair with an optional PSK (nil = plaintext).
func newMuxPairPSK(t *testing.T, psk []byte) (*Mux, *Mux) {
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
	return cm, sm
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
				st.Close()
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
