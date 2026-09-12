package exit

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/mux"
	"github.com/leon03131/fork-openflux/session"
	"github.com/leon03131/fork-openflux/transport"
)

// newExitPair returns a connected client mux / exit mux pair over
// in-process sessions.
func newExitPair(t *testing.T) (*mux.Mux, *mux.Mux) {
	t.Helper()
	ta, tb := transport.NewMemoryTransportPair(transport.DefaultConfig())
	if err := ta.Start(); err != nil {
		t.Fatal(err)
	}
	if err := tb.Start(); err != nil {
		t.Fatal(err)
	}
	sa, err := session.New(ta, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := session.New(tb, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := sa.Start(); err != nil {
		t.Fatal(err)
	}
	if err := sb.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sa.Handshake() }()
	if err := sb.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	cm := mux.NewClientMux(sa)
	em := mux.NewServerMux(sb)
	t.Cleanup(func() {
		cm.Close()
		em.Close()
	})
	return cm, em
}

// TestExitEndToEnd runs the full v2 pipeline in-process:
//
//	client mux -> session -> memory transport -> session -> exit server
//	-> real TCP echo server on localhost
//
// The dial target is given as a HOSTNAME to prove that DNS resolution
// happens on the exit side.
func TestExitEndToEnd(t *testing.T) {
	// Real echo server.
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	go func() {
		for {
			c, err := echoListener.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	echoPort := echoListener.Addr().(*net.TCPAddr).Port

	// Session pair.
	ta, tb := transport.NewMemoryTransportPair(transport.DefaultConfig())
	ta.Start()
	tb.Start()
	sa, _ := session.New(ta, nil, true)
	sb, _ := session.New(tb, nil, false)
	sa.Start()
	sb.Start()
	done := make(chan struct{})
	go func() { sa.Handshake(); close(done) }()
	if err := sb.Handshake(); err != nil {
		t.Fatal(err)
	}
	<-done

	clientMux := mux.NewClientMux(sa)
	exitMux := mux.NewServerMux(sb)
	defer clientMux.Close()
	defer exitMux.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go NewServer(exitMux).Serve(ctx)

	// Dial the echo server BY HOSTNAME through the tunnel.
	conn, err := clientMux.DialTCP(net.JoinHostPort("localhost", strconv.Itoa(echoPort)))
	if err != nil {
		t.Fatalf("DialTCP via exit: %v", err)
	}
	defer conn.Close()

	msg := bytes.Repeat([]byte("hello-exit"), 5000) // 50 KiB
	go conn.Write(msg)

	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatal("echo mismatch")
	}
}

// TestExitDialCap fills the dial semaphore to simulate maxConcurrentDials
// dials already in flight: the next stream must be rejected with
// "exit busy". Once the slots are freed, dials must go through again.
func TestExitDialCap(t *testing.T) {
	clientMux, exitMux := newExitPair(t)

	srv := NewServer(exitMux)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Occupy every dial slot.
	for i := 0; i < maxConcurrentDials; i++ {
		srv.dialSem <- struct{}{}
	}

	go func() {
		for {
			st, err := exitMux.Accept()
			if err != nil {
				return
			}
			go srv.handle(ctx, st)
		}
	}()

	_, err := clientMux.Open("127.0.0.1", 1)
	if err == nil {
		t.Fatal("Open must be rejected when all dial slots are busy")
	}
	if !strings.Contains(err.Error(), "exit busy") {
		t.Fatalf("expected \"exit busy\" rejection, got: %v", err)
	}

	// Free the slots: the next OPEN must pass the semaphore and fail at
	// the real dial instead (nothing listens on the port).
	for i := 0; i < maxConcurrentDials; i++ {
		<-srv.dialSem
	}
	_, err = clientMux.Open("127.0.0.1", 1)
	if err == nil {
		t.Fatal("Open to a closed port must fail")
	}
	if !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("expected \"dial failed\" rejection, got: %v", err)
	}
}

// TestRelayPropagatesError: the client vanishes mid-stream (abrupt CLOSE,
// not a graceful half-close); the exit must tear down the destination
// connection so it observes the closure instead of hanging.
func TestRelayPropagatesError(t *testing.T) {
	// Destination that reads but never closes on its own.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	clientMux, exitMux := newExitPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go NewServer(exitMux).Serve(ctx)

	st, err := clientMux.DialTCP(listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP via exit: %v", err)
	}

	var target net.Conn
	select {
	case target = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("exit never dialed the destination")
	}
	defer target.Close()

	// Some data flows, then the client aborts mid-stream.
	if _, err := st.Write([]byte("partial")); err != nil {
		t.Fatalf("write: %v", err)
	}
	target.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(target, make([]byte, 7)); err != nil {
		t.Fatalf("target read: %v", err)
	}
	st.Close()

	// The destination must see the closure promptly (a timeout = relay
	// hung or the abort was swallowed).
	target.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := target.Read(make([]byte, 1)); err == nil {
		t.Fatal("target must see the connection closed after client abort")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("target hung: client abort was not propagated")
	}
}

// TestRelayTargetAbortNotCleanFIN checks the opposite direction: when the
// destination dies with a hard error (TCP RST), the exit must fully Close
// the stream — the client must see an abort error, not a clean EOF (FIN).
func TestRelayTargetAbortNotCleanFIN(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		// Wait for the stream to be up and carrying data (so the RST
		// cannot race the exit's dial), then abort the connection.
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Read(make([]byte, 1)); err != nil {
			c.Close()
			return
		}
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetLinger(0) // force RST, not a graceful FIN
		}
		c.Close()
	}()

	clientMux, exitMux := newExitPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go NewServer(exitMux).Serve(ctx)

	st, err := clientMux.DialTCP(listener.Addr().String())
	if err != nil {
		t.Fatalf("DialTCP via exit: %v", err)
	}
	defer st.Close()

	if _, err := st.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}

	st.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = st.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("client read must fail after destination abort")
	}
	if err == io.EOF {
		t.Fatal("destination abort reached the client as a clean EOF (FIN); want an error")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("client hung: destination abort was not propagated")
	}
}
