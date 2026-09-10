package exit

import (
	"bytes"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/mux"
	"github.com/leon03131/fork-openflux/session"
	"github.com/leon03131/fork-openflux/transport"
)

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
