package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeDialer struct {
	gotAddr string
	conn    net.Conn
	err     error
}

func (d *fakeDialer) DialTCP(address string) (net.Conn, error) {
	d.gotAddr = address
	return d.conn, d.err
}

// startTestServer runs handleConnection on one end of a pipe.
func startTestServer(t *testing.T, dialer Dialer) net.Conn {
	t.Helper()
	serverEnd, clientEnd := net.Pipe()
	s := NewSOCKS5Server("127.0.0.1:0", dialer)
	go s.handleConnection(serverEnd)
	t.Cleanup(func() { clientEnd.Close() })
	return clientEnd
}

func socksGreeting(t *testing.T, c net.Conn) {
	t.Helper()
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("read greeting response: %v", err)
	}
	if !bytes.Equal(resp, []byte{0x05, 0x00}) {
		t.Fatalf("bad greeting response: %v", resp)
	}
}

func readReply(t *testing.T, c net.Conn) []byte {
	t.Helper()
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return resp
}

func TestConnectIPv4(t *testing.T) {
	targetServer, targetClient := net.Pipe()
	defer targetServer.Close()
	defer targetClient.Close()

	dialer := &fakeDialer{conn: targetClient}
	c := startTestServer(t, dialer)

	socksGreeting(t, c)
	// CONNECT 1.2.3.4:80
	if _, err := c.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := readReply(t, c)
	if resp[1] != repSucceeded {
		t.Fatalf("reply = %#x, want success", resp[1])
	}
	if dialer.gotAddr != "1.2.3.4:80" {
		t.Fatalf("dialed %q, want 1.2.3.4:80", dialer.gotAddr)
	}

	// Data must flow client -> target.
	go c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(targetServer, buf); err != nil {
		t.Fatalf("target read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("target got %q", buf)
	}

	// And target -> client.
	go targetServer.Write([]byte("pong"))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("client got %q", buf)
	}
}

func TestConnectDomain(t *testing.T) {
	targetServer, targetClient := net.Pipe()
	defer targetServer.Close()
	defer targetClient.Close()

	dialer := &fakeDialer{conn: targetClient}
	c := startTestServer(t, dialer)

	socksGreeting(t, c)
	domain := "example.com"
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}, []byte(domain)...)
	req = append(req, 0x01, 0xBB) // port 443
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := readReply(t, c)
	if resp[1] != repSucceeded {
		t.Fatalf("reply = %#x, want success", resp[1])
	}
	if dialer.gotAddr != "example.com:443" {
		t.Fatalf("dialed %q, want example.com:443", dialer.gotAddr)
	}
}

func TestFragmentedWrites(t *testing.T) {
	// The old parser read the request with a single Read(); feed the
	// handshake byte-by-byte to prove framing is now correct.
	targetServer, targetClient := net.Pipe()
	defer targetServer.Close()
	defer targetClient.Close()

	dialer := &fakeDialer{conn: targetClient}
	c := startTestServer(t, dialer)

	msg := []byte{0x05, 0x01, 0x00}
	msg = append(msg, 0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x1F, 0x90)
	go func() {
		for _, b := range msg {
			if _, err := c.Write([]byte{b}); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	resp := make([]byte, 12) // 2 (method) + 10 (reply)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("bad method choice: %v", resp[:2])
	}
	if resp[2] != 0x05 || resp[3] != repSucceeded {
		t.Fatalf("bad connect reply: %v", resp[2:])
	}
	if dialer.gotAddr != "10.0.0.1:8080" {
		t.Fatalf("dialed %q, want 10.0.0.1:8080", dialer.gotAddr)
	}
}

func TestUnsupportedCommand(t *testing.T) {
	dialer := &fakeDialer{}
	c := startTestServer(t, dialer)

	socksGreeting(t, c)
	// BIND is not supported. Write in background: net.Pipe is synchronous
	// and the server stops reading after the 4-byte header.
	go c.Write([]byte{0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
	resp := readReply(t, c)
	if resp[1] != repCommandNotSupported {
		t.Fatalf("reply = %#x, want command-not-supported", resp[1])
	}
}

func TestUnsupportedAddressType(t *testing.T) {
	dialer := &fakeDialer{}
	c := startTestServer(t, dialer)

	socksGreeting(t, c)
	if _, err := c.Write([]byte{0x05, 0x01, 0x00, 0x7F}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := readReply(t, c)
	if resp[1] != repAddressTypeNotSupported {
		t.Fatalf("reply = %#x, want atyp-not-supported", resp[1])
	}
}

func TestBadVersion(t *testing.T) {
	dialer := &fakeDialer{}
	c := startTestServer(t, dialer)

	// Write in background: server reads only the 2-byte header before closing.
	go c.Write([]byte{0x04, 0x01, 0x00})
	// Server must close the connection without a reply.
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected connection close")
	}
}

func TestNoAcceptableMethods(t *testing.T) {
	dialer := &fakeDialer{}
	c := startTestServer(t, dialer)

	// Offer only GSSAPI (0x01), no no-auth.
	if _, err := c.Write([]byte{0x05, 0x01, 0x01}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp[1] != 0xFF {
		t.Fatalf("method = %#x, want 0xFF (no acceptable methods)", resp[1])
	}
}

func TestDialFailure(t *testing.T) {
	dialer := &fakeDialer{err: errors.New("boom")}
	c := startTestServer(t, dialer)

	socksGreeting(t, c)
	if _, err := c.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := readReply(t, c)
	if resp[1] == repSucceeded {
		t.Fatal("expected failure reply")
	}
}

func TestConnectIPv6(t *testing.T) {
	targetServer, targetClient := net.Pipe()
	defer targetServer.Close()
	defer targetClient.Close()

	dialer := &fakeDialer{conn: targetClient}
	c := startTestServer(t, dialer)

	socksGreeting(t, c)
	req := []byte{0x05, 0x01, 0x00, 0x04}
	req = append(req, make([]byte, 15)...)
	req = append(req, 1)       // ::1
	req = append(req, 0, 0x50) // port 80
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := readReply(t, c)
	if resp[1] != repSucceeded {
		t.Fatalf("reply = %#x, want success", resp[1])
	}
	if dialer.gotAddr != "[::1]:80" {
		t.Fatalf("dialed %q, want [::1]:80", dialer.gotAddr)
	}
}

// TestRelayPropagatesError: the client dies abruptly mid-data; the target
// must observe the teardown (EOF/error), not hang waiting for more.
func TestRelayPropagatesError(t *testing.T) {
	targetServer, targetClient := net.Pipe()
	defer targetServer.Close()
	defer targetClient.Close()

	dialer := &fakeDialer{conn: targetClient}
	c := startTestServer(t, dialer)

	socksGreeting(t, c)
	if _, err := c.Write([]byte{0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := readReply(t, c)
	if resp[1] != repSucceeded {
		t.Fatalf("reply = %#x, want success", resp[1])
	}

	// Some data flows, then the client vanishes mid-stream.
	go c.Write([]byte("partial"))
	buf := make([]byte, 7)
	if _, err := io.ReadFull(targetServer, buf); err != nil {
		t.Fatalf("target read: %v", err)
	}
	c.Close()

	// The target must see the closure promptly (a timeout = relay hung).
	targetServer.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := targetServer.Read(make([]byte, 1)); err == nil {
		t.Fatal("target must see the connection closed after client abort")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("target hung: client abort was not propagated")
	}
}

// trackConn is an in-memory net.Conn that records Close/CloseWrite calls
// and fails reads with readErr when set (io.EOF once closed otherwise).
type trackConn struct {
	readErr error

	closed    chan struct{}
	closeOnce sync.Once
	wroteFin  chan struct{}
	finOnce   sync.Once
}

func newTrackConn() *trackConn {
	return &trackConn{closed: make(chan struct{}), wroteFin: make(chan struct{})}
}

func (c *trackConn) Read([]byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	<-c.closed
	return 0, io.EOF
}

func (c *trackConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	default:
		return len(b), nil
	}
}

func (c *trackConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *trackConn) CloseWrite() error {
	c.finOnce.Do(func() { close(c.wroteFin) })
	return nil
}

type dummyAddr string

func (a dummyAddr) Network() string { return "dummy" }
func (a dummyAddr) String() string  { return string(a) }

func (c *trackConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *trackConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *trackConn) SetDeadline(time.Time) error      { return nil }
func (c *trackConn) SetReadDeadline(time.Time) error  { return nil }
func (c *trackConn) SetWriteDeadline(time.Time) error { return nil }

// TestRelayAbortsOnError: a hard read failure (not EOF) must fully Close
// BOTH sides; turning it into CloseWrite would disguise the abort as a
// clean FIN.
func TestRelayAbortsOnError(t *testing.T) {
	client := newTrackConn()
	client.readErr = errors.New("connection reset by peer")
	target := newTrackConn()

	done := make(chan struct{})
	go func() {
		relay(client, target)
		close(done)
	}()

	select {
	case <-target.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("target not closed after client failure")
	}
	select {
	case <-target.wroteFin:
		t.Fatal("abort propagated as CloseWrite (clean FIN); want full Close")
	default:
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay hung after client failure")
	}
}

// TestRelayCleanEOFHalfClose: a graceful EOF must still propagate as a
// half-close (CloseWrite), exactly as before the error handling change.
func TestRelayCleanEOFHalfClose(t *testing.T) {
	client := newTrackConn()
	target := newTrackConn()

	done := make(chan struct{})
	go func() {
		relay(client, target)
		close(done)
	}()

	// Client finishes gracefully: EOF -> CloseWrite on the target.
	client.Close()
	select {
	case <-target.wroteFin:
	case <-time.After(2 * time.Second):
		t.Fatal("clean EOF must propagate as CloseWrite")
	}

	// The target answers the FIN with its own EOF; relay must terminate.
	target.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay hung after clean shutdown")
	}
}
