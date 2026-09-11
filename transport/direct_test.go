package transport

import (
	"bytes"
	"net"
	"testing"
)

// TestDirectTransportConformance runs the shared conformance suite over a
// real TCP loopback connection.
func TestDirectTransportConformance(t *testing.T) {
	listenAddr := freeTCPAddr(t)
	exit := NewDirectTransport(listenAddr, true, DefaultConfig())
	client := NewDirectTransport(listenAddr, false, DefaultConfig())

	// The client dials with retries until the exit side starts listening.
	RunConformance(t, client, exit)
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// partialWriteConn writes at most 7 bytes per Write call, simulating
// partial writes that desynced the stream in production.
type partialWriteConn struct {
	net.Conn
	written bytes.Buffer
}

func (c *partialWriteConn) Write(p []byte) (int, error) {
	n := min(7, len(p))
	return c.written.Write(p[:n])
}

func TestWriteAllHandlesPartialWrites(t *testing.T) {
	c := &partialWriteConn{}
	payload := make([]byte, 1000)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := writeAll(c, payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.written.Bytes(), payload) {
		t.Fatalf("partial writes lost/corrupted data: got %d bytes", c.written.Len())
	}
}
