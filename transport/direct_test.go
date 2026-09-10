package transport

import (
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
