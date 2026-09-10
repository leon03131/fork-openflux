package tunnel

import (
	"bytes"
	"io"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/leon03131/fork-openflux/transport"
)

// newTestServerStack builds a gVisor stack that plays the role of "the
// internet" without raw sockets: a promiscuous+spoofing NIC that accepts
// packets for any destination and answers from any address.
func newTestServerStack(t *testing.T, trans transport.Transport) (*stack.Stack, *TunnelLinkEndpoint) {
	t.Helper()

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	ep := NewTunnelLinkEndpoint()
	ep.onOutgoingPacket = func(data []byte) error {
		return trans.Send(data)
	}
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("server CreateNIC: %v", err)
	}
	// Accept packets for any destination...
	if err := s.SetPromiscuousMode(1, true); err != nil {
		t.Fatalf("SetPromiscuousMode: %v", err)
	}
	// ...and reply from addresses we do not own.
	if err := s.SetSpoofing(1, true); err != nil {
		t.Fatalf("SetSpoofing: %v", err)
	}
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})

	trans.Receive(func(data []byte) {
		ep.InjectInbound(data)
	})
	return s, ep
}

// TestTunnelEndToEnd runs a real TCP connection through: client gVisor
// stack -> compressed memory transport -> server gVisor stack -> echo
// listener, and verifies data in both directions.
func TestTunnelEndToEnd(t *testing.T) {
	cfg := transport.DefaultConfig()
	ta, tb := transport.NewMemoryTransportPair(cfg)

	ca := transport.NewCompressedTransport(ta)
	cb := transport.NewCompressedTransport(tb)
	if err := ca.Start(); err != nil {
		t.Fatal(err)
	}
	if err := cb.Start(); err != nil {
		t.Fatal(err)
	}
	defer ca.Stop()
	defer cb.Stop()

	// Server side: echo listener on an address the stack does not own.
	serverStack, _ := newTestServerStack(t, cb)
	defer serverStack.Close()

	listener, err := gonet.ListenTCP(serverStack, tcpip.FullAddress{
		NIC:  1,
		Port: 8080,
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go io.Copy(conn, conn) // echo
		}
	}()

	// Client side: the real tunnel code path.
	clientTun, err := NewTCPTunnel(ca, false)
	if err != nil {
		t.Fatalf("NewTCPTunnel: %v", err)
	}
	defer clientTun.Close()

	conn, err := clientTun.DialTCP("10.9.9.9:8080")
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()

	// Packets are <= 200 bytes (small) and >= 200 bytes (compressed path).
	for _, size := range []int{5, 1000, 60000} {
		msg := bytes.Repeat([]byte("a"), size)
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("write %d: %v", size, err)
		}
		buf := make([]byte, size)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read %d: %v", size, err)
		}
		if !bytes.Equal(buf, msg) {
			t.Fatalf("echo mismatch at size %d", size)
		}
	}
}
