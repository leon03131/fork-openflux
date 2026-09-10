package tunnel

import (
	"fmt"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/utils"
)

type TCPTunnel struct {
	gvisorStack *stack.Stack
	tunnelEP    *TunnelLinkEndpoint
	transport   transport.Transport
	isExitNode  bool
	rawEP       *RawSocketEndpoint
	startTime   time.Time
}

func NewTCPTunnel(trans transport.Transport, isExitNode bool) (*TCPTunnel, error) {
	t := &TCPTunnel{
		transport:  trans,
		isExitNode: isExitNode,
		startTime:  time.Now(),
	}

	utils.Debugf("[TUNNEL] Net stack init...")
	t.gvisorStack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	if err := t.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: 65536, Default: 262144, Max: 1048576}); err != nil {
		return nil, fmt.Errorf("set TCP recv buffer: %v", err)
	}
	if err := t.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPSendBufferSizeRangeOption{Min: 65536, Default: 262144, Max: 1048576}); err != nil {
		return nil, fmt.Errorf("set TCP send buffer: %v", err)
	}

	tunnelEP := NewTunnelLinkEndpoint()
	tunnelEP.onOutgoingPacket = func(data []byte) error {
		return trans.Send(data)
	}
	t.tunnelEP = tunnelEP

	tunnelNIC := tcpip.NICID(1)
	if err := t.gvisorStack.CreateNIC(tunnelNIC, tunnelEP); err != nil {
		return nil, fmt.Errorf("create tunnel NIC: %v", err)
	}

	var err error
	if isExitNode {
		err = t.setupExitNode(tunnelNIC)
	} else {
		err = t.setupClient(tunnelNIC)
	}
	if err != nil {
		return nil, err
	}

	trans.Receive(func(data []byte) {
		tunnelEP.InjectInbound(data)
	})

	go t.printStats()
	return t, nil
}

func (t *TCPTunnel) setupExitNode(tunnelNIC tcpip.NICID) error {
	localIP, err := detectLocalIP()
	if err != nil {
		return err
	}
	utils.Debugf("[TUNNEL] EXIT NODE - Local IP: %s", net.IP(localIP[:]))

	rawEP, err := NewRawSocketEndpoint(tcpip.NICID(2), localIP)
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}

	t.rawEP = rawEP
	rawEP.SetTransportSender(func(data []byte) {
		if err := t.transport.Send(data); err != nil {
			utils.Debugf("[TUNNEL] transport send failed: %v", err)
		}
	})

	internetNIC := tcpip.NICID(2)
	if err := t.gvisorStack.CreateNIC(internetNIC, rawEP); err != nil {
		return fmt.Errorf("create internet NIC: %v", err)
	}

	if err := t.gvisorStack.AddProtocolAddress(internetNIC, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(localIP),
			PrefixLen: 24,
		},
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("add internet NIC address: %v", err)
	}

	if err := t.gvisorStack.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		return fmt.Errorf("enable forwarding: %v", err)
	}
	t.gvisorStack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         internetNIC,
	})

	tunnelSubnet := tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFrom4([4]byte{10, 10, 10, 0}),
		PrefixLen: 24,
	}.Subnet()
	t.gvisorStack.AddRoute(tcpip.Route{
		Destination: tunnelSubnet,
		NIC:         tunnelNIC,
	})
	return nil
}

func (t *TCPTunnel) setupClient(tunnelNIC tcpip.NICID) error {
	if err := t.gvisorStack.AddProtocolAddress(tunnelNIC, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(tunnelClientIP),
			PrefixLen: 24,
		},
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("add tunnel NIC address: %v", err)
	}

	t.gvisorStack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         tunnelNIC,
	})
	return nil
}

func (t *TCPTunnel) DialTCP(address string) (net.Conn, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}

	ip := tcpAddr.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("IPv6 not supported")
	}

	nic := tcpip.NICID(1)
	if t.isExitNode {
		nic = tcpip.NICID(2)
	}

	conn, err := gonet.DialTCP(t.gvisorStack, tcpip.FullAddress{
		NIC:  nic,
		Addr: tcpip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]}),
		Port: uint16(tcpAddr.Port),
	}, ipv4.ProtocolNumber)

	return conn, err
}

func (t *TCPTunnel) ListenTCP(port uint16) (net.Listener, error) {
	return gonet.ListenTCP(t.gvisorStack, tcpip.FullAddress{
		NIC:  1,
		Port: port,
	}, ipv4.ProtocolNumber)
}

func (t *TCPTunnel) printStats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := t.gvisorStack.Stats()
		var rawIn, rawOut uint64
		if t.rawEP != nil {
			rawIn = t.rawEP.packetIn.Load()
			rawOut = t.rawEP.packetOut.Load()
		}
		utils.Debugf("[STATS] uptime=%v tunnel_in=%d tunnel_out=%d raw_in=%d raw_out=%d connected=%d established=%d retrans=%d",
			time.Since(t.startTime).Round(time.Second),
			t.tunnelEP.packetIn.Load(),
			t.tunnelEP.packetOut.Load(),
			rawIn,
			rawOut,
			stats.TCP.CurrentConnected.Value(),
			stats.TCP.CurrentEstablished.Value(),
			stats.TCP.Retransmits.Value(),
		)
	}
}
