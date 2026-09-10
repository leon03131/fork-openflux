package tunnel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/leon03131/fork-openflux/network"
)

// flowCloseGrace is how long a flow stays in the closing set after a FIN/RST
// was seen, so the remaining teardown packets still get forwarded.
const flowCloseGrace = 30 * time.Second

// tunnelClientIP is the client's address inside the tunnel subnet.
var tunnelClientIP = [4]byte{10, 10, 10, 2}

// tcpFlag masks.
const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10
)

// rawSocketState holds the platform-independent state and packet logic of
// the exit-node raw socket endpoint. Platform files embed it and provide
// only socket creation, recv/send syscalls and Close.
type rawSocketState struct {
	dispatcher stack.NetworkDispatcher
	nicID      tcpip.NICID

	packetIn  atomic.Uint64
	packetOut atomic.Uint64

	// outgoingSYNs holds SEQ numbers of SYN packets sent to the internet,
	// used to validate incoming SYN-ACKs.
	outgoingSYNs sync.Map // uint32 -> struct{}
	// activeFlows holds local ports with live tunneled connections.
	// Only packets destined to these ports are forwarded to the tunnel.
	activeFlows sync.Map // uint16 -> struct{}
	// closingFlows marks flows that saw FIN/RST; removed after grace period.
	closingFlows sync.Map // uint16 -> time.Time

	sendToTransport func([]byte)
	localIP         [4]byte
}

func newRawSocketState(nicID tcpip.NICID, localIP [4]byte) *rawSocketState {
	return &rawSocketState{
		nicID:   nicID,
		localIP: localIP,
	}
}

// SetTransportSender sets the callback used to forward packets
// arriving from the internet into the tunnel transport.
func (s *rawSocketState) SetTransportSender(sendFunc func([]byte)) {
	s.sendToTransport = sendFunc
}

// detectLocalIP determines the primary outbound IPv4 address. It is called
// once at startup; there is no fake fallback address.
func detectLocalIP() ([4]byte, error) {
	var zero [4]byte
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return zero, fmt.Errorf("detect local IP: %w", err)
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return zero, fmt.Errorf("detect local IP: unexpected address type %T", conn.LocalAddr())
	}
	ip4 := addr.IP.To4()
	if ip4 == nil {
		return zero, fmt.Errorf("detect local IP: %s is not IPv4", addr.IP)
	}
	var out [4]byte
	copy(out[:], ip4)
	return out, nil
}

// handleIncomingPacket processes one raw packet read from the OS socket.
// buf must hold exactly n valid bytes starting at the IP header.
func (s *rawSocketState) handleIncomingPacket(buf []byte, n int) {
	s.sweepClosingFlows()

	// IPv4 header (>=20 bytes) + TCP header (>=20 bytes).
	if n < 20 {
		return
	}
	ihl := int(buf[0]&0x0F) * 4
	if ihl < 20 || n < ihl+20 {
		return
	}
	if buf[9] != 6 { // TCP only
		return
	}
	if !bytes.Equal(buf[16:20], s.localIP[:]) {
		return
	}

	tcp := buf[ihl:n]
	dstPort := binary.BigEndian.Uint16(tcp[2:4])

	if _, active := s.activeFlows.Load(dstPort); !active {
		return
	}

	flags := tcp[13]
	if flags&(tcpFlagSYN|tcpFlagACK) == tcpFlagSYN|tcpFlagACK {
		ackNum := binary.BigEndian.Uint32(tcp[8:12])
		synSeq := ackNum - 1
		if _, ok := s.outgoingSYNs.Load(synSeq); !ok {
			return
		}
		s.outgoingSYNs.Delete(synSeq)
	}

	if flags&(tcpFlagFIN|tcpFlagRST) != 0 {
		s.closingFlows.Store(dstPort, time.Now())
	}

	pktCopy := make([]byte, n)
	copy(pktCopy, buf[:n])

	// Rewrite destination to the tunnel client address.
	copy(pktCopy[16:20], tunnelClientIP[:])
	rewriteChecksums(pktCopy, ihl)

	s.packetIn.Add(1)
	if s.sendToTransport != nil {
		s.sendToTransport(pktCopy)
	}
}

// prepareOutgoing rewrites a packet produced by the gVisor stack so it can
// be sent to the internet: source IP becomes the host's real address and
// checksums are recomputed. It also tracks flow state. Returns the modified
// copy and the destination address.
func (s *rawSocketState) prepareOutgoing(ipPacket []byte) (prepared []byte, dst [4]byte, ok bool) {
	if len(ipPacket) < 20 {
		return nil, dst, false
	}
	ihl := int(ipPacket[0]&0x0F) * 4
	if ihl < 20 || len(ipPacket) < ihl+20 {
		return nil, dst, false
	}

	pkt := make([]byte, len(ipPacket))
	copy(pkt, ipPacket)

	copy(pkt[12:16], s.localIP[:])
	rewriteChecksums(pkt, ihl)

	tcp := pkt[ihl:]
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	flags := tcp[13]

	if flags&tcpFlagSYN != 0 {
		seq := binary.BigEndian.Uint32(tcp[4:8])
		s.outgoingSYNs.Store(seq, struct{}{})
		s.activeFlows.Store(srcPort, struct{}{})
	}
	if flags&(tcpFlagFIN|tcpFlagRST) != 0 {
		s.closingFlows.Store(srcPort, time.Now())
	}

	copy(dst[:], pkt[16:20])
	return pkt, dst, true
}

// rewriteChecksums recomputes IPv4 header and TCP checksums in place.
// pkt must be a valid IPv4+TCP packet and ihl its IP header length in bytes.
func rewriteChecksums(pkt []byte, ihl int) {
	pkt[10], pkt[11] = 0, 0
	ipSum := network.IPChecksum(pkt[:ihl])
	binary.BigEndian.PutUint16(pkt[10:12], ipSum)

	tcp := pkt[ihl:]
	tcp[16], tcp[17] = 0, 0
	var src, dst [4]byte
	copy(src[:], pkt[12:16])
	copy(dst[:], pkt[16:20])
	tcpSum := network.TCPChecksum(tcp, src, dst)
	binary.BigEndian.PutUint16(tcp[16:18], tcpSum)
}

// sweepClosingFlows removes flows that have been closing longer than
// flowCloseGrace. It is called from the receive path (no extra goroutine).
func (s *rawSocketState) sweepClosingFlows() {
	now := time.Now()
	s.closingFlows.Range(func(key, value any) bool {
		t, ok := value.(time.Time)
		if !ok || now.Sub(t) > flowCloseGrace {
			s.activeFlows.Delete(key)
			s.closingFlows.Delete(key)
		}
		return true
	})
}

// --- stack.LinkEndpoint boilerplate (promoted to the platform endpoint) ---

func (s *rawSocketState) MTU() uint32                    { return 1500 }
func (s *rawSocketState) MaxHeaderLength() uint16        { return 0 }
func (s *rawSocketState) LinkAddress() tcpip.LinkAddress { return "" }
func (s *rawSocketState) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}
func (s *rawSocketState) Attach(dispatcher stack.NetworkDispatcher) {
	s.dispatcher = dispatcher
}
func (s *rawSocketState) IsAttached() bool                        { return s.dispatcher != nil }
func (s *rawSocketState) Wait()                                   {}
func (s *rawSocketState) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (s *rawSocketState) AddHeader(*stack.PacketBuffer)           {}
func (s *rawSocketState) SetMTU(uint32)                           {}
func (s *rawSocketState) SetLinkAddress(tcpip.LinkAddress)        {}
func (s *rawSocketState) ParseHeader(*stack.PacketBuffer) bool    { return true }
func (s *rawSocketState) SetOnCloseAction(func())                 {}
