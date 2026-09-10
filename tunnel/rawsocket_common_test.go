package tunnel

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/network"
)

var testLocalIP = [4]byte{192, 168, 1, 10}

// buildPacket creates an IPv4+TCP packet (IHL=5, zeroed checksums).
func buildPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32, flags byte) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	totalLen := len(pkt)
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	return pkt
}

func TestPrepareOutgoingTracksSYNFlow(t *testing.T) {
	s := newRawSocketState(2, testLocalIP)

	pkt := buildPacket(tunnelClientIP, [4]byte{8, 8, 8, 8}, 40000, 443, 1000, 0, tcpFlagSYN)
	out, dst, ok := s.prepareOutgoing(pkt)
	if !ok {
		t.Fatal("prepareOutgoing rejected valid packet")
	}

	if dst != [4]byte{8, 8, 8, 8} {
		t.Fatalf("dst = %v", dst)
	}
	// Source IP must be rewritten to the host address.
	if got := out[12:16]; !equalBytes(got, testLocalIP[:]) {
		t.Fatalf("srcIP not rewritten: %v", got)
	}
	// Flow must be tracked by the LOCAL port.
	if _, active := s.activeFlows.Load(uint16(40000)); !active {
		t.Fatal("local port not in activeFlows after SYN")
	}
	if _, ok := s.outgoingSYNs.Load(uint32(1000)); !ok {
		t.Fatal("SYN seq not tracked")
	}
	// Checksums must be valid: recomputing over the packet yields 0.
	if sum := network.IPChecksum(out[:20]); sum != 0 {
		t.Fatalf("bad IP checksum (%#04x)", sum)
	}
	var src, dstA [4]byte
	copy(src[:], out[12:16])
	copy(dstA[:], out[16:20])
	if sum := network.TCPChecksum(out[20:], src, dstA); sum != 0 {
		t.Fatalf("bad TCP checksum (%#04x)", sum)
	}
}

func TestIncomingOnlyForActiveFlows(t *testing.T) {
	s := newRawSocketState(2, testLocalIP)

	var forwarded [][]byte
	s.sendToTransport = func(b []byte) { forwarded = append(forwarded, b) }

	// No active flow: packet to random port must be dropped.
	srv := [4]byte{8, 8, 8, 8}
	in := buildPacket(srv, testLocalIP, 443, 40000, 5000, 0, tcpFlagACK)
	s.handleIncomingPacket(in, len(in))
	if len(forwarded) != 0 {
		t.Fatal("packet forwarded for inactive flow")
	}

	// Activate flow via outgoing SYN.
	outPkt := buildPacket(tunnelClientIP, srv, 40000, 443, 1000, 0, tcpFlagSYN)
	if _, _, ok := s.prepareOutgoing(outPkt); !ok {
		t.Fatal("prepareOutgoing failed")
	}

	// Pure ACK data packet now passes.
	s.handleIncomingPacket(in, len(in))
	if len(forwarded) != 1 {
		t.Fatalf("expected 1 forwarded packet, got %d", len(forwarded))
	}

	// Destination must be rewritten to the tunnel client.
	fwd := forwarded[0]
	if got := fwd[16:20]; !equalBytes(got, tunnelClientIP[:]) {
		t.Fatalf("dstIP not rewritten to tunnel client: %v", got)
	}
	if sum := network.IPChecksum(fwd[:20]); sum != 0 {
		t.Fatalf("bad IP checksum in forwarded packet (%#04x)", sum)
	}
}

func TestIncomingSYNACKRequiresTrackedSYN(t *testing.T) {
	s := newRawSocketState(2, testLocalIP)

	var forwarded [][]byte
	s.sendToTransport = func(b []byte) { forwarded = append(forwarded, b) }

	srv := [4]byte{8, 8, 8, 8}
	outPkt := buildPacket(tunnelClientIP, srv, 40000, 443, 1000, 0, tcpFlagSYN)
	s.prepareOutgoing(outPkt)

	// SYN-ACK with wrong ack number (not synSeq+1) must be dropped.
	bad := buildPacket(srv, testLocalIP, 443, 40000, 5000, 9999, tcpFlagSYN|tcpFlagACK)
	s.handleIncomingPacket(bad, len(bad))
	if len(forwarded) != 0 {
		t.Fatal("SYN-ACK with unknown seq was forwarded")
	}

	// Correct SYN-ACK (ack = 1000+1) passes.
	good := buildPacket(srv, testLocalIP, 443, 40000, 5000, 1001, tcpFlagSYN|tcpFlagACK)
	s.handleIncomingPacket(good, len(good))
	if len(forwarded) != 1 {
		t.Fatalf("valid SYN-ACK not forwarded (got %d packets)", len(forwarded))
	}
}

func TestFlowCleanupAfterFINGrace(t *testing.T) {
	s := newRawSocketState(2, testLocalIP)

	srv := [4]byte{8, 8, 8, 8}
	outPkt := buildPacket(tunnelClientIP, srv, 40000, 443, 1000, 0, tcpFlagSYN)
	s.prepareOutgoing(outPkt)

	// Outgoing FIN marks the flow as closing but keeps it active
	// so teardown packets still pass.
	fin := buildPacket(tunnelClientIP, srv, 40000, 443, 2000, 1001, tcpFlagFIN|tcpFlagACK)
	s.prepareOutgoing(fin)

	if _, active := s.activeFlows.Load(uint16(40000)); !active {
		t.Fatal("flow removed too early (right after FIN)")
	}
	if _, closing := s.closingFlows.Load(uint16(40000)); !closing {
		t.Fatal("flow not marked closing after FIN")
	}

	// Incoming FIN-ACK still forwarded during grace period.
	var forwarded [][]byte
	s.sendToTransport = func(b []byte) { forwarded = append(forwarded, b) }
	inFin := buildPacket(srv, testLocalIP, 443, 40000, 6000, 2001, tcpFlagFIN|tcpFlagACK)
	s.handleIncomingPacket(inFin, len(inFin))
	if len(forwarded) != 1 {
		t.Fatal("teardown packet dropped during grace period")
	}

	// Simulate grace expiry.
	s.closingFlows.Store(uint16(40000), time.Now().Add(-2*flowCloseGrace))
	s.sweepClosingFlows()
	if _, active := s.activeFlows.Load(uint16(40000)); active {
		t.Fatal("flow not removed after grace expiry")
	}
	if _, closing := s.closingFlows.Load(uint16(40000)); closing {
		t.Fatal("closing entry not swept")
	}
}

func TestPrepareOutgoingRejectsMalformed(t *testing.T) {
	s := newRawSocketState(2, testLocalIP)

	if _, _, ok := s.prepareOutgoing([]byte{0x45}); ok {
		t.Fatal("accepted short packet")
	}

	bad := buildPacket(tunnelClientIP, [4]byte{8, 8, 8, 8}, 1, 2, 0, 0, 0)
	bad[0] = 0x41 // invalid IHL
	if _, _, ok := s.prepareOutgoing(bad); ok {
		t.Fatal("accepted invalid IHL")
	}
}

func TestHandleIncomingRejectsMalformed(t *testing.T) {
	s := newRawSocketState(2, testLocalIP)
	s.sendToTransport = func(b []byte) { t.Error("forwarded malformed packet") }

	s.handleIncomingPacket([]byte{0x45, 0x00}, 2)
	s.handleIncomingPacket(make([]byte, 40), 40) // dstIP != localIP anyway
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
