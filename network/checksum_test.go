package network

import (
	"strings"
	"testing"
)

// buildIPv4TCPPacket builds a minimal IPv4+TCP packet with the given IHL
// (in 32-bit words) and TCP flags. Payload may be nil.
func buildIPv4TCPPacket(ihlWords int, tcpFlags byte, payload []byte) []byte {
	ipHeaderLen := ihlWords * 4
	totalLen := ipHeaderLen + 20 + len(payload)
	pkt := make([]byte, totalLen)

	pkt[0] = byte(0x40 | ihlWords) // version 4, IHL
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen & 0xFF)
	pkt[8] = 64 // TTL
	pkt[9] = 6  // TCP
	copy(pkt[12:16], []byte{10, 0, 0, 1})
	copy(pkt[16:20], []byte{10, 0, 0, 2})

	tcp := pkt[ipHeaderLen:]
	tcp[0], tcp[1] = 0x30, 0x39                   // src port 12345
	tcp[2], tcp[3] = 0x01, 0xBB                   // dst port 443
	tcp[4], tcp[5], tcp[6], tcp[7] = 0, 0, 0, 1   // seq
	tcp[8], tcp[9], tcp[10], tcp[11] = 0, 0, 0, 0 // ack
	tcp[12] = 5 << 4                              // data offset
	tcp[13] = tcpFlags
	tcp[14], tcp[15] = 0xFF, 0xFF // window
	return pkt
}

func TestIPChecksumKnownVector(t *testing.T) {
	// RFC 1071 example header (without checksum): 45 00 00 73 00 00 40 00
	// 40 11 c0 a8 00 01 c0 a8 00 c7 -> checksum 0x20EE (known vector variant)
	header := []byte{
		0x45, 0x00, 0x00, 0x73,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00,
		0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
	}
	sum := IPChecksum(header)
	// Verify by inserting the checksum: recomputed checksum over full header must be 0.
	header[10] = byte(sum >> 8)
	header[11] = byte(sum & 0xFF)
	if got := IPChecksum(header); got != 0 {
		t.Fatalf("checksum over header with inserted checksum = %#04x, want 0", got)
	}
}

func TestTCPChecksumVerifyByInsertion(t *testing.T) {
	src := [4]byte{192, 168, 0, 1}
	dst := [4]byte{192, 168, 0, 2}
	tcp := []byte{
		0x30, 0x39, 0x01, 0xBB, // ports
		0, 0, 0, 1, // seq
		0, 0, 0, 0, // ack
		0x50, 0x02, 0x20, 0x00, // offset, flags, window
		0, 0, 0, 0, // checksum, urg
	}
	sum := TCPChecksum(tcp, src, dst)
	tcp[16] = byte(sum >> 8)
	tcp[17] = byte(sum & 0xFF)
	if got := TCPChecksum(tcp, src, dst); got != 0 {
		t.Fatalf("checksum over segment with inserted checksum = %#04x, want 0", got)
	}
}

func TestParsePacketInfoBasic(t *testing.T) {
	pkt := buildIPv4TCPPacket(5, 0x02, nil) // SYN
	info := ParsePacketInfo(pkt)
	if !strings.Contains(info, "10.0.0.1:12345 -> 10.0.0.2:443") {
		t.Fatalf("unexpected info: %s", info)
	}
	if !strings.Contains(info, "SYN") {
		t.Fatalf("expected SYN flag in: %s", info)
	}
}

func TestParsePacketInfoWithIPOptions(t *testing.T) {
	pkt := buildIPv4TCPPacket(6, 0x10, nil) // IHL=6 (4 bytes of options), ACK
	info := ParsePacketInfo(pkt)
	if !strings.Contains(info, "10.0.0.1:12345 -> 10.0.0.2:443") {
		t.Fatalf("TCP fields misread with IP options present: %s", info)
	}
	if !strings.Contains(info, "ACK") {
		t.Fatalf("expected ACK flag in: %s", info)
	}
}

func TestParsePacketInfoMalformed(t *testing.T) {
	short := make([]byte, 10)
	if info := ParsePacketInfo(short); !strings.Contains(info, "short packet") {
		t.Fatalf("expected short packet note, got: %s", info)
	}

	badIHL := buildIPv4TCPPacket(5, 0x02, nil)
	badIHL[0] = 0x41 // IHL=1 (invalid, <5)
	if info := ParsePacketInfo(badIHL); !strings.Contains(info, "malformed") {
		t.Fatalf("expected malformed note, got: %s", info)
	}

	truncated := buildIPv4TCPPacket(5, 0x02, nil)[:30] // TCP header cut off
	if info := ParsePacketInfo(truncated); !strings.Contains(info, "truncated") {
		t.Fatalf("expected truncated note, got: %s", info)
	}
}

func FuzzParsePacketInfo(f *testing.F) {
	f.Add(buildIPv4TCPPacket(5, 0x02, []byte("hello")))
	f.Add([]byte{})
	f.Add(make([]byte, 20))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic.
		_ = ParsePacketInfo(data)
	})
}

func FuzzChecksums(f *testing.F) {
	f.Add([]byte{0x45, 0x00, 0x00, 0x14}, byte(1), byte(2), byte(3), byte(4))
	f.Fuzz(func(t *testing.T, data []byte, a, b, c, d byte) {
		// Must never panic.
		_ = IPChecksum(data)
		_ = TCPChecksum(data, [4]byte{a, b, c, d}, [4]byte{1, 2, 3, 4})
	})
}
