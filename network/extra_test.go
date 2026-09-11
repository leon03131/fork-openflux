package network

import (
	"math/rand"
	"testing"
)

// TestIPChecksumIdempotent is a property test over random headers: when
// the checksum field (bytes 10-11) carries the value IPChecksum computed
// over the same packet with that field zeroed, recomputing the checksum
// over the full packet must yield zero (RFC 1071 verification step).
// Complements FuzzChecksums/FuzzParsePacketInfo (checksum_test.go), which
// only check the no-panic property.
func TestIPChecksumIdempotent(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	buf := make([]byte, 64)
	for iter := 0; iter < 20000; iter++ {
		// 12..64 bytes: always room for the checksum field, mixed parity.
		n := 12 + rng.Intn(len(buf)-11)
		pkt := buf[:n]
		rng.Read(pkt)
		pkt[10], pkt[11] = 0, 0
		sum := IPChecksum(pkt)
		pkt[10] = byte(sum >> 8)
		pkt[11] = byte(sum & 0xFF)
		if got := IPChecksum(pkt); got != 0 {
			t.Fatalf("iter %d: len=%d sum=%#04x, recompute=%#04x, want 0", iter, n, sum, got)
		}
	}
}

// TestTCPChecksumRoundtrip is the same property for TCPChecksum with its
// pseudo-header: inserting the computed checksum into bytes 16-17 of a
// segment (computed with the field zeroed) must make the recompute zero,
// for any segment length parity and any src/dst addresses.
func TestTCPChecksumRoundtrip(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	buf := make([]byte, 128)
	for iter := 0; iter < 20000; iter++ {
		// 18..128 bytes: always room for the checksum field, mixed parity.
		n := 18 + rng.Intn(len(buf)-17)
		seg := buf[:n]
		rng.Read(seg)
		var src, dst [4]byte
		rng.Read(src[:])
		rng.Read(dst[:])
		seg[16], seg[17] = 0, 0
		sum := TCPChecksum(seg, src, dst)
		seg[16] = byte(sum >> 8)
		seg[17] = byte(sum & 0xFF)
		if got := TCPChecksum(seg, src, dst); got != 0 {
			t.Fatalf("iter %d: len=%d sum=%#04x, recompute=%#04x, want 0", iter, n, sum, got)
		}
	}
}
