package volga

import (
	"bytes"
	"testing"
)

// FuzzDecodeBlob feeds untrusted blob binaries into the marker check +
// length-prefix splitter. Rule: never panic; a rejected blob returns nil;
// an accepted packet set re-encodes (with the same marker) into a blob
// that decodes to the same packets.
func FuzzDecodeBlob(f *testing.F) {
	marker := []byte(framePrefixFor("https://disk.yandex.ru/i/fuzz"))
	valid := encodeBlob(marker, [][]byte{[]byte("hello"), {0x00, 0xFF}, []byte("world")})

	f.Add(valid)
	f.Add(encodeBlob(marker, nil))                                     // keepalive form
	f.Add([]byte{})                                                    // empty
	f.Add(marker)                                                      // marker only
	f.Add([]byte("OFX1deadbeef:\x00\x00\x00\x05a"))                    // foreign marker
	f.Add(append(append([]byte{}, marker...), 0x7F, 0xFF, 0xFF, 0xFF)) // oversize length
	f.Add(append(append([]byte{}, marker...), 0, 0, 0, 5, 'a'))        // truncated payload
	f.Add(bytes.Repeat([]byte{0x41}, 300))

	f.Fuzz(func(t *testing.T, data []byte) {
		packets := decodeBlob(data, marker)
		if packets == nil {
			return
		}
		if len(packets) > maxBatchPackets {
			t.Fatalf("decodeBlob returned %d packets, cap is %d", len(packets), maxBatchPackets)
		}
		again := decodeBlob(encodeBlob(marker, packets), marker)
		if len(again) != len(packets) {
			t.Fatalf("roundtrip mismatch: %d packets re-decoded to %d", len(packets), len(again))
		}
		for i := range packets {
			if !bytes.Equal(again[i], packets[i]) {
				t.Fatalf("packet %d changed in roundtrip", i)
			}
		}
	})
}
