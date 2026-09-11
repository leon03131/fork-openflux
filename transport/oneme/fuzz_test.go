package oneme

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/pierrec/lz4/v4"
)

// vcpSeed builds a valid vcp blob for the seed corpus: 3-digit
// decompressed-size prefix, one separator byte, base64(lz4(payload)).
func vcpSeed(t *testing.F, payload string) string {
	t.Helper()
	buf := make([]byte, lz4.CompressBlockBound(len(payload)))
	n, err := lz4.CompressBlock([]byte(payload), buf, nil)
	if err != nil {
		t.Fatalf("lz4.CompressBlock: %v", err)
	}
	return fmt.Sprintf("%03d|%s", len(payload), base64.StdEncoding.EncodeToString(buf[:n]))
}

// FuzzDecodeCallDetails feeds untrusted vcp strings (incoming-call
// payloads arriving over the MAX websocket) into the size-prefix +
// base64 + lz4 decoder. Rule: it must never panic, and a successful
// decode must stay within the maxVCPSize bound.
func FuzzDecodeCallDetails(f *testing.F) {
	f.Add(vcpSeed(f, "hello")) // valid vcp: "005|UGhlbGxv"
	f.Add("")
	f.Add("-12")
	f.Add("999")
	f.Add("0050aGVsbG8=") // valid base64, not an lz4 block
	f.Add("9999xxxx")     // in-range size, garbage payload
	f.Add("000|AAAA")     // zero size
	f.Add("abc!@#$%^&*()")
	f.Add("\x00\x01\x02\x03\x04")
	f.Fuzz(func(t *testing.T, vcp string) {
		out, err := decodeCallDetails(vcp)
		if err == nil && len(out) > maxVCPSize {
			t.Fatalf("decoded %d bytes, bound is %d", len(out), maxVCPSize)
		}
	})
}
