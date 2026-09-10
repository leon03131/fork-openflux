package transport

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestCompressRoundtripSmall(t *testing.T) {
	data := []byte("small payload")
	out, err := decompress(compress(data))
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Fatalf("roundtrip mismatch: got %q", out)
	}
}

func TestCompressRoundtripLargeCompressible(t *testing.T) {
	data := bytes.Repeat([]byte("abcdefgh"), 1024) // 8 KiB, highly compressible
	framed := compress(data)
	if framed[0] != CompressionMarker {
		t.Fatalf("expected compressed marker, got %#x", framed[0])
	}
	if len(framed) >= len(data) {
		t.Fatalf("compression ineffective: %d >= %d", len(framed), len(data))
	}
	out, err := decompress(framed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestCompressIncompressibleFallsBackToRaw(t *testing.T) {
	// Truly random data is incompressible.
	data := make([]byte, 4096)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	framed := compress(data)
	if framed[0] != markerRaw {
		t.Fatalf("expected raw marker for incompressible data, got %#x", framed[0])
	}
	out, err := decompress(framed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Fatalf("roundtrip mismatch")
	}
}

func TestDecompressRejectsUnknownMarker(t *testing.T) {
	_, err := decompress([]byte{0x42, 0x01, 0x02})
	if !errors.Is(err, ErrUnknownMarker) {
		t.Fatalf("want ErrUnknownMarker, got %v", err)
	}
}

func TestDecompressRejectsGarbageLZ4(t *testing.T) {
	_, err := decompress([]byte{CompressionMarker, 0xFF, 0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected error for garbage lz4 payload")
	}
}

func TestDecompressRejectsEmpty(t *testing.T) {
	if _, err := decompress(nil); err == nil {
		t.Fatal("expected error for empty frame")
	}
}

func FuzzDecompress(f *testing.F) {
	f.Add([]byte{markerRaw, 0x01})
	f.Add(compress(bytes.Repeat([]byte("x"), 1000)))
	f.Add([]byte{CompressionMarker})
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := decompress(data) // must never panic
		if err == nil && len(out) > maxDecompressedSize {
			t.Fatalf("decompressed size %d exceeds bound", len(out))
		}
	})
}
