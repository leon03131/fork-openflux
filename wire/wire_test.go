package wire

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeDecodeRoundtrip(t *testing.T) {
	f := Frame{Type: TypeData, StreamID: 42, Payload: []byte("hello")}
	buf, err := Encode(nil, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf) != HeaderSize+5 {
		t.Fatalf("encoded len %d", len(buf))
	}
	got, err := Decode(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != f.Type || got.StreamID != f.StreamID || !bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("mismatch: %+v", got)
	}
}

func TestDecodeRejectsBadMagic(t *testing.T) {
	buf, _ := Encode(nil, Frame{Type: TypePing})
	buf[0] = 'X'
	if _, err := Decode(buf); !errors.Is(err, ErrBadMagic) {
		t.Fatalf("want ErrBadMagic, got %v", err)
	}
}

func TestDecodeRejectsBadVersion(t *testing.T) {
	buf, _ := Encode(nil, Frame{Type: TypePing})
	buf[2] = 99
	if _, err := Decode(buf); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

func TestDecodeRejectsOversizedDeclaredLength(t *testing.T) {
	buf, _ := Encode(nil, Frame{Type: TypePing})
	// Claim a huge payload.
	buf[8], buf[9], buf[10], buf[11] = 0x7F, 0xFF, 0xFF, 0xFF
	if _, err := Decode(buf); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestDecodeRejectsTruncated(t *testing.T) {
	buf, _ := Encode(nil, Frame{Type: TypeData, Payload: []byte("hello")})
	if _, err := Decode(buf[:HeaderSize+2]); !errors.Is(err, ErrTooShort) {
		t.Fatalf("want ErrTooShort, got %v", err)
	}
	if _, err := Decode(buf[:5]); !errors.Is(err, ErrTooShort) {
		t.Fatalf("want ErrTooShort, got %v", err)
	}
}

func TestEncodeRejectsOversizedPayload(t *testing.T) {
	if _, err := Encode(nil, Frame{Type: TypeData, Payload: make([]byte, MaxPayload+1)}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestFrameLen(t *testing.T) {
	buf, _ := Encode(nil, Frame{Type: TypeData, Payload: make([]byte, 100)})
	n, err := FrameLen(buf)
	if err != nil || n != HeaderSize+100 {
		t.Fatalf("FrameLen = %d, %v", n, err)
	}
}

func TestAddressRoundtrip(t *testing.T) {
	cases := []struct {
		host string
		port uint16
	}{
		{"1.2.3.4", 80},
		{"example.com", 443},
		{"::1", 8080},
		{"2001:db8::1", 22},
	}
	for _, c := range cases {
		enc, err := EncodeAddress(c.host, c.port)
		if err != nil {
			t.Fatalf("%s: encode: %v", c.host, err)
		}
		host, port, err := DecodeAddress(enc)
		if err != nil {
			t.Fatalf("%s: decode: %v", c.host, err)
		}
		if port != c.port {
			t.Fatalf("%s: port %d != %d", c.host, port, c.port)
		}
		// Normalize IPv6 brackets for comparison.
		want := c.host
		if host[0] == '[' && want[0] != '[' {
			want = "[" + want + "]"
		}
		if host != want {
			t.Fatalf("host %q != %q", host, want)
		}
	}
}

func TestDecodeAddressRejectsGarbage(t *testing.T) {
	if _, _, err := DecodeAddress(nil); !errors.Is(err, ErrBadAddress) {
		t.Fatal("nil accepted")
	}
	if _, _, err := DecodeAddress([]byte{0x03, 0}); !errors.Is(err, ErrEmptyDomain) {
		t.Fatal("empty domain accepted")
	}
	if _, _, err := DecodeAddress([]byte{0x03, 5, 'a'}); !errors.Is(err, ErrBadAddress) {
		t.Fatal("truncated domain accepted")
	}
	if _, _, err := DecodeAddress([]byte{0x7F, 1, 2, 3}); !errors.Is(err, ErrBadAddress) {
		t.Fatal("unknown atyp accepted")
	}
}

func FuzzDecode(f *testing.F) {
	buf, _ := Encode(nil, Frame{Type: TypeData, StreamID: 7, Payload: []byte("seed")})
	f.Add(buf)
	f.Add([]byte{})
	f.Add([]byte{Magic0, Magic1})
	f.Fuzz(func(t *testing.T, data []byte) {
		fr, err := Decode(data) // must never panic
		if err == nil {
			if len(fr.Payload) > MaxPayload {
				t.Fatal("payload exceeds bound")
			}
			// Re-encoding a successfully decoded frame must work.
			if _, err := Encode(nil, fr); err != nil {
				t.Fatalf("re-encode: %v", err)
			}
		}
	})
}

func FuzzDecodeAddress(f *testing.F) {
	f.Add([]byte{0x01, 1, 2, 3, 4, 0, 80})
	f.Add([]byte{0x03, 3, 'a', 'b', 'c', 1, 187})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeAddress(data) // must never panic
	})
}
