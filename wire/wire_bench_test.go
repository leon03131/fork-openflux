package wire

import "testing"

var benchPayload = make([]byte, 4096)

func BenchmarkEncode(b *testing.B) {
	f := Frame{Type: TypeData, StreamID: 1, Payload: benchPayload}
	buf := make([]byte, 0, HeaderSize+len(benchPayload))
	b.ReportAllocs()
	b.SetBytes(int64(len(benchPayload)))
	for i := 0; i < b.N; i++ {
		out, err := Encode(buf[:0], f)
		if err != nil {
			b.Fatal(err)
		}
		_ = out
	}
}

func BenchmarkDecode(b *testing.B) {
	f := Frame{Type: TypeData, StreamID: 1, Payload: benchPayload}
	buf, _ := Encode(nil, f)
	b.ReportAllocs()
	b.SetBytes(int64(len(benchPayload)))
	for i := 0; i < b.N; i++ {
		if _, err := Decode(buf); err != nil {
			b.Fatal(err)
		}
	}
}
