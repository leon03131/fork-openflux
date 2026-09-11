package transport

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/pierrec/lz4/v4"

	"github.com/leon03131/fork-openflux/utils"
)

const (
	// MinCompressSize is the payload size below which compression is skipped.
	MinCompressSize = 200

	// CompressionMarker prefixes LZ4-compressed frames.
	CompressionMarker byte = 0x1F

	// markerRaw prefixes frames stored without compression.
	markerRaw byte = 0x00

	// maxDecompressedSize bounds decompression of untrusted input.
	maxDecompressedSize = 1 << 20 // 1 MiB
)

var (
	// ErrUnknownMarker is returned when a frame has an unrecognized
	// compression marker byte.
	ErrUnknownMarker = errors.New("transport: unknown compression marker")

	// ErrFrameTooLarge is returned when a decompressed frame exceeds
	// maxDecompressedSize.
	ErrFrameTooLarge = errors.New("transport: decompressed frame too large")
)

type CompressedTransport struct {
	Transport
}

func NewCompressedTransport(inner Transport) Transport {
	return &CompressedTransport{Transport: inner}
}

func (c *CompressedTransport) Send(data []byte) error {
	compressed := compress(data)
	return c.Transport.Send(compressed)
}

func (c *CompressedTransport) Receive(callback func([]byte)) {
	c.Transport.Receive(func(data []byte) {
		decompressed, err := decompress(data)
		if err != nil {
			// Drop malformed frames instead of forwarding garbage
			// into the network stack.
			utils.Debugf("[COMPRESS] dropping malformed frame: %v", err)
			return
		}
		callback(decompressed)
	})
}

func compress(data []byte) []byte {
	if len(data) <= MinCompressSize {
		return append([]byte{markerRaw}, data...)
	}

	var buf bytes.Buffer
	buf.WriteByte(CompressionMarker)

	w := lz4.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return append([]byte{markerRaw}, data...)
	}
	if err := w.Close(); err != nil {
		return append([]byte{markerRaw}, data...)
	}

	if buf.Len() >= len(data)+1 {
		return append([]byte{markerRaw}, data...)
	}

	return buf.Bytes()
}

func decompress(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("transport: empty frame")
	}

	switch data[0] {
	case markerRaw:
		return data[1:], nil
	case CompressionMarker:
		r := lz4.NewReader(bytes.NewReader(data[1:]))
		out, err := io.ReadAll(io.LimitReader(r, maxDecompressedSize+1))
		if err != nil {
			return nil, fmt.Errorf("transport: lz4 decode: %w", err)
		}
		if len(out) > maxDecompressedSize {
			return nil, ErrFrameTooLarge
		}
		return out, nil
	default:
		return nil, ErrUnknownMarker
	}
}
