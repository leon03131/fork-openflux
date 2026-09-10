// Package wire implements the OpenFlux wire protocol v2: a compact binary
// framing format carried over any reliable ordered message transport
// (the Carrier). Frames below the session/mux layers.
//
// Frame layout (12-byte header + payload):
//
//	0  : magic[2] = 'O' 'F'
//	2  : protocol version (1 byte)
//	3  : frame type (1 byte)
//	4  : stream ID (uint32 BE)
//	8  : payload length (uint32 BE)
//	12 : payload
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

const (
	Magic0 = 'O'
	Magic1 = 'F'

	// Version is the protocol version implemented by this package.
	Version byte = 2

	HeaderSize = 12

	// MaxPayload bounds a single frame payload. Decoders validate the
	// length BEFORE allocating.
	MaxPayload = 1 << 16 // 64 KiB
)

// Frame types.
const (
	TypeHello        byte = 0x01 // handshake (payload: Hello)
	TypeHelloAck     byte = 0x02 // handshake response (payload: HelloAck)
	TypeOpen         byte = 0x03 // open stream (payload: encoded address)
	TypeOpenOK       byte = 0x04 // stream opened
	TypeOpenError    byte = 0x05 // payload: error string
	TypeData         byte = 0x06 // stream payload
	TypeWindowUpdate byte = 0x07 // payload: uint32 credit
	TypeHalfClose    byte = 0x08 // sender will not write anymore
	TypeClose        byte = 0x09 // stream closed/reset
	TypePing         byte = 0x0A // payload: uint64 timestamp (ns)
	TypePong         byte = 0x0B // payload: echoed uint64
	TypeGoAway       byte = 0x0C // session teardown
)

var (
	ErrBadMagic    = errors.New("wire: bad magic")
	ErrBadVersion  = errors.New("wire: unsupported protocol version")
	ErrTooLarge    = errors.New("wire: payload length exceeds MaxPayload")
	ErrTooShort    = errors.New("wire: frame shorter than header")
	ErrBadAddress  = errors.New("wire: malformed address")
	ErrEmptyDomain = errors.New("wire: empty domain")
)

// Frame is a single protocol message. StreamID is 0 for session-level
// frames (HELLO/PING/PONG/GOAWAY).
type Frame struct {
	Type     byte
	StreamID uint32
	Payload  []byte
}

// Encode appends the encoded frame to buf and returns the result.
func Encode(buf []byte, f Frame) ([]byte, error) {
	if len(f.Payload) > MaxPayload {
		return nil, ErrTooLarge
	}
	buf = append(buf, Magic0, Magic1, Version, f.Type)
	var tmp [8]byte
	binary.BigEndian.PutUint32(tmp[0:4], f.StreamID)
	binary.BigEndian.PutUint32(tmp[4:8], uint32(len(f.Payload)))
	buf = append(buf, tmp[:]...)
	buf = append(buf, f.Payload...)
	return buf, nil
}

// Decode parses one frame. The payload slice references the input buffer.
func Decode(data []byte) (Frame, error) {
	if len(data) < HeaderSize {
		return Frame{}, ErrTooShort
	}
	if data[0] != Magic0 || data[1] != Magic1 {
		return Frame{}, ErrBadMagic
	}
	if data[2] != Version {
		return Frame{}, fmt.Errorf("%w: %d", ErrBadVersion, data[2])
	}
	payloadLen := binary.BigEndian.Uint32(data[8:12])
	if payloadLen > MaxPayload {
		return Frame{}, ErrTooLarge
	}
	if len(data) < HeaderSize+int(payloadLen) {
		return Frame{}, ErrTooShort
	}
	return Frame{
		Type:     data[3],
		StreamID: binary.BigEndian.Uint32(data[4:8]),
		Payload:  data[HeaderSize : HeaderSize+payloadLen],
	}, nil
}

// FrameLen returns the total encoded length of the frame at the start of
// data, or an error if the header is invalid/incomplete.
func FrameLen(data []byte) (int, error) {
	if len(data) < HeaderSize {
		return 0, ErrTooShort
	}
	if data[0] != Magic0 || data[1] != Magic1 {
		return 0, ErrBadMagic
	}
	payloadLen := binary.BigEndian.Uint32(data[8:12])
	if payloadLen > MaxPayload {
		return 0, ErrTooLarge
	}
	return HeaderSize + int(payloadLen), nil
}

// --- Address encoding for TypeOpen (same ATYP scheme as SOCKS5) ---

// EncodeAddress encodes host:port into the OPEN payload form.
// host may be an IPv4, IPv6 or a domain name.
func EncodeAddress(host string, port uint16) ([]byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			out := make([]byte, 1+4+2)
			out[0] = 0x01
			copy(out[1:5], ip4)
			binary.BigEndian.PutUint16(out[5:7], port)
			return out, nil
		}
		out := make([]byte, 1+16+2)
		out[0] = 0x04
		copy(out[1:17], ip.To16())
		binary.BigEndian.PutUint16(out[17:19], port)
		return out, nil
	}
	if len(host) == 0 {
		return nil, ErrEmptyDomain
	}
	if len(host) > 255 {
		return nil, fmt.Errorf("%w: domain too long (%d)", ErrBadAddress, len(host))
	}
	out := make([]byte, 1+1+len(host)+2)
	out[0] = 0x03
	out[1] = byte(len(host))
	copy(out[2:2+len(host)], host)
	binary.BigEndian.PutUint16(out[2+len(host):4+len(host)], port)
	return out, nil
}

// DecodeAddress parses an OPEN payload back into host and port.
func DecodeAddress(data []byte) (host string, port uint16, err error) {
	if len(data) < 1 {
		return "", 0, ErrBadAddress
	}
	switch data[0] {
	case 0x01:
		if len(data) != 1+4+2 {
			return "", 0, ErrBadAddress
		}
		host = net.IP(data[1:5]).String()
		port = binary.BigEndian.Uint16(data[5:7])
	case 0x03:
		if len(data) < 2 {
			return "", 0, ErrBadAddress
		}
		dlen := int(data[1])
		if dlen == 0 {
			return "", 0, ErrEmptyDomain
		}
		if len(data) != 2+dlen+2 {
			return "", 0, ErrBadAddress
		}
		host = string(data[2 : 2+dlen])
		port = binary.BigEndian.Uint16(data[2+dlen : 4+dlen])
	case 0x04:
		if len(data) != 1+16+2 {
			return "", 0, ErrBadAddress
		}
		host = "[" + net.IP(data[1:17]).String() + "]"
		port = binary.BigEndian.Uint16(data[17:19])
	default:
		return "", 0, fmt.Errorf("%w: unknown atyp %#x", ErrBadAddress, data[0])
	}
	return host, port, nil
}

// JoinHostPort formats host and port for net.Dial (handles IPv6 brackets).
func JoinHostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}
