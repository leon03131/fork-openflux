package socks5

import (
	"errors"
	"net"
	"testing"
	"time"
)

// FuzzNegotiate throws arbitrary bytes at the SOCKS5 handshake parser.
// The parser must never panic and must terminate.
func FuzzNegotiate(f *testing.F) {
	// Valid-ish seeds.
	f.Add([]byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
	f.Add([]byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 11})
	f.Add([]byte{})
	f.Add([]byte{0x05})
	f.Fuzz(func(t *testing.T, data []byte) {
		serverEnd, clientEnd := net.Pipe()
		defer clientEnd.Close()

		dialer := &fakeDialer{err: errors.New("no dial in fuzz")}
		s := NewSOCKS5Server("127.0.0.1:0", dialer)
		go s.handleConnection(serverEnd)

		// Bounded writes/reads: net.Pipe is synchronous, so a dead
		// parser would otherwise hang the fuzz worker.
		clientEnd.SetDeadline(time.Now().Add(500 * time.Millisecond))
		clientEnd.Write(data)
		buf := make([]byte, 64)
		clientEnd.Read(buf) // ignore result; server may legitimately close
		clientEnd.Close()
		serverEnd.Close()
	})
}
