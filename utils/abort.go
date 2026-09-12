package utils

import "net"

// AbortConn force-closes a connection. For TCP it sets SO_LINGER=0
// first, so the peer receives RST (abortive) instead of a clean FIN —
// an abort must not look like a graceful end-of-stream.
func AbortConn(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	c.Close()
}
