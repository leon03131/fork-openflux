package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/leon03131/fork-openflux/utils"
)

// SOCKS5 protocol constants (RFC 1928).
const (
	socksVersion5 = 0x05

	cmdConnect = 0x01
	// BIND (0x02) and UDP ASSOCIATE (0x03) are intentionally not supported.

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded               = 0x00
	repGeneralFailure          = 0x01
	repHostUnreachable         = 0x04
	repCommandNotSupported     = 0x07
	repAddressTypeNotSupported = 0x08

	methodNoAuth = 0x00

	handshakeTimeout = 30 * time.Second
	dialTimeout      = 20 * time.Second
)

type Dialer interface {
	DialTCP(address string) (net.Conn, error)
}

type SOCKS5Server struct {
	listenAddr string
	dialer     Dialer

	mu       sync.Mutex
	listener net.Listener
}

func NewSOCKS5Server(addr string, dialer Dialer) *SOCKS5Server {
	return &SOCKS5Server{listenAddr: addr, dialer: dialer}
}

// Close stops accepting new connections; Start returns nil afterwards.
func (s *SOCKS5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *SOCKS5Server) Start() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	defer listener.Close()

	utils.Debugf("[SOCKS5] Listening on %s", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			// A permanent listener error (e.g. closed socket) must not
			// spin the loop forever.
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && !ne.Timeout() {
				return err
			}
			utils.Debugf("[SOCKS5] Accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *SOCKS5Server) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Bound the whole handshake so idle peers cannot hold goroutines forever.
	clientConn.SetDeadline(time.Now().Add(handshakeTimeout))
	defer clientConn.SetDeadline(time.Time{})

	targetAddr, replyCode, err := s.negotiate(clientConn)
	if err != nil {
		utils.Debugf("[SOCKS5] Handshake error: %v", err)
		if replyCode != repSucceeded {
			s.writeReply(clientConn, replyCode)
		}
		return
	}

	utils.Debugf("[SOCKS5] CONNECT %s", targetAddr)

	targetConn, err := s.dialWithTimeout(targetAddr)
	if err != nil {
		utils.Debugf("[SOCKS5] Dial failed: %v", err)
		s.writeReply(clientConn, repHostUnreachable)
		return
	}
	defer targetConn.Close()

	if err := s.writeReply(clientConn, repSucceeded); err != nil {
		return
	}

	// Handshake done; streaming below must not be deadline-bound.
	clientConn.SetDeadline(time.Time{})

	relay(clientConn, targetConn)
}

// negotiate parses the method-negotiation and the CONNECT request.
// It returns the target address, or a SOCKS reply code describing the failure.
func (s *SOCKS5Server) negotiate(conn net.Conn) (target string, replyCode byte, err error) {
	// --- Method negotiation: VER NMETHODS METHODS... ---
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", repSucceeded, fmt.Errorf("read greeting: %w", err)
	}
	if head[0] != socksVersion5 {
		return "", repSucceeded, fmt.Errorf("unsupported version %#x", head[0])
	}
	nMethods := int(head[1])
	if nMethods == 0 {
		return "", repSucceeded, fmt.Errorf("no auth methods offered")
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", repSucceeded, fmt.Errorf("read methods: %w", err)
	}

	offered := false
	for _, m := range methods {
		if m == methodNoAuth {
			offered = true
			break
		}
	}
	if !offered {
		// 0xFF = no acceptable methods.
		conn.Write([]byte{socksVersion5, 0xFF})
		return "", repSucceeded, fmt.Errorf("client does not offer no-auth method")
	}
	if _, err := conn.Write([]byte{socksVersion5, methodNoAuth}); err != nil {
		return "", repSucceeded, fmt.Errorf("write method choice: %w", err)
	}

	// --- Request: VER CMD RSV ATYP DST.ADDR DST.PORT ---
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return "", repSucceeded, fmt.Errorf("read request header: %w", err)
	}
	if req[0] != socksVersion5 {
		return "", repSucceeded, fmt.Errorf("bad request version %#x", req[0])
	}
	if req[1] != cmdConnect {
		return "", repCommandNotSupported, fmt.Errorf("unsupported command %#x", req[1])
	}

	switch req[3] {
	case atypIPv4:
		buf := make([]byte, 4+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", repSucceeded, fmt.Errorf("read ipv4 addr: %w", err)
		}
		target = fmt.Sprintf("%d.%d.%d.%d:%d", buf[0], buf[1], buf[2], buf[3],
			binary.BigEndian.Uint16(buf[4:6]))
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", repSucceeded, fmt.Errorf("read domain len: %w", err)
		}
		dlen := int(lenBuf[0])
		if dlen == 0 {
			return "", repGeneralFailure, fmt.Errorf("empty domain")
		}
		buf := make([]byte, dlen+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", repSucceeded, fmt.Errorf("read domain addr: %w", err)
		}
		target = fmt.Sprintf("%s:%d", string(buf[:dlen]),
			binary.BigEndian.Uint16(buf[dlen:dlen+2]))
	case atypIPv6:
		buf := make([]byte, 16+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", repSucceeded, fmt.Errorf("read ipv6 addr: %w", err)
		}
		target = fmt.Sprintf("[%s]:%d", net.IP(buf[:16]).String(),
			binary.BigEndian.Uint16(buf[16:18]))
	default:
		return "", repAddressTypeNotSupported, fmt.Errorf("unsupported atyp %#x", req[3])
	}

	return target, repSucceeded, nil
}

// dialWithTimeout bounds the dial: gonet.DialTCP has no connect timeout of
// its own, so a dead route would otherwise hang the handshake forever.
// A dial that completes AFTER the timeout has its connection closed.
func (s *SOCKS5Server) dialWithTimeout(address string) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	// Unbuffered: after a timeout the goroutine's only ready case is
	// <-abandoned, so the late connection is deterministically closed.
	ch := make(chan result)
	abandoned := make(chan struct{})
	go func() {
		conn, err := s.dialer.DialTCP(address)
		select {
		case ch <- result{conn, err}:
		case <-abandoned:
			// The caller timed out; do not leak a successfully dialed
			// connection.
			if conn != nil {
				conn.Close()
			}
		}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-time.After(dialTimeout):
		close(abandoned)
		return nil, fmt.Errorf("dial %s: timeout", address)
	}
}

func (s *SOCKS5Server) writeReply(conn net.Conn, rep byte) error {
	// BND.ADDR/BND.PORT are zeroed: we do not expose the tunnel-side address.
	_, err := conn.Write([]byte{socksVersion5, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// relay copies data in both directions, propagating half-closes when the
// underlying connections support CloseWrite. A clean EOF (nil error) is a
// graceful end of stream and propagates as CloseWrite; any other error is
// an abort and must NOT look like a clean FIN to the peer, so BOTH sides
// are fully closed instead.
func relay(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	relayOne := func(dst, src net.Conn, dir string) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil && !errors.Is(err, io.EOF) {
			utils.Debugf("[SOCKS5] relay %s aborted: %v", dir, err)
			src.Close()
			dst.Close()
			return
		}
		closeWrite(dst)
	}

	go relayOne(target, client, "client->target")
	go relayOne(client, target, "target->client")

	wg.Wait()
}

func closeWrite(c net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := c.(closeWriter); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}
