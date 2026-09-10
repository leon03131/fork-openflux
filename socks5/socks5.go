package socks5

import (
	"encoding/binary"
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

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded               = 0x00
	repGeneralFailure          = 0x01
	repHostUnreachable         = 0x04
	repCommandNotSupported     = 0x07
	repAddressTypeNotSupported = 0x08

	methodNoAuth = 0x00

	maxDomainLen = 255

	handshakeTimeout = 30 * time.Second
)

type Dialer interface {
	DialTCP(address string) (net.Conn, error)
}

type SOCKS5Server struct {
	listenAddr string
	dialer     Dialer
}

func NewSOCKS5Server(addr string, dialer Dialer) *SOCKS5Server {
	return &SOCKS5Server{listenAddr: addr, dialer: dialer}
}

func (s *SOCKS5Server) Start() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	utils.Debugf("[SOCKS5] Listening on %s", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
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

	targetConn, err := s.dialer.DialTCP(targetAddr)
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
		if dlen == 0 || dlen > maxDomainLen {
			return "", repGeneralFailure, fmt.Errorf("bad domain length %d", dlen)
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

func (s *SOCKS5Server) writeReply(conn net.Conn, rep byte) error {
	// BND.ADDR/BND.PORT are zeroed: we do not expose the tunnel-side address.
	_, err := conn.Write([]byte{socksVersion5, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// relay copies data in both directions, propagating half-closes when the
// underlying connections support CloseWrite.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(b, a)
		closeWrite(b)
	}()

	go func() {
		defer wg.Done()
		io.Copy(a, b)
		closeWrite(a)
	}()

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
