// Package mux multiplexes independent streams (net.Conn) over a single
// session. It implements OPEN/OPEN_OK/OPEN_ERROR handshakes, credit-based
// per-stream flow control and TCP-like half-close semantics.
//
// Stream ID namespaces are split by parity: the client side allocates odd
// IDs, the exit side even ones, so no coordination is needed.
package mux

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/leon03131/fork-openflux/session"
	"github.com/leon03131/fork-openflux/utils"
	"github.com/leon03131/fork-openflux/wire"
)

const (
	// DefaultWindowSize is the per-stream receive window in bytes.
	// The sender blocks when the peer's window is exhausted, which
	// propagates backpressure to the local reader.
	DefaultWindowSize = 512 * 1024

	// OpenTimeout bounds the OPEN -> OPEN_OK/OPEN_ERROR handshake.
	OpenTimeout = 15 * time.Second

	// maxPendingAccepts bounds streams opened by the peer but not yet
	// picked up via Accept.
	maxPendingAccepts = 64
)

var (
	ErrClosed                = errors.New("mux: closed")
	ErrStreamClosed          = errors.New("mux: stream closed")
	ErrWriteClosed           = errors.New("mux: write side closed")
	ErrOpenTimeout           = errors.New("mux: open timed out")
	ErrStreamExists          = errors.New("mux: duplicate stream id")
	ErrTooManyOpens          = errors.New("mux: too many pending streams")
	errTimeout               = timeoutError{}
	_               net.Conn = (*Stream)(nil)
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type Mux struct {
	sess *session.Session

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32

	acceptCh  chan *Stream
	closed    chan struct{}
	closeOnce sync.Once
}

// NewClientMux allocates odd stream IDs.
func NewClientMux(s *session.Session) *Mux { return newMux(s, 1) }

// NewServerMux allocates even stream IDs.
func NewServerMux(s *session.Session) *Mux { return newMux(s, 2) }

func newMux(s *session.Session, firstID uint32) *Mux {
	m := &Mux{
		sess:     s,
		streams:  make(map[uint32]*Stream),
		nextID:   firstID,
		acceptCh: make(chan *Stream, maxPendingAccepts),
		closed:   make(chan struct{}),
	}
	s.OnFrame(m.handleFrame)
	// If the session dies, the mux must die too: wake all blocked
	// Read/Write and fail Accept/Open.
	go func() {
		<-s.Closed()
		m.Close()
	}()
	return m
}

// Open asks the peer to connect to host:port and returns the stream once
// the peer confirmed.
func (m *Mux) Open(host string, port uint16) (*Stream, error) {
	payload, err := wire.EncodeAddress(host, port)
	if err != nil {
		return nil, err
	}

	st := newStream(m, 0, "", 0)
	m.mu.Lock()
	select {
	case <-m.closed:
		m.mu.Unlock()
		return nil, ErrClosed
	default:
	}
	st.id = m.nextID
	m.nextID += 2
	m.streams[st.id] = st
	m.mu.Unlock()

	if err := m.send(wire.Frame{Type: wire.TypeOpen, StreamID: st.id, Payload: payload}); err != nil {
		m.removeStream(st.id)
		return nil, err
	}

	select {
	case err := <-st.openCh:
		if err != nil {
			m.removeStream(st.id)
			return nil, err
		}
		return st, nil
	case <-time.After(OpenTimeout):
		m.removeStream(st.id)
		st.closeNoSend()
		return nil, ErrOpenTimeout
	case <-m.closed:
		return nil, ErrClosed
	}
}

// DialTCP adapts the mux to the socks5 Dialer interface. The hostname is
// passed through to the exit node unmodified (remote DNS resolution).
func (m *Mux) DialTCP(address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("mux: bad address %q: %w", address, err)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("mux: bad port in %q: %w", address, err)
	}
	return m.Open(host, uint16(p))
}

// Accept returns the next stream opened by the peer (exit-node side).
func (m *Mux) Accept() (*Stream, error) {
	select {
	case st := <-m.acceptCh:
		return st, nil
	case <-m.closed:
		return nil, ErrClosed
	}
}

func (m *Mux) Close() {
	m.closeOnce.Do(func() {
		// GOAWAY first: once m.closed is closed, send() refuses to send.
		m.sess.SendFrame(wire.Frame{Type: wire.TypeGoAway})
		close(m.closed)
		m.mu.Lock()
		for _, st := range m.streams {
			st.closeNoSend()
		}
		m.mu.Unlock()
		m.sess.Close()
	})
}

// Closed returns a channel closed when the mux ends.
func (m *Mux) Closed() <-chan struct{} { return m.closed }

func (m *Mux) send(f wire.Frame) error {
	select {
	case <-m.closed:
		return ErrClosed
	default:
	}
	return m.sess.SendFrame(f)
}

func (m *Mux) removeStream(id uint32) {
	m.mu.Lock()
	delete(m.streams, id)
	m.mu.Unlock()
}

func (m *Mux) handleFrame(f wire.Frame) {
	if f.Type == wire.TypeOpen {
		m.handleOpen(f)
		return
	}
	if f.Type == wire.TypeGoAway {
		m.Close()
		return
	}

	m.mu.Lock()
	st := m.streams[f.StreamID]
	m.mu.Unlock()

	switch f.Type {
	case wire.TypeData:
		if st == nil {
			// Stale data for a closed stream: tell the peer to drop it.
			m.send(wire.Frame{Type: wire.TypeClose, StreamID: f.StreamID})
			return
		}
		st.feedData(f.Payload)
	case wire.TypeWindowUpdate:
		if st != nil && len(f.Payload) == 4 {
			st.addSendWindow(int(binary.BigEndian.Uint32(f.Payload)))
		}
	case wire.TypeHalfClose:
		if st != nil {
			st.remoteHalfClose()
		}
	case wire.TypeClose:
		if st != nil {
			st.remoteClose()
			m.removeStream(f.StreamID)
		}
	case wire.TypeOpenOK:
		if st != nil {
			st.openResult(nil)
		}
	case wire.TypeOpenError:
		if st != nil {
			st.openResult(errors.New(string(f.Payload)))
		}
	default:
		utils.Debugf("[MUX] ignoring unknown frame type %#x", f.Type)
	}
}

func (m *Mux) handleOpen(f wire.Frame) {
	host, port, err := wire.DecodeAddress(f.Payload)
	if err != nil {
		m.send(wire.Frame{Type: wire.TypeOpenError, StreamID: f.StreamID, Payload: []byte(err.Error())})
		return
	}

	st := newStream(m, f.StreamID, host, port)
	m.mu.Lock()
	if _, exists := m.streams[f.StreamID]; exists {
		m.mu.Unlock()
		m.send(wire.Frame{Type: wire.TypeOpenError, StreamID: f.StreamID, Payload: []byte(ErrStreamExists.Error())})
		return
	}
	m.streams[f.StreamID] = st
	m.mu.Unlock()

	select {
	case m.acceptCh <- st:
	case <-m.closed:
	default:
		// Never block the session dispatch loop on a slow acceptor.
		m.removeStream(st.id)
		st.closeNoSend()
		m.send(wire.Frame{Type: wire.TypeOpenError, StreamID: f.StreamID, Payload: []byte(ErrTooManyOpens.Error())})
	}
}

// --- Stream ---

type streamAddr string

func (a streamAddr) Network() string { return "openflux" }
func (a streamAddr) String() string  { return string(a) }

// Stream is a single multiplexed connection. It implements net.Conn.
type Stream struct {
	id uint32
	m  *Mux

	destHost string
	destPort uint16

	openCh chan error // buffered (1)

	mu          sync.Mutex
	recvBuf     bytes.Buffer
	readEOF     bool // peer half-closed; drained reads return io.EOF
	closed      bool
	writeClosed bool
	sendWindow  int
	// pendingCredit is WINDOW_UPDATE credit we owe the peer because a
	// previous WINDOW_UPDATE frame failed to send.
	pendingCredit int
	// recvUnacked bounds unread buffered data so a misbehaving peer
	// cannot grow recvBuf without limit.
	recvUnacked  int
	peerNotified bool // we sent Close

	recvNotify    chan struct{} // cap 1
	sendNotify    chan struct{} // cap 1
	closedCh      chan struct{}
	closeOnce     sync.Once
	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func newStream(m *Mux, id uint32, destHost string, destPort uint16) *Stream {
	return &Stream{
		id:         id,
		m:          m,
		destHost:   destHost,
		destPort:   destPort,
		openCh:     make(chan error, 1),
		sendWindow: DefaultWindowSize,
		recvNotify: make(chan struct{}, 1),
		sendNotify: make(chan struct{}, 1),
		closedCh:   make(chan struct{}),
	}
}

// ID returns the stream identifier.
func (s *Stream) ID() uint32 { return s.id }

// DestHost/DestPort describe the address requested in OPEN (exit side).
func (s *Stream) DestHost() string { return s.destHost }
func (s *Stream) DestPort() uint16 { return s.destPort }

// AcceptOpen confirms the stream to the opener (exit side).
func (s *Stream) AcceptOpen() error {
	return s.m.send(wire.Frame{Type: wire.TypeOpenOK, StreamID: s.id})
}

// RejectOpen fails the stream on the opener side (exit side).
func (s *Stream) RejectOpen(reason string) {
	s.m.send(wire.Frame{Type: wire.TypeOpenError, StreamID: s.id, Payload: []byte(reason)})
	s.closeNoSend()
	s.m.removeStream(s.id)
}

func (s *Stream) openResult(err error) {
	select {
	case s.openCh <- err:
	default:
	}
}

func (s *Stream) feedData(payload []byte) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	// Flow control enforcement: the peer may legally have up to
	// DefaultWindowSize unacked bytes in flight. Allow one extra frame
	// of slack, then treat excess as a protocol violation.
	s.recvUnacked += len(payload)
	if s.recvUnacked > DefaultWindowSize+s.m.sess.MaxFramePayload() {
		s.mu.Unlock()
		utils.Debugf("[MUX] stream %d exceeded receive window, resetting", s.id)
		s.Close()
		return
	}
	s.recvBuf.Write(append([]byte(nil), payload...))
	s.mu.Unlock()
	notify(s.recvNotify)
}

func (s *Stream) addSendWindow(n int) {
	s.mu.Lock()
	// Cap at the negotiated window: the peer must not inflate it.
	s.sendWindow += n
	if s.sendWindow > DefaultWindowSize {
		s.sendWindow = DefaultWindowSize
	}
	s.mu.Unlock()
	notify(s.sendNotify)
}

func (s *Stream) remoteHalfClose() {
	s.mu.Lock()
	s.readEOF = true
	s.mu.Unlock()
	notify(s.recvNotify)
}

func (s *Stream) remoteClose() {
	s.mu.Lock()
	s.readEOF = true
	s.closed = true
	s.mu.Unlock()
	s.closeOnce.Do(func() { close(s.closedCh) })
	notify(s.recvNotify)
	notify(s.sendNotify)
}

func (s *Stream) closeNoSend() {
	s.mu.Lock()
	s.closed = true
	s.readEOF = true
	s.mu.Unlock()
	s.closeOnce.Do(func() { close(s.closedCh) })
	notify(s.recvNotify)
	notify(s.sendNotify)
}

func notify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (s *Stream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		if s.recvBuf.Len() > 0 {
			n, _ := s.recvBuf.Read(b)
			s.recvUnacked -= n
			credit := n + s.pendingCredit
			s.pendingCredit = 0
			s.mu.Unlock()
			// Grant the consumed bytes back to the peer. If the update
			// fails to send, remember the credit instead of losing it.
			if err := s.m.send(wire.Frame{Type: wire.TypeWindowUpdate, StreamID: s.id, Payload: uint32Bytes(uint32(credit))}); err != nil {
				s.mu.Lock()
				s.pendingCredit += credit
				s.mu.Unlock()
			}
			return n, nil
		}
		if s.readEOF {
			s.mu.Unlock()
			return 0, io.EOF
		}
		if s.closed {
			s.mu.Unlock()
			return 0, ErrStreamClosed
		}
		s.mu.Unlock()

		dch, expired := deadlineChan(s.getReadDeadline())
		if expired {
			return 0, errTimeout
		}
		select {
		case <-s.recvNotify:
		case <-s.closedCh:
		case <-dch:
			return 0, errTimeout
		}
	}
}

func (s *Stream) Write(b []byte) (int, error) {
	total := 0
	for total < len(b) {
		s.mu.Lock()
		for s.sendWindow == 0 && !s.closed && !s.writeClosed {
			s.mu.Unlock()
			dch, expired := deadlineChan(s.getWriteDeadline())
			if expired {
				return total, errTimeout
			}
			select {
			case <-s.sendNotify:
			case <-s.closedCh:
			case <-dch:
				return total, errTimeout
			}
			s.mu.Lock()
		}
		if s.closed {
			s.mu.Unlock()
			return total, ErrStreamClosed
		}
		if s.writeClosed {
			s.mu.Unlock()
			return total, ErrWriteClosed
		}

		n := len(b) - total
		if maxP := s.m.sess.MaxFramePayload(); n > maxP {
			n = maxP
		}
		if n > s.sendWindow {
			n = s.sendWindow
		}
		s.sendWindow -= n
		s.mu.Unlock()

		err := s.m.send(wire.Frame{Type: wire.TypeData, StreamID: s.id, Payload: b[total : total+n]})
		if err != nil {
			// The frame was not sent: return the credit so the window
			// accounting does not leak.
			s.mu.Lock()
			s.sendWindow += n
			s.mu.Unlock()
			return total, err
		}
		total += n
	}
	return total, nil
}

// CloseWrite half-closes the stream: no more data will be written, but
// reads still work. Mirrors TCP CloseWrite.
func (s *Stream) CloseWrite() error {
	s.mu.Lock()
	if s.writeClosed || s.closed {
		s.mu.Unlock()
		return nil
	}
	s.writeClosed = true
	s.mu.Unlock()
	return s.m.send(wire.Frame{Type: wire.TypeHalfClose, StreamID: s.id})
}

func (s *Stream) Close() error {
	s.mu.Lock()
	already := s.closed || s.peerNotified
	if !already {
		s.peerNotified = true
	}
	s.closed = true
	s.mu.Unlock()

	if !already {
		s.m.send(wire.Frame{Type: wire.TypeClose, StreamID: s.id})
	}
	s.closeNoSend()
	s.m.removeStream(s.id)
	return nil
}

func (s *Stream) LocalAddr() net.Addr { return streamAddr("openflux-local") }
func (s *Stream) RemoteAddr() net.Addr {
	return streamAddr(net.JoinHostPort(s.destHost, strconv.Itoa(int(s.destPort))))
}

func (s *Stream) SetDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.readDeadline = t
	s.writeDeadline = t
	s.deadlineMu.Unlock()
	return nil
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.readDeadline = t
	s.deadlineMu.Unlock()
	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.writeDeadline = t
	s.deadlineMu.Unlock()
	return nil
}

func (s *Stream) getReadDeadline() time.Time {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	return s.readDeadline
}

func (s *Stream) getWriteDeadline() time.Time {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	return s.writeDeadline
}

// deadlineChan returns a channel firing at the deadline, and expired=true
// if the deadline is already in the past. A zero deadline blocks forever.
func deadlineChan(deadline time.Time) (<-chan time.Time, bool) {
	if deadline.IsZero() {
		return nil, false
	}
	d := time.Until(deadline)
	if d <= 0 {
		return nil, true
	}
	return time.After(d), false
}

func uint32Bytes(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}
