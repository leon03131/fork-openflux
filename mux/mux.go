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
	"os"
	"strconv"
	"sync"
	"sync/atomic"
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
	// It is deliberately larger than the exit's dial timeout (10s) so
	// the exit can always answer OPEN_ERROR before we give up.
	OpenTimeout = 25 * time.Second

	// maxPendingAccepts bounds streams opened by the peer but not yet
	// picked up via Accept.
	maxPendingAccepts = 64

	// MaxActiveStreams bounds the total number of live streams; beyond
	// it, OPEN is rejected. Prevents OOM/FD exhaustion by a hostile or
	// buggy peer.
	MaxActiveStreams = 4096

	// MaxSessionBuffer bounds the total unread stream data buffered
	// across the mux (all streams combined).
	MaxSessionBuffer = 64 << 20 // 64 MiB

	// openRateLimit/openRateBurst bound how fast the PEER may send OPEN
	// frames (token bucket): flood protection for the accept path.
	openRateLimit = 128 // OPENs per second
	openRateBurst = 256
)

var (
	ErrClosed       = errors.New("mux: closed")
	ErrStreamClosed = errors.New("mux: stream closed")
	// ErrPeerClosed resets a stream aborted by the peer's CLOSE frame
	// without a prior half-close: the data may be truncated.
	ErrPeerClosed   = errors.New("mux: peer closed the stream")
	ErrWriteClosed  = errors.New("mux: write side closed")
	ErrOpenTimeout  = errors.New("mux: open timed out")
	ErrStreamExists = errors.New("mux: duplicate stream id")
	ErrTooManyOpens = errors.New("mux: too many pending streams")
	// errTimeout is os.ErrDeadlineExceeded: it satisfies net.Error and
	// errors.Is(os.ErrDeadlineExceeded), per the net.Conn contract.
	errTimeout          = os.ErrDeadlineExceeded
	_          net.Conn = (*Stream)(nil)
)

type Mux struct {
	sess *session.Session

	mu      sync.Mutex
	streams map[uint32]*Stream
	nextID  uint32
	// closeErr is the reason the mux died (e.g. the session's death
	// cause); it flows into the resetErr of every stream torn down by
	// the mux. nil = streams get the default ErrStreamClosed.
	closeErr error

	// buffered tracks unread stream payload bytes across all streams.
	buffered atomic.Int64

	acceptCh  chan *Stream
	closed    chan struct{}
	closeOnce sync.Once

	// openRate throttles inbound OPEN frames (see handleOpen).
	openRate *tokenBucket
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
		openRate: newTokenBucket(openRateLimit, openRateBurst),
	}
	s.OnFrame(m.handleFrame)
	// If the session dies, the mux must die too: wake all blocked
	// Read/Write and fail Accept/Open. The session's close reason is
	// propagated into every live stream.
	go func() {
		<-s.Closed()
		m.CloseWithError(s.Err())
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
	if len(m.streams) >= MaxActiveStreams {
		m.mu.Unlock()
		return nil, ErrTooManyOpens
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
		// Tell the peer: without CLOSE the exit side would keep a
		// phantom connection forever.
		m.send(wire.Frame{Type: wire.TypeClose, StreamID: st.id})
		m.removeStream(st.id)
		st.closeNoSend()
		return nil, ErrOpenTimeout
	case <-m.closed:
		m.removeStream(st.id)
		st.closeNoSend()
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
// Streams closed by the peer before acceptance are skipped.
func (m *Mux) Accept() (*Stream, error) {
	for {
		select {
		case st := <-m.acceptCh:
			if st.IsClosed() {
				continue // stale OPEN: peer already cancelled
			}
			return st, nil
		case <-m.closed:
			return nil, ErrClosed
		}
	}
}

// Close shuts the mux down with the default stream reset reason
// (ErrStreamClosed).
func (m *Mux) Close() { m.CloseWithError(nil) }

// CloseWithError is Close with a cause: err is propagated to every live
// stream as its reset reason (a nil err keeps the default). The first
// call wins.
func (m *Mux) CloseWithError(err error) {
	m.closeOnce.Do(func() {
		if err != nil {
			m.mu.Lock()
			m.closeErr = err
			m.mu.Unlock()
		}
		// GOAWAY first: once m.closed is closed, send() refuses to send.
		m.sess.SendFrame(wire.Frame{Type: wire.TypeGoAway})
		close(m.closed)
		// Snapshot, then close WITHOUT holding m.mu: closeNoSend locks
		// m.mu again (resetReason) — holding it here would self-deadlock.
		m.mu.Lock()
		streams := make([]*Stream, 0, len(m.streams))
		for _, st := range m.streams {
			streams = append(streams, st)
		}
		m.mu.Unlock()
		for _, st := range streams {
			st.closeNoSend()
		}
		m.sess.Close()
	})
}

// resetReason reports the abort cause for streams torn down with the
// mux: the mux close reason if set, ErrStreamClosed otherwise.
func (m *Mux) resetReason() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closeErr != nil {
		return m.closeErr
	}
	return ErrStreamClosed
}

// Closed returns a channel closed when the mux ends.
func (m *Mux) Closed() <-chan struct{} { return m.closed }

func (m *Mux) send(f wire.Frame) error {
	return m.sendDeadline(f, time.Time{})
}

// sendDeadline sends a frame, bounding the session-queue wait.
func (m *Mux) sendDeadline(f wire.Frame, deadline time.Time) error {
	select {
	case <-m.closed:
		return ErrClosed
	default:
	}
	return m.sess.SendFrameDeadline(f, deadline)
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
			// Stale data for a closed stream. Do NOT reply: a garbage
			// storm would otherwise be amplified 1:1 with CLOSE frames
			// and block the dispatch loop. The peer recovers via its
			// own timeouts/session rebuild.
			return
		}
		st.feedData(f.Payload)
	case wire.TypeWindowUpdate:
		if st != nil && len(f.Payload) == 4 {
			st.addSendWindow(binary.BigEndian.Uint32(f.Payload))
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
	reject := func(reason string) {
		m.send(wire.Frame{Type: wire.TypeOpenError, StreamID: f.StreamID, Payload: []byte(reason)})
	}

	// OPEN flood protection: reject excess OPENs before spending any
	// work on validation/allocation.
	if !m.openRate.allow() {
		reject("rate limited")
		return
	}

	// Stream 0 is reserved for session-level frames; the peer must use
	// IDs of ITS parity (clients odd, servers even) — enforced on BOTH
	// sides, so a rogue/buggy peer can't collide with our namespace.
	if f.StreamID == 0 {
		reject("stream id 0 is reserved")
		return
	}
	weAreExit := m.nextID%2 == 0
	peerIsClient := weAreExit
	if peerIsClient && f.StreamID%2 != 1 {
		reject("bad stream id parity")
		return
	}
	if !peerIsClient && f.StreamID%2 != 0 {
		reject("bad stream id parity")
		return
	}

	host, port, err := wire.DecodeAddress(f.Payload)
	if err != nil {
		reject(err.Error())
		return
	}

	m.mu.Lock()
	if _, exists := m.streams[f.StreamID]; exists {
		m.mu.Unlock()
		reject(ErrStreamExists.Error())
		return
	}
	if len(m.streams) >= MaxActiveStreams {
		m.mu.Unlock()
		reject("too many active streams")
		return
	}
	st := newStream(m, f.StreamID, host, port)
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

// tokenBucket is a minimal dependency-free rate limiter: tokens refill
// at a fixed rate up to a burst cap; each allowed event consumes one.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64 // tokens per second
	burst  float64
}

func newTokenBucket(rate, burst int) *tokenBucket {
	return &tokenBucket{
		tokens: float64(burst),
		last:   time.Now(),
		rate:   float64(rate),
		burst:  float64(burst),
	}
}

// allow reports whether one event is permitted right now.
func (b *tokenBucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
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

	mu      sync.Mutex
	recvBuf bytes.Buffer
	// readEOF: peer half-closed gracefully — drained reads return
	// io.EOF (complete data). resetErr: stream aborted (peer CLOSE,
	// session death) — drained reads return the error (data may be
	// truncated). resetErr is checked FIRST: an abort beats a graceful
	// EOF — a half-close followed by carrier death means the tail of
	// the data may have been lost in flight. A peer CLOSE after a
	// half-close is still a clean finish and does NOT set resetErr
	// (see remoteClose).
	readEOF     bool
	resetErr    error
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

	// Broadcast notify channels (wake ALL waiters, net.Conn allows
	// concurrent I/O from multiple goroutines).
	recvNotify broadcast
	sendNotify broadcast
	closedCh   chan struct{}
	closeOnce  sync.Once
	// Deadline broadcast: generation channels wake ALL pending waiters
	// (net.Conn allows concurrent I/O from multiple goroutines).
	readDeadline  broadcast
	writeDeadline broadcast
	// bufferReleased guards one-time release of the global buffer
	// accounting on terminal close.
	bufferReleased bool
}

// broadcast is a generation-based notify protecting a deadline value:
// Wait returns the current generation channel and value; Set wakes ALL
// current waiters (net.Conn allows concurrent I/O from many goroutines).
type broadcast struct {
	mu sync.Mutex
	ch chan struct{}
	t  time.Time
}

func newBroadcast() broadcast {
	return broadcast{ch: make(chan struct{})}
}

func (b *broadcast) Set(t time.Time) {
	b.mu.Lock()
	b.t = t
	close(b.ch)
	b.ch = make(chan struct{})
	b.mu.Unlock()
}

// Wait returns the current generation channel and the deadline value,
// atomically.
func (b *broadcast) Wait() (<-chan struct{}, time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ch, b.t
}

// Ping wakes all current waiters (no value attached).
func (b *broadcast) Ping() { b.Set(time.Now()) }

func newStream(m *Mux, id uint32, destHost string, destPort uint16) *Stream {
	return &Stream{
		id:            id,
		m:             m,
		destHost:      destHost,
		destPort:      destPort,
		openCh:        make(chan error, 1),
		sendWindow:    DefaultWindowSize,
		recvNotify:    newBroadcast(),
		sendNotify:    newBroadcast(),
		closedCh:      make(chan struct{}),
		readDeadline:  newBroadcast(),
		writeDeadline: newBroadcast(),
	}
}

// Done returns a channel closed when the stream is fully closed.
func (s *Stream) Done() <-chan struct{} { return s.closedCh }

// IsClosed reports whether the stream is fully closed.
func (s *Stream) IsClosed() bool {
	select {
	case <-s.closedCh:
		return true
	default:
		return false
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
	// Global session budget across all streams.
	if s.m.buffered.Add(int64(len(payload))) > MaxSessionBuffer {
		s.m.buffered.Add(-int64(len(payload)))
		s.mu.Unlock()
		utils.Debugf("[MUX] session buffer budget exceeded, resetting stream %d", s.id)
		s.Close()
		return
	}
	s.recvBuf.Write(append([]byte(nil), payload...))
	s.mu.Unlock()
	s.recvNotify.Ping()
}

func (s *Stream) addSendWindow(n uint32) {
	s.mu.Lock()
	// Clamp via int64 (32-bit safe) and cap at the negotiated window:
	// the peer must not inflate it.
	credit := int64(s.sendWindow) + int64(n)
	if credit > DefaultWindowSize {
		credit = DefaultWindowSize
	}
	s.sendWindow = int(credit)
	s.mu.Unlock()
	s.sendNotify.Ping()
}

func (s *Stream) remoteHalfClose() {
	s.mu.Lock()
	s.readEOF = true
	s.mu.Unlock()
	s.recvNotify.Ping()
}

// setResetLocked records the abort reason, first write wins: the
// earliest failure is the root cause and must not be masked by later
// teardown. Caller must hold s.mu.
func (s *Stream) setResetLocked(err error) {
	if s.resetErr == nil && err != nil {
		s.resetErr = err
	}
}

func (s *Stream) remoteClose() {
	s.mu.Lock()
	s.closed = true
	// A CLOSE after a half-close (FIN) is the peer's graceful teardown:
	// the data up to the FIN is complete, so keep the clean EOF. A
	// CLOSE out of the blue is an abortive reset (data truncated).
	if !s.readEOF {
		s.setResetLocked(ErrPeerClosed)
	}
	s.releaseBufferLocked()
	s.mu.Unlock()
	s.closeOnce.Do(func() { close(s.closedCh) })
	s.recvNotify.Ping()
	s.sendNotify.Ping()
}

func (s *Stream) closeNoSend() {
	s.mu.Lock()
	s.closed = true
	s.setResetLocked(s.m.resetReason())
	s.releaseBufferLocked()
	s.mu.Unlock()
	s.closeOnce.Do(func() { close(s.closedCh) })
	s.recvNotify.Ping()
	s.sendNotify.Ping()
}

// releaseBufferLocked returns the remaining unread buffer's share of the
// global session budget, exactly once. The buffer content itself stays
// drainable (CLOSE is terminal, but in-flight data already delivered may
// still be read). Caller must hold s.mu.
func (s *Stream) releaseBufferLocked() {
	if !s.bufferReleased {
		s.bufferReleased = true
		if n := s.recvBuf.Len(); n > 0 {
			s.m.buffered.Add(-int64(n))
		}
	}
}

func (s *Stream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		// Subscribe while holding the lock: any state change after we
		// unlock is guaranteed to ping our channel.
		nch, _ := s.recvNotify.Wait()
		if s.recvBuf.Len() > 0 {
			n, _ := s.recvBuf.Read(b)
			if s.bufferReleased {
				// Terminal close already released the accounting;
				// just drain.
				s.mu.Unlock()
				return n, nil
			}
			s.recvUnacked -= n
			s.m.buffered.Add(-int64(n))
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
		// An abortive reset beats a graceful EOF: after a half-close
		// the carrier may still have died with data in flight.
		if s.resetErr != nil {
			s.mu.Unlock()
			return 0, s.resetErr
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

		dlCh, deadline := s.readDeadline.Wait()
		dch, expired := deadlineChan(deadline)
		if expired {
			return 0, errTimeout
		}
		select {
		case <-nch:
		case <-s.closedCh:
		case <-dlCh: // deadline changed: recompute
		case <-dch:
			return 0, errTimeout
		}
	}
}

func (s *Stream) Write(b []byte) (int, error) {
	// The write deadline bounds the WHOLE Write call, including the
	// session queue wait — per net.Conn semantics.
	if _, dl := s.writeDeadline.Wait(); !dl.IsZero() && time.Now().After(dl) {
		return 0, errTimeout
	}
	total := 0
	for total < len(b) {
		s.mu.Lock()
		for s.sendWindow == 0 && !s.closed && !s.writeClosed {
			// Subscribe while still holding the lock: any state change
			// after we unlock is guaranteed to ping our channel.
			nch, _ := s.sendNotify.Wait()
			s.mu.Unlock()
			dlCh, deadline := s.writeDeadline.Wait()
			dch, expired := deadlineChan(deadline)
			if expired {
				return total, errTimeout
			}
			select {
			case <-nch:
			case <-s.closedCh:
			case <-dlCh: // deadline changed: recompute
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

		_, wdl := s.writeDeadline.Wait()
		err := s.m.sendDeadline(wire.Frame{Type: wire.TypeData, StreamID: s.id, Payload: b[total : total+n]}, wdl)
		if err != nil {
			// The frame was not sent: return the credit so the window
			// accounting does not leak, and wake other writers.
			s.mu.Lock()
			s.sendWindow += n
			s.mu.Unlock()
			s.sendNotify.Ping()
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
	// Wake any writer blocked on an exhausted window.
	s.sendNotify.Ping()
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
	s.readDeadline.Set(t)
	s.writeDeadline.Set(t)
	return nil
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.readDeadline.Set(t)
	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.writeDeadline.Set(t)
	return nil
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
