// Package session sits between a Transport (reliable ordered message
// carrier) and the stream multiplexer: it serializes wire frames onto
// carrier messages, verifies peer compatibility via a HELLO handshake and
// provides keepalive (PING/PONG).
//
// One frame per carrier message; stream-level chunking in the mux layer
// keeps frames within the carrier payload budget.
package session

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/utils"
	"github.com/leon03131/fork-openflux/wire"
)

// defaultCarrierPayload is assumed when the transport does not report its
// own payload limit. Conservative: fits both websocket-based carriers.
const defaultCarrierPayload = 16 * 1024

const (
	// KeepAliveInterval is how often a PING is sent.
	KeepAliveInterval = 10 * time.Second
	// KeepAliveTimeout is how long without ANY inbound frame the session
	// is considered dead.
	KeepAliveTimeout = 45 * time.Second
	// HelloTimeout bounds the handshake.
	HelloTimeout = 15 * time.Second
)

var (
	ErrClosed         = errors.New("session: closed")
	ErrNotConnected   = errors.New("session: transport not connected")
	ErrHandshake      = errors.New("session: handshake failed")
	ErrDeadConnection = errors.New("session: keepalive timeout")
)

// payloadCapacitor is an optional Transport extension for carriers that
// know their payload budget.
type payloadCapacitor interface {
	MaxPayload() int
}

type Session struct {
	trans transport.Transport

	maxPayload int // carrier message budget
	// cryptoOverhead reserves bytes for the stage-7 AEAD tag so the mux
	// never has to re-chunk when crypto is enabled.
	frameBudget int

	handler   func(wire.Frame)
	handlerMu sync.RWMutex

	sendMu sync.Mutex // frame ordering on the wire

	lastRecvNano atomic.Int64
	closed       chan struct{}
	closeOnce    sync.Once
	closeErr     error

	helloCh chan error
}

func New(t transport.Transport) *Session {
	maxP := defaultCarrierPayload
	if pc, ok := t.(payloadCapacitor); ok && pc.MaxPayload() > 0 {
		maxP = pc.MaxPayload()
	}
	s := &Session{
		trans:        t,
		maxPayload:   maxP,
		closed:       make(chan struct{}),
		helloCh:      make(chan error, 1),
		lastRecvNano: atomic.Int64{},
	}
	s.lastRecvNano.Store(time.Now().UnixNano())
	// cryptoOverhead(0) for now; stage 7 wraps SendFrame/dispatch.
	s.frameBudget = maxP - wire.HeaderSize - 16
	if s.frameBudget > wire.MaxPayload {
		s.frameBudget = wire.MaxPayload
	}
	return s
}

// MaxFramePayload is the largest DATA payload the mux may put in one frame.
func (s *Session) MaxFramePayload() int { return s.frameBudget }

// Start hooks the session into the transport. The caller owns the
// transport lifecycle (it must be started before Start and stopped after
// Close); a session never stops the transport, which allows the
// supervisor to build a fresh session over a reconnected carrier.
func (s *Session) Start() error {
	s.trans.Receive(func(msg []byte) {
		f, err := wire.Decode(msg)
		if err != nil {
			utils.Debugf("[SESSION] dropping undecodable message: %v", err)
			return
		}
		s.lastRecvNano.Store(time.Now().UnixNano())
		s.dispatch(f)
	})
	go s.keepaliveLoop()
	return nil
}

// waitConnected blocks until the carrier reports connectivity.
func (s *Session) waitConnected(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for !s.trans.IsConnected() {
		if time.Now().After(deadline) {
			return ErrNotConnected
		}
		select {
		case <-s.closed:
			return ErrClosed
		case <-time.After(20 * time.Millisecond):
		}
	}
	return nil
}

// Handshake exchanges HELLO/HELLO_ACK. Both sides call it; both send
// first and then await the peer's HELLO. It first waits for the carrier
// to become connected (carriers may connect asynchronously).
func (s *Session) Handshake() error {
	if err := s.waitConnected(HelloTimeout); err != nil {
		return fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	nonce := time.Now().UnixNano()
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, uint64(nonce))
	if err := s.SendFrame(wire.Frame{Type: wire.TypeHello, Payload: payload}); err != nil {
		return fmt.Errorf("%w: send hello: %v", ErrHandshake, err)
	}
	select {
	case err := <-s.helloCh:
		if err != nil {
			return err
		}
	case <-time.After(HelloTimeout):
		return fmt.Errorf("%w: timeout", ErrHandshake)
	case <-s.closed:
		return ErrClosed
	}
	// From now on, loss of carrier connectivity kills the session; the
	// supervisor builds a fresh one over the reconnected carrier.
	go s.watchdog()
	return nil
}

// watchdog closes the session when the carrier drops. Keepalive
// separately covers the case of a silently dead peer.
func (s *Session) watchdog() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
			if !s.trans.IsConnected() {
				utils.Debugf("[SESSION] carrier disconnected, closing session")
				s.CloseWithError(ErrNotConnected)
				return
			}
		}
	}
}

func (s *Session) dispatch(f wire.Frame) {
	switch f.Type {
	case wire.TypeHello:
		// Acknowledge and (idempotently) complete our own handshake.
		s.SendFrame(wire.Frame{Type: wire.TypeHelloAck, Payload: f.Payload})
		select {
		case s.helloCh <- nil:
		default:
		}
	case wire.TypeHelloAck:
		select {
		case s.helloCh <- nil:
		default:
		}
	case wire.TypePing:
		s.SendFrame(wire.Frame{Type: wire.TypePong, Payload: f.Payload})
	case wire.TypePong:
		if len(f.Payload) == 8 {
			sent := time.Unix(0, int64(binary.BigEndian.Uint64(f.Payload)))
			utils.Debugf("[SESSION] rtt=%v", time.Since(sent).Round(time.Millisecond))
		}
	default:
		s.handlerMu.RLock()
		h := s.handler
		s.handlerMu.RUnlock()
		if h != nil {
			h(f)
		}
	}
}

// OnFrame registers the mux-level frame handler.
func (s *Session) OnFrame(cb func(wire.Frame)) {
	s.handlerMu.Lock()
	s.handler = cb
	s.handlerMu.Unlock()
}

func (s *Session) SendFrame(f wire.Frame) error {
	select {
	case <-s.closed:
		return ErrClosed
	default:
	}
	if !s.trans.IsConnected() {
		return ErrNotConnected
	}
	buf, err := wire.Encode(nil, f)
	if err != nil {
		return err
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.trans.Send(buf)
}

func (s *Session) keepaliveLoop() {
	ticker := time.NewTicker(KeepAliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.closed:
			return
		case <-ticker.C:
		}

		idle := time.Since(time.Unix(0, s.lastRecvNano.Load()))
		if idle > KeepAliveTimeout {
			utils.Debugf("[SESSION] no inbound frames for %v, closing", idle.Round(time.Second))
			s.CloseWithError(ErrDeadConnection)
			return
		}
		payload := make([]byte, 8)
		binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))
		if err := s.SendFrame(wire.Frame{Type: wire.TypePing, Payload: payload}); err != nil {
			utils.Debugf("[SESSION] ping failed: %v", err)
		}
	}
}

// CloseWithError terminates the session with a reason. The transport is
// NOT stopped: its lifecycle belongs to the caller.
func (s *Session) CloseWithError(err error) {
	s.closeOnce.Do(func() {
		s.closeErr = err
		close(s.closed)
	})
}

func (s *Session) Close() { s.CloseWithError(ErrClosed) }

// Closed returns a channel closed when the session ends.
func (s *Session) Closed() <-chan struct{} { return s.closed }

// Err reports why the session closed (nil while alive / clean Close).
func (s *Session) Err() error { return s.closeErr }
