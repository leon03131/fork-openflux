// Package session sits between a Transport (reliable ordered message
// carrier) and the stream multiplexer: it serializes wire frames onto
// carrier messages, verifies peer compatibility via a HELLO handshake and
// provides keepalive (PING/PONG).
//
// One frame per carrier message; stream-level chunking in the mux layer
// keeps frames within the carrier payload budget.
package session

import (
	"crypto/ecdh"
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
	ErrPeerReset      = errors.New("session: peer restarted its session")
	ErrRoleConflict   = errors.New("session: both peers have the same role")
)

// sendQueueSize bounds the outbound frame queue feeding the writer
// goroutine. A full queue applies backpressure to SendFrame callers.
const sendQueueSize = 256

// Capability bits exchanged in HELLO/HELLO_ACK (informational for now;
// unknown bits are ignored for forward compatibility).
const (
	capHalfClose   byte = 1 << 0
	capFlowControl byte = 1 << 1
	capOFX1        byte = 1 << 2
)

// ourCapabilities is what this build supports.
const ourCapabilities = capHalfClose | capFlowControl | capOFX1

// payloadCapacitor is an optional Transport extension for carriers that
// know their payload budget.
type payloadCapacitor interface {
	MaxPayload() int
}

type Session struct {
	trans transport.Transport

	maxPayload int // carrier message budget
	// frameBudget is MaxPayload minus frame header and AEAD overhead.
	frameBudget int

	psk      []byte
	isClient bool
	priv     *ecdh.PrivateKey
	crypto   atomic.Pointer[sessionCrypto]

	handler   func(wire.Frame)
	handlerMu sync.RWMutex

	// sendMu serializes encode -> encrypt(seq allocation) -> queue
	// insertion, so queue order always matches sequence order even with
	// concurrent SendFrame callers.
	sendMu sync.Mutex

	// sendQueue feeds the single writer goroutine; this keeps the
	// inbound dispatch path non-blocking even when the carrier write
	// stalls (no lock is ever held across a network write).
	sendQueue chan []byte

	lastRecvNano atomic.Int64
	closed       chan struct{}
	closeOnce    sync.Once
	closeErr     error

	helloCh chan error

	// confirmCh closes when the peer first proves PSK knowledge by
	// delivering a valid encrypted frame (exit side only).
	confirmCh   chan struct{}
	confirmOnce sync.Once

	// peerCaps holds the peer's capability bits (0 if none/legacy).
	peerCaps atomic.Uint32
}

// New creates a session over the transport. With a non-nil PSK the
// session performs an authenticated X25519 handshake and encrypts every
// frame (ChaCha20-Poly1305). psk=nil disables crypto (tests only).
func New(t transport.Transport, psk []byte, isClient bool) (*Session, error) {
	maxP := defaultCarrierPayload
	if pc, ok := t.(payloadCapacitor); ok && pc.MaxPayload() > 0 {
		maxP = pc.MaxPayload()
	}
	if len(psk) == 0 {
		psk = nil // empty PSK means crypto off, not "empty key"
	}
	s := &Session{
		trans:      t,
		maxPayload: maxP,
		psk:        psk,
		isClient:   isClient,
		sendQueue:  make(chan []byte, sendQueueSize),
		closed:     make(chan struct{}),
		helloCh:    make(chan error, 1),
		confirmCh:  make(chan struct{}),
	}
	s.lastRecvNano.Store(time.Now().UnixNano())
	reserve := wire.HeaderSize
	if psk != nil {
		reserve += aeadOverhead
		priv, err := generateEphemeralKey()
		if err != nil {
			return nil, fmt.Errorf("session: keygen: %w", err)
		}
		s.priv = priv
	}
	s.frameBudget = maxP - reserve
	if s.frameBudget > wire.MaxPayload {
		s.frameBudget = wire.MaxPayload
	}
	if s.frameBudget < 512 {
		return nil, fmt.Errorf("session: carrier MaxPayload %d too small", maxP)
	}
	return s, nil
}

// MaxFramePayload is the largest DATA payload the mux may put in one frame.
func (s *Session) MaxFramePayload() int { return s.frameBudget }

// Start hooks the session into the transport. The caller owns the
// transport lifecycle (it must be started before Start and stopped after
// Close); a session never stops the transport, which allows the
// supervisor to build a fresh session over a reconnected carrier.
func (s *Session) Start() error {
	s.trans.Receive(func(msg []byte) {
		if c := s.crypto.Load(); c != nil {
			plain, err := c.decrypt(msg)
			if err != nil {
				// Replay or gap: the carrier broke its reliable+ordered
				// contract (or an attack). Kill the session at once.
				if errors.Is(err, errReplayedMessage) || errors.Is(err, errOutOfOrder) {
					utils.Debugf("[SESSION] fatal ordering violation: %v", err)
					s.CloseWithError(err)
					return
				}
				// A plaintext HELLO while crypto is on means the peer
				// rebuilt its session from scratch: reset immediately
				// instead of burning decrypt-failure budget.
				if looksLikePlaintextHello(msg) {
					utils.Debugf("[SESSION] plaintext HELLO over encrypted session: peer reset")
					s.CloseWithError(ErrPeerReset)
					return
				}
				n := c.consecutiveFailures.Add(1)
				utils.Debugf("[SESSION] decrypt failed (%d): %v", n, err)
				if n >= maxDecryptFailures {
					s.CloseWithError(ErrCryptoMismatch)
				}
				return
			}
			c.consecutiveFailures.Store(0)
			// First successfully decrypted frame = the peer proved it
			// holds the PSK (client confirmation on the exit side).
			s.confirmOnce.Do(func() { close(s.confirmCh) })
			msg = plain
		}
		f, err := wire.Decode(msg)
		if err != nil {
			utils.Debugf("[SESSION] dropping undecodable message: %v", err)
			return
		}
		s.lastRecvNano.Store(time.Now().UnixNano())
		s.dispatch(f)
	})
	go s.writerLoop()
	// keepaliveLoop starts only after a successful Handshake so no
	// control traffic is emitted mid-handshake.
	return nil
}

// looksLikePlaintextHello reports whether msg is an unencrypted v2 HELLO
// frame (magic + version + type).
func looksLikePlaintextHello(msg []byte) bool {
	return len(msg) >= wire.HeaderSize+1 &&
		msg[0] == wire.Magic0 && msg[1] == wire.Magic1 &&
		msg[2] == wire.Version && msg[3] == wire.TypeHello
}

// writerLoop is the ONLY goroutine that calls trans.Send. Keeping network
// writes off the dispatch path prevents the "write stalls -> dispatch
// blocks -> peer stops reading" deadlock cycle.
func (s *Session) writerLoop() {
	for {
		select {
		case msg := <-s.sendQueue:
			// A fatal close must not leave the writer sending dead
			// generation frames: select may still pick the queue over
			// the closed channel.
			select {
			case <-s.closed:
				if s.closeErr != ErrClosed {
					return
				}
			default:
			}
			if err := s.trans.Send(msg); err != nil {
				// Carriers are reliable-ordered by contract; a send
				// failure means the carrier is broken, and silently
				// dropping the frame would corrupt stream accounting.
				utils.Debugf("[SESSION] transport send failed: %v", err)
				s.CloseWithError(fmt.Errorf("session: carrier send: %w", err))
				return
			}
		case <-s.closed:
			// Drain only on GRACEFUL shutdown (GOAWAY/CLOSE matter).
			// On fatal errors the queue holds frames of a dead
			// generation — sending them would poison the next session
			// on the same carrier.
			if s.closeErr != ErrClosed {
				return
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				select {
				case msg := <-s.sendQueue:
					s.trans.Send(msg)
				default:
					return
				case <-time.After(time.Until(deadline)):
					return
				}
			}
		}
	}
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
	// Asymmetric handshake: only the client sends HELLO; the exit side
	// waits for it (its dispatch completes the handshake). This avoids
	// stray plaintext HELLO frames racing with crypto activation.
	if s.isClient {
		var payload []byte
		if s.psk != nil {
			// [role byte][32-byte ephemeral X25519 public key][caps]
			payload = append([]byte{roleByte(true)}, s.priv.PublicKey().Bytes()...)
			payload = append(payload, ourCapabilities)
		} else {
			payload = make([]byte, 8)
			binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))
		}
		if err := s.SendFrame(wire.Frame{Type: wire.TypeHello, Payload: payload}); err != nil {
			return fmt.Errorf("%w: send hello: %v", ErrHandshake, err)
		}
	}
	select {
	case err := <-s.helloCh:
		if err != nil {
			// A session that failed its handshake must not linger:
			// its keepalive would inject plaintext PINGs into the
			// peer's encrypted session and burn its failure budget.
			s.CloseWithError(err)
			return err
		}
	case <-time.After(HelloTimeout):
		err := fmt.Errorf("%w: timeout", ErrHandshake)
		s.CloseWithError(err)
		return err
	case <-s.closed:
		return ErrClosed
	}
	if s.psk != nil {
		if s.isClient {
			// Prove our keys to the exit at once, then wait for its
			// encrypted PONG: only then is the session mutually
			// authenticated and Ready on both sides.
			ping := make([]byte, 8)
			binary.BigEndian.PutUint64(ping, uint64(time.Now().UnixNano()))
			if err := s.SendFrame(wire.Frame{Type: wire.TypePing, Payload: ping}); err != nil {
				s.CloseWithError(err)
				return fmt.Errorf("%w: confirmation ping: %v", ErrHandshake, err)
			}
		}
		// Both sides: Ready only after the peer proved PSK knowledge
		// (first valid encrypted frame: client PING on exit, server PONG
		// on client).
		select {
		case <-s.confirmCh:
		case <-time.After(HelloTimeout):
			err := fmt.Errorf("%w: peer confirmation timeout", ErrHandshake)
			s.CloseWithError(err)
			return err
		case <-s.closed:
			return ErrClosed
		}
	}
	// From now on, loss of carrier connectivity kills the session; the
	// supervisor builds a fresh one over the reconnected carrier.
	go s.watchdog()
	go s.keepaliveLoop()
	return nil
}

func roleByte(isClient bool) byte {
	if isClient {
		return 1
	}
	return 0
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
		// Roles are asymmetric in the handshake: only the client sends
		// HELLO; the exit side answers with HELLO_ACK; the client
		// completes the handshake by verifying the key-confirmation tag.
		if s.isClient {
			// A HELLO carrying a client role byte means two clients
			// misconfigured to talk to each other.
			if s.psk != nil && len(f.Payload) == 33 && f.Payload[0] == roleByte(true) {
				s.failHello(ErrRoleConflict)
			}
			return
		}
		// A valid encrypted HELLO arriving after the handshake means the
		// peer restarted its session over the same carrier.
		if s.psk != nil && s.crypto.Load() != nil {
			utils.Debugf("[SESSION] HELLO over established session: peer reset")
			s.CloseWithError(ErrPeerReset)
			return
		}
		if s.psk != nil {
			// Payload: [role][32-byte pubkey][optional caps byte].
			if len(f.Payload) != 33 && len(f.Payload) != 34 {
				s.failHello(fmt.Errorf("bad HELLO length %d", len(f.Payload)))
				return
			}
			if f.Payload[0] == roleByte(s.isClient) {
				s.failHello(ErrRoleConflict)
				return
			}
			if len(f.Payload) == 34 {
				s.peerCaps.Store(uint32(f.Payload[33]))
			}
			peerPub := f.Payload[1:33]
			c, err := deriveSession(s.psk, s.priv, peerPub, s.isClient)
			if err != nil {
				s.failHello(err)
				return
			}
			clientPub, serverPub := orderPubs(s.priv.PublicKey().Bytes(), peerPub, s.isClient)
			tag := c.computeKeyConfirm(clientPub, serverPub)
			// [role][pubkey][caps][tag]
			ackPayload := append(append(append([]byte{roleByte(s.isClient)}, s.priv.PublicKey().Bytes()...), ourCapabilities), tag...)
			// HELLO_ACK must leave in plaintext: the client derives keys
			// from it. Enqueued before crypto is enabled, and the writer
			// preserves order.
			if err := s.SendFrame(wire.Frame{Type: wire.TypeHelloAck, Payload: ackPayload}); err != nil {
				utils.Debugf("[SESSION] HELLO_ACK send failed: %v", err)
			}
			s.crypto.Store(c)
		} else {
			if err := s.SendFrame(wire.Frame{Type: wire.TypeHelloAck, Payload: f.Payload}); err != nil {
				utils.Debugf("[SESSION] HELLO_ACK send failed: %v", err)
			}
		}
		select {
		case s.helloCh <- nil:
		default:
		}
	case wire.TypeHelloAck:
		if !s.isClient {
			return // the exit side does not expect HELLO_ACK
		}
		if s.psk != nil {
			if s.crypto.Load() != nil {
				return // duplicate HELLO_ACK
			}
			// [role][server pubkey][optional caps][key confirmation tag]
			if len(f.Payload) != 1+32+keyConfirmTagLen && len(f.Payload) != 1+32+1+keyConfirmTagLen {
				s.failHello(fmt.Errorf("bad HELLO_ACK length %d", len(f.Payload)))
				return
			}
			if f.Payload[0] == roleByte(s.isClient) {
				s.failHello(ErrRoleConflict)
				return
			}
			peerPub := f.Payload[1:33]
			tagOffset := 33
			if len(f.Payload) == 1+32+1+keyConfirmTagLen {
				s.peerCaps.Store(uint32(f.Payload[33]))
				tagOffset = 34
			}
			c, err := deriveSession(s.psk, s.priv, peerPub, s.isClient)
			if err != nil {
				s.failHello(err)
				return
			}
			clientPub, serverPub := orderPubs(s.priv.PublicKey().Bytes(), peerPub, s.isClient)
			if !c.verifyKeyConfirm(clientPub, serverPub, f.Payload[tagOffset:]) {
				s.failHello(errors.New("key confirmation failed (PSK mismatch?)"))
				return
			}
			s.crypto.Store(c)
		}
		select {
		case s.helloCh <- nil:
		default:
		}
	case wire.TypePing:
		if err := s.SendFrame(wire.Frame{Type: wire.TypePong, Payload: f.Payload}); err != nil {
			utils.Debugf("[SESSION] PONG send failed: %v", err)
		}
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
	// Serialized: the sequence allocated in encrypt() must match the
	// position in the queue, otherwise a concurrent sender could
	// enqueue a higher seq first and the peer would report a gap.
	s.sendMu.Lock()
	if c := s.crypto.Load(); c != nil {
		buf, err = c.encrypt(buf)
		if err != nil {
			s.sendMu.Unlock()
			return err
		}
	}
	// Enqueue for the writer goroutine. Blocks (applying backpressure)
	// when the carrier is saturated; unblocks with ErrClosed on Close.
	select {
	case s.sendQueue <- buf:
		s.sendMu.Unlock()
		return nil
	case <-s.closed:
		s.sendMu.Unlock()
		return ErrClosed
	}
}

func (s *Session) failHello(err error) {
	select {
	case s.helloCh <- fmt.Errorf("%w: %v", ErrHandshake, err):
	default:
	}
}

// orderPubs returns (clientPub, serverPub) given our and the peer's keys.
func orderPubs(ourPub, peerPub []byte, isClient bool) ([]byte, []byte) {
	if isClient {
		return ourPub, peerPub
	}
	return peerPub, ourPub
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
// Race-free: reading closeErr only after the closed channel fired gives
// a happens-before edge (channel close synchronizes with the write).
func (s *Session) Err() error {
	select {
	case <-s.closed:
		return s.closeErr
	default:
		return nil
	}
}
