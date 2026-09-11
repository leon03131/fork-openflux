package transport

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

// DirectTransport is the reference carrier: a plain TCP connection with
// 4-byte length-prefixed messages. The exit side listens, the client
// dials. It is fully controlled by this project, so it is used to
// distinguish core bugs from provider-specific carrier breakage — and
// doubles as a fast non-obfuscated transport.
type DirectTransport struct {
	*BaseTransport

	addr       string // client: dial address; exit: listen address
	isExit     bool
	maxPayload int

	mu       sync.Mutex
	listener net.Listener
	conn     net.Conn
	doneCh   chan struct{}
	started  bool
}

func NewDirectTransport(addr string, isExit bool, config TransportConfig) *DirectTransport {
	return &DirectTransport{
		BaseTransport: NewBaseTransport(config),
		addr:          addr,
		isExit:        isExit,
		maxPayload:    64 * 1024,
	}
}

func (t *DirectTransport) Start() error {
	t.mu.Lock()
	if t.started {
		t.mu.Unlock()
		return errors.New("direct: already started")
	}
	t.started = true
	t.mu.Unlock()

	if err := t.BaseTransport.Start(); err != nil {
		return err
	}
	if t.isExit {
		listener, err := net.Listen("tcp", t.addr)
		if err != nil {
			// Allow Start to be retried after a failed listen.
			t.mu.Lock()
			t.started = false
			t.mu.Unlock()
			return fmt.Errorf("direct listen: %w", err)
		}
		t.mu.Lock()
		t.listener = listener
		t.mu.Unlock()
		go t.acceptLoop(listener)
		return nil
	}
	go t.dialLoop()
	return nil
}

func (t *DirectTransport) acceptLoop(listener net.Listener) {
	for t.IsRunning() {
		conn, err := listener.Accept()
		if err != nil {
			if t.IsRunning() {
				utils.Debugf("[DIRECT] accept error: %v", err)
			}
			return
		}
		t.setConn(conn)
		go t.readLoop(conn)
	}
}

func (t *DirectTransport) dialLoop() {
	first := true
	for t.IsRunning() {
		if !first {
			t.RecordReconnect()
		}
		first = false
		conn, err := net.DialTimeout("tcp", t.addr, 10*time.Second)
		if err != nil {
			utils.Debugf("[DIRECT] dial error: %v", err)
			t.sleepBeforeRetry()
			continue
		}
		if !t.setConn(conn) {
			return // stopped while dialing
		}
		t.readLoop(conn) // blocks until connection dies
		// Back off after a dead connection too, so a bouncing peer
		// (or two clients fighting) does not cause a reconnect storm.
		t.sleepBeforeRetry()
	}
}

// setConn installs the connection. Returns false if the transport was
// stopped meanwhile (the caller must not proceed to readLoop).
func (t *DirectTransport) setConn(conn net.Conn) bool {
	t.mu.Lock()
	if !t.IsRunning() {
		t.mu.Unlock()
		conn.Close()
		return false
	}
	if t.conn != nil {
		t.conn.Close()
	}
	t.conn = conn
	t.mu.Unlock()
	t.SetConnected(true)
	utils.Debugf("[DIRECT] connection established: %s", conn.RemoteAddr())
	return true
}

func (t *DirectTransport) readLoop(conn net.Conn) {
	lenBuf := make([]byte, 4)
	for {
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			break
		}
		n := binary.BigEndian.Uint32(lenBuf)
		if n == 0 || n > uint32(t.maxPayload) {
			utils.Debugf("[DIRECT] bad frame length %d", n)
			break
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(conn, payload); err != nil {
			break
		}
		t.RecordReceive(len(payload))
		t.CallReceive(payload)
	}
	utils.Debugf("[DIRECT] connection closed")
	t.mu.Lock()
	if t.conn == conn {
		t.conn = nil
		t.SetConnected(false)
	}
	t.mu.Unlock()
	conn.Close()
	if t.IsRunning() && t.isExit {
		// Accept loop keeps running and accepts the next client.
		return
	}
}

func (t *DirectTransport) sleepBeforeRetry() {
	// Modest fixed delay; the session layer has its own supervision.
	select {
	case <-time.After(time.Second):
	case <-t.closedCh():
	}
}

// closedCh mirrors BaseTransport.running as a channel for select-based
// waits. It is closed by Stop.
func (t *DirectTransport) closedCh() <-chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.doneCh == nil {
		t.doneCh = make(chan struct{})
	}
	return t.doneCh
}

func (t *DirectTransport) Send(data []byte) error {
	if !t.IsConnected() {
		return errors.New("direct: not connected")
	}
	if len(data) > t.maxPayload {
		return fmt.Errorf("direct: payload %d exceeds %d", len(data), t.maxPayload)
	}
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()
	if conn == nil {
		return errors.New("direct: no connection")
	}

	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)
	// A wedged peer must not block the session writer forever.
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer conn.SetWriteDeadline(time.Time{})
	if err := writeAll(conn, frame); err != nil {
		// A partial write desyncs the length-prefixed stream forever;
		// the connection is unrecoverable — kill it so we reconnect
		// onto a fresh, clean stream.
		t.killConn(conn)
		return fmt.Errorf("direct: write: %w", err)
	}
	t.RecordSend(len(data))
	return nil
}

// writeAll writes the full frame: net.Conn.Write may legally return
// n < len(p), and a partial write would permanently desync the
// length-prefixed framing.
func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("zero-length write")
		}
	}
	return nil
}

// killConn closes conn if it is still the active one and marks the
// transport disconnected, so the dial/accept loops reconnect.
func (t *DirectTransport) killConn(conn net.Conn) {
	t.mu.Lock()
	if t.conn == conn {
		t.conn = nil
		t.SetConnected(false)
	}
	t.mu.Unlock()
	conn.Close()
}

// Bounce forces the current connection down; the dial/accept loops
// reconnect with a clean byte stream. Implements Bouncer.
func (t *DirectTransport) Bounce() {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()
	if conn != nil {
		t.killConn(conn)
	}
}

// MaxPayload implements the session payloadCapacitor extension.
func (t *DirectTransport) MaxPayload() int { return t.maxPayload }

func (t *DirectTransport) Stop() error {
	if err := t.BaseTransport.Stop(); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.doneCh != nil {
		close(t.doneCh)
		t.doneCh = nil
	}
	if t.listener != nil {
		t.listener.Close()
		t.listener = nil
	}
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
	return nil
}
