package transport

import (
	"errors"
	"sync"
)

// MemoryTransport is an in-process Transport for tests: a pair of endpoints
// connected by buffered channels. Delivery is asynchronous (a dispatcher
// goroutine per endpoint), which avoids re-entrant calls into the network
// stack of the sending side.
type MemoryTransport struct {
	*BaseTransport

	mu      sync.Mutex
	peer    *MemoryTransport
	inbound chan []byte
	done    chan struct{}
}

// NewMemoryTransportPair creates two connected endpoints.
func NewMemoryTransportPair(config TransportConfig) (*MemoryTransport, *MemoryTransport) {
	a := &MemoryTransport{
		BaseTransport: NewBaseTransport(config),
		inbound:       make(chan []byte, config.MaxQueueSize),
		done:          make(chan struct{}),
	}
	b := &MemoryTransport{
		BaseTransport: NewBaseTransport(config),
		inbound:       make(chan []byte, config.MaxQueueSize),
		done:          make(chan struct{}),
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (m *MemoryTransport) Start() error {
	if err := m.BaseTransport.Start(); err != nil {
		return err
	}
	m.SetConnected(true)
	go m.dispatchLoop()
	return nil
}

func (m *MemoryTransport) Stop() error {
	if !m.IsRunning() {
		return nil
	}
	if err := m.BaseTransport.Stop(); err != nil {
		return err
	}
	close(m.done)
	return nil
}

func (m *MemoryTransport) Send(data []byte) error {
	if !m.IsConnected() {
		return errors.New("memory transport not connected")
	}
	m.mu.Lock()
	peer := m.peer
	m.mu.Unlock()
	if peer == nil || !peer.IsRunning() {
		return errors.New("memory transport peer closed")
	}

	cp := append([]byte(nil), data...)
	select {
	case peer.inbound <- cp:
		m.RecordSend(len(data))
		return nil
	default:
		return errors.New("memory transport peer queue full")
	}
}

func (m *MemoryTransport) dispatchLoop() {
	for {
		select {
		case data := <-m.inbound:
			m.RecordReceive(len(data))
			m.CallReceive(data)
		case <-m.done:
			return
		}
	}
}
