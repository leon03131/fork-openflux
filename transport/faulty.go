package transport

import (
	"errors"
	"math/rand"
	"sync"
)

var (
	errNotConnected = errors.New("faulty: not connected")
	errQueueFull    = errors.New("faulty: peer queue full")
)

// FaultyTransport is a test-only carrier that injects delivery faults:
// drops, duplicates and bit corruption. Used to verify that the v2
// session layer detects every violation and dies loudly.
type FaultyTransport struct {
	*BaseTransport

	mu          sync.Mutex
	DropProb    float64
	DupProb     float64
	CorruptProb float64

	peer    *FaultyTransport
	inbound chan []byte
	done    chan struct{}
}

// NewFaultyPair creates two connected fault-injecting endpoints.
// Configure probabilities on each before Start.
func NewFaultyPair(config TransportConfig) (*FaultyTransport, *FaultyTransport) {
	a := &FaultyTransport{
		BaseTransport: NewBaseTransport(config),
		inbound:       make(chan []byte, config.MaxQueueSize),
		done:          make(chan struct{}),
	}
	b := &FaultyTransport{
		BaseTransport: NewBaseTransport(config),
		inbound:       make(chan []byte, config.MaxQueueSize),
		done:          make(chan struct{}),
	}
	a.peer, b.peer = b, a
	return a, b
}

func (f *FaultyTransport) Start() error {
	if err := f.BaseTransport.Start(); err != nil {
		return err
	}
	f.SetConnected(true)
	go f.dispatchLoop()
	return nil
}

func (f *FaultyTransport) Stop() error {
	if !f.running.CompareAndSwap(1, 0) {
		return nil
	}
	f.connected.Store(0)
	close(f.done)
	return nil
}

func (f *FaultyTransport) Send(data []byte) error {
	if !f.IsConnected() {
		return errNotConnected
	}
	f.mu.Lock()
	drop := rand.Float64() < f.DropProb
	dup := rand.Float64() < f.DupProb
	corrupt := rand.Float64() < f.CorruptProb
	f.mu.Unlock()

	if drop {
		f.RecordSend(len(data)) // accepted but lost on the wire
		return nil
	}

	cp := append([]byte(nil), data...)
	if corrupt && len(cp) > 0 {
		cp[rand.Intn(len(cp))] ^= 0xFF
	}
	select {
	case f.peer.inbound <- cp:
	default:
		return errQueueFull
	}
	f.RecordSend(len(data))
	if dup {
		select {
		case f.peer.inbound <- append([]byte(nil), cp...):
		default:
		}
	}
	return nil
}

func (f *FaultyTransport) dispatchLoop() {
	for {
		select {
		case data := <-f.inbound:
			f.RecordReceive(len(data))
			f.CallReceive(data)
		case <-f.done:
			return
		}
	}
}

// MaxPayload implements the session payloadCapacitor extension.
func (f *FaultyTransport) MaxPayload() int { return 256 * 1024 }
