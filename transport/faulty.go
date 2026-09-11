package transport

import (
	"errors"
	"math/rand"
	"sync"
	"time"
)

var (
	errNotConnected = errors.New("faulty: not connected")
	errQueueFull    = errors.New("faulty: peer queue full")
	errSendFailed   = errors.New("faulty: send failed (injected)")
)

// FaultyTransport is a test-only carrier that injects delivery faults:
// drops, duplicates and bit corruption. Used to verify that the v2
// session layer detects every violation and dies loudly.
//
// All fault knobs are exported fields guarded by mu; arm them before
// Start (or accept a benign race with in-flight Sends, as the existing
// probability knobs do).
type FaultyTransport struct {
	*BaseTransport

	mu          sync.Mutex
	DropProb    float64
	DupProb     float64
	CorruptProb float64
	started     bool

	// DisconnectAfterN, when >= 0, severs the link after N messages
	// were delivered to the peer: SetConnected(false) is latched and
	// every further Send fails with errNotConnected. N=0 disconnects
	// at Start, before anything can flow. -1 disables the trip.
	DisconnectAfterN int
	// FailSendAfterN, when >= 0, makes Send return errSendFailed once
	// N messages were accepted; the link stays connected (models a
	// carrier whose write path broke while the link is reported up).
	// -1 disables the trip.
	FailSendAfterN int
	// DelayMS, when > 0, delays every delivery by the SAME fixed
	// amount (DelayMS milliseconds). A uniform delay never reorders
	// messages, so the reliable+ordered carrier contract holds; a
	// random per-message delay would break FIFO and is not offered.
	DelayMS int

	sent      int // accepted Send calls (for FailSendAfterN)
	delivered int // messages actually handed to the peer (for DisconnectAfterN)

	// delayQueue + delayScheduled implement the FIFO delayed-delivery
	// drain: at most one timer is outstanding and each fire schedules
	// the next only after delivering, so order is strictly preserved
	// and Send never blocks on the delay.
	delayQueue     [][]byte
	delayScheduled bool

	peer    *FaultyTransport
	inbound chan []byte
	done    chan struct{}
}

// NewFaultyPair creates two connected fault-injecting endpoints.
// Configure probabilities on each before Start.
func NewFaultyPair(config TransportConfig) (*FaultyTransport, *FaultyTransport) {
	a := &FaultyTransport{
		BaseTransport:    NewBaseTransport(config),
		DisconnectAfterN: -1,
		FailSendAfterN:   -1,
		inbound:          make(chan []byte, config.MaxQueueSize),
		done:             make(chan struct{}),
	}
	b := &FaultyTransport{
		BaseTransport:    NewBaseTransport(config),
		DisconnectAfterN: -1,
		FailSendAfterN:   -1,
		inbound:          make(chan []byte, config.MaxQueueSize),
		done:             make(chan struct{}),
	}
	a.peer, b.peer = b, a
	return a, b
}

func (f *FaultyTransport) Start() error {
	f.mu.Lock()
	if f.started {
		f.mu.Unlock()
		return errors.New("faulty: already started")
	}
	f.started = true
	f.mu.Unlock()
	if err := f.BaseTransport.Start(); err != nil {
		return err
	}
	f.SetConnected(true)
	// DisconnectAfterN=0 means "down from the very start".
	f.mu.Lock()
	if f.DisconnectAfterN >= 0 && f.delivered >= f.DisconnectAfterN {
		f.SetConnected(false)
	}
	f.mu.Unlock()
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

// Reconnect restores connectivity after an injected DisconnectAfterN
// trip. The delivered-message budget is re-armed, otherwise the next
// Send would immediately trip the disconnect again.
func (f *FaultyTransport) Reconnect() {
	f.mu.Lock()
	f.delivered = 0
	f.mu.Unlock()
	f.SetConnected(true)
}

func (f *FaultyTransport) Send(data []byte) error {
	if !f.IsConnected() {
		return errNotConnected
	}
	f.mu.Lock()
	if f.DisconnectAfterN >= 0 && f.delivered >= f.DisconnectAfterN {
		f.SetConnected(false)
		f.mu.Unlock()
		return errNotConnected
	}
	if f.FailSendAfterN >= 0 && f.sent >= f.FailSendAfterN {
		f.mu.Unlock()
		return errSendFailed
	}
	drop := rand.Float64() < f.DropProb
	dup := rand.Float64() < f.DupProb
	corrupt := rand.Float64() < f.CorruptProb
	delay := time.Duration(f.DelayMS) * time.Millisecond
	f.sent++
	f.mu.Unlock()

	if drop {
		f.RecordSend(len(data)) // accepted but lost on the wire
		return nil
	}

	cp := append([]byte(nil), data...)
	if corrupt && len(cp) > 0 {
		cp[rand.Intn(len(cp))] ^= 0xFF
	}
	if delay > 0 {
		f.queueDelayed(cp, delay)
		f.RecordSend(len(data))
		if dup {
			f.queueDelayed(append([]byte(nil), cp...), delay)
		}
	} else {
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
	}

	f.mu.Lock()
	f.delivered++
	if f.DisconnectAfterN >= 0 && f.delivered >= f.DisconnectAfterN {
		f.SetConnected(false)
	}
	f.mu.Unlock()
	return nil
}

// queueDelayed appends a message to the delayed-delivery queue and arms
// the drain timer if none is outstanding.
func (f *FaultyTransport) queueDelayed(cp []byte, delay time.Duration) {
	f.mu.Lock()
	f.delayQueue = append(f.delayQueue, cp)
	if f.delayScheduled {
		f.mu.Unlock()
		return
	}
	f.delayScheduled = true
	f.mu.Unlock()
	time.AfterFunc(delay, f.drainDelayed)
}

// drainDelayed delivers the head of the delay queue and re-arms itself
// for the next message. Only one instance is ever scheduled, which is
// what keeps the delivery order strictly FIFO.
func (f *FaultyTransport) drainDelayed() {
	f.mu.Lock()
	if len(f.delayQueue) == 0 {
		f.delayScheduled = false
		f.mu.Unlock()
		return
	}
	cp := f.delayQueue[0]
	f.delayQueue = f.delayQueue[1:]
	delay := time.Duration(f.DelayMS) * time.Millisecond
	f.mu.Unlock()

	select {
	case <-f.done:
		f.mu.Lock()
		f.delayQueue = nil
		f.delayScheduled = false
		f.mu.Unlock()
		return
	default:
	}
	if f.IsConnected() {
		select {
		case f.peer.inbound <- cp:
		default:
		}
	}

	f.mu.Lock()
	if len(f.delayQueue) > 0 {
		// Keep delayScheduled=true and chain the next timer.
		time.AfterFunc(delay, f.drainDelayed)
	} else {
		f.delayScheduled = false
	}
	f.mu.Unlock()
}

func (f *FaultyTransport) dispatchLoop() {
	for {
		select {
		case data := <-f.inbound:
			// A severed link delivers nothing in either direction.
			if !f.IsConnected() {
				continue
			}
			f.RecordReceive(len(data))
			f.CallReceive(data)
		case <-f.done:
			return
		}
	}
}

// MaxPayload implements the session payloadCapacitor extension.
func (f *FaultyTransport) MaxPayload() int { return 256 * 1024 }
