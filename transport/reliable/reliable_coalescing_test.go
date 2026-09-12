package reliable

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/transport"
)

// LatestStateTransport is a test-only carrier modeling a cursor channel
// with COALESCING: the channel holds a SINGLE state slot, and a new Send
// overwrites whatever has not been published yet — intermediate states
// are lost by construction. A flush loop publishes the latest slot
// content every FlushInterval. Duplication and corruption of published
// states are injectable.
//
// This mirrors the OnlyOffice/Mail cursor channels, where the document
// keeps only the newest state: bursts of adapter snapshots collapse into
// one publication, and the reliability layer must recover purely from
// its cumulative snapshots.
type LatestStateTransport struct {
	*transport.BaseTransport

	// DupProb / CorruptProb apply to each PUBLISHED state. Arm before
	// Start (same convention as FaultyTransport).
	DupProb     float64
	CorruptProb float64

	mu      sync.Mutex
	slot    []byte // latest not-yet-published state
	hasSlot bool
	started bool
	peer    *LatestStateTransport
	done    chan struct{}

	flushInterval time.Duration

	sends     atomic.Uint64 // accepted Send calls
	published atomic.Uint64 // non-empty slot flushes (<= sends; the gap IS the coalescing)
}

// SetDup sets the duplicate probability (race-safe).
func (l *LatestStateTransport) SetDup(p float64) { l.mu.Lock(); l.DupProb = p; l.mu.Unlock() }

// SetCorrupt sets the corruption probability (race-safe).
func (l *LatestStateTransport) SetCorrupt(p float64) { l.mu.Lock(); l.CorruptProb = p; l.mu.Unlock() }

// NewLatestStatePair creates two connected coalescing endpoints publishing
// every flushInterval.
func NewLatestStatePair(config transport.TransportConfig, flushInterval time.Duration) (*LatestStateTransport, *LatestStateTransport) {
	a := &LatestStateTransport{
		BaseTransport: transport.NewBaseTransport(config),
		flushInterval: flushInterval,
		done:          make(chan struct{}),
	}
	b := &LatestStateTransport{
		BaseTransport: transport.NewBaseTransport(config),
		flushInterval: flushInterval,
		done:          make(chan struct{}),
	}
	a.peer, b.peer = b, a
	return a, b
}

var errLatestDown = errors.New("latest: not connected")

func (l *LatestStateTransport) Start() error {
	l.mu.Lock()
	if l.started {
		l.mu.Unlock()
		return errors.New("latest: already started")
	}
	l.started = true
	l.mu.Unlock()
	if err := l.BaseTransport.Start(); err != nil {
		return err
	}
	l.SetConnected(true)
	go l.flushLoop()
	return nil
}

func (l *LatestStateTransport) Stop() error {
	l.mu.Lock()
	if !l.started {
		l.mu.Unlock()
		return nil
	}
	l.started = false
	l.mu.Unlock()
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return l.BaseTransport.Stop()
}

// Send stores data as the current channel state, OVERWRITING any state
// that has not been published yet. That is the whole coalescing model.
func (l *LatestStateTransport) Send(data []byte) error {
	if !l.IsConnected() {
		return errLatestDown
	}
	l.mu.Lock()
	l.slot = append(l.slot[:0], data...)
	l.hasSlot = true
	l.mu.Unlock()
	l.sends.Add(1)
	l.RecordSend(len(data))
	return nil
}

// MaxPayload implements the session payloadCapacitor extension.
func (l *LatestStateTransport) MaxPayload() int { return 256 * 1024 }

// Sends reports accepted Send calls. Diagnostics for coalescing ratio.
func (l *LatestStateTransport) Sends() uint64 { return l.sends.Load() }

// Published reports how many states were actually flushed to the peer.
// Published < Sends means intermediate states were coalesced away.
func (l *LatestStateTransport) Published() uint64 { return l.published.Load() }

func (l *LatestStateTransport) flushLoop() {
	iv := l.flushInterval
	if iv <= 0 {
		iv = 2 * time.Millisecond
	}
	ticker := time.NewTicker(iv)
	defer ticker.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-ticker.C:
		}
		l.mu.Lock()
		if !l.hasSlot {
			l.mu.Unlock()
			continue
		}
		snap := l.slot
		l.slot = nil
		l.hasSlot = false
		dup := rand.Float64() < l.DupProb
		corrupt := rand.Float64() < l.CorruptProb
		l.mu.Unlock()

		l.published.Add(1)
		l.emit(snap, corrupt)
		if dup {
			// Same state published twice, in order; an independent
			// corruption roll per copy.
			l.mu.Lock()
			corrupt2 := rand.Float64() < l.CorruptProb
			l.mu.Unlock()
			l.emit(snap, corrupt2)
		}
	}
}

// emit hands one (possibly corrupted) copy of the state to the peer.
// Receive callbacks are serialized: each endpoint has exactly one
// flushLoop.
func (l *LatestStateTransport) emit(snap []byte, corrupt bool) {
	if !l.peer.IsConnected() {
		return // peer offline: the publication is lost on the wire
	}
	cp := append([]byte(nil), snap...)
	if corrupt && len(cp) > 0 {
		cp[rand.Intn(len(cp))] ^= 0xFF
	}
	l.peer.RecordReceive(len(cp))
	l.peer.CallReceive(cp)
}

// TestLatestStateSlotOverwrite: the defining property of the model —
// several states written between flushes collapse to exactly one
// delivery of the LATEST state.
func TestLatestStateSlotOverwrite(t *testing.T) {
	la, lb := NewLatestStatePair(transport.DefaultConfig(), 30*time.Millisecond)
	if err := la.Start(); err != nil {
		t.Fatal(err)
	}
	if err := lb.Start(); err != nil {
		t.Fatal(err)
	}
	defer la.Stop()
	defer lb.Stop()

	got := make(chan []byte, 4)
	lb.Receive(func(b []byte) { got <- b })

	for _, v := range []string{"v1", "v2", "v3"} {
		if err := la.Send([]byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case b := <-got:
		if string(b) != "v3" {
			t.Fatalf("delivered %q, want %q: intermediate states must be overwritten", b, "v3")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no delivery within 2s")
	}
	select {
	case b := <-got:
		t.Fatalf("unexpected extra delivery %q: the slot must publish once", b)
	case <-time.After(150 * time.Millisecond):
	}
	if la.Sends() != 3 || la.Published() != 1 {
		t.Fatalf("sends=%d published=%d, want 3/1", la.Sends(), la.Published())
	}
}

// TestCoalescingBidirectional: 2000 messages (1000 each way) over a
// coalescing + duplicating + corrupting pair of cursor channels. The
// upper layer must see a strict FIFO with no gaps and no duplicates in
// BOTH directions, even though intermediate snapshots are constantly
// overwritten before publication.
func TestCoalescingBidirectional(t *testing.T) {
	la, lb := NewLatestStatePair(transport.DefaultConfig(), 2*time.Millisecond)
	la.SetDup(0.15)
	la.SetCorrupt(0.05)
	lb.SetDup(0.15)
	lb.SetCorrupt(0.05)
	if err := la.Start(); err != nil {
		t.Fatal(err)
	}
	if err := lb.Start(); err != nil {
		t.Fatal(err)
	}

	ra := New(context.Background(), la, testConfig())
	rb := New(context.Background(), lb, testConfig())
	if err := ra.Start(); err != nil {
		t.Fatal(err)
	}
	if err := rb.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ra.Stop()
		rb.Stop()
		la.Stop()
		lb.Stop()
	})

	const total, size = 1000, 256 // 1000 per direction = 2000 total
	cAB := collect(rb, total)
	cBA := collect(ra, total)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < total; i++ {
			if err := rb.Send(makeMsg(i, size)); err != nil {
				t.Errorf("send b->a %d: %v", i, err)
				return
			}
		}
	}()
	for i := 0; i < total; i++ {
		if err := ra.Send(makeMsg(i, size)); err != nil {
			t.Fatalf("send a->b %d: %v", i, err)
		}
	}
	wg.Wait()

	expectMessages(t, cAB, 0, total, size)
	expectMessages(t, cBA, 0, total, size)
	expectNoExtra(t, cAB)
	expectNoExtra(t, cBA)

	t.Logf("coalescing A: sends=%d published=%d (%.1fx); B: sends=%d published=%d (%.1fx)",
		la.Sends(), la.Published(), float64(la.Sends())/float64(la.Published()),
		lb.Sends(), lb.Published(), float64(lb.Sends())/float64(lb.Published()))
	// The model must actually have coalesced: with 1000 sends against a
	// 2 ms flush, strictly fewer states may be published than written.
	if la.Published() >= la.Sends() {
		t.Errorf("A side: published=%d >= sends=%d — coalescing not exercised", la.Published(), la.Sends())
	}
	if lb.Published() >= lb.Sends() {
		t.Errorf("B side: published=%d >= sends=%d — coalescing not exercised", lb.Published(), lb.Sends())
	}
}
