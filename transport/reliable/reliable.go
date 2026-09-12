// Package reliable wraps a lossy Transport (cursor carriers that drop,
// duplicate, corrupt or coalesce messages) and exposes a strictly
// reliable, strictly FIFO-ordered Transport upward.
//
// The design is STATE REPLICATION, not generic ARQ: every outbound
// carrier message is a self-sufficient snapshot of ALL currently-unacked
// frames plus the cumulative inbound ack (ackThrough). Losing or
// coalescing intermediate snapshots is harmless — the receiver dedups
// frames by sequence number and only ever delivers the next contiguous
// seq upward, so the upper layer sees a perfect FIFO no matter what the
// carrier did to individual messages.
//
// Wire format of a carrier message (all integers big-endian):
//
//	magic "OFR1"   4 B
//	epoch         16 B   random per adapter instance (session generation)
//	ackThrough     8 B   highest contiguous inbound seq the sender saw
//	count          2 B   number of frames below
//	frames        ...    [seq 8B][len 4B][payload]...
//	crc32          4 B   IEEE CRC over everything above
//
// Backpressure: the unacked window is bounded (Config.MaxUnackedFrames /
// Config.MaxUnackedBytes, defaults 256 frames / 2 MiB). When the window
// is full Send blocks until ack progress frees space, the context is
// cancelled, or Stop is called — memory stays bounded no matter how
// lossy the peer's ack direction is.
//
// Lifecycle: the caller owns the inner carrier — start it BEFORE
// starting the adapter, stop it AFTER stopping the adapter (same
// convention as session over Transport). Start is single-use; Stop is
// idempotent. Carrier Send errors are surfaced fail-fast from Send, but
// the frame stays queued and the retransmit ticker keeps retrying: a
// carrier that recovers (e.g. cursor channel reconnect) heals the link
// with no message loss.
//
// Caveat: a snapshot is ONE carrier message carrying the whole window,
// so with a full window it can approach MaxUnackedBytes. Carriers whose
// real message budget is smaller than the current snapshot will make
// Send fail fast — on such carriers keep the window small (Config) so a
// snapshot always fits the budget.
package reliable

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"sync"
	"sync/atomic"
	"time"

	"github.com/leon03131/fork-openflux/transport"
)

const (
	epochSize   = 16
	headerSize  = 4 + epochSize + 8 + 2 // magic + epoch + ackThrough + count
	frameHeader = 8 + 4                 // seq + len
	crcSize     = 4

	// Overhead is the per-user-message cost of the adapter framing: one
	// snapshot header + one frame header + the CRC. MaxPayload reports
	// the inner carrier's budget minus this.
	Overhead = headerSize + frameHeader + crcSize // 46

	// DefaultMaxUnackedFrames bounds the retransmit window in frames.
	DefaultMaxUnackedFrames = 256
	// DefaultMaxUnackedBytes bounds the retransmit window in payload bytes.
	DefaultMaxUnackedBytes = 2 << 20 // 2 MiB
	// DefaultMaxPending bounds the inbound reorder buffer in frames.
	DefaultMaxPending = 256
	// DefaultRetransmitInterval is how often the current snapshot is
	// re-sent while unacked frames exist and no new Send resets the timer.
	DefaultRetransmitInterval = 500 * time.Millisecond

	// defaultInnerMaxPayload mirrors session's fallback for carriers
	// that do not report a payload budget.
	defaultInnerMaxPayload = 16 * 1024
)

var (
	ErrClosed     = errors.New("reliable: closed")
	ErrNotStarted = errors.New("reliable: not started")
	ErrTooLarge   = errors.New("reliable: payload exceeds MaxPayload")
)

// Config tunes the adapter. Zero fields get the Default* values.
type Config struct {
	MaxUnackedFrames   int
	MaxUnackedBytes    int
	MaxPending         int
	RetransmitInterval time.Duration
}

func (c Config) withDefaults() Config {
	if c.MaxUnackedFrames <= 0 {
		c.MaxUnackedFrames = DefaultMaxUnackedFrames
	}
	if c.MaxUnackedBytes <= 0 {
		c.MaxUnackedBytes = DefaultMaxUnackedBytes
	}
	if c.MaxPending <= 0 {
		c.MaxPending = DefaultMaxPending
	}
	if c.RetransmitInterval <= 0 {
		c.RetransmitInterval = DefaultRetransmitInterval
	}
	return c
}

type outFrame struct {
	seq     uint64
	payload []byte
}

// Transport is the reliability adapter. It implements transport.Transport
// plus the MaxPayload extension used by session.
type Transport struct {
	*transport.BaseTransport

	inner transport.Transport
	cfg   Config

	ctx    context.Context
	cancel context.CancelFunc

	epoch [epochSize]byte // our generation; random per adapter instance

	mu           sync.Mutex
	txSeq        uint64 // next outbound seq, starts at 1
	unacked      []outFrame
	unackedBytes int
	// ackSignal is a generation channel: closed+recreated to broadcast
	// ack progress (and closed a final time by Stop) to blocked Senders.
	ackSignal chan struct{}

	peerEpoch    [epochSize]byte
	peerEpochSet bool
	nextDeliver  uint64 // next inbound seq to deliver upward, starts at 1
	pending      map[uint64][]byte

	started bool
	stopped bool

	ackNeeded chan struct{} // cap 1: coalesced "send an ack now" requests
	resetTick chan struct{} // cap 1: coalesced retransmit-timer resets
	done      chan struct{}

	sendMu sync.Mutex // serializes inner.Send (Send path vs control loop)
	ticker *time.Ticker

	dropCnt atomic.Uint64 // inbound messages rejected by the receive filter
}

// New creates the adapter over inner. ctx cancellation unblocks Send
// waiters and stops the control loop; Stop does the same and is the
// normal shutdown path.
func New(ctx context.Context, inner transport.Transport, cfg Config) *Transport {
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithCancel(ctx)
	var epoch [epochSize]byte
	if _, err := rand.Read(epoch[:]); err != nil {
		// crypto/rand is not expected to fail; fall back to a time-based
		// generation rather than panic inside a library.
		binary.BigEndian.PutUint64(epoch[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(epoch[8:], uint64(time.Now().UnixNano())*0x9E3779B97F4A7C15)
	}
	return &Transport{
		BaseTransport: transport.NewBaseTransport(transport.DefaultConfig()),
		inner:         inner,
		cfg:           cfg.withDefaults(),
		ctx:           cctx,
		cancel:        cancel,
		epoch:         epoch,
		txSeq:         1,
		nextDeliver:   1,
		pending:       make(map[uint64][]byte),
		ackSignal:     make(chan struct{}),
		ackNeeded:     make(chan struct{}, 1),
		resetTick:     make(chan struct{}, 1),
		done:          make(chan struct{}),
	}
}

// Start hooks the adapter into the (already started) inner carrier and
// launches the retransmit/ack control loop. Single-use.
func (t *Transport) Start() error {
	t.mu.Lock()
	if t.started {
		t.mu.Unlock()
		return errors.New("reliable: already started")
	}
	if t.inner == nil {
		t.mu.Unlock()
		return errors.New("reliable: nil inner transport")
	}
	t.started = true
	t.ticker = time.NewTicker(t.cfg.RetransmitInterval)
	t.mu.Unlock()

	// The adapter owns the inner carrier's lifecycle; a pre-started
	// carrier (tests) is left alone.
	if !t.inner.IsRunning() {
		if err := t.inner.Start(); err != nil {
			return fmt.Errorf("reliable: start inner: %w", err)
		}
	}
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}
	t.SetConnected(true)
	t.inner.Receive(t.onMessage)
	go t.controlLoop()
	return nil
}

// Stop shuts the adapter down: blocked Senders wake with ErrClosed and
// the control loop exits. The inner carrier is NOT stopped (its owner
// decides) — the adapter may be rebuilt over a reused carrier.
// Idempotent.
func (t *Transport) Stop() error {
	t.mu.Lock()
	if !t.started || t.stopped {
		t.mu.Unlock()
		return nil
	}
	t.stopped = true
	t.cancel()
	close(t.ackSignal) // final broadcast: wake every blocked Sender
	t.mu.Unlock()

	close(t.done)
	t.SetConnected(false)
	return t.BaseTransport.Stop()
}

// MaxPayload implements the session payloadCapacitor extension: the
// inner carrier's budget minus the adapter's per-message overhead.
func (t *Transport) MaxPayload() int {
	inner := defaultInnerMaxPayload
	if pc, ok := t.inner.(interface{ MaxPayload() int }); ok && pc.MaxPayload() > 0 {
		inner = pc.MaxPayload()
	}
	return inner - Overhead
}

// IsConnected reports the adapter AND the carrier both being up.
func (t *Transport) IsConnected() bool {
	return t.BaseTransport.IsConnected() && t.inner != nil && t.inner.IsConnected()
}

// Stats reports adapter-level (user message) counters; the raw wire
// overhead is visible in the inner carrier's own stats.
func (t *Transport) Stats() transport.TransportStats {
	st := t.BaseTransport.Stats()
	st.Connected = t.IsConnected()
	return st
}

// Dropped reports how many inbound carrier messages were rejected by the
// receive filter (bad magic/CRC, self-echo, foreign epoch). Diagnostics.
func (t *Transport) Dropped() uint64 { return t.dropCnt.Load() }

// UnackedLen reports the current retransmit window occupancy in frames.
func (t *Transport) UnackedLen() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.unacked)
}

// UnackedBytes reports the current retransmit window occupancy in bytes.
func (t *Transport) UnackedBytes() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.unackedBytes
}

// Send accepts data into the retransmit window and ships a snapshot of
// ALL unacked frames. It blocks (backpressure) while the window is full,
// until ack progress, ctx cancellation or Stop. A carrier error is
// returned fail-fast, but the frame stays queued and will be
// retransmitted — a recovering carrier heals the link with no loss.
func (t *Transport) Send(data []byte) error {
	if len(data) > t.MaxPayload() {
		return fmt.Errorf("%w: %d > %d", ErrTooLarge, len(data), t.MaxPayload())
	}
	if len(data) > t.cfg.MaxUnackedBytes {
		return fmt.Errorf("%w: %d exceeds retransmit bound %d", ErrTooLarge, len(data), t.cfg.MaxUnackedBytes)
	}

	t.mu.Lock()
	if !t.started {
		t.mu.Unlock()
		return ErrNotStarted
	}
	// stopped is checked before ctx: Stop cancels the internal ctx, and
	// the adapter must report ErrClosed, not the cancellation cause.
	if t.stopped {
		t.mu.Unlock()
		return ErrClosed
	}
	if err := t.ctx.Err(); err != nil {
		t.mu.Unlock()
		return err
	}
	// Backpressure: hold NO lock while waiting so ack processing (which
	// needs mu) keeps making progress and can wake us.
	for len(t.unacked) >= t.cfg.MaxUnackedFrames || t.unackedBytes+len(data) > t.cfg.MaxUnackedBytes {
		ch := t.ackSignal
		t.mu.Unlock()
		select {
		case <-ch:
		case <-t.ctx.Done():
		case <-t.done:
		}
		t.mu.Lock()
		if t.stopped {
			t.mu.Unlock()
			return ErrClosed
		}
		if err := t.ctx.Err(); err != nil {
			t.mu.Unlock()
			return err
		}
	}

	cp := append([]byte(nil), data...)
	t.unacked = append(t.unacked, outFrame{seq: t.txSeq, payload: cp})
	t.txSeq++
	t.unackedBytes += len(cp)
	snap := t.buildSnapshotLocked()
	t.mu.Unlock()

	t.RecordSend(len(data))
	// New data resets the retransmit timer: the snapshot above already
	// carries the full state, an immediate tick would be redundant.
	select {
	case t.resetTick <- struct{}{}:
	default:
	}
	if err := t.transmit(snap); err != nil {
		return fmt.Errorf("reliable: carrier send: %w", err)
	}
	return nil
}

// transmit serializes the actual carrier write. The snapshot was built
// under mu but the carrier call holds only sendMu, so a slow carrier
// never blocks ack processing. Out-of-order snapshot delivery between
// concurrent transmitters is harmless: every snapshot is a consistent
// prefix state and the receiver dedups by seq / takes cumulative acks.
func (t *Transport) transmit(snap []byte) error {
	t.sendMu.Lock()
	err := t.inner.Send(snap)
	t.sendMu.Unlock()
	return err
}

// buildSnapshotLocked serializes the current state: cumulative ack for
// the inbound direction + every unacked outbound frame.
// Caller must hold mu.
func (t *Transport) buildSnapshotLocked() []byte {
	n := headerSize + crcSize
	for _, f := range t.unacked {
		n += frameHeader + len(f.payload)
	}
	buf := make([]byte, 0, n)
	buf = append(buf, "OFR1"...)
	buf = append(buf, t.epoch[:]...)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], t.nextDeliver-1) // ackThrough
	buf = append(buf, tmp[:]...)
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], uint16(len(t.unacked)))
	buf = append(buf, cnt[:]...)
	for _, f := range t.unacked {
		binary.BigEndian.PutUint64(tmp[:], f.seq)
		buf = append(buf, tmp[:]...)
		var ln [4]byte
		binary.BigEndian.PutUint32(ln[:], uint32(len(f.payload)))
		buf = append(buf, ln[:]...)
		buf = append(buf, f.payload...)
	}
	var cb [4]byte
	binary.BigEndian.PutUint32(cb[:], crc32.ChecksumIEEE(buf))
	buf = append(buf, cb[:]...)
	return buf
}

// controlLoop is the only owner of the retransmit ticker: it re-sends the
// snapshot while unacked data exists, and emits (possibly empty) ack
// messages when the receive path asks for one.
func (t *Transport) controlLoop() {
	defer t.ticker.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-t.ctx.Done():
			return
		case <-t.resetTick:
			t.ticker.Reset(t.cfg.RetransmitInterval)
		case <-t.ackNeeded:
			// Frames arrived from the peer: ack immediately. The ack
			// piggybacks on the full snapshot, or goes out as an empty
			// (count=0) message when we have no data outstanding.
			t.retransmit(true)
		case <-t.ticker.C:
			t.retransmit(false)
		}
	}
}

// retransmit ships the current snapshot. force=false (ticker path) skips
// the send when nothing is unacked. Carrier errors are swallowed here:
// the carrier may simply be reconnecting, and the next tick retries.
// Send is the only path that surfaces carrier errors (fail-fast).
func (t *Transport) retransmit(force bool) {
	t.mu.Lock()
	if t.stopped || (!force && len(t.unacked) == 0) {
		t.mu.Unlock()
		return
	}
	snap := t.buildSnapshotLocked()
	t.mu.Unlock()
	_ = t.transmit(snap)
}

// onMessage is the receive path, driven by the inner carrier's dispatch
// goroutine (serialized per the Transport contract).
func (t *Transport) onMessage(data []byte) {
	msg, ok := parseMessage(data)
	if !ok {
		// Corrupt/truncated/foreign garbage: counts as loss, stay silent.
		t.dropCnt.Add(1)
		return
	}
	if t.ctx.Err() != nil {
		return
	}

	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	switch {
	case msg.epoch == t.epoch:
		// Our own generation echoed back by the carrier: its ackThrough
		// refers to the PEER's seqs and must never free our unacked.
		t.mu.Unlock()
		t.dropCnt.Add(1)
		return
	case !t.peerEpochSet:
		// First valid message locks the peer generation.
		t.peerEpoch = msg.epoch
		t.peerEpochSet = true
	case t.peerEpoch != msg.epoch:
		// Stale generation or a foreign pair sharing the channel.
		t.mu.Unlock()
		t.dropCnt.Add(1)
		return
	}

	// 1) Cumulative ack: free everything the peer has contiguously seen.
	if msg.ackThrough > 0 && len(t.unacked) > 0 {
		freed := false
		for len(t.unacked) > 0 && t.unacked[0].seq <= msg.ackThrough {
			t.unackedBytes -= len(t.unacked[0].payload)
			t.unacked = t.unacked[1:]
			freed = true
		}
		if freed {
			close(t.ackSignal) // wake blocked Senders
			t.ackSignal = make(chan struct{})
		}
	}

	// 2) Frames: dedup by seq, deliver strictly in order, buffer the
	//    near-future, drop the rest (the retransmit ticker brings it back).
	var deliver [][]byte
	gotData := false
	for _, f := range msg.frames {
		gotData = true
		switch {
		case f.seq < t.nextDeliver:
			// Duplicate of an already-delivered frame.
		case f.seq == t.nextDeliver:
			deliver = append(deliver, f.payload)
			t.nextDeliver++
			// Drain everything the reorder buffer can now release.
			for {
				p, ok := t.pending[t.nextDeliver]
				if !ok {
					break
				}
				delete(t.pending, t.nextDeliver)
				deliver = append(deliver, p)
				t.nextDeliver++
			}
		default:
			// Future frame. The sender keeps at most MaxUnackedFrames in
			// flight, so a legit frame is never further than MaxPending
			// ahead; anything beyond that is garbage — drop it.
			if f.seq-t.nextDeliver < uint64(t.cfg.MaxPending) && len(t.pending) < t.cfg.MaxPending {
				if _, dup := t.pending[f.seq]; !dup {
					t.pending[f.seq] = append([]byte(nil), f.payload...)
				}
			}
		}
	}
	t.mu.Unlock()

	// Deliver WITHOUT holding mu: the upper callback may do arbitrary
	// work, and the receive path is serialized by the carrier contract.
	for _, p := range deliver {
		t.RecordReceive(len(p))
		t.CallReceive(p)
	}
	if gotData {
		select {
		case t.ackNeeded <- struct{}{}:
		default:
		}
	}
}

type inFrame struct {
	seq     uint64
	payload []byte
}

type message struct {
	epoch      [epochSize]byte
	ackThrough uint64
	frames     []inFrame
}

// parseMessage validates magic + CRC and decodes the frame list. All
// bounds are checked against the untrusted input; anything malformed is
// rejected (ok=false) without panicking.
func parseMessage(data []byte) (message, bool) {
	var m message
	if len(data) < headerSize+crcSize {
		return m, false
	}
	if string(data[:4]) != "OFR1" {
		return m, false
	}
	body := data[:len(data)-crcSize]
	if binary.BigEndian.Uint32(data[len(data)-crcSize:]) != crc32.ChecksumIEEE(body) {
		return m, false
	}
	copy(m.epoch[:], data[4:headerSize-10])
	m.ackThrough = binary.BigEndian.Uint64(data[headerSize-10 : headerSize-2])
	count := int(binary.BigEndian.Uint16(data[headerSize-2 : headerSize]))
	off := headerSize
	limit := len(data) - crcSize
	for i := 0; i < count; i++ {
		if limit-off < frameHeader {
			return message{}, false
		}
		seq := binary.BigEndian.Uint64(data[off:])
		ln := binary.BigEndian.Uint32(data[off+8:])
		off += frameHeader
		if uint64(ln) > uint64(limit-off) {
			return message{}, false
		}
		m.frames = append(m.frames, inFrame{seq: seq, payload: data[off : off+int(ln)]})
		off += int(ln)
	}
	if off != limit {
		return message{}, false // trailing garbage
	}
	return m, true
}
