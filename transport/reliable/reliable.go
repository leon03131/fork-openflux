// Package reliable wraps a lossy Transport (cursor carriers that drop,
// duplicate, corrupt or coalesce messages) and exposes a strictly
// reliable, strictly FIFO-ordered Transport upward.
//
// The design is SELECTIVE-REPEAT ARQ, not state replication: a new
// outbound frame is put on the wire exactly ONCE, immediately, as its
// own carrier message (multiple in-flight messages with a partially
// filled window are explicitly allowed by the wire format). Frames stay
// in the bounded unacked window until the peer's cumulative ack
// (ackThrough) covers them; acked frames are never re-sent.
// Retransmission happens only on:
//
//   - fast retransmit: an incoming ack repeats the previous ackThrough
//     while frames are outstanding — the peer only acks after receiving
//     data, so a repeated ackThrough means it saw something newer but is
//     stuck on a gap (dup-ack, TCP-style). After fastRetxThreshold
//     consecutive dup-acks the gap head (oldest unacked frame) is
//     re-sent, re-arming every fastRetxEvery further dup-acks while the
//     hole persists;
//   - RTO: no ack progress for max(Config.RetransmitInterval, 2×srtt),
//     where srtt is a Karn-smoothed RTT sampled only from frames that
//     were never retransmitted. The whole unacked window is then re-sent
//     in ONE carrier message — the byte budget below guarantees it
//     always fits — with exponential backoff (×2, capped at ×8).
//
// The retransmit timer has a single owner (controlLoop); it is (re)armed
// on new Sends and on ack progress, and stopped when the window drains.
//
// This replaces the previous every-Send-sends-a-full-snapshot design,
// which quadratically exploded wire traffic on non-coalescing carriers
// (cursor relays that forward every message): N messages × window size.
// Here wire traffic is O(1) messages per user message plus retransmits.
// The receive side dedups frames by sequence number and delivers only
// the next contiguous seq upward, so coalescing/loss/reorder on the
// carrier still yields a perfect FIFO; every inbound message triggers an
// ack, piggybacked on outbound data or as an empty (count=0) message.
//
// Wire format of a carrier message (OFR2, all integers big-endian):
//
//	magic "OFR2"   4 B
//	channelID      8 B   pair isolation; messages with a foreign ID are
//	                     dropped BEFORE any other processing
//	epoch         16 B   random per generation (New / NewGeneration)
//	ackThrough     8 B   highest contiguous inbound seq the sender saw
//	count          2 B   number of frames below
//	frames        ...    [seq 8B][len 4B][payload]...
//	mac           16 B   truncated HMAC-SHA256 over channelID..frames
//	                     (present only when Config.MacKey is set)
//	crc32          4 B   IEEE CRC over everything above
//
// Send contract (P0.1): once a frame is accepted into the retransmit
// window, carrier Send errors are NOT surfaced — the frame stays queued
// and the retransmit timer keeps retrying, so a carrier that recovers
// (cursor channel reconnect) heals the link with no message loss. Send
// returns an error only when the message can never fit (ErrTooLarge),
// the adapter is not started / stopped (ErrNotStarted / ErrClosed), the
// inner carrier is finally dead (ErrCarrierDown), the window stays full
// past Config.SendTimeout (ErrBackpressure), the parent context is
// cancelled, or a NewGeneration invalidated the wait
// (ErrGenerationClosed).
//
// IsConnected reports the ADAPTER being up (started && !stopped) and
// deliberately ignores transient inner-carrier disconnects: while the
// carrier reconnects the adapter simply buffers. The session watchdog
// therefore survives carrier reconnects; only a real Stop tears it down.
//
// Generations (P0.2): NewGeneration rotates the epoch, forgets the
// peer's epoch (re-learned from the next valid message, with the
// previous own/peer epochs explicitly denied), DROPS all unacked frames
// (a rebuilt session means dead streams — old data must not leak into
// the new generation), restarts txSeq/nextDeliver at 1 and clears the
// reorder buffer. Senders blocked on a full window are woken with
// ErrGenerationClosed. The supervisor calls it when rebuilding a
// session; BOTH sides must rotate for traffic to resume.
//
// Backpressure: the unacked window is bounded (Config.MaxUnackedFrames /
// Config.MaxUnackedBytes, defaults 256 frames / 2 MiB). Byte accounting
// is in WIRE bytes — every frame costs frameHeader+len(payload) — and
// the effective byte budget is additionally capped so that a full-window
// retransmit ALWAYS fits the inner carrier's MaxPayload in one message:
//
//	len(window message) = headerSize + sum(frameHeader+payload) + mac + crc
//	                    <= inner.MaxPayload()      (invariant, P0.4)
//
// MaxPayload reports the inner budget minus Overhead (which includes the
// per-frame header and the MAC slot even when the MAC is disabled), so a
// session sending MaxPayload-sized messages can never overflow a carrier
// message. When the window is full Send blocks until ack progress frees
// space, the context is cancelled, or Stop is called — memory stays
// bounded no matter how lossy the peer's ack direction is.
//
// Lifecycle: the caller owns the inner carrier — start it BEFORE
// starting the adapter, stop it AFTER stopping the adapter (same
// convention as session over Transport). Start is single-use; Stop is
// idempotent. The adapter may be rebuilt over a reused carrier.
package reliable

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/leon03131/fork-openflux/transport"
)

const (
	magicSize     = 4
	channelIDSize = 8
	epochSize     = 16
	headerSize    = magicSize + channelIDSize + epochSize + 8 + 2 // 38
	frameHeader   = 8 + 4                                         // 12: seq + len
	macSize       = 16                                            // truncated HMAC-SHA256
	crcSize       = 4

	// Overhead is the worst-case per-user-message cost of the adapter
	// framing: one message header + one frame header + the MAC slot +
	// the CRC. MaxPayload reports the inner carrier's budget minus this.
	// The MAC slot is reserved even when Config.MacKey is empty, keeping
	// the window-fit invariant independent of the MAC knob.
	Overhead = headerSize + frameHeader + macSize + crcSize // 70

	// DefaultMaxUnackedFrames bounds the retransmit window in frames.
	DefaultMaxUnackedFrames = 256
	// DefaultMaxUnackedBytes bounds the retransmit window in wire bytes
	// (frame header + payload per frame).
	DefaultMaxUnackedBytes = 2 << 20 // 2 MiB
	// DefaultMaxPending bounds the inbound reorder buffer in frames.
	DefaultMaxPending = 256
	// DefaultRetransmitInterval is the RTO floor: with no ack progress
	// for max(this, 2×smoothed RTT) the unacked window is retransmitted.
	DefaultRetransmitInterval = 500 * time.Millisecond

	// fastRetxThreshold is the number of consecutive duplicate acks that
	// triggers a fast retransmit of the gap head (TCP-style).
	fastRetxThreshold = 3
	// fastRetxEvery re-arms the fast retransmit every this many further
	// dup-acks while the hole persists (covers retransmits lost too).
	fastRetxEvery = 8
	// maxRTOBackoffShift caps the exponential RTO backoff at 1<<n.
	maxRTOBackoffShift = 3

	// defaultInnerMaxPayload mirrors session's fallback for carriers
	// that do not report a payload budget.
	defaultInnerMaxPayload = 16 * 1024
)

var (
	ErrClosed     = errors.New("reliable: closed")
	ErrNotStarted = errors.New("reliable: not started")
	ErrTooLarge   = errors.New("reliable: payload exceeds MaxPayload")
	// ErrCarrierDown: the inner carrier was stopped for good (not a
	// transient reconnect — a reconnecting carrier stays IsRunning).
	ErrCarrierDown = errors.New("reliable: inner carrier stopped")
	// ErrBackpressure: the window stayed full past Config.SendTimeout.
	ErrBackpressure = errors.New("reliable: send window full")
	// ErrGenerationClosed: a blocked Send was woken by NewGeneration;
	// the data belonged to the dead session and must not be re-sent.
	ErrGenerationClosed = errors.New("reliable: generation closed")
)

// Config tunes the adapter. Zero fields get the Default* values.
type Config struct {
	MaxUnackedFrames int
	MaxUnackedBytes  int
	MaxPending       int
	// RetransmitInterval is the RTO floor: with no ack progress for
	// max(RetransmitInterval, 2×smoothed RTT) the whole unacked window
	// is re-sent (a single carrier message) with exponential backoff.
	RetransmitInterval time.Duration
	// SendTimeout bounds how long Send blocks on a full window
	// (backpressure). Zero blocks until ack progress, ctx cancel, Stop
	// or NewGeneration — the historical behavior.
	SendTimeout time.Duration
	// ChannelID isolates logical pairs sharing one carrier/document:
	// snapshots with a foreign channel ID are dropped before any other
	// processing. Derive per pair from the PSK: DeriveChannelID.
	ChannelID [channelIDSize]byte
	// MacKey authenticates the snapshot metadata
	// (channelID+epoch+ackThrough+count+frames). Zero = MAC disabled
	// (tests). Derive from the PSK: DeriveMACKey.
	MacKey [32]byte
}

func (c Config) withDefaults() Config {
	if c.MaxUnackedFrames <= 0 {
		c.MaxUnackedFrames = DefaultMaxUnackedFrames
	}
	if c.MaxUnackedFrames > 65535 {
		c.MaxUnackedFrames = 65535 // message frame-count field is uint16
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

// deriveKey expands the PSK with HKDF-SHA256 for adapter-level purposes
// (independent of the session's own key schedule).
func deriveKey(psk []byte, info string, n int) []byte {
	out := make([]byte, n)
	// hkdf.Read cannot fail for a fixed-size output; the error is
	// returned for interface completeness only.
	_, _ = io.ReadFull(hkdf.New(sha256.New, psk, nil, []byte(info)), out)
	return out
}

// DeriveChannelID derives the pair's channel isolation ID from the PSK:
// identical for both ends of one pair, different across PSKs, so two
// pairs sharing one document cannot cross-latch.
func DeriveChannelID(psk []byte) (id [channelIDSize]byte) {
	copy(id[:], deriveKey(psk, "openflux-channel", channelIDSize))
	return id
}

// DeriveMACKey derives the snapshot metadata authentication key from the
// PSK. Feed it into Config.MacKey.
func DeriveMACKey(psk []byte) (key [32]byte) {
	copy(key[:], deriveKey(psk, "openflux-reliable-mac", 32))
	return key
}

type outFrame struct {
	seq     uint64
	payload []byte
	sentAt  time.Time // first transmission; RTT sampling (Karn)
	retxed  bool      // retransmitted at least once: excluded from RTT sampling
}

// Transport is the reliability adapter. It implements transport.Transport
// plus the MaxPayload extension used by session.
type Transport struct {
	*transport.BaseTransport

	inner  transport.Transport
	cfg    Config
	macKey []byte // nil = MAC disabled

	ctx    context.Context
	cancel context.CancelFunc

	epoch [epochSize]byte // our generation; random per New/NewGeneration

	mu           sync.Mutex
	genSeq       uint64 // bumped by NewGeneration to invalidate waiters
	txSeq        uint64 // next outbound seq, starts at 1
	unacked      []outFrame
	unackedBytes int // WIRE bytes: sum(frameHeader + len(payload))
	// ackSignal is a generation channel: closed+recreated to broadcast
	// ack progress (and closed by Stop / NewGeneration) to blocked Senders.
	ackSignal chan struct{}

	peerEpoch    [epochSize]byte
	peerEpochSet bool
	// denyEpochs holds the previous own+peer epochs after NewGeneration:
	// stale retransmits/echoes of the dead generation must never be
	// re-latched as a "new" peer.
	denyEpochs  [][epochSize]byte
	nextDeliver uint64 // next inbound seq to deliver upward, starts at 1
	pending     map[uint64][]byte

	started bool
	stopped bool

	ackNeeded chan struct{} // cap 1: coalesced "send an ack now" requests
	resetTick chan struct{} // cap 1: coalesced RTO-timer (re)arm requests
	fastRetx  chan struct{} // cap 1: coalesced fast-retransmit requests
	done      chan struct{}

	sendMu sync.Mutex // serializes inner.Send (Send path vs control loop)

	// Selective-repeat state, all guarded by mu. The RTO timer itself is
	// owned by controlLoop; these drive its (re)arming.
	srtt           time.Duration // smoothed RTT (Karn: never-retxed frames only)
	lastAckThrough uint64        // largest ackThrough seen (dup-ack detection)
	dupStreak      int           // consecutive acks with no ack progress
	lastFastRetx   int           // dupStreak value at the last fast retransmit

	dropCnt  atomic.Uint64 // inbound messages rejected by the receive filter
	txErrCnt atomic.Uint64 // swallowed carrier Send failures (healed by retransmit)
}

// randomEpoch returns a fresh generation ID; time-based fallback if
// crypto/rand ever fails (not expected — a library must not panic).
func randomEpoch() (epoch [epochSize]byte) {
	if _, err := rand.Read(epoch[:]); err != nil {
		binary.BigEndian.PutUint64(epoch[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(epoch[8:], uint64(time.Now().UnixNano())*0x9E3779B97F4A7C15)
	}
	return epoch
}

// New creates the adapter over inner. ctx cancellation unblocks Send
// waiters and stops the control loop; Stop does the same and is the
// normal shutdown path.
func New(ctx context.Context, inner transport.Transport, cfg Config) *Transport {
	if ctx == nil {
		ctx = context.Background()
	}
	cctx, cancel := context.WithCancel(ctx)
	cfg = cfg.withDefaults()
	var macKey []byte
	if cfg.MacKey != ([32]byte{}) {
		macKey = make([]byte, 32)
		copy(macKey, cfg.MacKey[:])
	}
	return &Transport{
		BaseTransport: transport.NewBaseTransport(transport.DefaultConfig()),
		inner:         inner,
		cfg:           cfg,
		macKey:        macKey,
		ctx:           cctx,
		cancel:        cancel,
		epoch:         randomEpoch(),
		txSeq:         1,
		nextDeliver:   1,
		pending:       make(map[uint64][]byte),
		ackSignal:     make(chan struct{}),
		ackNeeded:     make(chan struct{}, 1),
		resetTick:     make(chan struct{}, 1),
		fastRetx:      make(chan struct{}, 1),
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

// NewGeneration rotates the adapter into a fresh session generation,
// atomically: new random epoch, peer epoch forgotten (re-learned from
// the next valid message, with the previous own/peer epochs denied so
// stale retransmits of the dead generation can never re-latch), ALL
// unacked frames dropped (a rebuilt session means dead streams — old
// data must not leak into the new generation), txSeq/nextDeliver back
// to 1, reorder buffer cleared. Senders blocked on a full window are
// woken with ErrGenerationClosed.
//
// Called by the supervisor when rebuilding a session over a reused
// carrier. BOTH sides must rotate for traffic to resume: the peer
// latches our new epoch only after its own NewGeneration.
func (t *Transport) NewGeneration() error {
	t.mu.Lock()
	if !t.started {
		t.mu.Unlock()
		return ErrNotStarted
	}
	if t.stopped {
		t.mu.Unlock()
		return ErrClosed
	}

	// Bounded deny history (16 recent epochs): protects against
	// re-latching a stale peer epoch even after several unilateral
	// rotations in a row.
	deny := append(t.denyEpochs, t.epoch)
	if t.peerEpochSet {
		deny = append(deny, t.peerEpoch)
	}
	if len(deny) > 16 {
		deny = deny[len(deny)-16:]
	}
	t.denyEpochs = deny

	t.epoch = randomEpoch()
	t.peerEpoch = [epochSize]byte{}
	t.peerEpochSet = false
	t.unacked = nil
	t.unackedBytes = 0
	t.txSeq = 1
	t.nextDeliver = 1
	t.pending = make(map[uint64][]byte)
	// Dup-ack detection restarts with the generation's sequences. The
	// smoothed RTT survives: it is a property of the physical link, not
	// of the generation.
	t.lastAckThrough = 0
	t.dupStreak = 0
	t.lastFastRetx = 0
	t.genSeq++
	close(t.ackSignal) // wake blocked Senders: they see genSeq changed
	t.ackSignal = make(chan struct{})
	t.mu.Unlock()

	// Stop the retransmit timer (the window is empty now) and announce
	// the new epoch at once with an empty message; if the peer has not
	// rotated yet it drops it (epoch mismatch), which is fine — the
	// session handshake retries through the retransmit timer.
	select {
	case t.resetTick <- struct{}{}:
	default:
	}
	select {
	case t.ackNeeded <- struct{}{}:
	default:
	}
	return nil
}

// innerMaxPayload is the inner carrier's per-message budget.
func (t *Transport) innerMaxPayload() int {
	if pc, ok := t.inner.(interface{ MaxPayload() int }); ok && pc.MaxPayload() > 0 {
		return pc.MaxPayload()
	}
	return defaultInnerMaxPayload
}

// MaxPayload implements the session payloadCapacitor extension: the
// inner carrier's budget minus the adapter's per-message overhead.
func (t *Transport) MaxPayload() int {
	return t.innerMaxPayload() - Overhead
}

// windowByteBudget is the wire-byte bound for the unacked window:
// min(configured cap, what a single snapshot can ever carry). The MAC
// slot is reserved unconditionally (conservative when the MAC is off).
func (t *Transport) windowByteBudget() int {
	body := t.innerMaxPayload() - (headerSize + macSize + crcSize)
	if body < 0 {
		body = 0
	}
	if t.cfg.MaxUnackedBytes < body {
		return t.cfg.MaxUnackedBytes
	}
	return body
}

// IsConnected reports the ADAPTER being up (started and not stopped).
// It deliberately ignores the inner carrier's transient connectivity:
// while the carrier reconnects the adapter buffers outbound frames and
// the retransmit timer heals the link, so the session watchdog must
// not die on a temporary inner reconnect.
func (t *Transport) IsConnected() bool {
	return t.BaseTransport.IsConnected()
}

// Stats reports adapter-level (user message) counters; the raw wire
// overhead is visible in the inner carrier's own stats.
func (t *Transport) Stats() transport.TransportStats {
	st := t.BaseTransport.Stats()
	st.Connected = t.IsConnected()
	return st
}

// Dropped reports how many inbound carrier messages were rejected by the
// receive filter (bad magic/CRC/MAC, foreign channel, self-echo, stale or
// denied epoch). Diagnostics.
func (t *Transport) Dropped() uint64 { return t.dropCnt.Load() }

// TransmitErrors reports how many carrier Send calls failed after the
// frame was already accepted into the window. These errors are swallowed
// on purpose — the retransmit timer retries until the carrier heals.
func (t *Transport) TransmitErrors() uint64 { return t.txErrCnt.Load() }

// UnackedLen reports the current retransmit window occupancy in frames.
func (t *Transport) UnackedLen() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.unacked)
}

// UnackedBytes reports the current retransmit window occupancy in wire
// bytes (frame header + payload per frame).
func (t *Transport) UnackedBytes() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.unackedBytes
}

// Send accepts data into the retransmit window and ships the new frame
// exactly once, immediately, as its own carrier message (piggybacking
// the cumulative inbound ack). It blocks (backpressure) while the window
// is full, until ack progress, Config.SendTimeout, ctx cancellation,
// Stop or NewGeneration. Once the frame is queued, carrier errors are
// NOT surfaced: the retransmit timer keeps retrying and a recovering
// carrier heals the link with no loss.
func (t *Transport) Send(data []byte) error {
	if len(data) > t.MaxPayload() {
		return fmt.Errorf("%w: %d > %d", ErrTooLarge, len(data), t.MaxPayload())
	}
	wireLen := frameHeader + len(data)
	budget := t.windowByteBudget()
	if wireLen > budget {
		return fmt.Errorf("%w: %d (+frame header) exceeds retransmit budget %d", ErrTooLarge, len(data), budget)
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
	if !t.inner.IsRunning() {
		// Finally dead carrier (a reconnecting one stays IsRunning).
		t.mu.Unlock()
		return ErrCarrierDown
	}
	if err := t.ctx.Err(); err != nil {
		t.mu.Unlock()
		return err
	}

	gen := t.genSeq
	var timeout <-chan time.Time
	if t.cfg.SendTimeout > 0 {
		timer := time.NewTimer(t.cfg.SendTimeout)
		defer timer.Stop()
		timeout = timer.C
	}
	// Backpressure: hold NO lock while waiting so ack processing (which
	// needs mu) keeps making progress and can wake us.
	for len(t.unacked) >= t.cfg.MaxUnackedFrames || t.unackedBytes+wireLen > budget {
		ch := t.ackSignal
		t.mu.Unlock()
		select {
		case <-ch:
		case <-timeout:
			return fmt.Errorf("%w: no ack progress for %v", ErrBackpressure, t.cfg.SendTimeout)
		case <-t.ctx.Done():
		case <-t.done:
		}
		t.mu.Lock()
		if t.stopped {
			t.mu.Unlock()
			return ErrClosed
		}
		if t.genSeq != gen {
			t.mu.Unlock()
			return ErrGenerationClosed
		}
		if err := t.ctx.Err(); err != nil {
			t.mu.Unlock()
			return err
		}
	}

	cp := append([]byte(nil), data...)
	f := outFrame{seq: t.txSeq, payload: cp, sentAt: time.Now()}
	t.unacked = append(t.unacked, f)
	t.txSeq++
	t.unackedBytes += wireLen
	msg := t.buildMessageLocked([]outFrame{f}, wireLen)
	t.mu.Unlock()

	t.RecordSend(len(data))
	// New data (re)arms the retransmit timer: the message above carries
	// the new frame, an immediate RTO fire would be redundant.
	select {
	case t.resetTick <- struct{}{}:
	default:
	}
	if err := t.transmit(msg); err != nil {
		// P0.1: the frame is queued; the carrier may simply be
		// reconnecting. Count and swallow — the RTO timer retries.
		t.txErrCnt.Add(1)
	}
	return nil
}

// transmit serializes the actual carrier write. The message was built
// under mu but the carrier call holds only sendMu, so a slow carrier
// never blocks ack processing. Out-of-order delivery between concurrent
// transmitters is harmless: the receiver dedups by seq / takes
// cumulative acks.
func (t *Transport) transmit(msg []byte) error {
	t.sendMu.Lock()
	err := t.inner.Send(msg)
	t.sendMu.Unlock()
	return err
}

// computeMAC is the truncated HMAC-SHA256 over the authenticated region
// (channelID..frames, i.e. everything after the magic).
func computeMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)[:macSize]
}

// buildMessageLocked serializes one carrier message: the cumulative ack
// for the inbound direction + the given frames (possibly a single new
// frame, the gap head, the whole window, or none for a pure ack).
// wireBytes is sum(frameHeader+len(payload)) over frames.
// Caller must hold mu.
func (t *Transport) buildMessageLocked(frames []outFrame, wireBytes int) []byte {
	n := headerSize + wireBytes + crcSize
	if t.macKey != nil {
		n += macSize
	}
	buf := make([]byte, 0, n)
	buf = append(buf, "OFR2"...)
	buf = append(buf, t.cfg.ChannelID[:]...)
	buf = append(buf, t.epoch[:]...)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], t.nextDeliver-1) // ackThrough
	buf = append(buf, tmp[:]...)
	var cnt [2]byte
	binary.BigEndian.PutUint16(cnt[:], uint16(len(frames)))
	buf = append(buf, cnt[:]...)
	for _, f := range frames {
		binary.BigEndian.PutUint64(tmp[:], f.seq)
		buf = append(buf, tmp[:]...)
		var ln [4]byte
		binary.BigEndian.PutUint32(ln[:], uint32(len(f.payload)))
		buf = append(buf, ln[:]...)
		buf = append(buf, f.payload...)
	}
	if t.macKey != nil {
		buf = append(buf, computeMAC(t.macKey, buf[magicSize:])...)
	}
	var cb [4]byte
	binary.BigEndian.PutUint32(cb[:], crc32.ChecksumIEEE(buf))
	buf = append(buf, cb[:]...)
	return buf
}

// buildSnapshotLocked serializes the whole unacked window into a single
// message (used by the RTO full-window retransmit; the byte budget
// guarantees it fits the inner carrier). Caller must hold mu.
func (t *Transport) buildSnapshotLocked() []byte {
	return t.buildMessageLocked(t.unacked, t.unackedBytes)
}

// controlLoop is the single owner of the retransmit timer. It (re)arms
// the RTO timer on new Sends and ack progress, stops it when the window
// drains, emits pure-ack messages when the receive path asks for one,
// fast-retransmits the gap head on dup-acks, and on RTO expiry re-sends
// the whole unacked window with exponential backoff.
func (t *Transport) controlLoop() {
	rtoTimer := time.NewTimer(time.Hour)
	if !rtoTimer.Stop() {
		<-rtoTimer.C
	}
	defer rtoTimer.Stop()
	backoffShift := 0 // RTO multiplier is 1<<backoffShift; reset on progress

	// stopTimer disarms the RTO timer, draining a pending stale fire.
	stopTimer := func() {
		if !rtoTimer.Stop() {
			select {
			case <-rtoTimer.C:
			default:
			}
		}
	}

	for {
		select {
		case <-t.done:
			return
		case <-t.ctx.Done():
			return
		case <-t.resetTick:
			// New data sent or ack progress made: restart the clock at
			// the base RTO, or stop it when nothing is outstanding.
			backoffShift = 0
			t.mu.Lock()
			pending := len(t.unacked) > 0
			rto := t.rtoLocked()
			t.mu.Unlock()
			stopTimer()
			if pending {
				rtoTimer.Reset(rto)
			}
		case <-t.ackNeeded:
			// Frames arrived from the peer: ack immediately with an
			// empty (count=0) message. Outbound data frames piggyback
			// the same cumulative ackThrough anyway.
			t.sendAck()
		case <-t.fastRetx:
			t.fastRetransmit()
		case <-rtoTimer.C:
			t.retransmitAll()
			t.mu.Lock()
			pending := len(t.unacked) > 0
			rto := t.rtoLocked()
			t.mu.Unlock()
			if pending {
				if backoffShift < maxRTOBackoffShift {
					backoffShift++
				}
				rtoTimer.Reset(rto << backoffShift)
			}
		}
	}
}

// rtoLocked is the current retransmit timeout: max(configured floor,
// 2× smoothed RTT). Caller must hold mu.
func (t *Transport) rtoLocked() time.Duration {
	rto := t.cfg.RetransmitInterval
	if s := 2 * t.srtt; s > rto {
		rto = s
	}
	return rto
}

// sampleRTTLocked folds a Karn-valid RTT sample (from a frame that was
// never retransmitted) into the smoothed estimate. Caller must hold mu.
func (t *Transport) sampleRTTLocked(d time.Duration) {
	if d < time.Millisecond {
		d = time.Millisecond
	}
	if d > 30*time.Second {
		d = 30 * time.Second // defensive clamp against absurd samples
	}
	if t.srtt == 0 {
		t.srtt = d
	} else {
		t.srtt = t.srtt*7/8 + d/8
	}
}

// sendAck ships a pure-ack message (count=0): the cumulative ackThrough
// is part of every message header, so an ack needs no frames attached.
func (t *Transport) sendAck() {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	msg := t.buildMessageLocked(nil, 0)
	t.mu.Unlock()
	if err := t.transmit(msg); err != nil {
		// The carrier may simply be reconnecting; the next inbound frame
		// or retransmit re-asks for an ack.
		t.txErrCnt.Add(1)
	}
}

// retransmitAll fires on RTO expiry: re-send the WHOLE unacked window in
// one message (the byte budget guarantees it fits the inner carrier).
// All frames are marked retransmitted so their later acks do not poison
// the RTT estimate (Karn's algorithm). Carrier errors are counted and
// swallowed: the carrier may simply be reconnecting, and the timer
// retries with backoff.
func (t *Transport) retransmitAll() {
	t.mu.Lock()
	if t.stopped || len(t.unacked) == 0 {
		t.mu.Unlock()
		return
	}
	for i := range t.unacked {
		t.unacked[i].retxed = true
	}
	msg := t.buildSnapshotLocked()
	t.mu.Unlock()
	if err := t.transmit(msg); err != nil {
		t.txErrCnt.Add(1)
	}
}

// fastRetransmit re-sends only the oldest unacked frame (the gap head)
// after dup-acks signalled a hole. Never touches acked frames.
func (t *Transport) fastRetransmit() {
	t.mu.Lock()
	if t.stopped || len(t.unacked) == 0 {
		t.mu.Unlock()
		return
	}
	t.unacked[0].retxed = true
	msg := t.buildMessageLocked(t.unacked[:1], frameHeader+len(t.unacked[0].payload))
	t.mu.Unlock()
	if err := t.transmit(msg); err != nil {
		t.txErrCnt.Add(1)
	}
}

// onMessage is the receive path, driven by the inner carrier's dispatch
// goroutine (serialized per the Transport contract).
func (t *Transport) onMessage(data []byte) {
	msg, ok := t.parseMessage(data)
	if !ok {
		// Corrupt/truncated/forged/foreign-channel garbage: counts as
		// loss, stay silent.
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
		// First valid message locks the peer generation — except epochs
		// explicitly denied by NewGeneration (stale retransmits/echoes
		// of the dead generation).
		for _, d := range t.denyEpochs {
			if msg.epoch == d {
				t.mu.Unlock()
				t.dropCnt.Add(1)
				return
			}
		}
		t.peerEpoch = msg.epoch
		t.peerEpochSet = true
	case t.peerEpoch != msg.epoch:
		// Stale generation or a foreign pair sharing the channel.
		t.mu.Unlock()
		t.dropCnt.Add(1)
		return
	}

	// 1) Cumulative ack processing. A LARGER ackThrough is progress:
	//    free everything the peer has contiguously seen, sample the RTT,
	//    reset the dup-ack streak and the RTO clock. A REPEATED
	//    ackThrough while frames are outstanding is a dup-ack: the peer
	//    only acks after receiving data, so it saw something newer but
	//    is stuck on a gap — after fastRetxThreshold consecutive
	//    dup-acks, fast-retransmit the gap head. A smaller ackThrough is
	//    stale (duplicated/reordered ack) and ignored.
	if msg.ackThrough > t.lastAckThrough {
		t.lastAckThrough = msg.ackThrough
		t.dupStreak = 0
		t.lastFastRetx = 0
		freed := false
		now := time.Now()
		for len(t.unacked) > 0 && t.unacked[0].seq <= msg.ackThrough {
			f := t.unacked[0]
			t.unackedBytes -= frameHeader + len(f.payload)
			t.unacked = t.unacked[1:]
			freed = true
			if !f.retxed {
				t.sampleRTTLocked(now.Sub(f.sentAt))
			}
		}
		if freed {
			close(t.ackSignal) // wake blocked Senders
			t.ackSignal = make(chan struct{})
		}
		select {
		case t.resetTick <- struct{}{}: // restart the RTO clock
		default:
		}
	} else if msg.ackThrough == t.lastAckThrough && len(t.unacked) > 0 {
		t.dupStreak++
		if t.dupStreak == fastRetxThreshold ||
			(t.dupStreak > fastRetxThreshold && t.dupStreak-t.lastFastRetx >= fastRetxEvery) {
			t.lastFastRetx = t.dupStreak
			select {
			case t.fastRetx <- struct{}{}:
			default:
			}
		}
	}

	// 2) Frames: dedup by seq, deliver strictly in order, buffer the
	//    near-future, drop the rest (retransmission brings it back).
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

// parseMessage validates the envelope and decodes the frame list. Check
// order: magic, channel isolation (before anything else), CRC, MAC —
// content is only interpreted after all of them pass; a bad MAC means a
// silent drop without ever looking at the frames. All bounds are checked
// against the untrusted input; anything malformed is rejected (ok=false)
// without panicking.
func (t *Transport) parseMessage(data []byte) (message, bool) {
	var m message
	macLen := 0
	if t.macKey != nil {
		macLen = macSize
	}
	if len(data) < headerSize+macLen+crcSize {
		return m, false
	}
	if string(data[:magicSize]) != "OFR2" {
		return m, false
	}
	// Channel isolation (P0.3): foreign pairs on a shared carrier are
	// dropped before any further processing.
	if !bytes.Equal(data[magicSize:magicSize+channelIDSize], t.cfg.ChannelID[:]) {
		return m, false
	}
	body := data[:len(data)-crcSize]
	if binary.BigEndian.Uint32(data[len(data)-crcSize:]) != crc32.ChecksumIEEE(body) {
		return m, false
	}
	limit := len(data) - crcSize
	if t.macKey != nil {
		macStart := limit - macSize
		if !hmac.Equal(data[macStart:limit], computeMAC(t.macKey, data[magicSize:macStart])) {
			return m, false
		}
		limit = macStart
	}
	copy(m.epoch[:], data[magicSize+channelIDSize:headerSize-10])
	m.ackThrough = binary.BigEndian.Uint64(data[headerSize-10 : headerSize-2])
	count := int(binary.BigEndian.Uint16(data[headerSize-2 : headerSize]))
	off := headerSize
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
