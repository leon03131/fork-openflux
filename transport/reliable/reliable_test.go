package reliable

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/transport"
)

// testConfig keeps tests fast: aggressive retransmission instead of the
// production-tuned 500 ms, same window bounds as the defaults.
func testConfig() Config {
	return Config{
		MaxUnackedFrames:   DefaultMaxUnackedFrames,
		MaxUnackedBytes:    DefaultMaxUnackedBytes,
		MaxPending:         DefaultMaxPending,
		RetransmitInterval: 20 * time.Millisecond,
	}
}

type pair struct {
	fa, fb *transport.FaultyTransport
	ra, rb *Transport
}

func newPair(t *testing.T) *pair {
	t.Helper()
	return newPairCtx(t, context.Background())
}

func newPairCtx(t *testing.T, ctx context.Context) *pair {
	t.Helper()
	fa, fb := transport.NewFaultyPair(transport.DefaultConfig())
	if err := fa.Start(); err != nil {
		t.Fatalf("fa.Start: %v", err)
	}
	if err := fb.Start(); err != nil {
		t.Fatalf("fb.Start: %v", err)
	}
	ra := New(ctx, fa, testConfig())
	rb := New(ctx, fb, testConfig())
	if err := ra.Start(); err != nil {
		t.Fatalf("ra.Start: %v", err)
	}
	if err := rb.Start(); err != nil {
		t.Fatalf("rb.Start: %v", err)
	}
	p := &pair{fa: fa, fb: fb, ra: ra, rb: rb}
	t.Cleanup(func() {
		ra.Stop()
		rb.Stop()
		fa.Stop()
		fb.Stop()
	})
	return p
}

// makeMsg builds a deterministic, corruption-detectable payload.
func makeMsg(i, size int) []byte {
	m := make([]byte, size)
	binary.BigEndian.PutUint32(m, uint32(i))
	for j := 4; j < size; j++ {
		m[j] = byte(i*31 + j)
	}
	return m
}

func checkMsg(t *testing.T, got []byte, wantIdx, wantSize int) {
	t.Helper()
	if len(got) != wantSize {
		t.Fatalf("message %d: size %d, want %d", wantIdx, len(got), wantSize)
	}
	if idx := int(binary.BigEndian.Uint32(got)); idx != wantIdx {
		t.Fatalf("FIFO violation: got message %d, want %d", idx, wantIdx)
	}
	for j := 4; j < wantSize; j++ {
		if got[j] != byte(wantIdx*31+j) {
			t.Fatalf("message %d corrupted at byte %d", wantIdx, j)
		}
	}
}

type collector struct {
	ch chan []byte
}

// collect registers a non-blocking receive callback buffering up to cap.
func collect(tr *Transport, cap int) *collector {
	c := &collector{ch: make(chan []byte, cap)}
	tr.Receive(func(b []byte) { c.ch <- b })
	return c
}

// expectMessages verifies strict FIFO delivery of messages [from, to).
func expectMessages(t *testing.T, c *collector, from, to, size int) {
	t.Helper()
	for i := from; i < to; i++ {
		select {
		case got := <-c.ch:
			checkMsg(t, got, i, size)
		case <-time.After(60 * time.Second):
			t.Fatalf("timeout waiting for message %d of [%d,%d)", i, from, to)
		}
	}
}

// expectNoExtra asserts that nothing more is delivered (no duplicates,
// no stale frames) within a short window.
func expectNoExtra(t *testing.T, c *collector) {
	t.Helper()
	select {
	case extra := <-c.ch:
		idx := 0
		if len(extra) >= 4 {
			idx = int(binary.BigEndian.Uint32(extra))
		}
		t.Fatalf("unexpected extra/duplicate delivery (idx=%d, %d bytes)", idx, len(extra))
	case <-time.After(300 * time.Millisecond):
	}
}

// TestReliableUnderDrops: 30% message loss in BOTH directions (data and
// acks). All 500 messages must arrive, strictly in order.
func TestReliableUnderDrops(t *testing.T) {
	p := newPair(t)
	p.fa.SetDrop(0.3)
	p.fb.SetDrop(0.3)

	const total, size = 500, 512
	c := collect(p.rb, total)
	for i := 0; i < total; i++ {
		if err := p.ra.Send(makeMsg(i, size)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	expectMessages(t, c, 0, total, size)
	expectNoExtra(t, c)
	t.Logf("drops: ra=%d rb=%d (carrier-level, includes acks)", p.ra.Dropped(), p.rb.Dropped())
}

// TestReliableUnderDuplicates: 30% duplication in both directions. Not a
// single duplicate may reach the upper layer.
func TestReliableUnderDuplicates(t *testing.T) {
	p := newPair(t)
	p.fa.SetDup(0.3)
	p.fb.SetDup(0.3)

	const total, size = 500, 512
	c := collect(p.rb, total)
	for i := 0; i < total; i++ {
		if err := p.ra.Send(makeMsg(i, size)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	expectMessages(t, c, 0, total, size)
	expectNoExtra(t, c)
}

// TestReliableDropAndDup: 20% loss + 20% duplication simultaneously,
// with traffic in BOTH directions (ack piggybacking under load).
func TestReliableDropAndDup(t *testing.T) {
	p := newPair(t)
	p.fa.SetDrop(0.2)
	p.fa.SetDup(0.2)
	p.fb.SetDrop(0.2)
	p.fb.SetDup(0.2)

	const totalAB, sizeAB = 500, 512
	const totalBA, sizeBA = 100, 256
	cAB := collect(p.rb, totalAB)
	cBA := collect(p.ra, totalBA)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < totalBA; i++ {
			if err := p.rb.Send(makeMsg(i, sizeBA)); err != nil {
				t.Errorf("send b->a %d: %v", i, err)
				return
			}
		}
	}()
	for i := 0; i < totalAB; i++ {
		if err := p.ra.Send(makeMsg(i, sizeAB)); err != nil {
			t.Fatalf("send a->b %d: %v", i, err)
		}
	}
	wg.Wait()
	expectMessages(t, cAB, 0, totalAB, sizeAB)
	expectMessages(t, cBA, 0, totalBA, sizeBA)
	expectNoExtra(t, cAB)
	expectNoExtra(t, cBA)
}

// TestReliableUnderCorruption: 10% bit corruption in both directions.
// Corrupted snapshots fail the CRC and are dropped (counted); the upper
// layer must see only intact messages.
func TestReliableUnderCorruption(t *testing.T) {
	p := newPair(t)
	p.fa.SetCorrupt(0.1)
	p.fb.SetCorrupt(0.1)

	const total, size = 500, 512
	c := collect(p.rb, total)
	for i := 0; i < total; i++ {
		if err := p.ra.Send(makeMsg(i, size)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	expectMessages(t, c, 0, total, size)
	expectNoExtra(t, c)
	if d := p.ra.Dropped() + p.rb.Dropped(); d == 0 {
		t.Error("expected CRC drops with CorruptProb=0.1, got 0 — corruption path not exercised")
	} else {
		t.Logf("CRC drops: ra=%d rb=%d", p.ra.Dropped(), p.rb.Dropped())
	}
}

// craftMessageV2 builds a raw OFR2 adapter wire message for injection
// tests. macKey=nil builds a MAC-less message (matching Configs without
// a MacKey).
func craftMessageV2(channelID [channelIDSize]byte, macKey []byte, epoch [epochSize]byte, ackThrough, ackBits, seq uint64, payload []byte) []byte {
	buf := make([]byte, 0, headerSize+frameHeader+len(payload)+macSize+crcSize)
	buf = append(buf, "OFR2"...)
	buf = append(buf, channelID[:]...)
	buf = append(buf, epoch[:]...)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], ackThrough)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint64(tmp[:], ackBits)
	buf = append(buf, tmp[:]...)
	buf = append(buf, 0, 1) // count=1
	binary.BigEndian.PutUint64(tmp[:], seq)
	buf = append(buf, tmp[:]...)
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(len(payload)))
	buf = append(buf, ln[:]...)
	buf = append(buf, payload...)
	if macKey != nil {
		buf = append(buf, computeMAC(macKey, buf[magicSize:])...)
	}
	var cb [4]byte
	binary.BigEndian.PutUint32(cb[:], crc32.ChecksumIEEE(buf))
	buf = append(buf, cb[:]...)
	return buf
}

// craftAckV2 builds a raw pure-ack (count=0) OFR2 message with the given
// cumulative ackThrough and SACK bitmap — for driving the sender's ack
// processing deterministically in dup-ack/threshold tests.
func craftAckV2(channelID [channelIDSize]byte, epoch [epochSize]byte, ackThrough, ackBits uint64) []byte {
	buf := make([]byte, 0, headerSize+crcSize)
	buf = append(buf, "OFR2"...)
	buf = append(buf, channelID[:]...)
	buf = append(buf, epoch[:]...)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], ackThrough)
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint64(tmp[:], ackBits)
	buf = append(buf, tmp[:]...)
	buf = append(buf, 0, 0) // count=0
	var cb [4]byte
	binary.BigEndian.PutUint32(cb[:], crc32.ChecksumIEEE(buf))
	buf = append(buf, cb[:]...)
	return buf
}

// parseSeqs extracts the frame seqs of a raw OFR2 wire message
// (bounds-checked; ok=false if it is not a well-formed frame list).
func parseSeqs(data []byte) (seqs []uint64, ok bool) {
	if len(data) < headerSize+crcSize || string(data[:magicSize]) != "OFR2" {
		return nil, false
	}
	count := int(binary.BigEndian.Uint16(data[headerSize-2 : headerSize]))
	off := headerSize
	for i := 0; i < count; i++ {
		if off+frameHeader > len(data) {
			return nil, false
		}
		seq := binary.BigEndian.Uint64(data[off:])
		ln := binary.BigEndian.Uint32(data[off+8:])
		off += frameHeader
		if uint64(ln) > uint64(len(data)-off) {
			return nil, false
		}
		seqs = append(seqs, seq)
		off += int(ln)
	}
	return seqs, true
}

// waitDropped polls until r's drop counter reaches want.
func waitDropped(t *testing.T, r *Transport, want uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for r.Dropped() < want {
		if time.Now().After(deadline) {
			t.Fatalf("dropped=%d, want >= %d", r.Dropped(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitDrained polls until r's retransmit window is fully acked.
func waitDrained(t *testing.T, r *Transport) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for r.UnackedLen() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("window did not drain: %d frames left", r.UnackedLen())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestReliableReconnect: the carrier dies mid-stream (DisconnectAfterN),
// gets reconnected, and the link self-heals from the retransmit timer
// with zero loss. Per the P0.1 Send contract, Send does NOT fail while
// the carrier is down — frames buffer in the window and carrier errors
// are swallowed (counted in TransmitErrors). Afterwards a NEW adapter
// generation takes over the same carriers and messages from the old
// generation are dropped.
func TestReliableReconnect(t *testing.T) {
	p := newPair(t)
	p.fb.SetDisconnectAfterN(50) // b's carrier dies after 50 sends

	const total, size = 100, 256
	cA := collect(p.ra, total)

	go func() {
		for i := 0; i < total; i++ {
			// Never fails while the window has room: carrier errors are
			// swallowed and healed by the retransmit timer.
			if err := p.rb.Send(makeMsg(i, size)); err != nil {
				t.Errorf("send %d: %v (must buffer, not fail)", i, err)
				return
			}
		}
	}()

	// Wait for the trip, then follow the scenario: explicit down + reconnect.
	deadline := time.Now().Add(10 * time.Second)
	for p.fb.IsConnected() {
		if time.Now().After(deadline) {
			t.Fatal("carrier did not trip on DisconnectAfterN=50")
		}
		time.Sleep(5 * time.Millisecond)
	}
	p.fb.SetConnected(false)
	p.fb.Reconnect()

	// Self-healing: the retransmit timer re-sends the unacked window once
	// the carrier is back; frames the peer already saw are deduped.
	expectMessages(t, cA, 0, total, size)
	expectNoExtra(t, cA)
	if n := p.rb.TransmitErrors(); n == 0 {
		t.Error("expected swallowed carrier transmit errors during the outage")
	} else {
		t.Logf("swallowed carrier errors during outage: %d (all healed)", n)
	}

	// --- old generation drop + handover to a new generation ---
	oldEpoch := p.ra.epoch
	if err := p.ra.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := p.rb.Stop(); err != nil {
		t.Fatal(err)
	}

	ra2 := New(context.Background(), p.fa, testConfig())
	rb2 := New(context.Background(), p.fb, testConfig())
	if err := ra2.Start(); err != nil {
		t.Fatal(err)
	}
	if err := rb2.Start(); err != nil {
		t.Fatal(err)
	}
	defer ra2.Stop()
	defer rb2.Stop()

	const fresh, freshSize = 20, 128
	cB2 := collect(rb2, fresh+1)
	// First real message locks rb2 onto the NEW generation's epoch.
	if err := ra2.Send(makeMsg(7000, freshSize)); err != nil {
		t.Fatal(err)
	}
	expectMessages(t, cB2, 7000, 7001, freshSize)

	// Inject a perfectly well-formed message from the OLD generation:
	// huge ackThrough and a seq=1 frame — all of it must be ignored.
	stale := craftMessageV2([channelIDSize]byte{}, nil, oldEpoch, 1_000_000, 0, 1, []byte("STALE-GENERATION"))
	dropsBefore := rb2.Dropped()
	if err := p.fa.Send(stale); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for rb2.Dropped() == dropsBefore {
		if time.Now().After(deadline) {
			t.Fatal("stale-generation message was not observed/dropped")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The new generation still flows cleanly after the injection.
	for i := 7001; i < 7000+fresh; i++ {
		if err := ra2.Send(makeMsg(i, freshSize)); err != nil {
			t.Fatalf("fresh send %d: %v", i, err)
		}
	}
	expectMessages(t, cB2, 7001, 7000+fresh, freshSize)
	expectNoExtra(t, cB2)

	rb2.mu.Lock()
	nd := rb2.nextDeliver
	rb2.mu.Unlock()
	if nd != uint64(fresh)+1 {
		t.Errorf("nextDeliver=%d after stale injection, want %d (untouched)", nd, fresh+1)
	}
}

// TestNewGeneration: rotation is atomic — blocked Senders wake with
// ErrGenerationClosed, unacked/txSeq/nextDeliver/pending reset, peer
// epoch re-learned, previous epochs denied, and fresh traffic flows
// once BOTH sides rotated.
func TestNewGeneration(t *testing.T) {
	p := newPair(t)
	const size = 256

	// Caps must absorb the 256 fill-phase deliveries: a full collector
	// channel would park the carrier dispatch goroutine forever.
	cB := collect(p.rb, 600)
	cA := collect(p.ra, 600)
	for i := 0; i < 5; i++ {
		if err := p.ra.Send(makeMsg(i, size)); err != nil {
			t.Fatal(err)
		}
		if err := p.rb.Send(makeMsg(100+i, size)); err != nil {
			t.Fatal(err)
		}
	}
	expectMessages(t, cB, 0, 5, size)
	expectMessages(t, cA, 100, 105, size)
	waitDrained(t, p.ra)
	waitDrained(t, p.rb)

	oldEpochA := p.ra.epoch
	oldEpochB := p.rb.epoch

	// Fill A's window with the ack path down and park a blocked Sender.
	p.fb.SetDrop(1.0)
	payload := makeMsg(0, 512)
	for i := 0; i < DefaultMaxUnackedFrames; i++ {
		if err := p.ra.Send(payload); err != nil {
			t.Fatal(err)
		}
	}
	blocked := make(chan error, 1)
	go func() { blocked <- p.ra.Send(payload) }()
	select {
	case err := <-blocked:
		t.Fatalf("Send returned %v with a full window; must block", err)
	case <-time.After(300 * time.Millisecond):
	}

	if err := p.ra.NewGeneration(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-blocked:
		if !errors.Is(err, ErrGenerationClosed) {
			t.Fatalf("blocked Send: %v, want ErrGenerationClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked Send not woken by NewGeneration")
	}
	if n := p.ra.UnackedLen(); n != 0 {
		t.Fatalf("unacked=%d after NewGeneration, want 0", n)
	}
	if b := p.ra.UnackedBytes(); b != 0 {
		t.Fatalf("unackedBytes=%d after NewGeneration, want 0", b)
	}
	p.ra.mu.Lock()
	if p.ra.txSeq != 1 || p.ra.nextDeliver != 1 || len(p.ra.pending) != 0 || p.ra.peerEpochSet {
		t.Fatalf("state not reset: txSeq=%d nextDeliver=%d pending=%d peerEpochSet=%v",
			p.ra.txSeq, p.ra.nextDeliver, len(p.ra.pending), p.ra.peerEpochSet)
	}
	newEpochA := p.ra.epoch
	denyA := append([][epochSize]byte(nil), p.ra.denyEpochs...)
	p.ra.mu.Unlock()
	if newEpochA == oldEpochA {
		t.Fatal("epoch not rotated")
	}
	if len(denyA) != 2 || denyA[0] != oldEpochA || denyA[1] != oldEpochB {
		t.Fatalf("deny list = %v, want [%x %x]", denyA, oldEpochA[:4], oldEpochB[:4])
	}

	// Heal b->a (with B still on the old generation nothing flows
	// spontaneously: both windows are empty and the timers stay silent),
	// then inject a well-formed old-epoch-B message: it must NOT re-latch
	// as the new peer generation — the epoch is on A's deny list. The
	// sleep lets any ack signal pending from the fill phase fire and
	// settle first, so the drop baseline below is exact.
	p.fb.SetDrop(0)
	time.Sleep(100 * time.Millisecond)
	drops := p.ra.Dropped()
	if err := p.fb.Send(craftMessageV2([channelIDSize]byte{}, nil, oldEpochB, 999, 0, 1, []byte("STALE-B"))); err != nil {
		t.Fatal(err)
	}
	waitDropped(t, p.ra, drops+1)
	p.ra.mu.Lock()
	stillFresh := !p.ra.peerEpochSet
	p.ra.mu.Unlock()
	if !stillFresh {
		t.Fatal("denied epoch re-latched as the new peer generation")
	}

	// Rotate B too, and fresh traffic must flow cleanly with sequences
	// restarted from 1 on both sides.
	if err := p.rb.NewGeneration(); err != nil {
		t.Fatal(err)
	}

	cB2 := collect(p.rb, 32)
	cA2 := collect(p.ra, 32)
	for i := 0; i < 10; i++ {
		if err := p.ra.Send(makeMsg(9000+i, size)); err != nil {
			t.Fatalf("fresh a->b %d: %v", i, err)
		}
	}
	expectMessages(t, cB2, 9000, 9010, size)
	for i := 0; i < 10; i++ {
		if err := p.rb.Send(makeMsg(9100+i, size)); err != nil {
			t.Fatalf("fresh b->a %d: %v", i, err)
		}
	}
	expectMessages(t, cA2, 9100, 9110, size)
	expectNoExtra(t, cB2)
	expectNoExtra(t, cA2)

	// Old-generation injections are still dropped after the re-latch.
	drops = p.rb.Dropped()
	if err := p.fa.Send(craftMessageV2([channelIDSize]byte{}, nil, oldEpochA, 999999, 0, 1, []byte("STALE-A"))); err != nil {
		t.Fatal(err)
	}
	waitDropped(t, p.rb, drops+1)

	// NewGeneration on a stopped adapter fails honestly.
	if err := p.ra.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := p.ra.NewGeneration(); !errors.Is(err, ErrClosed) {
		t.Fatalf("NewGeneration after Stop: %v, want ErrClosed", err)
	}
}

// TestChannelIsolation: two pairs with different ChannelIDs on a shared
// carrier must not cross-latch — a foreign-channel snapshot is dropped
// BEFORE any other processing, even when its epoch and seq would
// otherwise be accepted (and delivered).
func TestChannelIsolation(t *testing.T) {
	p := newPair(t) // default config: ChannelID all-zero
	const size = 256
	cB := collect(p.rb, 16)
	for i := 0; i < 5; i++ {
		if err := p.ra.Send(makeMsg(i, size)); err != nil {
			t.Fatal(err)
		}
	}
	expectMessages(t, cB, 0, 5, size)

	// A forged snapshot from a DIFFERENT channel carrying rb's latched
	// peer epoch and the exact next expected seq: without channel
	// isolation this would be accepted and delivered (poison).
	p.rb.mu.Lock()
	nd, peerEp := p.rb.nextDeliver, p.rb.peerEpoch
	p.rb.mu.Unlock()
	foreignCh := [channelIDSize]byte{0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4}
	poison := craftMessageV2(foreignCh, nil, peerEp, 0, 0, nd, []byte("POISON-PAYLOAD"))
	drops := p.rb.Dropped()
	if err := p.fa.Send(poison); err != nil {
		t.Fatal(err)
	}
	waitDropped(t, p.rb, drops+1)

	// The legit next message is still delivered as #5, poison never was.
	if err := p.ra.Send(makeMsg(5, size)); err != nil {
		t.Fatal(err)
	}
	expectMessages(t, cB, 5, 6, size)
	expectNoExtra(t, cB)
}

// TestMACProtection: with a MacKey configured, forged/tampered snapshots
// are dropped silently before their content is ever looked at, while
// authentic traffic flows untouched.
func TestMACProtection(t *testing.T) {
	psk := []byte("0123456789abcdef0123456789abcdef")
	cfg := testConfig()
	cfg.MacKey = DeriveMACKey(psk)
	cfg.ChannelID = DeriveChannelID(psk)

	fa, fb := transport.NewFaultyPair(transport.DefaultConfig())
	if err := fa.Start(); err != nil {
		t.Fatal(err)
	}
	if err := fb.Start(); err != nil {
		t.Fatal(err)
	}
	defer fa.Stop()
	defer fb.Stop()
	ra := New(context.Background(), fa, cfg)
	rb := New(context.Background(), fb, cfg)
	if err := ra.Start(); err != nil {
		t.Fatal(err)
	}
	if err := rb.Start(); err != nil {
		t.Fatal(err)
	}
	defer ra.Stop()
	defer rb.Stop()

	const size = 128
	c := collect(rb, 16)
	for i := 0; i < 5; i++ {
		if err := ra.Send(makeMsg(i, size)); err != nil {
			t.Fatal(err)
		}
	}
	expectMessages(t, c, 0, 5, size)

	drops := rb.Dropped()
	// (a) Right channel, MAC computed with the WRONG key: CRC is valid,
	//     MAC is not — silent drop before content inspection.
	wrongKey := DeriveMACKey([]byte("attacker-psk"))
	if err := fa.Send(craftMessageV2(cfg.ChannelID, wrongKey[:], [epochSize]byte{1}, 0, 0, 1, []byte("forged"))); err != nil {
		t.Fatal(err)
	}
	// (b) Right channel and key, but a MAC byte flipped (CRC re-fixed):
	//     proves the MAC is really verified, not just the CRC.
	tampered := craftMessageV2(cfg.ChannelID, cfg.MacKey[:], [epochSize]byte{2}, 0, 0, 1, []byte("x"))
	macStart := len(tampered) - crcSize - macSize
	tampered[macStart] ^= 0xFF
	binary.BigEndian.PutUint32(tampered[len(tampered)-crcSize:], crc32.ChecksumIEEE(tampered[:len(tampered)-crcSize]))
	if err := fa.Send(tampered); err != nil {
		t.Fatal(err)
	}
	// (c) MAC-less message on a MAC-enabled link: too short / fails MAC.
	if err := fa.Send(craftMessageV2(cfg.ChannelID, nil, [epochSize]byte{3}, 0, 0, 1, []byte("no-mac"))); err != nil {
		t.Fatal(err)
	}
	waitDropped(t, rb, drops+3)

	// The link is unaffected afterwards.
	for i := 5; i < 10; i++ {
		if err := ra.Send(makeMsg(i, size)); err != nil {
			t.Fatal(err)
		}
	}
	expectMessages(t, c, 5, 10, size)
	expectNoExtra(t, c)
}

// strictCap wraps a FaultyTransport with a hard 64 KiB budget and
// rejects oversize Sends (production-like carrier).
type strictCap struct {
	*transport.FaultyTransport
}

func (s *strictCap) MaxPayload() int { return 65536 }

func (s *strictCap) Send(data []byte) error {
	if len(data) > 65536 {
		return errors.New("oversize")
	}
	return s.FaultyTransport.Send(data)
}

// TestProductionConfigMaxPayload regression: with a strict 64 KiB inner
// carrier and MAC enabled (production), Send(MaxPayload()) MUST succeed
// and every snapshot on the wire MUST be <= inner.MaxPayload().
func TestProductionConfigMaxPayload(t *testing.T) {
	fa, fb := transport.NewFaultyPair(transport.DefaultConfig())
	fa.Start()
	fb.Start()
	t.Cleanup(func() { fa.Stop(); fb.Stop() })

	psk := []byte("0123456789abcdef0123456789abcdef")
	cfg := testConfig()
	cfg.ChannelID = DeriveChannelID(psk)
	cfg.MacKey = DeriveMACKey(psk)

	sa, sb := &strictCap{fa}, &strictCap{fb}
	ra := New(context.Background(), sa, cfg)
	rb := New(context.Background(), sb, cfg)
	if err := ra.Start(); err != nil {
		t.Fatal(err)
	}
	if err := rb.Start(); err != nil {
		t.Fatal(err)
	}
	defer ra.Stop()
	defer rb.Stop()

	// MaxPayload must be accepted: ErrTooLarge here = the off-by-N bug.
	maxMsg := makeMsg(1, ra.MaxPayload())
	if err := ra.Send(maxMsg); err != nil {
		t.Fatalf("Send(MaxPayload=%d): %v", ra.MaxPayload(), err)
	}

	// Receive it back to prove the full path works at the boundary.
	got := make(chan []byte, 1)
	rb.Receive(func(d []byte) { got <- d })
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("MaxPayload message never delivered")
	}
}

// TestDoubleRotationDenyHistory: A rotates twice without B; an old B
// epoch must NOT re-latch onto A; after B rotates, fresh traffic works.
func TestDoubleRotationDenyHistory(t *testing.T) {
	p := newPair(t)

	// Establish: exchange one message so peerEpoch is latched on both.
	cB := collect(p.rb, 64)
	if err := p.ra.Send([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-cB.ch:
		if string(got) != "hello" {
			t.Fatalf("got %q, want hello", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hello never delivered")
	}

	p.rb.mu.Lock()
	epochB0 := p.rb.epoch
	p.rb.mu.Unlock()

	// Wait until A has actually latched B's epoch (the ACK arrives
	// asynchronously); otherwise the deny history lacks B0.
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.ra.mu.Lock()
		latched := p.ra.peerEpochSet && p.ra.peerEpoch == epochB0
		p.ra.mu.Unlock()
		if latched {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("A never latched B's epoch")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// A rotates twice without B.
	p.ra.NewGeneration()
	p.ra.NewGeneration()

	// Inject a frame from B's OLD epoch INTO A (fb sends → fa receives):
	// must be dropped (deny history covers it), and A must not latch it.
	stale := craftMessageV2([channelIDSize]byte{}, nil, epochB0, 0, 0, 1, []byte("stale"))
	p.fb.Send(stale) // B's carrier → A

	p.ra.mu.Lock()
	latched := p.ra.peerEpochSet && p.ra.peerEpoch == epochB0
	p.ra.mu.Unlock()
	if latched {
		t.Fatal("A latched onto a stale B epoch after double rotation")
	}

	// B rotates too; fresh traffic must flow on the new generations.
	p.rb.NewGeneration()
	cB2 := collect(p.rb, 64)
	if err := p.ra.Send([]byte("fresh")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-cB2.ch:
		if string(got) != "fresh" {
			t.Fatalf("got %q, want fresh", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fresh traffic did not flow after both rotated")
	}
}

// TestSnapshotFitsCarrierBudget: the P0.4 invariant — ANY snapshot is
// always <= inner.MaxPayload(), no matter how the window is filled, and
// a single MaxPayload-sized message fits exactly.
func TestSnapshotFitsCarrierBudget(t *testing.T) {
	const innerMax = 256 * 1024 // FaultyTransport.MaxPayload

	p := newPair(t)
	p.fb.SetDrop(1.0) // pin everything in the window

	// Fill with a realistic size mix until the window refuses more.
	sizes := []int{100, 1000, 5000, 20000}
	sent := 0
loop:
	for sent < DefaultMaxUnackedFrames {
		sz := sizes[sent%len(sizes)]
		done := make(chan error, 1)
		go func() { done <- p.ra.Send(makeMsg(sent, sz)) }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("send %d: %v", sent, err)
			}
			sent++
		case <-time.After(300 * time.Millisecond):
			break loop
		}
	}
	if sent == 0 {
		t.Fatal("nothing fit in the window")
	}
	p.ra.mu.Lock()
	snap := p.ra.buildSnapshotLocked()
	want := headerSize + p.ra.unackedBytes + crcSize // no MAC configured
	p.ra.mu.Unlock()
	if len(snap) != want {
		t.Fatalf("snapshot len=%d, want exactly header+window+crc=%d", len(snap), want)
	}
	if len(snap) > innerMax {
		t.Fatalf("snapshot %d B exceeds inner budget %d B", len(snap), innerMax)
	}
	t.Logf("full window: %d frames, snapshot %d/%d B", sent, len(snap), innerMax)

	// Single MaxPayload-sized message fits exactly (MAC off and on).
	for _, withMAC := range []bool{false, true} {
		cfg := testConfig()
		if withMAC {
			cfg.MacKey = DeriveMACKey([]byte("budget-psk"))
		}
		r := New(context.Background(), p.fa, cfg)
		r.mu.Lock()
		r.unacked = []outFrame{{seq: 1, payload: make([]byte, r.MaxPayload())}}
		r.unackedBytes = frameHeader + r.MaxPayload()
		s := r.buildSnapshotLocked()
		r.mu.Unlock()
		if len(s) > innerMax {
			t.Fatalf("withMAC=%v: max-payload snapshot %d B > inner %d B", withMAC, len(s), innerMax)
		}
		if withMAC && len(s) != innerMax {
			t.Fatalf("max-payload snapshot with MAC: %d B, want exactly %d B", len(s), innerMax)
		}
	}

	// And a MaxPayload message round-trips end to end.
	p.fb.SetDrop(0)
	waitDrained(t, p.ra)
	c := collect(p.rb, 1)
	big := makeMsg(777, p.ra.MaxPayload())
	if err := p.ra.Send(big); err != nil {
		t.Fatalf("MaxPayload send: %v", err)
	}
	select {
	case got := <-c.ch:
		checkMsg(t, got, 777, p.ra.MaxPayload())
	case <-time.After(15 * time.Second):
		t.Fatal("MaxPayload message not delivered")
	}
}

// TestReliableBackpressure: with the ack path fully down the window
// fills, Send blocks without growing memory, and unblocks on ack
// progress. Also: byte bound, send timeout, dead carrier, ctx cancel
// and Stop as unblock paths.
func TestReliableBackpressure(t *testing.T) {
	t.Run("FrameBoundBlocksAndHeals", func(t *testing.T) {
		p := newPair(t)
		p.fb.SetDrop(1.0) // no ack ever reaches a

		const window = DefaultMaxUnackedFrames
		// 512 B payloads: 256*(512+12) = 134,144 wire bytes, well under
		// the snapshot-fit byte budget, so the FRAME bound is what trips.
		const size = 512
		payload := makeMsg(0, size)
		for i := 0; i < window; i++ {
			if err := p.ra.Send(payload); err != nil {
				t.Fatalf("fill send %d: %v", i, err)
			}
		}
		if n := p.ra.UnackedLen(); n != window {
			t.Fatalf("unacked=%d, want %d", n, window)
		}

		done := make(chan error, 1)
		go func() { done <- p.ra.Send(payload) }()
		select {
		case err := <-done:
			t.Fatalf("Send returned %v with a full window; must block", err)
		case <-time.After(300 * time.Millisecond):
		}
		// Bounded memory while blocked: window and byte count frozen.
		if n := p.ra.UnackedLen(); n != window {
			t.Fatalf("window grew while blocked: %d", n)
		}
		if b, want := p.ra.UnackedBytes(), window*(size+frameHeader); b != want {
			t.Fatalf("unackedBytes=%d, want %d (wire accounting)", b, want)
		}

		p.fb.SetDrop(0) // heal the ack path
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("blocked Send after heal: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("blocked Send did not wake on ack progress")
		}
		// The window drains fully once acks flow.
		waitDrained(t, p.ra)
	})

	t.Run("ByteBound", func(t *testing.T) {
		p := newPair(t)
		p.fb.SetDrop(1.0)

		// Wire accounting: each frame costs frameHeader+payload, and the
		// byte budget is min(MaxUnackedBytes, what fits one snapshot on
		// the 256 KiB faulty carrier) = 262144 - (46+16+4) = 262,078.
		const payloadSize = 100 * 1024
		budget := 256*1024 - (headerSize + macSize + crcSize)
		if DefaultMaxUnackedBytes < budget {
			budget = DefaultMaxUnackedBytes
		}
		want := budget / (frameHeader + payloadSize) // 2
		big := makeMsg(0, payloadSize)
		sent := 0
		for sent < DefaultMaxUnackedFrames { // frame bound must NOT trigger first
			done := make(chan error, 1)
			go func() { done <- p.ra.Send(big) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("send %d: %v", sent, err)
				}
				sent++
			case <-time.After(300 * time.Millisecond):
				goto full
			}
		}
	full:
		if sent != want {
			t.Fatalf("byte bound: %d payloads fit, want %d", sent, want)
		}
		if b := p.ra.UnackedBytes(); b > budget {
			t.Fatalf("unackedBytes=%d exceeds budget %d", b, budget)
		}
	})

	t.Run("SendTimeout", func(t *testing.T) {
		fa, fb := transport.NewFaultyPair(transport.DefaultConfig())
		if err := fa.Start(); err != nil {
			t.Fatal(err)
		}
		if err := fb.Start(); err != nil {
			t.Fatal(err)
		}
		defer fa.Stop()
		defer fb.Stop()

		cfg := testConfig()
		cfg.SendTimeout = 200 * time.Millisecond
		ra := New(context.Background(), fa, cfg)
		rb := New(context.Background(), fb, cfg)
		if err := ra.Start(); err != nil {
			t.Fatal(err)
		}
		if err := rb.Start(); err != nil {
			t.Fatal(err)
		}
		defer ra.Stop()
		defer rb.Stop()
		fb.SetDrop(1.0) // no ack ever reaches ra

		payload := makeMsg(0, 512)
		for i := 0; i < DefaultMaxUnackedFrames; i++ {
			if err := ra.Send(payload); err != nil {
				t.Fatal(err)
			}
		}
		start := time.Now()
		err := ra.Send(payload)
		if !errors.Is(err, ErrBackpressure) {
			t.Fatalf("Send with full window: %v, want ErrBackpressure", err)
		}
		if d := time.Since(start); d < 150*time.Millisecond || d > 10*time.Second {
			t.Fatalf("Send unblocked after %v, want ~200ms (SendTimeout)", d)
		}
	})

	t.Run("CarrierStoppedFails", func(t *testing.T) {
		fa, fb := transport.NewFaultyPair(transport.DefaultConfig())
		if err := fa.Start(); err != nil {
			t.Fatal(err)
		}
		if err := fb.Start(); err != nil {
			t.Fatal(err)
		}
		defer fb.Stop()
		ra := New(context.Background(), fa, Config{})
		rb := New(context.Background(), fb, Config{})
		if err := ra.Start(); err != nil {
			t.Fatal(err)
		}
		if err := rb.Start(); err != nil {
			t.Fatal(err)
		}
		defer ra.Stop()
		defer rb.Stop()

		fa.Stop() // the carrier is finally dead (not a reconnect)
		if err := ra.Send(makeMsg(0, 64)); !errors.Is(err, ErrCarrierDown) {
			t.Fatalf("Send over stopped carrier: %v, want ErrCarrierDown", err)
		}
	})

	t.Run("CtxCancelUnblocks", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		p := newPairCtx(t, ctx)
		p.fb.SetDrop(1.0)

		payload := makeMsg(0, 512)
		for i := 0; i < DefaultMaxUnackedFrames; i++ {
			if err := p.ra.Send(payload); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan error, 1)
		go func() { done <- p.ra.Send(payload) }()
		time.Sleep(100 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("blocked Send after cancel: %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("blocked Send ignored ctx cancellation")
		}
	})

	t.Run("StopUnblocks", func(t *testing.T) {
		p := newPair(t)
		p.fb.SetDrop(1.0)

		payload := makeMsg(0, 512)
		for i := 0; i < DefaultMaxUnackedFrames; i++ {
			if err := p.ra.Send(payload); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan error, 1)
		go func() { done <- p.ra.Send(payload) }()
		time.Sleep(100 * time.Millisecond)
		if err := p.ra.Stop(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, ErrClosed) {
				t.Fatalf("blocked Send after Stop: %v, want ErrClosed", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("blocked Send ignored Stop")
		}
	})
}

// TestLifecycleGuards: started guard, single-use Start, idempotent Stop,
// honest errors, MaxPayload accounting.
func TestLifecycleGuards(t *testing.T) {
	fa, fb := transport.NewFaultyPair(transport.DefaultConfig())
	if err := fa.Start(); err != nil {
		t.Fatal(err)
	}
	if err := fb.Start(); err != nil {
		t.Fatal(err)
	}
	defer fa.Stop()
	defer fb.Stop()

	r := New(context.Background(), fa, Config{})
	defer r.Stop()

	if err := r.Send([]byte("x")); !errors.Is(err, ErrNotStarted) {
		t.Errorf("Send before Start: %v, want ErrNotStarted", err)
	}
	if err := r.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := r.Start(); err == nil {
		t.Error("second Start: got nil, want error")
	}
	if got, want := r.MaxPayload(), 256*1024-Overhead; got != want {
		t.Errorf("MaxPayload=%d, want %d (faulty 256 KiB - %d overhead)", got, want, Overhead)
	}
	if err := r.Send(make([]byte, r.MaxPayload()+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized Send: %v, want ErrTooLarge", err)
	}
	// P0.1 watchdog contract: a transient inner disconnect must NOT kill
	// the adapter's IsConnected — the session survives carrier reconnects.
	if !r.IsConnected() {
		t.Error("IsConnected=false on a started adapter")
	}
	fa.SetConnected(false)
	if !r.IsConnected() {
		t.Error("IsConnected must ignore transient inner disconnect")
	}
	fa.SetConnected(true)
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("second Stop: %v (must be idempotent)", err)
	}
	if err := r.Send([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Errorf("Send after Stop: %v, want ErrClosed", err)
	}
}

// TestBuildParseRoundtrip: snapshot build/parse symmetry, incl. empty
// payloads and an empty (pure-ack) snapshot.
func TestBuildParseRoundtrip(t *testing.T) {
	r := New(context.Background(), nil, Config{})
	r.mu.Lock()
	r.unacked = []outFrame{
		{seq: 1, payload: []byte("hello")},
		{seq: 2, payload: nil},
		{seq: 3, payload: makeMsg(42, 1000)},
	}
	r.unackedBytes = 5 + 0 + 1000
	r.nextDeliver = 77
	r.pending = map[uint64][]byte{78: []byte("a"), 80: []byte("b")} // SACK bits 1 and 3
	snap := r.buildSnapshotLocked()
	r.mu.Unlock()

	m, ok := r.parseMessage(snap)
	if !ok {
		t.Fatal("parseMessage rejected our own snapshot")
	}
	if m.epoch != r.epoch {
		t.Error("epoch mismatch")
	}
	if m.ackThrough != 76 {
		t.Errorf("ackThrough=%d, want 76", m.ackThrough)
	}
	if m.ackBits != (1<<1)|(1<<3) {
		t.Errorf("ackBits=%#x, want %#x (pending 78,80 past ackThrough 76)", m.ackBits, (1<<1)|(1<<3))
	}
	if len(m.frames) != 3 {
		t.Fatalf("frames=%d, want 3", len(m.frames))
	}
	for i, f := range m.frames {
		if f.seq != uint64(i+1) {
			t.Errorf("frame %d seq=%d", i, f.seq)
		}
		if string(f.payload) != string(r.unacked[i].payload) {
			t.Errorf("frame %d payload mismatch", i)
		}
	}

	// Pure ack (count=0).
	r.mu.Lock()
	r.unacked = nil
	snap = r.buildSnapshotLocked()
	r.mu.Unlock()
	m, ok = r.parseMessage(snap)
	if !ok || len(m.frames) != 0 {
		t.Fatalf("empty snapshot: ok=%v frames=%d", ok, len(m.frames))
	}
}

// FuzzParseMessage: the parser must never panic on untrusted input.
func FuzzParseMessage(f *testing.F) {
	r := New(context.Background(), nil, Config{})
	r.mu.Lock()
	r.unacked = []outFrame{{seq: 1, payload: []byte("seed")}, {seq: 2, payload: nil}}
	r.unackedBytes = 2*frameHeader + 4
	valid := r.buildSnapshotLocked()
	r.mu.Unlock()
	f.Add(valid)
	f.Add([]byte(""))
	f.Add([]byte("OFR2"))
	f.Add(valid[:len(valid)-2])          // truncated
	f.Add(append([]byte("X"), valid...)) // prefixed garbage
	mut := append([]byte(nil), valid...)
	mut[len(mut)/2] ^= 0xFF // bit flip -> CRC must reject
	f.Add(mut)

	f.Fuzz(func(t *testing.T, data []byte) {
		m, ok := r.parseMessage(data) // must not panic
		if !ok {
			return
		}
		// If it parsed, the frames must fit inside the input.
		total := 0
		for _, fr := range m.frames {
			total += len(fr.payload)
		}
		if total > len(data) {
			t.Fatalf("frames carry %d bytes from a %d-byte input", total, len(data))
		}
	})
}

// FuzzParseMessageMAC: same, with metadata authentication enabled.
func FuzzParseMessageMAC(f *testing.F) {
	cfg := Config{}
	cfg.MacKey = DeriveMACKey([]byte("fuzz-psk"))
	cfg.ChannelID = DeriveChannelID([]byte("fuzz-psk"))
	r := New(context.Background(), nil, cfg)
	r.mu.Lock()
	r.unacked = []outFrame{{seq: 1, payload: []byte("seed")}, {seq: 2, payload: nil}}
	r.unackedBytes = 2*frameHeader + 4
	valid := r.buildSnapshotLocked()
	r.mu.Unlock()
	f.Add(valid)
	f.Add(valid[:len(valid)-2])
	mut := append([]byte(nil), valid...)
	mut[len(mut)/2] ^= 0xFF
	f.Add(mut)

	f.Fuzz(func(t *testing.T, data []byte) {
		m, ok := r.parseMessage(data) // must not panic
		if !ok {
			return
		}
		total := 0
		for _, fr := range m.frames {
			total += len(fr.payload)
		}
		if total > len(data) {
			t.Fatalf("frames carry %d bytes from a %d-byte input", total, len(data))
		}
	})
}

// byteCounter wraps a FaultyTransport and counts every byte the adapter
// successfully hands to the carrier — the true wire cost of the
// reliability layer (including frames the fault injector later drops:
// those cost wire bandwidth on a real link too).
type byteCounter struct {
	*transport.FaultyTransport
	wireBytes atomic.Uint64
}

func (b *byteCounter) Send(data []byte) error {
	err := b.FaultyTransport.Send(data)
	if err == nil {
		b.wireBytes.Add(uint64(len(data)))
	}
	return err
}

// TestNoQuadraticBlowup is THE regression test for the production
// failure that killed the snapshot design: with a non-coalescing carrier
// the wire traffic must stay LINEAR in the payload, not N×window.
// Sustained 2000 × 1 KiB messages one way; total wire bytes (both
// directions: data + retransmits + acks) must stay under 3× payload
// without loss and under 5× with 10% loss in both directions. The old
// snapshot-of-all-unacked-per-Send design would land at ~250× here.
func TestNoQuadraticBlowup(t *testing.T) {
	run := func(t *testing.T, dropProb, maxFactor float64) {
		fa, fb := transport.NewFaultyPair(transport.DefaultConfig())
		ca, cb := &byteCounter{FaultyTransport: fa}, &byteCounter{FaultyTransport: fb}
		if err := fa.Start(); err != nil {
			t.Fatal(err)
		}
		if err := fb.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { fa.Stop(); fb.Stop() })
		ra := New(context.Background(), ca, testConfig())
		rb := New(context.Background(), cb, testConfig())
		if err := ra.Start(); err != nil {
			t.Fatal(err)
		}
		if err := rb.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ra.Stop(); rb.Stop() })

		ca.SetDrop(dropProb)
		cb.SetDrop(dropProb)

		const total, size = 2000, 1024
		c := collect(rb, total)
		for i := 0; i < total; i++ {
			if err := ra.Send(makeMsg(i, size)); err != nil {
				t.Fatalf("send %d: %v", i, err)
			}
		}
		expectMessages(t, c, 0, total, size)
		waitDrained(t, ra)
		expectNoExtra(t, c) // also a 300 ms settle window for trailing acks

		wire := ca.wireBytes.Load() + cb.wireBytes.Load()
		payload := uint64(total * size)
		factor := float64(wire) / float64(payload)
		t.Logf("drop=%.2f: wire=%d payload=%d factor=%.2f (limit %.0f)",
			dropProb, wire, payload, factor, maxFactor)
		if factor > maxFactor {
			t.Fatalf("wire bytes %d = %.2fx payload %d, want < %.0fx — quadratic blowup",
				wire, factor, payload, maxFactor)
		}
	}
	t.Run("NoLoss", func(t *testing.T) { run(t, 0, 3) })
	t.Run("Loss10Percent", func(t *testing.T) { run(t, 0.10, 5) })
}

// TestThroughputRegression: 10 MiB through a pair must take well under
// 30 s — on an in-memory carrier with the selective-repeat sender this
// is a few seconds at most; the snapshot design burned the time
// re-serializing the whole window per message.
func TestThroughputRegression(t *testing.T) {
	p := newPair(t)
	const size = 4 * 1024
	const total = (10 << 20) / size // 2560 messages = 10 MiB
	c := collect(p.rb, total)

	start := time.Now()
	for i := 0; i < total; i++ {
		if err := p.ra.Send(makeMsg(i, size)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	expectMessages(t, c, 0, total, size)
	waitDrained(t, p.ra)
	d := time.Since(start)
	t.Logf("10 MiB through the pair in %v (%.1f MiB/s)", d, 10/d.Seconds())
	if d > 30*time.Second {
		t.Fatalf("10 MiB took %v, want < 30s", d)
	}
}

// sackDropper wraps a FaultyTransport and drops the FIRST outbound
// carrier message carrying each target frame seq (a single-loss model);
// later retransmissions of those seqs pass. It also counts retransmitted
// frames: any frame whose seq goes on the wire more than once.
type sackDropper struct {
	*transport.FaultyTransport
	mu         sync.Mutex
	dropSeqs   map[uint64]bool
	dropped    map[uint64]bool
	sent       map[uint64]int
	retxFrames int
}

func newSackDropper(f *transport.FaultyTransport, seqs ...uint64) *sackDropper {
	s := &sackDropper{
		FaultyTransport: f,
		dropSeqs:        make(map[uint64]bool),
		dropped:         make(map[uint64]bool),
		sent:            make(map[uint64]int),
	}
	for _, sq := range seqs {
		s.dropSeqs[sq] = true
	}
	return s
}

func (s *sackDropper) Send(data []byte) error {
	if seqs, ok := parseSeqs(data); ok {
		s.mu.Lock()
		drop := false
		for _, seq := range seqs {
			s.sent[seq]++
			if s.sent[seq] > 1 {
				s.retxFrames++
			}
			if s.dropSeqs[seq] && !s.dropped[seq] {
				s.dropped[seq] = true
				drop = true // first transmission of a target frame: lost on the wire
			}
		}
		s.mu.Unlock()
		if drop {
			return nil
		}
	}
	return s.FaultyTransport.Send(data)
}

// RetxFrames reports how many retransmitted frames went on the wire.
func (s *sackDropper) RetxFrames() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retxFrames
}

// TestSACKMultipleLosses: 3 holes (frames 5, 12, 18 of 30 lost once) are
// all repaired FAST by the SACK-driven fast retransmit — not one hole
// per RTO — and the retransmit count stays minimal (≈3 frames, one per
// hole; never the whole window). RTO is set to 10 s so any RTO-based
// recovery is caught by the 5 s wall-clock bound.
func TestSACKMultipleLosses(t *testing.T) {
	fa, fb := transport.NewFaultyPair(transport.DefaultConfig())
	if err := fa.Start(); err != nil {
		t.Fatal(err)
	}
	if err := fb.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fa.Stop(); fb.Stop() })

	sd := newSackDropper(fa, 5, 12, 18)
	cfg := testConfig()
	cfg.RetransmitInterval = 10 * time.Second // RTO must NOT be the recovery path
	ra := New(context.Background(), sd, cfg)
	rb := New(context.Background(), fb, cfg)
	if err := ra.Start(); err != nil {
		t.Fatal(err)
	}
	if err := rb.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ra.Stop(); rb.Stop() })

	const total, size = 30, 256
	c := collect(rb, total)
	start := time.Now()
	for i := 0; i < total; i++ { // seq = i+1; drops hit i = 4, 11, 17
		if err := ra.Send(makeMsg(i, size)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	expectMessages(t, c, 0, total, size)
	d := time.Since(start)
	if d > 5*time.Second {
		t.Fatalf("recovery took %v — holes repaired by RTO, not by SACK fast retransmit", d)
	}
	waitDrained(t, ra)
	n := sd.RetxFrames()
	t.Logf("3 holes recovered in %v with %d retransmitted frames (retransmitsTotal=%d)",
		d, n, ra.Retransmits())
	if n < 3 || n > 8 {
		t.Fatalf("retransmitted frames=%d, want ≈3 (one per hole; SACK must avoid window floods)", n)
	}
	expectNoExtra(t, c)
}

// seqRecorder wraps a FaultyTransport and counts how many wire messages
// carried each frame seq (retransmit observation for threshold tests).
type seqRecorder struct {
	*transport.FaultyTransport
	mu     sync.Mutex
	counts map[uint64]int
}

func (s *seqRecorder) Send(data []byte) error {
	if seqs, ok := parseSeqs(data); ok {
		s.mu.Lock()
		for _, sq := range seqs {
			s.counts[sq]++
		}
		s.mu.Unlock()
	}
	return s.FaultyTransport.Send(data)
}

func (s *seqRecorder) count(seq uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[seq]
}

// TestFastRetransmitThreshold: 1-2 consecutive dup-acks must NOT trigger
// a retransmit (reorder-safe, RFC 9002); the 3rd must. Phase 1 drives
// SACK bitmaps with growing coverage (the loss is provable only at the
// 3rd dup-ack); phase 2 drives pure dup-acks with an empty bitmap, where
// the dupStreak counter is the only trigger and the gap head is re-sent.
// RetransmitInterval is huge so the RTO path can never fire here — every
// observed retransmit is a fast retransmit.
func TestFastRetransmitThreshold(t *testing.T) {
	fa, fb := transport.NewFaultyPair(transport.DefaultConfig())
	if err := fa.Start(); err != nil {
		t.Fatal(err)
	}
	if err := fb.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fa.Stop(); fb.Stop() })

	rec := &seqRecorder{FaultyTransport: fa, counts: make(map[uint64]int)}
	cfg := testConfig()
	cfg.RetransmitInterval = 10 * time.Second
	ra := New(context.Background(), rec, cfg)
	if err := ra.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ra.Stop() })

	// Latch a peer epoch so crafted acks are accepted.
	peerEpoch := [epochSize]byte{0xBE, 1, 2, 3}
	if err := fb.Send(craftAckV2([channelIDSize]byte{}, peerEpoch, 0, 0)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		ra.mu.Lock()
		latched := ra.peerEpochSet
		ra.mu.Unlock()
		if latched {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("peer epoch never latched")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 9 frames outstanding (seqs 1..9), hole at 6 (peer never got it).
	for i := 1; i <= 9; i++ {
		if err := ra.Send(makeMsg(i, 128)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}

	const (
		settle  = 200 * time.Millisecond
		pollMax = 5 * time.Second
	)
	// sackBits returns the bitmap for the given ackThrough with the
	// listed seqs marked received (bit i = seq ackThrough+1+i).
	sackBits := func(ackThrough uint64, seqs ...uint64) uint64 {
		var b uint64
		for _, s := range seqs {
			b |= 1 << (s - ackThrough - 1)
		}
		return b
	}

	// Setup: cumulative ack through 5 (progress; frees seqs 1..5). The
	// bitmap shows only seq 7 — one later seq past the hole at 6, NOT
	// enough to prove the loss — so no retransmit may happen.
	if err := fb.Send(craftAckV2([channelIDSize]byte{}, peerEpoch, 5, sackBits(5, 7))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(settle)
	if n := rec.count(6); n != 1 {
		t.Fatalf("after progress ack: seq 6 sent %d times, want 1 (no retransmit)", n)
	}

	// Phase 1: dup-acks 1 and 2 — fewer than 3 later seqs sacked above
	// the hole and the dup streak below threshold — NO retransmit.
	if err := fb.Send(craftAckV2([channelIDSize]byte{}, peerEpoch, 5, sackBits(5, 7, 8))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(settle)
	if n := rec.count(6); n != 1 {
		t.Fatalf("after dup-ack 1: seq 6 sent %d times, want 1 (no retransmit)", n)
	}
	if err := fb.Send(craftAckV2([channelIDSize]byte{}, peerEpoch, 5, sackBits(5, 7, 8))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(settle)
	if n := rec.count(6); n != 1 {
		t.Fatalf("after dup-ack 2: seq 6 sent %d times, want 1 (no retransmit)", n)
	}

	// Dup-ack 3: the bitmap now proves the hole (3 later seqs sacked)
	// AND the dup streak hits the threshold — frame 6 is re-sent,
	// exactly once; the sacked frames 7-9 are NOT re-sent.
	if err := fb.Send(craftAckV2([channelIDSize]byte{}, peerEpoch, 5, sackBits(5, 7, 8, 9))); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(pollMax)
	for rec.count(6) != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("after dup-ack 3: seq 6 sent %d times, want 2 (fast retransmit)", rec.count(6))
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(settle)
	if n := rec.count(6); n != 2 {
		t.Fatalf("seq 6 sent %d times, want exactly 2 (selective retransmit)", n)
	}
	for _, sq := range []uint64{5, 7, 8, 9} {
		if n := rec.count(sq); n != 1 {
			t.Fatalf("seq %d sent %d times, want 1 — sacked/acked frames must not be re-sent", sq, n)
		}
	}

	// Phase 2: pure dup-acks with an EMPTY bitmap. Move ackThrough to 6
	// (progress, streak reset; peer reports 8,9 sacked), then drive acks
	// that carry no SACK info: 1-2 dups do nothing, the 3rd re-sends
	// the gap head (seq 7) via the dupStreak fallback.
	if err := fb.Send(craftAckV2([channelIDSize]byte{}, peerEpoch, 6, sackBits(6, 8, 9))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(settle) // progress ack frees seq 6; 7 not provably lost
	if n := rec.count(7); n != 1 {
		t.Fatalf("after progress ack: seq 7 sent %d times, want 1", n)
	}
	for dup := 1; dup <= 2; dup++ {
		if err := fb.Send(craftAckV2([channelIDSize]byte{}, peerEpoch, 6, 0)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(settle)
		if n := rec.count(7); n != 1 {
			t.Fatalf("after pure dup-ack %d: seq 7 sent %d times, want 1 (no retransmit)", dup, n)
		}
	}
	if err := fb.Send(craftAckV2([channelIDSize]byte{}, peerEpoch, 6, 0)); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(pollMax)
	for rec.count(7) != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("after pure dup-ack 3: seq 7 sent %d times, want 2 (gap-head fallback)", rec.count(7))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := rec.count(8); n != 1 {
		t.Fatalf("seq 8 sent %d times, want 1 (only the gap head is re-sent)", n)
	}
}

// --- benchmarks: adapter overhead vs raw carrier ---

func benchmarkThroughput(b *testing.B, useReliable bool, payloadSize int) {
	fa, fb := transport.NewFaultyPair(transport.DefaultConfig())
	if err := fa.Start(); err != nil {
		b.Fatal(err)
	}
	if err := fb.Start(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { fa.Stop(); fb.Stop() })

	var received atomic.Int64
	var sender transport.Transport
	var ra, rb *Transport
	if useReliable {
		cfg := Config{RetransmitInterval: 500 * time.Millisecond}
		ra = New(context.Background(), fa, cfg)
		rb = New(context.Background(), fb, cfg)
		if err := ra.Start(); err != nil {
			b.Fatal(err)
		}
		if err := rb.Start(); err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { ra.Stop(); rb.Stop() })
		rb.Receive(func([]byte) { received.Add(1) })
		sender = ra
	} else {
		fb.Receive(func([]byte) { received.Add(1) })
		sender = fa
	}

	msg := make([]byte, payloadSize)
	for i := range msg {
		msg[i] = byte(i)
	}

	b.SetBytes(int64(payloadSize))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Retries only apply to the raw carrier (errQueueFull when the
		// 1024-deep channel momentarily fills): that IS the backpressure
		// a raw carrier exposes. The adapter blocks instead of erroring.
		for retries := 0; ; retries++ {
			if err := sender.Send(msg); err == nil {
				break
			} else if retries > 100000 {
				b.Fatalf("send: %v", err)
			}
		}
	}
	b.StopTimer()
	deadline := time.Now().Add(120 * time.Second)
	for received.Load() < int64(b.N) {
		if time.Now().After(deadline) {
			b.Fatalf("lost messages: %d/%d delivered", received.Load(), b.N)
		}
		time.Sleep(time.Millisecond)
	}
}

func BenchmarkRawFaulty1K(b *testing.B)  { benchmarkThroughput(b, false, 1024) }
func BenchmarkReliable1K(b *testing.B)   { benchmarkThroughput(b, true, 1024) }
func BenchmarkRawFaulty32K(b *testing.B) { benchmarkThroughput(b, false, 32*1024) }
func BenchmarkReliable32K(b *testing.B)  { benchmarkThroughput(b, true, 32*1024) }
