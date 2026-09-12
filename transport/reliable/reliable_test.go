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
	p.fa.DropProb = 0.3
	p.fb.DropProb = 0.3

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
	p.fa.DupProb = 0.3
	p.fb.DupProb = 0.3

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
	p.fa.DropProb, p.fa.DupProb = 0.2, 0.2
	p.fb.DropProb, p.fb.DupProb = 0.2, 0.2

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
	p.fa.CorruptProb = 0.1
	p.fb.CorruptProb = 0.1

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
func craftMessageV2(channelID [channelIDSize]byte, macKey []byte, epoch [epochSize]byte, ackThrough, seq uint64, payload []byte) []byte {
	buf := make([]byte, 0, headerSize+frameHeader+len(payload)+macSize+crcSize)
	buf = append(buf, "OFR2"...)
	buf = append(buf, channelID[:]...)
	buf = append(buf, epoch[:]...)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], ackThrough)
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
// gets reconnected, and the link self-heals from retransmit snapshots
// with zero loss. Per the P0.1 Send contract, Send does NOT fail while
// the carrier is down — frames buffer in the window and carrier errors
// are swallowed (counted in TransmitErrors). Afterwards a NEW adapter
// generation takes over the same carriers and messages from the old
// generation are dropped.
func TestReliableReconnect(t *testing.T) {
	p := newPair(t)
	p.fb.DisconnectAfterN = 50 // b's carrier dies after 50 sends

	const total, size = 100, 256
	cA := collect(p.ra, total)

	go func() {
		for i := 0; i < total; i++ {
			// Never fails while the window has room: carrier errors are
			// swallowed and healed by the retransmit ticker.
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

	// Self-healing: the retransmit ticker re-sends the full snapshot once
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
	stale := craftMessageV2([channelIDSize]byte{}, nil, oldEpoch, 1_000_000, 1, []byte("STALE-GENERATION"))
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
	p.fb.DropProb = 1.0
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
	// spontaneously: both windows are empty and the tickers stay silent),
	// then inject a well-formed old-epoch-B message: it must NOT re-latch
	// as the new peer generation — the epoch is on A's deny list. The
	// sleep lets any ack signal pending from the fill phase fire and
	// settle first, so the drop baseline below is exact.
	p.fb.DropProb = 0
	time.Sleep(100 * time.Millisecond)
	drops := p.ra.Dropped()
	if err := p.fb.Send(craftMessageV2([channelIDSize]byte{}, nil, oldEpochB, 999, 1, []byte("STALE-B"))); err != nil {
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
	if err := p.fa.Send(craftMessageV2([channelIDSize]byte{}, nil, oldEpochA, 999999, 1, []byte("STALE-A"))); err != nil {
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
	poison := craftMessageV2(foreignCh, nil, peerEp, 0, nd, []byte("POISON-PAYLOAD"))
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
	if err := fa.Send(craftMessageV2(cfg.ChannelID, wrongKey[:], [epochSize]byte{1}, 0, 1, []byte("forged"))); err != nil {
		t.Fatal(err)
	}
	// (b) Right channel and key, but a MAC byte flipped (CRC re-fixed):
	//     proves the MAC is really verified, not just the CRC.
	tampered := craftMessageV2(cfg.ChannelID, cfg.MacKey[:], [epochSize]byte{2}, 0, 1, []byte("x"))
	macStart := len(tampered) - crcSize - macSize
	tampered[macStart] ^= 0xFF
	binary.BigEndian.PutUint32(tampered[len(tampered)-crcSize:], crc32.ChecksumIEEE(tampered[:len(tampered)-crcSize]))
	if err := fa.Send(tampered); err != nil {
		t.Fatal(err)
	}
	// (c) MAC-less message on a MAC-enabled link: too short / fails MAC.
	if err := fa.Send(craftMessageV2(cfg.ChannelID, nil, [epochSize]byte{3}, 0, 1, []byte("no-mac"))); err != nil {
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

// TestSnapshotFitsCarrierBudget: the P0.4 invariant — ANY snapshot is
// always <= inner.MaxPayload(), no matter how the window is filled, and
// a single MaxPayload-sized message fits exactly.
func TestSnapshotFitsCarrierBudget(t *testing.T) {
	const innerMax = 256 * 1024 // FaultyTransport.MaxPayload

	p := newPair(t)
	p.fb.DropProb = 1.0 // pin everything in the window

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
	p.fb.DropProb = 0
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
		p.fb.DropProb = 1.0 // no ack ever reaches a

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

		p.fb.DropProb = 0 // heal the ack path
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
		p.fb.DropProb = 1.0

		// Wire accounting: each frame costs frameHeader+payload, and the
		// byte budget is min(MaxUnackedBytes, what fits one snapshot on
		// the 256 KiB faulty carrier) = 262144 - (38+16+4) = 262,086.
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
		fb.DropProb = 1.0 // no ack ever reaches ra

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
		p.fb.DropProb = 1.0

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
		p.fb.DropProb = 1.0

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
