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

// craftMessage builds a raw adapter wire message for injection tests.
func craftMessage(epoch [epochSize]byte, ackThrough, seq uint64, payload []byte) []byte {
	buf := make([]byte, 0, headerSize+frameHeader+len(payload)+crcSize)
	buf = append(buf, "OFR1"...)
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
	var cb [4]byte
	binary.BigEndian.PutUint32(cb[:], crc32.ChecksumIEEE(buf))
	buf = append(buf, cb[:]...)
	return buf
}

// TestReliableReconnect: the carrier dies mid-stream (DisconnectAfterN),
// gets reconnected, and the link self-heals from retransmit snapshots
// with zero loss. Afterwards a NEW adapter generation takes over the
// same carriers and messages from the old generation are dropped.
func TestReliableReconnect(t *testing.T) {
	p := newPair(t)
	p.fb.DisconnectAfterN = 50 // b's carrier dies after 50 sends

	const total, size = 100, 256
	cA := collect(p.ra, total)

	var sendErrs atomic.Int64
	go func() {
		for i := 0; i < total; i++ {
			if err := p.rb.Send(makeMsg(i, size)); err != nil {
				// Fail-fast error — but the frame stays queued for
				// retransmission, so nothing is lost.
				sendErrs.Add(1)
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
	if sendErrs.Load() == 0 {
		t.Error("expected fail-fast Send errors while the carrier was down")
	}
	t.Logf("send errors during outage: %d/%d (all healed)", sendErrs.Load(), total)

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
	stale := craftMessage(oldEpoch, 1_000_000, 1, []byte("STALE-GENERATION"))
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

// TestReliableBackpressure: with the ack path fully down the window
// fills, Send blocks without growing memory, and unblocks on ack
// progress. Also: byte bound, ctx cancel and Stop as unblock paths.
func TestReliableBackpressure(t *testing.T) {
	t.Run("FrameBoundBlocksAndHeals", func(t *testing.T) {
		p := newPair(t)
		p.fb.DropProb = 1.0 // no ack ever reaches a

		const window = DefaultMaxUnackedFrames
		payload := makeMsg(0, 1024)
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
		if b := p.ra.UnackedBytes(); b != window*1024 {
			t.Fatalf("unackedBytes=%d, want %d", b, window*1024)
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
		deadline := time.Now().Add(15 * time.Second)
		for p.ra.UnackedLen() > 0 {
			if time.Now().After(deadline) {
				t.Fatalf("window did not drain: %d frames left", p.ra.UnackedLen())
			}
			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("ByteBound", func(t *testing.T) {
		p := newPair(t)
		p.fb.DropProb = 1.0

		big := makeMsg(0, 100*1024)
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
		// 20 x 100 KiB = 2,048,000 <= 2 MiB; the 21st would overflow.
		if sent != 20 {
			t.Fatalf("byte bound: %d payloads fit, want 20", sent)
		}
		if b := p.ra.UnackedBytes(); b > DefaultMaxUnackedBytes {
			t.Fatalf("unackedBytes=%d exceeds bound %d", b, DefaultMaxUnackedBytes)
		}
	})

	t.Run("CtxCancelUnblocks", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		p := newPairCtx(t, ctx)
		p.fb.DropProb = 1.0

		payload := makeMsg(0, 1024)
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

		payload := makeMsg(0, 1024)
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

	m, ok := parseMessage(snap)
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
	m, ok = parseMessage(snap)
	if !ok || len(m.frames) != 0 {
		t.Fatalf("empty snapshot: ok=%v frames=%d", ok, len(m.frames))
	}
}

// FuzzParseMessage: the parser must never panic on untrusted input.
func FuzzParseMessage(f *testing.F) {
	r := New(context.Background(), nil, Config{})
	r.mu.Lock()
	r.unacked = []outFrame{{seq: 1, payload: []byte("seed")}, {seq: 2, payload: nil}}
	valid := r.buildSnapshotLocked()
	r.mu.Unlock()
	f.Add(valid)
	f.Add([]byte(""))
	f.Add([]byte("OFR1"))
	f.Add(valid[:len(valid)-2])          // truncated
	f.Add(append([]byte("X"), valid...)) // prefixed garbage
	mut := append([]byte(nil), valid...)
	mut[len(mut)/2] ^= 0xFF // bit flip -> CRC must reject
	f.Add(mut)

	f.Fuzz(func(t *testing.T, data []byte) {
		m, ok := parseMessage(data) // must not panic
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
