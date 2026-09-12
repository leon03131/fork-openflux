package volga

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/transport"
)

// The live exchange test needs a real Volga document URL provided via
// environment (never hardcode/share real links in the repo).
var liveDocURL = os.Getenv("OPENFLUX_TEST_VOLGA_URL")

func requireLiveDoc(t *testing.T) {
	t.Helper()
	if liveDocURL == "" {
		t.Skip("set OPENFLUX_TEST_VOLGA_URL to run the live document test")
	}
}

func waitConnected(t *testing.T, name string, tr *VolgaTransport, budget time.Duration) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if tr.IsConnected() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s did not connect within %v", name, budget)
}

// TestLiveDocExchange runs two carrier instances against the live test
// document and verifies bidirectional delivery. It really talks to
// Yandex servers. Both instances are started before waiting, so the two
// authorize+subscribe sequences run concurrently; a healthy run takes
// only a few seconds, well inside the 60s budget.
func TestLiveDocExchange(t *testing.T) {
	requireLiveDoc(t)
	cfg := transport.DefaultConfig()
	a := NewVolgaTransport(liveDocURL, cfg)
	b := NewVolgaTransport(liveDocURL, cfg)

	aRecv := make(chan []byte, 16)
	bRecv := make(chan []byte, 16)
	a.Receive(func(d []byte) { aRecv <- d })
	b.Receive(func(d []byte) { bRecv <- d })

	if err := a.Start(); err != nil {
		t.Fatalf("A.Start: %v", err)
	}
	defer a.Stop()
	if err := b.Start(); err != nil {
		t.Fatalf("B.Start: %v", err)
	}
	defer b.Stop()

	waitConnected(t, "A", a, 45*time.Second)
	t.Logf("A connected")
	waitConnected(t, "B", b, 45*time.Second)
	t.Logf("B connected")

	// A -> B
	msgAB := []byte("hello-from-openflux-A")
	if err := a.Send(msgAB); err != nil {
		t.Fatalf("A.Send: %v", err)
	}
	select {
	case got := <-bRecv:
		if string(got) != string(msgAB) {
			t.Fatalf("B received %q, want %q", got, msgAB)
		}
		t.Logf("B received %q", got)
	case <-time.After(15 * time.Second):
		t.Fatal("B did not receive A's message within 15s")
	}

	// B -> A
	msgBA := []byte("hello-from-openflux-B")
	if err := b.Send(msgBA); err != nil {
		t.Fatalf("B.Send: %v", err)
	}
	select {
	case got := <-aRecv:
		if string(got) != string(msgBA) {
			t.Fatalf("A received %q, want %q", got, msgBA)
		}
		t.Logf("A received %q", got)
	case <-time.After(15 * time.Second):
		t.Fatal("A did not receive B's message within 15s")
	}
}

// TestFramePrefixFor checks the deterministic channel-marker derivation:
// the same document URL must always yield the same marker (client and
// exit compute it independently), different URLs must not collide.
func TestFramePrefixFor(t *testing.T) {
	const url = "https://disk.yandex.ru/i/example"
	p1 := framePrefixFor(url)
	if p1 != framePrefixFor(url) {
		t.Fatal("framePrefixFor is not deterministic")
	}
	if framePrefixFor(url+"x") == p1 {
		t.Fatal("different URLs must not share a channel marker")
	}
	if !strings.HasPrefix(p1, "OFX1") || !strings.HasSuffix(p1, ":") {
		t.Errorf("bad marker shape: %q", p1)
	}
	if len(p1) != len("OFX1")+8+1 {
		t.Errorf("bad marker length: %q", p1)
	}
}

// TestEncodeDecodeBlobRoundtrip verifies that our own batches survive
// the encode/decode roundtrip byte-identically, that the base64 form
// carries the constant marker prefix (the cheap pre-decode filter), and
// that blobs with a foreign marker are rejected.
func TestEncodeDecodeBlobRoundtrip(t *testing.T) {
	marker := []byte(framePrefixFor("https://disk.yandex.ru/i/roundtrip"))
	batch := [][]byte{
		[]byte("hello"),
		{0x00, 0x01, 0x02, 0xfa, 0xff},
		bytes.Repeat([]byte{0xAB}, 70000), // > 64 KiB: needs the 4-byte prefix
	}

	blob := encodeBlob(marker, batch)
	if !bytes.HasPrefix(blob, marker) {
		t.Fatal("encodeBlob does not start with the marker")
	}

	// The base64 prefix filter must match our blob.
	b64 := base64.StdEncoding.EncodeToString(blob)
	prefix := base64.StdEncoding.EncodeToString(marker[:12])
	if !strings.HasPrefix(b64, prefix) {
		t.Fatalf("base64 blob lacks the constant marker prefix: %q vs %q", b64[:16], prefix)
	}

	got := decodeBlob(blob, marker)
	if len(got) != len(batch) {
		t.Fatalf("decodeBlob returned %d packets, want %d", len(got), len(batch))
	}
	for i := range batch {
		if !bytes.Equal(got[i], batch[i]) {
			t.Fatalf("packet %d mismatch: got %d bytes, want %d", i, len(got[i]), len(batch[i]))
		}
	}

	// Empty batch (the keepalive form) must decode to zero packets.
	if got := decodeBlob(encodeBlob(marker, nil), marker); len(got) != 0 {
		t.Fatalf("empty batch decoded to %d packets", len(got))
	}

	// Foreign marker: rejected.
	foreign := []byte(framePrefixFor("https://disk.yandex.ru/i/other"))
	if got := decodeBlob(blob, foreign); got != nil {
		t.Error("decodeBlob accepted a blob with a foreign marker")
	}
}

// TestDecodeBatch covers the length-prefixed packet splitter on
// adversarial input (untrusted wire data must never panic and must be
// strictly bounded).
func TestDecodeBatch(t *testing.T) {
	marker := []byte(framePrefixFor("https://disk.yandex.ru/i/batch"))

	cases := []struct {
		name string
		in   []byte
		want int
	}{
		{"empty", nil, 0},
		{"short header", []byte{0, 0, 0}, 0},
		{"zero length packet", []byte{0, 0, 0, 0}, 0},
		{"truncated payload", []byte{0, 0, 0, 5, 'a', 'b'}, 0},
		{"oversize length", []byte{0x7F, 0xFF, 0xFF, 0xFF}, 0},
		{"garbage", bytes.Repeat([]byte{0xFF}, 64), 0},
		{"header only then garbage", []byte{0, 0, 0, 1, 'x', 0, 0}, 1},
	}
	for _, c := range cases {
		if got := decodeBatch(c.in); len(got) != c.want {
			t.Errorf("%s: decodeBatch returned %d packets, want %d", c.name, len(got), c.want)
		}
	}

	// A blob claiming more packets than the cap is truncated, not fatal.
	var big []byte
	big = append(big, marker...)
	for i := 0; i < maxBatchPackets+100; i++ {
		big = append(big, 0, 0, 0, 1, 0x41)
	}
	if got := decodeBlob(big, marker); len(got) > maxBatchPackets {
		t.Errorf("decodeBlob returned %d packets, cap is %d", len(got), maxBatchPackets)
	}
}

// TestHandleBlobString exercises the full untrusted-entry path on the
// transport: our framed blob is delivered in order, foreign blobs and
// garbage are dropped before ever reaching the receive callback.
func TestHandleBlobString(t *testing.T) {
	const url = "https://disk.yandex.ru/i/handle"
	tr := NewVolgaTransport(url, transport.DefaultConfig())

	var received [][]byte
	tr.Receive(func(d []byte) { received = append(received, d) })

	// Foreign: no marker in the base64 prefix.
	foreignMarker := []byte(framePrefixFor(url + "-other"))
	foreignBlob := base64.StdEncoding.EncodeToString(encodeBlob(foreignMarker, [][]byte{[]byte("x")}))
	tr.handleBlobString(foreignBlob)
	if len(received) != 0 {
		t.Fatalf("foreign blob delivered %d packets", len(received))
	}

	// Foreign: same prefix class but broken base64 / missing marker.
	tr.handleBlobString(tr.markerB64Prefix[:8] + "!!!!not-base64!!!!")
	tr.handleBlobString("")
	tr.handleBlobString("AAAA")
	if len(received) != 0 {
		t.Fatalf("garbage delivered %d packets", len(received))
	}

	// Ours: two packets in one blob.
	blob := base64.StdEncoding.EncodeToString(encodeBlob(tr.frameMarker, [][]byte{[]byte("one"), []byte("two")}))
	tr.handleBlobString(blob)
	if len(received) != 2 || string(received[0]) != "one" || string(received[1]) != "two" {
		t.Fatalf("received %v, want [one two]", received)
	}
}

// TestSendErrors verifies Send is honest: empty, oversized and
// disconnected sends all fail instead of being silently dropped.
func TestSendErrors(t *testing.T) {
	tr := NewVolgaTransport("https://127.0.0.1:1/unreachable", transport.DefaultConfig())
	if err := tr.Send(nil); err == nil {
		t.Error("Send(nil): want error")
	}
	if err := tr.Send(make([]byte, maxPayloadSize+1)); err == nil {
		t.Error("oversized Send: want error")
	}
	if err := tr.Send([]byte("x")); err == nil {
		t.Error("Send before connect: want error")
	}
}

// TestDoubleStartRejected verifies that a second Start() returns an
// "already started" error instead of spawning duplicate
// keepalive/writer/reconnect goroutines.
func TestDoubleStartRejected(t *testing.T) {
	tr := NewVolgaTransport("https://127.0.0.1:1/unreachable", transport.DefaultConfig())
	if err := tr.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}
	defer tr.Stop()
	if err := tr.Start(); err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("second Start: got %v, want already started error", err)
	}
}

// TestStartAfterStopRejected verifies that restart is not supported:
// started stays set after Stop(), so a later Start fails honestly
// instead of reviving background loops on a cancelled context.
func TestStartAfterStopRejected(t *testing.T) {
	tr := NewVolgaTransport("https://127.0.0.1:1/unreachable", transport.DefaultConfig())
	if err := tr.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := tr.Start(); err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("Start after Stop: got %v, want already started error", err)
	}
}

// TestStopIdempotent verifies that Stop can be called twice and tears
// down promptly even with no reachable document (the transport context
// cancels the in-flight authorize and any pending reconnect).
func TestStopIdempotent(t *testing.T) {
	tr := NewVolgaTransport("https://127.0.0.1:1/unreachable", transport.DefaultConfig())
	if err := tr.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := tr.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	if tr.IsRunning() || tr.IsConnected() {
		t.Error("transport still running/connected after Stop")
	}
}
