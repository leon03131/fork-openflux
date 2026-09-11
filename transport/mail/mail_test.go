package mail

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/transport"
)

// The live exchange test needs a real Mail.ru Cloud public document URL
// provided via environment (never hardcode/share real links in the repo).
var liveDocURL = os.Getenv("OPENFLUX_TEST_MAIL_URL")

func requireLiveDoc(t *testing.T) {
	t.Helper()
	if liveDocURL == "" {
		t.Skip("set OPENFLUX_TEST_MAIL_URL to run the live document test")
	}
}

func waitConnected(t *testing.T, name string, tr *MailTransport, budget time.Duration) {
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
// Mail.ru/R7 servers. Worst-case timing: one side may sit in waitAuth
// until the other unlocks (instant when both are this transport) or
// until the server lock timer fires (stale lock holder).
func TestLiveDocExchange(t *testing.T) {
	requireLiveDoc(t)
	cfg := transport.DefaultConfig()
	a := NewMailTransport(liveDocURL, cfg)
	b := NewMailTransport(liveDocURL, cfg)

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

	waitConnected(t, "A", a, 60*time.Second)
	t.Logf("A connected")
	waitConnected(t, "B", b, 60*time.Second)
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
	const url = "https://cloud.mail.ru/public/MLKF/example"
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

// TestEncodeDecodeCursorRoundtrip verifies that our own frames survive
// the encode/decode roundtrip while frames with a foreign channel marker
// are dropped.
func TestEncodeDecodeCursorRoundtrip(t *testing.T) {
	prefix := framePrefixFor("https://cloud.mail.ru/public/MLKF/roundtrip")
	payload := []byte{0x00, 0x01, 0x02, 0xfa, 0xff}

	wire := encodeCursor(prefix, payload)
	if !strings.HasPrefix(wire, "18;"+prefix) {
		t.Fatalf("encodeCursor produced %q, want prefix %q", wire, "18;"+prefix)
	}

	got, ok := decodeCursor(wire, prefix)
	if !ok {
		t.Fatalf("decodeCursor(%q) rejected our own frame", wire)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("decodeCursor(%q) = %v, want %v", wire, got, payload)
	}

	// A peer with a different channel (or a stale marker) must not be
	// able to feed us payloads.
	if _, ok := decodeCursor(wire, "OFX1deadbeef:"); ok {
		t.Error("decodeCursor accepted a frame with a foreign channel marker")
	}
}

// TestDecodeCursor covers the cursor payload extraction on adversarial
// input (untrusted wire data must never panic, and anything without our
// exact OFX1 marker must be silently dropped).
func TestDecodeCursor(t *testing.T) {
	const prefix = "OFX1deadbeef:"
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"18;OFX1deadbeef:aGVsbG8=", "hello", true},
		{"0;OFX1deadbeef:AAECAw==", "\x00\x01\x02\x03", true},
		{"999;OFX1deadbeef:aGVsbG8=", "hello", true}, // any cursor index is fine
		{"18;OFX1cafebabe:aGVsbG8=", "", false},      // foreign channel
		{"18;aGVsbG8=", "", false},                   // legacy format without marker
		{"18;OFX1deadbeef:", "", false},              // empty payload
		{"18;OFX1deadbeef:!!!not-base64!!!", "", false},
		{"18;OFX1deadbeef:aGVsbG8", "", false}, // bad padding
		{"18;OFX1deadbee:aGVsbG8=", "", false}, // truncated marker
		{"18;OFX1deadbeefaGVsbG8=", "", false}, // missing ':' separator
		{"OFX1deadbeef:aGVsbG8=", "", false},   // missing cursor index
		{";", "", false},
		{"18;", "", false},
		{"no-separator", "", false},
		{"", "", false},
	}

	for _, c := range cases {
		got, ok := decodeCursor(c.in, prefix)
		if ok != c.wantOK {
			t.Errorf("decodeCursor(%q): ok=%v want %v", c.in, ok, c.wantOK)
			continue
		}
		if ok && string(got) != c.want {
			t.Errorf("decodeCursor(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestStopIdempotent verifies that Stop can be called twice and tears
// down promptly even with no reachable document (the transport context
// cancels the in-flight connect attempt and any pending reconnect).
func TestStopIdempotent(t *testing.T) {
	tr := NewMailTransport("https://127.0.0.1:1/public/abc/def", transport.DefaultConfig())
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

// TestParseEvent checks the socket.io event envelope parser on malformed
// input (must never panic, always report ok=false).
func TestParseEvent(t *testing.T) {
	if ev, _, ok := parseEvent(`42["message",{"type":"cursor"}]`); !ok || ev != "message" {
		t.Errorf("valid frame: ok=%v ev=%q", ok, ev)
	}
	for _, bad := range []string{
		"", "4", "42", "42[", `42["message"`, `42["message"]`,
		`42[1,2]`, `42["message",{}]extra`, "hello", `0{"sid":"x"}`,
		`42["message",{}, "extra"]`,
	} {
		if _, _, ok := parseEvent(bad); ok {
			t.Errorf("parseEvent(%q) unexpectedly ok", bad)
		}
	}
}

// TestPublicPath covers the public-link path extraction (the r7/edit
// "public" field is the link path without the "/public" prefix).
func TestPublicPath(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"https://cloud.mail.ru/public/MLKF/6CEdaR5Qf", "/MLKF/6CEdaR5Qf", false},
		{"https://cloud.mail.ru/public/MLKF/6CEdaR5Qf/", "/MLKF/6CEdaR5Qf", false},
		{"https://cloud.mail.ru/public/A/b?x=1#frag", "/A/b", false},
		{"http://cloud.mail.ru/public/ABC", "/ABC", false},
		{"https://cloud.mail.ru/private/ABC", "", true},
		{"https://cloud.mail.ru/", "", true},
		{"https://cloud.mail.ru/public/", "", true}, // "/public" alone is not a link
		{"://bad", "", true},
		{"ftp://cloud.mail.ru/public/ABC", "", true},
	}
	for _, c := range cases {
		got, err := publicPath(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("publicPath(%q): err=%v wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if err == nil && got != c.want {
			t.Errorf("publicPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
