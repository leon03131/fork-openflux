package onlyoffice

import (
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/transport"
)

// liveDocURL is a public Yandex Disk document served by the OnlyOffice
// editor, used for the live exchange test.
const liveDocURL = "https://disk.yandex.ru/i/XqMY_GarArEoFA"

func waitConnected(t *testing.T, name string, tr *OnlyOfficeTransport, budget time.Duration) {
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
// Yandex/OnlyOffice servers. Worst-case timing: one side may sit in
// waitAuth until the other unlocks (instant when both are this transport)
// or until the 30s server lock timer fires (stale lock holder).
func TestLiveDocExchange(t *testing.T) {
	cfg := transport.DefaultConfig()
	a := NewOnlyOfficeTransport(liveDocURL, cfg)
	b := NewOnlyOfficeTransport(liveDocURL, cfg)

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

// TestDecodeCursor covers the cursor payload extraction on adversarial
// input (untrusted wire data must never panic).
func TestDecodeCursor(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"18;aGVsbG8=", "hello", true},
		{"0;AAECAw==", "\x00\x01\x02\x03", true},
		{";", "", false},
		{"18;", "", false},
		{"no-separator", "", false},
		{"", "", false},
		{"18;!!!not-base64!!!", "", false},
		{"18;aGVsbG8", "", false}, // bad padding
	}

	for _, c := range cases {
		got, ok := decodeCursor(c.in)
		if ok != c.wantOK {
			t.Errorf("decodeCursor(%q): ok=%v want %v", c.in, ok, c.wantOK)
			continue
		}
		if ok && string(got) != c.want {
			t.Errorf("decodeCursor(%q) = %q, want %q", c.in, got, c.want)
		}
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
