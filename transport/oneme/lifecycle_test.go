package oneme

import (
	"strings"
	"testing"

	"github.com/leon03131/fork-openflux/transport"
)

// A successful Start requires network access to the MAX websocket, so
// these tests drive the started guard directly (white-box) instead of
// exercising the real connect/login path.

func TestOneMeTransportDoubleStart(t *testing.T) {
	tr := NewOneMeTransport(false, "token", 123, transport.DefaultConfig())
	// Simulate a completed first Start (the real one needs network).
	tr.started.Store(true)

	err := tr.Start()
	if err == nil {
		t.Fatal("second Start succeeded, want already-started error")
	}
	if !strings.Contains(err.Error(), "already started") {
		t.Fatalf("second Start error = %q, want it to mention %q", err, "already started")
	}
}

func TestOneMeTransportNoRestartAfterStop(t *testing.T) {
	tr := NewOneMeTransport(false, "token", 123, transport.DefaultConfig())
	// Simulate a completed Start, then stop the transport.
	tr.started.Store(true)
	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// Stop must not reset started: restart is not supported.
	if !tr.started.Load() {
		t.Fatal("Stop reset the started flag")
	}
	err := tr.Start()
	if err == nil {
		t.Fatal("Start after Stop succeeded, restart must not be supported")
	}
	if !strings.Contains(err.Error(), "already started") {
		t.Fatalf("Start after Stop error = %q, want it to mention %q", err, "already started")
	}
}

func TestOneMeTransportFreshNotStarted(t *testing.T) {
	tr := NewOneMeTransport(true, "token", 123, transport.DefaultConfig())
	if tr.started.Load() {
		t.Fatal("fresh transport is marked as started")
	}
	if tr.oneMeClient != nil || tr.ch != nil {
		t.Fatal("fresh transport has client/call handler assigned")
	}
}
