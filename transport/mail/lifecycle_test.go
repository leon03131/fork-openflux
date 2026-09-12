package mail

import (
	"strings"
	"testing"

	"github.com/leon03131/fork-openflux/transport"
)

// TestDoubleStartRejected verifies that a second Start() returns an
// "already started" error instead of spawning duplicate
// keepalive/writer/reconnect goroutines.
func TestDoubleStartRejected(t *testing.T) {
	tr := NewMailTransport("https://127.0.0.1:1/public/unreachable", transport.DefaultConfig())
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
	tr := NewMailTransport("https://127.0.0.1:1/public/unreachable", transport.DefaultConfig())
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
