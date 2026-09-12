package utils

import (
	"io"
	"os"
	"strings"
	"testing"
)

// TestDebugfDisabled runs before any EnableDebug call in this package
// (tests run in source order): Debugf must be a cheap no-op and, above
// all, must not panic when debug was never enabled.
func TestDebugfDisabled(t *testing.T) {
	Debugf("this message must be dropped: %d", 42)
}

func TestEnableDebugPrints(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStderr := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = origStderr }()

	// EnableDebug binds its logger to the current os.Stderr, so the
	// redirect must happen first.
	EnableDebug()
	Debugf("debug-test-marker %d", 42)

	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	if !strings.Contains(string(out), "debug-test-marker 42") {
		t.Fatalf("Debugf output %q does not contain the formatted message", out)
	}
}
