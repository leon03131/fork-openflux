package session

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/wire"
)

// phaseDeadline bounds every handshake in this file. Handshake timeouts
// are HelloTimeout (15s), so 20s leaves margin while still proving that
// nothing hangs forever.
const phaseDeadline = 20 * time.Second

// newFaultyPhasePair builds a faulty carrier pair plus client/exit
// sessions WITHOUT starting anything, so a test can arm transport
// faults (DisconnectAfterN, FailSendAfterN, DelayMS) before the first
// byte flows. Arming before Start also keeps the knob writes race-free.
func newFaultyPhasePair(t *testing.T) (*Session, *Session, *transport.FaultyTransport, *transport.FaultyTransport) {
	t.Helper()
	ta, tb := transport.NewFaultyPair(transport.DefaultConfig())
	sa, err := New(ta, []byte("test-key-0123456789abcdef01234567"), true)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := New(tb, []byte("test-key-0123456789abcdef01234567"), false)
	if err != nil {
		t.Fatal(err)
	}
	return sa, sb, ta, tb
}

// startPhasePair starts carriers and sessions and registers cleanup.
func startPhasePair(t *testing.T, sa, sb *Session, ta, tb *transport.FaultyTransport) {
	t.Helper()
	if err := ta.Start(); err != nil {
		t.Fatal(err)
	}
	if err := tb.Start(); err != nil {
		t.Fatal(err)
	}
	sa.Start()
	sb.Start()
	t.Cleanup(func() {
		sa.Close()
		sb.Close()
		ta.Stop()
		tb.Stop()
	})
}

// handshakeAsync runs both handshakes concurrently and returns the
// result channels (client, exit).
func handshakeAsync(sa, sb *Session) (chan error, chan error) {
	errA := make(chan error, 1)
	errB := make(chan error, 1)
	go func() { errA <- sa.Handshake() }()
	go func() { errB <- sb.Handshake() }()
	return errA, errB
}

// recvHandshakeErr collects one handshake result per channel before the
// deadline; a missing result means a hung handshake, which is the bug
// these tests hunt.
func recvHandshakeErr(t *testing.T, errA, errB chan error) (clientErr, exitErr error) {
	t.Helper()
	deadline := time.After(phaseDeadline)
	for i := 0; i < 2; i++ {
		select {
		case clientErr = <-errA:
		case exitErr = <-errB:
		case <-deadline:
			t.Fatal("handshake did not finish before the deadline (hung)")
		}
	}
	return clientErr, exitErr
}

// TestDisconnectDuringHello severs the EXIT carrier before any byte can
// flow (DisconnectAfterN=0). The client HELLO is dropped on the floor;
// the client handshake must fail with a HELLO timeout and the exit
// handshake with waitConnected/ErrNotConnected — neither may hang.
//
// Slow: ~15s (HelloTimeout on both sides, running concurrently).
func TestDisconnectDuringHello(t *testing.T) {
	sa, sb, ta, tb := newFaultyPhasePair(t)
	tb.DisconnectAfterN = 0 // exit link is down from the very start
	startPhasePair(t, sa, sb, ta, tb)

	if tb.IsConnected() {
		t.Fatal("exit carrier must be disconnected by DisconnectAfterN=0")
	}
	if !ta.IsConnected() {
		t.Fatal("client carrier must stay connected")
	}

	errA, errB := handshakeAsync(sa, sb)
	clientErr, exitErr := recvHandshakeErr(t, errA, errB)

	if clientErr == nil || !errors.Is(clientErr, ErrHandshake) {
		t.Fatalf("client handshake = %v, want ErrHandshake (timeout)", clientErr)
	}
	if exitErr == nil || !errors.Is(exitErr, ErrHandshake) {
		t.Fatalf("exit handshake = %v, want ErrHandshake (not connected)", exitErr)
	}

	// A failed handshake must close its own session, not linger.
	select {
	case <-sa.Closed():
	case <-time.After(time.Second):
		t.Fatal("client session still open after failed handshake")
	}
}

// TestDisconnectDuringHelloAck severs the CLIENT carrier right after
// its HELLO is delivered (DisconnectAfterN=1): the exit side answers
// HELLO_ACK into the void (a down link delivers nothing in either
// direction), so the client times out waiting for HELLO_ACK and the
// exit side times out waiting for the key confirmation.
//
// Slow: ~15s (HelloTimeout on both sides, running concurrently).
func TestDisconnectDuringHelloAck(t *testing.T) {
	sa, sb, ta, tb := newFaultyPhasePair(t)
	ta.DisconnectAfterN = 1 // client link dies right after HELLO leaves
	startPhasePair(t, sa, sb, ta, tb)

	errA, errB := handshakeAsync(sa, sb)
	clientErr, exitErr := recvHandshakeErr(t, errA, errB)

	if clientErr == nil || !errors.Is(clientErr, ErrHandshake) {
		t.Fatalf("client handshake = %v, want ErrHandshake (HELLO_ACK timeout)", clientErr)
	}
	if exitErr == nil || !errors.Is(exitErr, ErrHandshake) {
		t.Fatalf("exit handshake = %v, want ErrHandshake (confirmation timeout)", exitErr)
	}
	if !strings.Contains(exitErr.Error(), "confirmation") {
		t.Fatalf("exit handshake = %v, want peer confirmation timeout", exitErr)
	}
}

// TestDisconnectDuringConfirmation severs the EXIT carrier right after
// its HELLO_ACK (DisconnectAfterN=1 on the exit side: HELLO_ACK is the
// first and last message it delivers). The client's confirmation PING
// never reaches the exit side, so neither side becomes Ready: the exit
// times out waiting for the client's proof, and the client times out
// waiting for the exit's encrypted PONG. Mutual confirmation is fully
// enforced.
//
// Slow: ~15s (HelloTimeout on both sides). session.go is not modified,
// so the test really waits out the full confirmation timeout.
func TestDisconnectDuringConfirmation(t *testing.T) {
	sa, sb, ta, tb := newFaultyPhasePair(t)
	tb.DisconnectAfterN = 1 // exit link dies right after HELLO_ACK
	startPhasePair(t, sa, sb, ta, tb)

	errA, errB := handshakeAsync(sa, sb)
	clientErr, exitErr := recvHandshakeErr(t, errA, errB)

	// The client must fail with a confirmation timeout (it never gets
	// the exit's encrypted PONG).
	if clientErr == nil || !errors.Is(clientErr, ErrHandshake) {
		t.Fatalf("client handshake = %v, want ErrHandshake", clientErr)
	}
	if !strings.Contains(clientErr.Error(), "confirmation") {
		t.Fatalf("client handshake = %v, want confirmation timeout", clientErr)
	}
	// The exit must also fail — but the exact reason is timing-dependent:
	// if the link dies before/while the exit's handshake starts, the
	// failure is "transport not connected"; if the HELLO was delivered
	// first, it is the confirmation timeout (or the carrier send error
	// closing the session). All are correct clean failures.
	if exitErr == nil {
		t.Fatal("exit handshake succeeded despite severed carrier")
	}
	select {
	case <-sb.Closed():
	default:
		t.Fatal("exit session still open after failed handshake")
	}
}

// TestCarrierSendErrorKillsSession lets the handshake complete and then
// fails every further carrier Send: the session writer goroutine must
// treat a carrier send failure as fatal and close the session.
//
// FailSendAfterN=2 because the client spends two sends on the handshake
// itself (HELLO + encrypted confirmation PING); the next send — the
// test's DATA frame — is the one that fails. Fast test (<1s).
func TestCarrierSendErrorKillsSession(t *testing.T) {
	sa, sb, ta, tb := newFaultyPhasePair(t)
	ta.FailSendAfterN = 2 // budget covers HELLO + confirmation PING
	startPhasePair(t, sa, sb, ta, tb)

	// Handshake must succeed: sends #1 (HELLO) and #2 (PING) are allowed.
	handshakeBoth(t, sa, sb)

	// The DATA frame is accepted into the send queue (the carrier still
	// reports connected), but the writer goroutine's Send fails.
	if err := sa.SendFrame(wire.Frame{Type: wire.TypeData, StreamID: 1, Payload: []byte("x")}); err != nil {
		t.Fatalf("SendFrame: %v (enqueue must succeed; the failure is async)", err)
	}
	select {
	case <-sa.Closed():
		if sa.Err() == nil || !strings.Contains(sa.Err().Error(), "carrier send") {
			t.Fatalf("session closed with %v, want carrier send error", sa.Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session survived a carrier send failure")
	}
}

// TestSlowCarrierHandshakeTimeout delays every client->exit delivery by
// more than HelloTimeout: the HELLO lands only after both handshake
// deadlines have fired, so both sides must fail with a timeout instead
// of waiting on the slow carrier forever.
//
// The uniform fixed delay preserves FIFO (a per-message random delay
// would reorder). Slow: ~15s (HelloTimeout).
func TestSlowCarrierHandshakeTimeout(t *testing.T) {
	sa, sb, ta, tb := newFaultyPhasePair(t)
	ta.DelayMS = 16000 // HELLO arrives after the 15s handshake deadline
	startPhasePair(t, sa, sb, ta, tb)

	errA, errB := handshakeAsync(sa, sb)
	clientErr, exitErr := recvHandshakeErr(t, errA, errB)

	if clientErr == nil || !errors.Is(clientErr, ErrHandshake) {
		t.Fatalf("client handshake = %v, want ErrHandshake (timeout)", clientErr)
	}
	if !strings.Contains(clientErr.Error(), "timeout") {
		t.Fatalf("client handshake = %v, want timeout", clientErr)
	}
	if exitErr == nil || !errors.Is(exitErr, ErrHandshake) {
		t.Fatalf("exit handshake = %v, want ErrHandshake (timeout)", exitErr)
	}
}
