package session

import (
	"testing"
	"time"

	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/wire"
)

var compatPSK = []byte("0123456789abcdef0123456789abcdef")

// runLegacyServer answers a HELLO with the LEGACY format
// ([role][pub][tag91], tag computed WITHOUT capability bytes) and then
// echoes decrypted DATA frames back (encrypted).
func runLegacyServer(t *testing.T, tr transport.Transport, psk []byte) {
	t.Helper()
	priv, err := generateEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	var crypto *sessionCrypto
	var cryptoMu = make(chan *sessionCrypto, 1)

	tr.Receive(func(msg []byte) {
		select {
		case c := <-cryptoMu:
			crypto = c
		default:
		}
		if crypto != nil {
			plain, err := crypto.decrypt(msg)
			if err != nil {
				t.Logf("legacy server: decrypt failed: %v", err)
				return
			}
			t.Logf("legacy server: decrypted %d bytes", len(plain))
			f, err := wire.Decode(plain)
			if err != nil {
				return
			}
			if f.Type == wire.TypePing {
				// Echo as PONG, encrypted.
				buf, _ := wire.Encode(nil, wire.Frame{Type: wire.TypePong, Payload: f.Payload})
				enc, err := crypto.encrypt(buf)
				if err == nil {
					tr.Send(enc)
				}
			}
			return
		}
		f, err := wire.Decode(msg)
		if err != nil || f.Type != wire.TypeHello {
			return
		}
		// Tolerant legacy peer: accepts 33 (no caps) or 34 (with caps),
		// always answers with the legacy 124-byte ACK.
		if len(f.Payload) != 33 && len(f.Payload) != 34 {
			t.Logf("legacy server: HELLO payload len=%d", len(f.Payload))
			return
		}
		t.Logf("legacy server: got HELLO (len=%d)", len(f.Payload))
		c, err := deriveSession(psk, priv, f.Payload[1:33], false)
		if err != nil {
			return
		}
		clientPub := f.Payload[1:33]
		tag := c.computeKeyConfirm(clientPub, priv.PublicKey().Bytes(), 0, 0, false)
		ack := append(append([]byte{0}, priv.PublicKey().Bytes()...), tag...)
		buf, _ := wire.Encode(nil, wire.Frame{Type: wire.TypeHelloAck, Payload: ack})
		tr.Send(buf)
		cryptoMu <- c
	})
}

// TestNewClientLegacyServer: a current client must complete the
// handshake with a legacy server (legacy tag, no caps) and exchange
// encrypted frames.
func TestNewClientLegacyServer(t *testing.T) {
	ta, tb := transport.NewMemoryTransportPair(transport.DefaultConfig())
	ta.Start()
	tb.Start()
	defer ta.Stop()
	defer tb.Stop()

	runLegacyServer(t, tb, compatPSK)

	client, err := New(ta, compatPSK, true)
	if err != nil {
		t.Fatal(err)
	}
	client.Start()
	defer client.Close()

	if err := client.Handshake(); err != nil {
		t.Fatalf("new client vs legacy server handshake: %v", err)
	}
	// Legacy peer advertised no caps.
	if got := client.peerCaps.Load(); got != 0 {
		t.Fatalf("peerCaps = %d, want 0 for legacy", got)
	}
}

// TestLegacyClientNewServer: a legacy client (33-byte HELLO) must get a
// legacy 124-byte ACK from the current server, and the crypto must line
// up (we prove it by decrypting nothing — the tag itself is validated by
// the client side in the reverse test; here we assert wire shape).
func TestLegacyClientNewServer(t *testing.T) {
	ta, tb := transport.NewMemoryTransportPair(transport.DefaultConfig())
	ta.Start()
	tb.Start()
	defer ta.Stop()
	defer tb.Stop()

	server, err := New(tb, compatPSK, false)
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	defer server.Close()
	go server.Handshake() // server waits for HELLO + confirmation

	// Register the ACK listener BEFORE sending HELLO: under -race the
	// server's answer can otherwise arrive before registration and be
	// dropped silently.
	ackCh := make(chan wire.Frame, 1)
	ta.Receive(func(msg []byte) {
		f, err := wire.Decode(msg)
		if err == nil && f.Type == wire.TypeHelloAck {
			ackCh <- f
		}
	})

	priv, _ := generateEphemeralKey()
	payload := append([]byte{1}, priv.PublicKey().Bytes()...)
	buf, _ := wire.Encode(nil, wire.Frame{Type: wire.TypeHello, Payload: payload})
	if err := ta.Send(buf); err != nil {
		t.Fatal(err)
	}

	select {
	case f := <-ackCh:
		if len(f.Payload) != 124 {
			t.Fatalf("legacy ACK length = %d, want 124", len(f.Payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no ACK for legacy HELLO")
	}
}
