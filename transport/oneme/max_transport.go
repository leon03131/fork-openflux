package oneme

import (
	"fmt"
	"sync/atomic"

	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/utils"
)

type OneMeTransport struct {
	b     *transport.BaseTransport
	token string
	uid   int64
	exit  bool

	// started guards against a second Start. It is never reset: Stop
	// shuts the transport down for good, restart is not supported.
	started atomic.Bool

	oneMeClient *MaxClient
	ch          *CallHandler
}

func (t *OneMeTransport) Receive(callback func([]byte)) {
	t.b.Receive(callback)
}

func (t *OneMeTransport) Stats() transport.TransportStats {
	return t.b.Stats()
}

func NewOneMeTransport(isExit bool, maxToken string, maxUid int64, config transport.TransportConfig) *OneMeTransport {
	return &OneMeTransport{
		b:     transport.NewBaseTransport(config),
		token: maxToken,
		uid:   maxUid,
		exit:  isExit,
	}
}

func (t *OneMeTransport) Start() error {
	if !t.started.CompareAndSwap(false, true) {
		return fmt.Errorf("transport already started")
	}

	utils.Debugf("creating max client ...")
	client := NewMaxClient()
	if err := client.Connect(); err != nil {
		client.Close()
		return fmt.Errorf("max connect: %w", err)
	}
	if err := client.LoginByToken(t.token); err != nil {
		client.Close()
		return fmt.Errorf("max login: %w", err)
	}

	var ch *CallHandler
	if t.exit {
		utils.Debugf("configured ch for exit node")
		ch = startIncomingListener(client)
	} else {
		utils.Debugf("configured ch for client mode")
		ch = startOutgoingCall(client, t.uid)
	}

	ch.onStateChange = func(connected bool) {
		t.b.SetConnected(connected)
	}
	// Sync the initial state: the callback may have missed an early
	// transition fired before it was assigned.
	t.b.SetConnected(ch.connected.Load())

	utils.Debugf("configured dc inbound")
	ch.dcInbound = func(data []byte) {
		t.b.RecordReceive(len(data))
		t.b.CallReceive(data)
	}

	if err := t.b.Start(); err != nil {
		ch.Close()
		client.Close()
		return err
	}

	// All fallible steps succeeded — publish to the transport.
	t.oneMeClient = client
	t.ch = ch

	// Keep the main MAX websocket alive across drops.
	go client.Supervise(t.token)

	return nil
}

func (t *OneMeTransport) Stop() error {
	if err := t.b.Stop(); err != nil {
		return err
	}
	if t.ch != nil {
		t.ch.Close()
	}
	if t.oneMeClient != nil {
		t.oneMeClient.Close()
	}
	return nil
}

func (t *OneMeTransport) IsConnected() bool {
	return t.b.IsConnected()
}

// Bounce drops the current call signaling connection; the caller loop
// reconnects. Implements transport.Bouncer.
func (t *OneMeTransport) Bounce() {
	if t.ch == nil {
		return
	}
	t.ch.mu.Lock()
	conn := t.ch.conn
	t.ch.mu.Unlock()
	if conn != nil {
		t.ch.failConnection(conn)
	}
}

// MaxPayload is the raw message budget for the MAX signaling carrier
// (payloads are base64-wrapped into JSON "ICE candidate" messages).
func (t *OneMeTransport) MaxPayload() int { return 16 * 1024 }

func (t *OneMeTransport) Send(data []byte) error {
	if !t.b.IsConnected() {
		return fmt.Errorf("transport not connected")
	}
	if t.ch == nil {
		return fmt.Errorf("call handler not initialized")
	}
	if err := t.ch.Send(data); err != nil {
		return err
	}
	t.b.RecordSend(len(data))
	return nil
}
