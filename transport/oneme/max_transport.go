package oneme

import (
	"fmt"

	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/utils"
)

type OneMeTransport struct {
	b     *transport.BaseTransport
	token string
	uid   int64
	exit  bool

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
	utils.Debugf("creating max client ...")
	t.oneMeClient = NewMaxClient()
	if err := t.oneMeClient.Connect(); err != nil {
		return fmt.Errorf("max connect: %w", err)
	}
	if err := t.oneMeClient.LoginByToken(t.token); err != nil {
		return fmt.Errorf("max login: %w", err)
	}

	if t.exit {
		utils.Debugf("configured ch for exit node")
		t.ch = startIncomingListener(t.oneMeClient)
	} else {
		utils.Debugf("configured ch for client mode")
		t.ch = startOutgoingCall(t.oneMeClient, t.uid)
	}

	t.ch.onStateChange = func(connected bool) {
		t.b.SetConnected(connected)
	}
	// Sync the initial state: the callback may have missed an early
	// transition fired before it was assigned.
	t.b.SetConnected(t.ch.connected.Load())

	// Keep the main MAX websocket alive across drops.
	go t.oneMeClient.Supervise(t.token)

	utils.Debugf("configured dc inbound")
	t.ch.dcInbound = func(data []byte) {
		t.b.RecordReceive(len(data))
		t.b.CallReceive(data)
	}

	return t.b.Start()
}

func (t *OneMeTransport) Stop() error {
	if err := t.b.Stop(); err != nil {
		return err
	}
	if t.oneMeClient != nil {
		t.oneMeClient.Close()
	}
	if t.ch != nil {
		t.ch.mu.Lock()
		if t.ch.conn != nil {
			t.ch.conn.Close()
			t.ch.conn = nil
		}
		t.ch.mu.Unlock()
	}
	return nil
}

func (t *OneMeTransport) IsConnected() bool {
	return t.b.IsConnected()
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
