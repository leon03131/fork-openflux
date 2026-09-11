package oneme

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
)

type MaxPacket struct {
	Ver     int             `json:"ver"`
	Cmd     int             `json:"cmd"`
	Opcode  int             `json:"opcode"`
	Seq     int             `json:"seq"`
	Payload json.RawMessage `json:"payload"`
}

type InternalCallerParams struct {
	ID           CallerID  `json:"id"`
	IsConcurrent bool      `json:"isConcurrent"`
	Endpoint     string    `json:"endpoint"`
	Turn         IceServer `json:"turn"`
	Stun         IceServer `json:"stun"`
}

type CallerID struct {
	Internal int64  `json:"internal"`
	External string `json:"external"`
}

type IceServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

type WebRTCConfig struct {
	Token             string `json:"tkn"`
	WebsocketEndpoint string `json:"wse"`
	TurnUsername      string `json:"trnu"`
}

type MaxClient struct {
	conn          *websocket.Conn
	mu            sync.Mutex
	seq           atomic.Int64
	pending       sync.Map
	deviceID      string
	loggedIn      atomic.Bool
	dead          atomic.Bool
	keepaliveStop chan struct{}
	keepaliveOnce sync.Once
	closedCh      chan struct{}
	closeOnce     sync.Once
	onEvent       func(MaxPacket)
	// ctx cancels any in-flight websocket dial; cancel is called by Close.
	ctx    context.Context
	cancel context.CancelFunc
}

type CallHandler struct {
	tag               string
	role              string
	pc                *webrtc.PeerConnection
	dc                *webrtc.DataChannel
	conn              *websocket.Conn
	localID           int64
	seq               int64
	callAccepted      atomic.Bool
	acceptSent        atomic.Bool
	hasRemoteDesc     bool
	pendingCandidates []map[string]interface{}
	dcInbound         func([]byte)
	msgHandler        func(string)
	reconnectCh       chan struct{}
	connected         atomic.Bool
	onStateChange     func(bool)
	// mu guards conn, pc, dc, localID and seq.
	mu sync.Mutex
	// msgCh feeds the single dispatcher goroutine: signaling messages
	// are handled strictly in arrival order (data integrity depends on
	// it in ICE-injection mode).
	msgCh chan string
	// outQueue feeds the single signaling writer goroutine, so h.mu is
	// never held across a network write.
	outQueue chan []byte
	// done stops dispatchLoop/signalingWriter/reconnect goroutines.
	done     chan struct{}
	doneOnce sync.Once
	// msgMu serializes msgHandler against resetCallState.
	msgMu sync.Mutex
	// ctx cancels any in-flight websocket dial; cancel is called by Close.
	ctx    context.Context
	cancel context.CancelFunc
}
