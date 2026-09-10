package oneme

import (
	"encoding/json"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v3"
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
	loggedIn      bool
	keepaliveStop chan struct{}
	onEvent       func(MaxPacket)
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
	// msgMu serializes signaling message handlers (they are dispatched
	// as goroutines from the read loop).
	msgMu sync.Mutex
}
