package oneme

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
)

var (
	useICEInjection = true
)

// setConnected updates the connection state and notifies the transport.
func (h *CallHandler) setConnected(connected bool) {
	if h.connected.Swap(connected) != connected && h.onStateChange != nil {
		h.onStateChange(connected)
	}
}

// deliverInbound passes received payload to the transport (nil-safe).
func (h *CallHandler) deliverInbound(data []byte) {
	if h.dcInbound != nil {
		h.dcInbound(data)
	}
}

func (h *CallHandler) Send(data []byte) error {
	if useICEInjection {
		return h.injectICE(data)
	}
	h.mu.Lock()
	dc := h.dc
	h.mu.Unlock()
	if dc == nil {
		return fmt.Errorf("data channel not ready")
	}
	return dc.Send(data)
}

// readLoop processes the signaling websocket. The connection is captured
// as a parameter so a superseded connection never interferes with the
// current one.
func (h *CallHandler) readLoop(conn *websocket.Conn) {
	logInfo("[%s] Signaling connected", h.tag)
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			logError("[%s] Signaling disconnected: %v", h.tag, err)
			h.mu.Lock()
			current := h.conn == conn
			h.mu.Unlock()
			if current {
				h.setConnected(false)
				h.signalReconnect()
			}
			return
		}
		text := string(message)

		if strings.Contains(text, "accepted-call") {
			logInfo("[%s] call accepted", h.tag)
			h.callAccepted.Store(true)
			continue
		}

		if text == "ping" {
			h.mu.Lock()
			if h.conn == conn {
				h.queueSignaling("pong")
			}
			h.mu.Unlock()
			continue
		}
		if len(text) < 10 {
			continue
		}
		var data map[string]interface{}
		if json.Unmarshal([]byte(text), &data) != nil {
			continue
		}
		if t, _ := data["type"].(string); t == "response" {
			continue
		}
		if t, _ := data["type"].(string); t == "error" {
			logError("[%s] SIGNALING ERROR: %v", h.tag, data["message"])
			continue
		}

		// Ordered FIFO dispatch: handlers may mutate state and block,
		// and data frames must keep their arrival order.
		h.msgCh <- text
	}
}

// dispatchLoop is the single consumer of signaling messages, keeping
// strict FIFO order. Started once per CallHandler.
func (h *CallHandler) dispatchLoop() {
	for text := range h.msgCh {
		h.msgMu.Lock()
		h.msgHandler(text)
		h.msgMu.Unlock()
	}
}

// signalingWriter is the only writer of the call websocket. Started once
// per CallHandler. Messages queued while disconnected are dropped (the
// call is dead anyway; a new call re-establishes state).
func (h *CallHandler) signalingWriter() {
	for msg := range h.outQueue {
		h.mu.Lock()
		conn := h.conn
		h.mu.Unlock()
		if conn == nil {
			continue
		}
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		err := conn.WriteMessage(websocket.TextMessage, msg)
		conn.SetWriteDeadline(time.Time{})
		if err != nil {
			logError("[%s] signaling write failed: %v", h.tag, err)
		}
	}
}

// queueSignaling enqueues a message for the signaling writer.
// Caller must hold h.mu (to keep h.seq order == write order).
func (h *CallHandler) queueSignaling(msg string) error {
	select {
	case h.outQueue <- []byte(msg):
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("signaling queue full")
	}
}

func (h *CallHandler) signalReconnect() {
	if h.role == "caller" {
		select {
		case h.reconnectCh <- struct{}{}:
		default:
		}
	} else {
		// A library must never kill the process. The receiver drops
		// the dead signaling connection and keeps waiting for new
		// incoming calls via the MAX client event callback.
		logError("[%s] Receiver connection died, waiting for new calls", h.tag)
		h.mu.Lock()
		if h.conn != nil {
			h.conn.Close()
			h.conn = nil
		}
		h.mu.Unlock()
	}
}

func (h *CallHandler) sendAcceptCall() {
	if !h.acceptSent.CompareAndSwap(false, true) {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conn == nil {
		return
	}
	msg := fmt.Sprintf(`{"command":"accept-call","sequence":%d,"mediaSettings":{"isAudioEnabled":true,"isVideoEnabled":false,"isScreenSharingEnabled":false,"isFastScreenSharingEnabled":false,"isAudioSharingEnabled":false,"isAnimojiEnabled":false}}`, h.seq)
	h.seq++
	h.queueSignaling(msg)
	logInfo("[%s] Accept-call sent", h.tag)
}

// resetCallState clears all per-call state. Caller must hold h.msgMu
// (this guarantees no handler is executing and the queue drain below
// cannot race with dispatch).
func (h *CallHandler) resetCallState() {
	h.mu.Lock()
	h.callAccepted.Store(false)
	h.acceptSent.Store(false)
	h.hasRemoteDesc = false
	h.pendingCandidates = nil
	h.localID = 0
	h.seq = 1
	if h.conn != nil {
		h.conn.Close()
		h.conn = nil
	}
	if h.pc != nil {
		old := h.pc
		h.pc = nil
		h.mu.Unlock()
		old.Close() // pion callbacks may need h.mu; do not hold it
		h.mu.Lock()
	}
	h.dc = nil
	h.mu.Unlock()

	// Drop messages queued by the previous connection.
	for {
		select {
		case <-h.msgCh:
		default:
			return
		}
	}
}

func (h *CallHandler) createPeerConnection(convParams map[string]interface{}) {
	logInfo("[%s] Creating PeerConnection...", h.tag)

	// Everything below is untrusted provider input: no panicking
	// type assertions.
	turn, _ := convParams["turn"].(map[string]interface{})
	stun, _ := convParams["stun"].(map[string]interface{})
	var stunURLs, turnURLs []string
	if urls, ok := stun["urls"].([]interface{}); ok && len(urls) > 0 {
		if u, ok := urls[0].(string); ok {
			stunURLs = []string{u}
		}
	}
	if urls, ok := turn["urls"].([]interface{}); ok {
		for _, u := range urls {
			if s, ok := u.(string); ok {
				turnURLs = append(turnURLs, s)
			}
		}
	}
	username, _ := turn["username"].(string)
	credential, _ := turn["credential"].(string)
	logInfo("[%s] STUN: %v  TURN: %v", h.tag, stunURLs, turnURLs)

	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs:           turnURLs,
				Username:       username,
				Credential:     credential,
				CredentialType: webrtc.ICECredentialTypePassword,
			},
		},
		ICETransportPolicy: webrtc.ICETransportPolicyRelay,
	}

	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		logError("[%s] ERROR creating PC: %v", h.tag, err)
		return
	}
	h.mu.Lock()
	if h.pc != nil {
		h.pc.Close()
	}
	h.pc = pc
	h.mu.Unlock()

	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			jsonC, _ := json.Marshal(c.ToJSON())
			logInfo("[%s] Local ICE: %s", h.tag, string(jsonC))
			h.sendICE(string(jsonC))
		} else {
			logInfo("[%s] ICE gathering complete", h.tag)
		}
	})
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		logInfo("[%s] ICE: %s", h.tag, s.String())
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		logInfo("[%s] Connection: %s", h.tag, s.String())
	})
	pc.OnSignalingStateChange(func(s webrtc.SignalingState) {
		logInfo("[%s] Signaling: %s", h.tag, s.String())
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		dcID := uint16(0)
		if dc.ID() != nil {
			dcID = *dc.ID()
		}
		logInfo("[%s] Remote DC: %s (id=%d)", h.tag, dc.Label(), dcID)
		h.mu.Lock()
		h.dc = dc
		h.mu.Unlock()
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			h.deliverInbound(msg.Data)
		})
	})

	ordered := true
	maxRetransmits := uint16(0)
	dc, err := pc.CreateDataChannel("x", &webrtc.DataChannelInit{
		Ordered: &ordered, MaxRetransmits: &maxRetransmits,
	})
	if err != nil {
		logError("[%s] ERROR creating DC: %v", h.tag, err)
		return
	}
	if dc == nil {
		logError("[%s] DC is nil", h.tag)
		return
	}
	h.mu.Lock()
	h.dc = dc
	h.mu.Unlock()
	dc.OnOpen(func() { logInfo("[%s] DC opened", h.tag) })
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		h.deliverInbound(msg.Data)
	})
}

func (h *CallHandler) sendSDP(sdp string, sdpType string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conn == nil {
		return
	}
	if !useICEInjection {
		// Real WebRTC path: the SDP must actually go over signaling.
		escaped, _ := json.Marshal(sdp)
		msg := fmt.Sprintf(`{"command":"transmit-data","sequence":%d,"participantId":%d,"data":{"sdp":{"type":"%s","sdp":%s},"animojiVersion":1},"participantType":"USER"}`,
			h.seq, h.localID, sdpType, string(escaped))
		if err := h.queueSignaling(msg); err != nil {
			logError("[%s] SDP send failed: %v", h.tag, err)
		}
	}
	// NOTE: with useICEInjection the SDP is intentionally NOT sent over
	// signaling; data flows through injected ICE candidates instead.
	h.seq++
	logInfo("[%s] Sent SDP %s (%d bytes)", h.tag, sdpType, len(sdp))
}

func (h *CallHandler) injectICE(payload []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conn == nil {
		return fmt.Errorf("signaling connection not established")
	}
	type ice struct {
		Candidate string `json:"candidate"`
	}
	structPayload := ice{Candidate: base64.StdEncoding.EncodeToString(payload)}
	escaped, _ := json.Marshal(structPayload.Candidate)
	msg := fmt.Sprintf(`{"command":"transmit-data","sequence":%d,"participantId":%d,"data":{"candidate":{"candidate":%s}},"participantType":"USER"}`,
		h.seq, h.localID, string(escaped))
	h.seq++
	return h.queueSignaling(msg)
}

func (h *CallHandler) sendICE(candidateJSON string) {
	if useICEInjection {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.conn == nil {
		return
	}
	var ice struct {
		Candidate string `json:"candidate"`
	}
	json.Unmarshal([]byte(candidateJSON), &ice)
	escaped, _ := json.Marshal(ice.Candidate)
	msg := fmt.Sprintf(`{"command":"transmit-data","sequence":%d,"participantId":%d,"data":{"candidate":{"candidate":%s}},"participantType":"USER"}`,
		h.seq, h.localID, string(escaped))
	h.seq++
	h.queueSignaling(msg)
}

func (h *CallHandler) addICECandidate(c map[string]interface{}) {
	h.mu.Lock()
	pc := h.pc
	h.mu.Unlock()
	if pc == nil {
		return
	}
	candidateStr, _ := c["candidate"].(string)
	sdpMid, _ := c["sdpMid"].(string)
	sdpMLineIndex := uint16(0)
	if idx, ok := c["sdpMLineIndex"].(float64); ok {
		sdpMLineIndex = uint16(idx)
	}
	if err := pc.AddICECandidate(webrtc.ICECandidateInit{
		Candidate: candidateStr, SDPMid: &sdpMid, SDPMLineIndex: &sdpMLineIndex,
	}); err != nil {
		logError("[%s] ICE error: %v", h.tag, err)
	}
}

func (h *CallHandler) bufferOrAddICE(c map[string]interface{}) {
	if !h.hasRemoteDesc {
		h.pendingCandidates = append(h.pendingCandidates, c)
		logInfo("[%s] Buffered ICE (%d total)", h.tag, len(h.pendingCandidates))
	} else {
		h.addICECandidate(c)
	}
}

func (h *CallHandler) flushPendingCandidates() {
	if len(h.pendingCandidates) == 0 {
		return
	}
	logInfo("[%s] Flushing %d buffered ICE", h.tag, len(h.pendingCandidates))
	for _, c := range h.pendingCandidates {
		h.addICECandidate(c)
	}
	h.pendingCandidates = nil
}

func (h *CallHandler) handleSDP(sdpType string, sdpStr string) {
	h.mu.Lock()
	pc := h.pc
	h.mu.Unlock()
	if pc == nil {
		return
	}
	logInfo("[%s] handleSDP: %s (%d bytes)", h.tag, sdpType, len(sdpStr))

	switch sdpType {
	case "offer":
		logInfo("[%s] Setting remote offer...", h.tag)
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{
			Type: webrtc.SDPTypeOffer, SDP: sdpStr,
		}); err != nil {
			logError("[%s] ERROR: %v", h.tag, err)
			return
		}
		time.Sleep(300 * time.Millisecond)
		h.hasRemoteDesc = true
		h.flushPendingCandidates()

		logInfo("[%s] Creating answer...", h.tag)
		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			logError("[%s] ERROR: %v", h.tag, err)
			return
		}
		//pc.SetLocalDescription(answer)
		h.sendSDP(answer.SDP, "answer")

	case "answer":
		logInfo("[%s] Setting remote answer...", h.tag)
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{
			Type: webrtc.SDPTypeAnswer, SDP: sdpStr,
		}); err != nil {
			logError("[%s] ERROR: %v", h.tag, err)
			return
		}
		h.hasRemoteDesc = true
		h.flushPendingCandidates()
	}
}

// detectLocalID extracts our participant id from a conversation object.
// All input is provider-controlled: no panicking type assertions.
func (h *CallHandler) detectLocalID(data map[string]interface{}, wantCreator bool) {
	h.mu.Lock()
	already := h.localID != 0
	h.mu.Unlock()
	if already {
		return
	}
	conv, ok := data["conversation"].(map[string]interface{})
	if !ok {
		return
	}
	parts, ok := conv["participants"].([]interface{})
	if !ok {
		return
	}
	for _, p := range parts {
		part, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		roles, _ := part["roles"].([]interface{})
		isCreator := false
		for _, r := range roles {
			if rs, ok := r.(string); ok && rs == "CREATOR" {
				isCreator = true
			}
		}
		if isCreator == wantCreator {
			if id, ok := part["id"].(float64); ok {
				h.mu.Lock()
				if h.localID == 0 {
					h.localID = int64(id)
				}
				localID := h.localID
				h.mu.Unlock()
				logInfo("[%s] Local ID: %d", h.tag, localID)
				return
			}
		}
	}
}

// handleCandidate processes a data.candidate signaling message: in ICE
// injection mode it carries a base64 payload, otherwise it is a real
// ICE candidate for the peer connection.
func (h *CallHandler) handleCandidate(c map[string]interface{}) {
	if useICEInjection {
		candidateStr, _ := c["candidate"].(string)
		decoded, err := base64.StdEncoding.DecodeString(candidateStr)
		if err != nil {
			logError("[%s] bad injected candidate: %v", h.tag, err)
			return
		}
		h.deliverInbound(decoded)
		return
	}
	h.bufferOrAddICE(c)
}

func startOutgoingCall(client *MaxClient, calleeID int64) *CallHandler {
	h := &CallHandler{tag: "CALLER", role: "caller"}
	h.seq = 1
	h.reconnectCh = make(chan struct{}, 1)
	h.msgCh = make(chan string, 1024)
	h.outQueue = make(chan []byte, 1024)
	go h.dispatchLoop()
	go h.signalingWriter()
	h.msgHandler = func(text string) {
		var data map[string]interface{}
		json.Unmarshal([]byte(text), &data)

		// Our participant id is the one WITHOUT the CREATOR role.
		h.detectLocalID(data, false)

		if cp, ok := data["conversationParams"].(map[string]interface{}); ok {
			logInfo("[%s] conversationParams - creating offer", h.tag)
			for !h.callAccepted.Load() && !useICEInjection {
				time.Sleep(200 * time.Millisecond)
			}
			h.createPeerConnection(cp)
			time.Sleep(200 * time.Millisecond)
			h.mu.Lock()
			pc := h.pc
			h.mu.Unlock()
			if pc == nil {
				logError("[%s] no peer connection, skipping offer", h.tag)
				return
			}
			offer, err := pc.CreateOffer(nil)
			if err != nil {
				logError("[%s] ERROR: %v", h.tag, err)
				return
			}
			//pc.SetLocalDescription(offer)
			h.sendSDP(offer.SDP, "offer")
			return
		}
		d, _ := data["data"].(map[string]interface{})
		if d == nil {
			return
		}
		if sdp, ok := d["sdp"].(map[string]interface{}); ok {
			sdpType, _ := sdp["type"].(string)
			sdpStr, _ := sdp["sdp"].(string)
			if sdpType == "answer" {
				if useICEInjection {
					return
				}
				h.handleSDP(sdpType, sdpStr)
			}
			return
		}
		if c, ok := d["candidate"].(map[string]interface{}); ok {
			h.handleCandidate(c)
		}
	}

	logInfo("[CALLER] Calling %d", calleeID)

	// Connect with auto-reconnect loop
	go func() {
		for {
			h.msgMu.Lock()
			h.resetCallState()
			h.msgMu.Unlock()

			resp, err := client.invoke(78, map[string]interface{}{
				"conversationId": genUUID(),
				"calleeIds":      []int64{calleeID},
				"internalParams": fmt.Sprintf(`{"deviceId":"%s","sdkVersion":"2.8.9","clientAppKey":"CNHIJPLGDIHBABABA","platform":"WEB","protocolVersion":5,"domainId":"","capabilities":"2A03F"}`, client.deviceID),
				"isVideo":        false,
			})
			if err != nil {
				logError("[CALLER] invoke error: %v, retrying...", err)
				time.Sleep(1 * time.Second)
				continue
			}
			var payload map[string]interface{}
			json.Unmarshal(resp.Payload, &payload)
			paramsStr, _ := payload["internalCallerParams"].(string)
			var params InternalCallerParams
			json.Unmarshal([]byte(paramsStr), &params)
			if params.Endpoint == "" {
				logError("[CALLER] empty call endpoint, retrying...")
				time.Sleep(1 * time.Second)
				continue
			}

			endpoint := params.Endpoint + "&platform=WEB&appVersion=1.1&version=5&device=browser&capabilities=2A03F&clientType=ONE_ME&tgt=start"
			conn, _, err := websocket.DefaultDialer.Dial(endpoint, nil)
			if err != nil {
				// Dial errors may embed the URL with credentials.
				logError("[CALLER] Dial error: %v, retrying...", redactEndpointToken(err.Error()))
				time.Sleep(1 * time.Second)
				continue
			}
			h.mu.Lock()
			h.conn = conn
			h.mu.Unlock()
			h.setConnected(true)
			go h.readLoop(conn)

			// Wait for disconnect signal
			<-h.reconnectCh
			h.setConnected(false)
			logInfo("[CALLER] Reconnecting in 1s...")
			time.Sleep(1 * time.Second)
		}
	}()

	return h
}

func startIncomingListener(client *MaxClient) *CallHandler {
	h := &CallHandler{tag: "RECEIVER", role: "receiver"}
	h.seq = 1
	h.msgCh = make(chan string, 1024)
	h.outQueue = make(chan []byte, 1024)
	go h.dispatchLoop()
	go h.signalingWriter()
	h.msgHandler = func(text string) {
		var data map[string]interface{}
		json.Unmarshal([]byte(text), &data)

		// Our participant id is the one WITH the CREATOR role.
		h.detectLocalID(data, true)

		if cp, ok := data["conversationParams"].(map[string]interface{}); ok {
			h.createPeerConnection(cp)
			return
		}
		d, _ := data["data"].(map[string]interface{})
		if d == nil {
			return
		}
		if sdp, ok := d["sdp"].(map[string]interface{}); ok {
			sdpType, _ := sdp["type"].(string)
			sdpStr, _ := sdp["sdp"].(string)
			h.handleSDP(sdpType, sdpStr)
			return
		}
		if c, ok := d["candidate"].(map[string]interface{}); ok {
			h.handleCandidate(c)
		}
	}

	client.SetEventCallback(func(p MaxPacket) {
		if p.Opcode == 137 {
			logInfo("[RECEIVER] Incoming call!")
			var payload map[string]interface{}
			json.Unmarshal(p.Payload, &payload)
			convID, _ := payload["conversationId"].(string)
			vcp, _ := payload["vcp"].(string)
			callDetails, err := decodeCallDetails(vcp)
			if err != nil {
				logError("[RECEIVER] Decode error: %v", err)
				return
			}

			endpoint := craftEndpoint(convID, callDetails)
			logInfo("[RECEIVER] Initial endpoint: %s", redactEndpointToken(endpoint))

			conn, _, err := websocket.DefaultDialer.Dial(endpoint, nil)
			if err != nil {
				logError("[RECEIVER] Connect error: %v", redactEndpointToken(err.Error()))
				return
			}

			// New call: reset all per-call state and drop the previous
			// signaling connection (its read loop will exit on its own).
			h.msgMu.Lock()
			h.resetCallState()
			h.msgMu.Unlock()

			h.mu.Lock()
			if h.conn != nil {
				h.conn.Close()
			}
			h.conn = conn
			h.mu.Unlock()
			h.setConnected(true)
			go h.readLoop(conn)
			go func() {
				time.Sleep(1 * time.Second)
				h.sendAcceptCall()
			}()
		}
	})
	logInfo("[RECEIVER] Waiting for calls...")
	return h
}
