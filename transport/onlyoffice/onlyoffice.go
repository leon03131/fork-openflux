// Package onlyoffice implements a carrier over the OnlyOffice co-editing
// websocket that serves public Yandex Disk documents (the "new editor").
// The legacy Yandex editor (transport/yandex) no longer serves public
// links; this carrier speaks the OnlyOffice Docs socket.io protocol
// instead.
//
// Data frames ride as OnlyOffice "cursor" messages:
//
//	42["message",{"type":"cursor","cursor":"18;OFX1<channelID>:<base64 payload>"}]
//
// The OFX1<channelID>: marker identifies frames belonging to this tunnel
// pair; channelID is derived deterministically from the document URL
// (first 8 hex chars of sha256), so both tunnel ends compute it without
// negotiation. Cursors without our exact marker (real editors' cursor
// positions, foreign sessions, stale garbage in the document) are
// silently dropped before base64 decoding ever happens.
//
// The server relays them to every other participant as
// {"type":"cursor","messages":[{"cursor":"18;OFX1<channelID>:<base64>","useridoriginal":...}]}.
// The sender never receives its own cursor back (excluded server-side);
// as defense in depth we additionally drop messages whose useridoriginal
// matches the id the server assigned to us.
//
// Protocol quirks discovered by live probing (DocsCoServer.js semantics):
//   - When the SECOND editor joins a document, the server locks it and
//     answers the joiner with {"type":"waitAuth"} instead of auth. The
//     first participant is notified via {"type":"connectState",...,
//     "waitAuth":true} and must send {"type":"unLockDocument",
//     "unlock":true,...}; otherwise the lock expires after 30s and the
//     lock holder is DROPPED with disconnectReason 4007. We therefore
//     answer every waitAuth connectState with unLockDocument.
//   - The server listens only on the socket.io "message" event; the
//     cursor type lives inside the payload. Sending 42["cursor",...]
//     is silently ignored.
//   - Idle sessions are closed after expire.sessionidle (default 1h);
//     only a periodic {"type":"extendSession","idletime":0} refreshes
//     sessionTimeLastAction, so we send it on the keep-alive ticker.
package onlyoffice

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/utils"
)

// docInfo is everything a websocket session needs, extracted from the
// document page's client-config.
type docInfo struct {
	CookieStr   string
	Token       string
	DocKey      string
	Origin      string
	Host        string
	WsURL       string
	Permissions map[string]interface{}
	OpenCmd     map[string]interface{}
}

type ooSession struct {
	Info       docInfo
	Conn       *websocket.Conn
	WriteQueue chan []byte
	writeMu    sync.Mutex

	// myIDOriginal is the idOriginal the server assigned to us (from the
	// auth result); cursor messages carrying it in useridoriginal are our
	// own and must be dropped. Set once before the read loop starts.
	myIDOriginal string

	// ready becomes true after auth result=1. Cursor payloads received
	// before that belong to no live v2 session and are dropped instead
	// of being fed to a half-initialised AEAD handshake.
	ready bool
}

func (s *ooSession) safeWrite(messageType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	// A wedged connection must not block writers forever.
	s.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	err := s.Conn.WriteMessage(messageType, data)
	s.Conn.SetWriteDeadline(time.Time{})
	return err
}

type OnlyOfficeTransport struct {
	*transport.BaseTransport

	url     string
	session *ooSession

	// ctx/cancel drive the whole transport lifecycle: cancel (called by
	// Stop) aborts an in-flight websocket dial, pending reconnect timers
	// and all background loops.
	ctx    context.Context
	cancel context.CancelFunc

	// framePrefix is the OFX1 protocol marker ("OFX1<channelID>:") that
	// identifies our frames inside the cursor channel. Derived
	// deterministically from the document URL, so both tunnel ends share
	// it without negotiation. Immutable after construction.
	framePrefix string

	userCounter atomic.Int32
	baseUserID  string

	connectInFlight atomic.Int32
}

// MaxPayload is the raw message budget for the OnlyOffice carrier.
// Payloads are base64-wrapped into JSON cursor messages, so the wire size
// is ~1.37x (~90 KiB for 64 KiB); the server's socket.io maxHttpBufferSize
// is 100 MB, leaving an enormous margin.
func (t *OnlyOfficeTransport) MaxPayload() int { return 64 * 1024 }

func NewOnlyOfficeTransport(url string, config transport.TransportConfig) *OnlyOfficeTransport {
	ctx, cancel := context.WithCancel(context.Background())
	t := &OnlyOfficeTransport{
		BaseTransport: transport.NewBaseTransport(config),
		url:           url,
		ctx:           ctx,
		cancel:        cancel,
		framePrefix:   framePrefixFor(url),
	}
	t.baseUserID = randUserID()
	return t
}

func (t *OnlyOfficeTransport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	t.baseUserID = randUserID()
	go t.keepAliveLoop()
	go t.writerLoop()
	t.connectToDoc(0)

	return nil
}

// Stop shuts the transport down: it cancels the transport context
// (aborting any in-flight dial, pending reconnect timer and the
// background loops) and closes the active websocket so the read loop can
// actually exit (it would otherwise block in ReadMessage). Idempotent.
func (t *OnlyOfficeTransport) Stop() error {
	if err := t.BaseTransport.Stop(); err != nil {
		return err
	}
	t.cancel()
	t.Mu.RLock()
	session := t.session
	t.Mu.RUnlock()
	if session != nil && session.Conn != nil {
		session.Conn.Close()
	}
	return nil
}

func (t *OnlyOfficeTransport) Send(data []byte) error {
	if !t.IsConnected() {
		return fmt.Errorf("transport not connected")
	}

	t.Mu.RLock()
	session := t.session
	t.Mu.RUnlock()

	if session == nil {
		return fmt.Errorf("no active session")
	}

	select {
	case session.WriteQueue <- data:
		return nil
	default:
		return fmt.Errorf("write queue full")
	}
}

func (t *OnlyOfficeTransport) connectToDoc(attempt int) {
	if !t.IsRunning() {
		return
	}
	// Only one connect sequence at a time; if another is in flight,
	// it owns the retry chain. The flag is held for the WHOLE
	// goroutine lifecycle (dial + auth + read loop), not just this call.
	if !t.connectInFlight.CompareAndSwap(0, 1) {
		return
	}

	utils.Debugf("[ONLYOFFICE] connectToDoc attempt %d", attempt)

	go func() {
		defer t.connectInFlight.Store(0)
		t.Mu.Lock()
		existingSession := t.session
		t.Mu.Unlock()

		suffix := fmt.Sprintf("%03d", t.userCounter.Add(1)%1000)
		userID := "yandexuid:" + t.baseUserID + suffix

		info, err := t.fetchDocInfo(t.url, userID)
		if err != nil {
			if t.ctx.Err() != nil {
				return // Stop() fired mid-fetch
			}
			utils.Debugf("[ONLYOFFICE] fetchDocInfo failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}

		dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
		headers := http.Header{}
		headers.Set("User-Agent", "Mozilla/5.0")
		headers.Set("Origin", info.Origin)
		headers.Set("Cookie", info.CookieStr)
		headers.Set("Host", info.Host)

		conn, _, err := dialer.DialContext(t.ctx, info.WsURL, headers)
		if err != nil {
			if t.ctx.Err() != nil {
				return // Stop() fired mid-dial
			}
			utils.Debugf("[ONLYOFFICE] WebSocket dial failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}
		// Bound inbound frames (defense in depth; cursors are tiny).
		conn.SetReadLimit(maxWireMessageSize)

		// Fresh queue per connection: stale frames from a dead
		// connection are poison for a new v2 session (old keys, old
		// sequence numbers), and in legacy mode gVisor's TCP
		// retransmission recovers losses anyway.
		writeQueue := make(chan []byte, t.GetConfig().MaxQueueSize)

		session := &ooSession{
			Info:       info,
			Conn:       conn,
			WriteQueue: writeQueue,
		}

		// Re-check under the same critical section that installs the
		// session: Stop() may have fired during the blocking dial.
		t.Mu.Lock()
		if !t.IsRunning() {
			t.Mu.Unlock()
			conn.Close()
			return
		}
		t.session = session
		t.Mu.Unlock()

		// EIO4 + socket.io + OnlyOffice auth handshake. Connected is
		// reported ONLY after auth result=1: Ready must mean the
		// provider can actually carry application payload.
		if err := t.handshake(session); err != nil {
			utils.Debugf("[ONLYOFFICE] handshake failed: %v", err)
			t.Mu.Lock()
			if t.session == session {
				t.session = nil
			}
			t.Mu.Unlock()
			conn.Close()
			t.scheduleReconnect(attempt)
			return
		}

		t.SetConnected(true)

		// Close the superseded connection AFTER the new session is
		// installed: its read loop will error out, see it is no longer
		// the active session and exit without scheduling a reconnect.
		if existingSession != nil && existingSession.Conn != nil {
			existingSession.Conn.Close()
		}

		establishedAt := time.Now()

		conn.SetReadDeadline(time.Now().Add(readDeadline))
		for t.IsRunning() {
			_, message, err := conn.ReadMessage()
			if err != nil {
				utils.Debugf("[ONLYOFFICE] Read error: %v", err)
				// Only the active session's failure drives reconnects;
				// the staleness check and the state change must be
				// atomic (a new session may install concurrently).
				t.Mu.Lock()
				current := t.session == session
				if current {
					t.SetConnected(false)
					session.Conn.Close()
				}
				t.Mu.Unlock()
				if !current {
					return
				}
				// A session that lived long enough was healthy:
				// restart the backoff sequence.
				if time.Since(establishedAt) > 30*time.Second {
					attempt = 0
				}
				t.scheduleReconnect(attempt)
				return
			}
			// Any inbound message proves the connection is alive.
			conn.SetReadDeadline(time.Now().Add(readDeadline))
			t.handleMessage(session, string(message))
		}
	}()
}

// handshake performs EIO4 open -> socket.io namespace connect ->
// OnlyOffice auth, waiting for auth result=1. During the wait it keeps
// the connection alive (pongs) and honours the co-editing document lock
// (unLockDocument) so a peer waiting on us is not stuck.
func (t *OnlyOfficeTransport) handshake(s *ooSession) error {
	readWithDeadline := func(d time.Duration) (string, error) {
		s.Conn.SetReadDeadline(time.Now().Add(d))
		_, msg, err := s.Conn.ReadMessage()
		if err != nil {
			return "", err
		}
		return string(msg), nil
	}

	// 1. EIO4 open packet: 0{"sid":...,"pingInterval":25000,...}
	open, err := readWithDeadline(15 * time.Second)
	if err != nil {
		return fmt.Errorf("EIO4 open: %w", err)
	}
	if !strings.HasPrefix(open, "0{") {
		return fmt.Errorf("EIO4 open: unexpected packet %q", truncForLog(open))
	}

	// 2. Namespace connect with the JWT, expect ack 40{"sid":"..."}.
	tokenJSON, _ := json.Marshal(s.Info.Token)
	if err := s.safeWrite(websocket.TextMessage, []byte(`40{"token":`+string(tokenJSON)+`}`)); err != nil {
		return fmt.Errorf("namespace connect write: %w", err)
	}
	for {
		msg, err := readWithDeadline(15 * time.Second)
		if err != nil {
			return fmt.Errorf("namespace ack: %w", err)
		}
		if msg == "2" {
			s.safeWrite(websocket.TextMessage, []byte("3"))
			continue
		}
		if strings.HasPrefix(msg, "40") {
			break
		}
		if strings.HasPrefix(msg, "4") { // 41 = socket.io close, 44 = connect error
			return fmt.Errorf("namespace connect rejected: %q", truncForLog(msg))
		}
	}

	// 3. OnlyOffice auth.
	authData := map[string]interface{}{
		"type": "auth", "docid": s.Info.DocKey, "token": s.Info.Token,
		"user": map[string]interface{}{
			"id": authUserID(s.Info), "name": "Anonymous", "firstname": "Anonymous", "lastname": "",
		},
		"editorType": 0, "lastOtherSaveTime": -1,
		"permissions": s.Info.Permissions,
		"openCmd":     s.Info.OpenCmd,
		// Fast co-editing: both participants may edit simultaneously.
		"coEditingMode": "fast", "jwtOpen": s.Info.Token,
		"bothEditing": true, "isAnonymous": true,
	}
	part, _ := json.Marshal([]interface{}{"message", authData})
	if err := s.safeWrite(websocket.TextMessage, []byte("42"+string(part))); err != nil {
		return fmt.Errorf("auth write: %w", err)
	}

	// 4. Wait for auth result=1. A waitAuth means the document is locked
	// by the first participant: either it unlocks (we answer connectState
	// in kind when we are the holder) or the 30s server-side lock timer
	// unlocks us. Budget the wait accordingly.
	deadline := time.Now().Add(authWaitTimeout)
	for time.Now().Before(deadline) {
		msg, err := readWithDeadline(time.Until(deadline))
		if err != nil {
			return fmt.Errorf("auth wait: %w", err)
		}
		t.handleMessage(s, msg) // pongs, unLockDocument, stray cursors

		ev, body, ok := parseEvent(msg)
		if !ok || ev != "message" {
			continue
		}
		var auth authResult
		if err := json.Unmarshal(body, &auth); err != nil || auth.Type != "auth" {
			continue
		}
		if auth.Result != 1 {
			return fmt.Errorf("auth rejected: result=%d", auth.Result)
		}
		// Learn the idOriginal the server assigned to us so we can
		// drop our own cursor messages if they ever come back.
		for _, p := range auth.Participants {
			if p.ConnectionID == auth.SessionID {
				s.myIDOriginal = p.IDOriginal
				break
			}
		}
		s.ready = true
		return nil
	}
	return fmt.Errorf("auth wait timeout")
}

func (t *OnlyOfficeTransport) writerLoop() {
	for {
		t.Mu.RLock()
		session := t.session
		t.Mu.RUnlock()

		if session == nil || session.Conn == nil {
			select {
			case <-time.After(50 * time.Millisecond):
			case <-t.ctx.Done():
				return
			}
			continue
		}

		select {
		case packet := <-session.WriteQueue:
			msg := `42["message",{"type":"cursor","cursor":"` + encodeCursor(t.framePrefix, packet) + `"}]`

			err := session.safeWrite(websocket.TextMessage, []byte(msg))
			if err != nil {
				utils.Debugf("[ONLYOFFICE] Write error: %v", err)
				// A failed write means the connection is broken:
				// close it so the read loop wakes and reconnects.
				t.Mu.Lock()
				if t.session == session {
					t.SetConnected(false)
					session.Conn.Close()
				}
				t.Mu.Unlock()
			} else {
				// Count only bytes actually written to the socket, not
				// merely queued.
				t.RecordSend(len(packet))
			}
		case <-time.After(250 * time.Millisecond):
			// Periodic wake-up to re-check the session.
		case <-t.ctx.Done():
			return
		}
	}
}

// keepAliveLoop refreshes the OnlyOffice session idle timer; without
// extendSession the server drops the connection after expire.sessionidle
// (default 1h) regardless of cursor traffic. The socket.io ping/pong
// ("2"/"3") is handled by the read loop.
func (t *OnlyOfficeTransport) keepAliveLoop() {
	ticker := time.NewTicker(t.GetConfig().KeepAliveInterval)
	defer ticker.Stop()
	extendMsg := `42["message",{"type":"extendSession","idletime":0}]`

	for {
		select {
		case <-ticker.C:
		case <-t.ctx.Done():
			return
		}

		t.Mu.RLock()
		session := t.session
		t.Mu.RUnlock()

		if session == nil || session.Conn == nil || !t.IsConnected() {
			continue
		}
		if err := session.safeWrite(websocket.TextMessage, []byte(extendMsg)); err != nil {
			utils.Debugf("[ONLYOFFICE] extendSession failed: %v", err)
			// Only the CURRENT session may trigger teardown; the
			// staleness check and the state change must be atomic
			// (a new session may install concurrently).
			t.Mu.Lock()
			if t.session == session {
				t.SetConnected(false)
				// Kill the connection so the read loop wakes up and
				// schedules a reconnect; otherwise the transport
				// would stay disconnected forever on a half-open
				// socket.
				session.Conn.Close()
			}
			t.Mu.Unlock()
		}
	}
}

// unLockDocumentMsg releases the co-editing document lock the server
// places on the first participant when a second editor joins. Fields
// mirror DocsCoServer.checkEndAuthLock: unlock the auth lock, nothing to
// save (isSave=false), no object locks held (releaseLocks=false), no
// history rewrite (deleteIndex=-1).
const unLockDocumentMsg = `42["message",{"type":"unLockDocument","unlock":true,"isSave":false,"releaseLocks":false,"deleteIndex":-1}]`

func (t *OnlyOfficeTransport) handleMessage(session *ooSession, text string) {
	// Socket.IO ping/pong.
	if text == "2" {
		if session != nil && session.Conn != nil {
			session.safeWrite(websocket.TextMessage, []byte("3"))
		}
		return
	}
	if len(text) < 2 || text[0] != '4' {
		return
	}

	ev, body, ok := parseEvent(text)
	if !ok || ev != "message" {
		return
	}

	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &head); err != nil {
		return
	}

	switch head.Type {
	case "connectState":
		// A second editor joined and the server locked the document.
		// If we are the lock holder we must release it, otherwise the
		// peer waits 30s and we get dropped (disconnectReason 4007).
		// Sending this when we are NOT the holder is a server-side no-op.
		var cs struct {
			WaitAuth bool `json:"waitAuth"`
		}
		if err := json.Unmarshal(body, &cs); err == nil && cs.WaitAuth {
			utils.Debugf("[ONLYOFFICE] peer waiting on document lock, releasing")
			session.safeWrite(websocket.TextMessage, []byte(unLockDocumentMsg))
		}
	case "cursor":
		if !session.ready {
			return
		}
		var cur cursorMessage
		if err := json.Unmarshal(body, &cur); err != nil {
			return
		}
		for _, m := range cur.Messages {
			// Drop our own messages if the server ever sends them back
			// (normally the sender is excluded from cursor publish).
			if session.myIDOriginal != "" && m.UserIDOriginal == session.myIDOriginal {
				continue
			}
			payload, ok := decodeCursor(m.Cursor, t.framePrefix)
			if !ok {
				continue
			}
			t.RecordReceive(len(payload))
			t.CallReceive(payload)
		}
	case "disconnectReason":
		// Server-initiated drop (lock timeout, idle, duplicate). The
		// socket close follows immediately; the read loop reconnects.
		utils.Debugf("[ONLYOFFICE] disconnectReason: %s", truncForLog(text))
	}
}

// framePrefixFor derives the OFX1 protocol marker for a document URL.
// The channel id is deterministic (first 8 hex chars of sha256(url)), so
// the client and the exit — configured with the same document URL —
// compute the same marker without any negotiation.
func framePrefixFor(docURL string) string {
	sum := sha256.Sum256([]byte(docURL))
	return "OFX1" + hex.EncodeToString(sum[:])[:8] + ":"
}

// encodeCursor wraps a payload into the wire cursor form
// "18;OFX1<channelID>:<base64>". The "18;" cursor-index prefix keeps the
// frame looking like an ordinary editor cursor to the relay server.
func encodeCursor(framePrefix string, payload []byte) string {
	return "18;" + framePrefix + base64.StdEncoding.EncodeToString(payload)
}

// decodeCursor extracts the payload from a cursor string of the form
// "<index>;OFX1<channelID>:<base64>". Anything without our exact OFX1
// marker — real editors' cursor positions, foreign or stale sessions,
// random garbage — is silently dropped BEFORE base64 decoding, so it can
// never reach the session layer as a decrypt failure.
func decodeCursor(cursor, framePrefix string) ([]byte, bool) {
	i := strings.IndexByte(cursor, ';')
	if i < 0 || i+1 >= len(cursor) {
		return nil, false
	}
	rest := cursor[i+1:]
	if !strings.HasPrefix(rest, framePrefix) {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(rest[len(framePrefix):])
	if err != nil || len(decoded) == 0 {
		return nil, false
	}
	return decoded, true
}

// parseEvent decodes a socket.io event frame "42[<event>,<json>]"
// (EIO4 packet '4', socket.io type '2' = EVENT). It returns the event
// name and the raw JSON of its first payload object.
func parseEvent(text string) (string, json.RawMessage, bool) {
	if len(text) < 2 || text[:2] != "42" {
		return "", nil, false
	}
	var parts []json.RawMessage
	if err := json.Unmarshal([]byte(text[2:]), &parts); err != nil || len(parts) != 2 {
		return "", nil, false
	}
	var ev string
	if err := json.Unmarshal(parts[0], &ev); err != nil {
		return "", nil, false
	}
	return ev, parts[1], true
}

// maxReconnectDelay caps the exponential reconnect backoff.
const maxReconnectDelay = 30 * time.Second

// readDeadline is the steady-state read deadline, extended by every
// inbound message (the server's 25s ping keeps it alive by itself).
const readDeadline = 75 * time.Second

// authWaitTimeout covers the worst case where the document lock holder
// is a dead connection: the server unlocks us only after expire.lockDoc
// (30s) fires.
const authWaitTimeout = 45 * time.Second

// maxWireMessageSize bounds a single websocket message we are willing to
// buffer. Cursor batches carrying 64 KiB payloads stay far below this.
const maxWireMessageSize = 4 << 20 // 4 MiB

func (t *OnlyOfficeTransport) scheduleReconnect(attempt int) {
	if !t.IsRunning() || attempt >= t.GetConfig().MaxReconnectAttempts {
		return
	}

	t.RecordReconnect()

	cfg := t.GetConfig()
	delay := cfg.ReconnectDelay
	for i := 0; i < attempt; i++ {
		delay = time.Duration(float64(delay) * cfg.ReconnectMultiplier)
		if delay >= maxReconnectDelay {
			delay = maxReconnectDelay
			break
		}
	}
	// Add jitter (50%-150% of the delay) to avoid reconnect storms.
	delay = delay/2 + time.Duration(rand.Int63n(int64(delay/2)+1))

	utils.Debugf("[ONLYOFFICE] Reconnect #%d in %v", attempt+1, delay)
	// The timer is tied to the transport context: Stop() cancels it
	// immediately instead of letting a stale reconnect fire.
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			t.connectToDoc(attempt + 1)
		case <-t.ctx.Done():
		}
	}()
}

// clientConfigDoc is the typed subset of the Yandex Disk "client-config"
// JSON that this transport depends on. Any provider schema change results
// in a validation error instead of a panic.
type clientConfigDoc struct {
	OfficeType       string `json:"officeType"` // root level
	OfficeActionData struct {
		BalancerURL  string `json:"balancer_url"`
		EditorType   string `json:"office_online_editor_type"`
		EditorConfig *struct {
			Token    string `json:"token"`
			Document struct {
				Key         string                 `json:"key"`
				URL         string                 `json:"url"`
				Title       string                 `json:"title"`
				FileType    string                 `json:"fileType"`
				Permissions map[string]interface{} `json:"permissions"`
			} `json:"document"`
		} `json:"editor_config"`
	} `json:"officeActionData"`
}

// authResult is the server-side {"type":"auth","result":1,...} message.
type authResult struct {
	Type         string `json:"type"`
	Result       int    `json:"result"`
	SessionID    string `json:"sessionId"`
	Participants []struct {
		IDOriginal   string `json:"idOriginal"`
		ConnectionID string `json:"connectionId"`
	} `json:"participants"`
}

// cursorMessage is the relayed {"type":"cursor","messages":[...]} message.
type cursorMessage struct {
	Messages []struct {
		Cursor         string `json:"cursor"`
		UserIDOriginal string `json:"useridoriginal"`
	} `json:"messages"`
}

// maxConfigPageSize bounds the HTML page we parse (defense in depth).
const maxConfigPageSize = 8 << 20 // 8 MiB

// (?s): the embedded JSON may span newlines.
var clientConfigRe = regexp.MustCompile(`(?s)<script[^>]*id="client-config"[^>]*>(.*?)</script>`)

func (t *OnlyOfficeTransport) fetchDocInfo(url, userID string) (docInfo, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return nil },
		Timeout:       30 * time.Second,
	}

	req, err := http.NewRequestWithContext(t.ctx, "GET", url, nil)
	if err != nil {
		return docInfo{}, fmt.Errorf("bad document URL: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return docInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return docInfo{}, fmt.Errorf("document page returned HTTP %d", resp.StatusCode)
	}

	htmlBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxConfigPageSize))
	if err != nil {
		return docInfo{}, fmt.Errorf("read document page: %w", err)
	}
	html := string(htmlBytes)

	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}

	matches := clientConfigRe.FindStringSubmatch(html)
	if len(matches) < 2 {
		return docInfo{}, fmt.Errorf("client-config script not found (provider schema changed?)")
	}

	var config clientConfigDoc
	if err := json.Unmarshal([]byte(matches[1]), &config); err != nil {
		return docInfo{}, fmt.Errorf("client-config JSON: %w", err)
	}

	// This transport speaks the OnlyOffice editor protocol only.
	if config.OfficeType != "only_office" && config.OfficeActionData.EditorType != "only_office" {
		return docInfo{}, fmt.Errorf("not an OnlyOffice document (officeType=%q office_online_editor_type=%q)", config.OfficeType, config.OfficeActionData.EditorType)
	}

	ec := config.OfficeActionData.EditorConfig
	if ec == nil {
		return docInfo{}, fmt.Errorf("editor_config missing (not an office document?)")
	}
	if ec.Token == "" || ec.Document.Key == "" || config.OfficeActionData.BalancerURL == "" {
		return docInfo{}, fmt.Errorf("client-config missing required fields (provider schema changed?)")
	}

	balancerURL := config.OfficeActionData.BalancerURL
	host := strings.TrimPrefix(balancerURL, "https://")
	document := ec.Document

	perms := document.Permissions
	if perms == nil {
		perms = make(map[string]interface{})
	}

	return docInfo{
		CookieStr:   strings.Join(cookies, "; "),
		Token:       ec.Token,
		DocKey:      document.Key,
		Origin:      balancerURL,
		Host:        host,
		WsURL:       fmt.Sprintf("wss://%s/doc/%s/c/?EIO=4&transport=websocket", host, document.Key),
		Permissions: perms,
		OpenCmd: map[string]interface{}{
			"c":      "open",
			"id":     document.Key,
			"userid": userID,
			"format": document.FileType,
			"url":    document.URL,
			"title":  document.Title,
			"lcid":   25,
		},
	}, nil
}

// authUserID returns the user id used in the auth message (the same id
// that was embedded into openCmd.userid by fetchDocInfo).
func authUserID(info docInfo) string {
	if id, ok := info.OpenCmd["userid"].(string); ok {
		return id
	}
	return ""
}

func randUserID() string {
	return fmt.Sprintf("%010d", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(1000000000))
}

// truncForLog keeps provider messages in debug logs short; payloads are
// base64 (no PII), tokens are never logged.
func truncForLog(s string) string {
	const max = 200
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// Bounce drops the current websocket; the reconnect chain rebuilds it.
// Implements transport.Bouncer.
func (t *OnlyOfficeTransport) Bounce() {
	t.Mu.RLock()
	s := t.session
	t.Mu.RUnlock()
	if s != nil && s.Conn != nil {
		s.Conn.Close()
	}
}

// CheckDoc verifies that the document URL is reachable, has a compatible
// client-config and is served by the OnlyOffice editor (used by
// `openflux doctor`).
func CheckDoc(url string) error {
	t := NewOnlyOfficeTransport(url, transport.DefaultConfig())
	_, err := t.fetchDocInfo(url, "yandexuid:doctor000")
	return err
}

// CheckLive goes further than CheckDoc: it dials the provider websocket
// and performs the full EIO4 + auth handshake, proving the server accepts
// us. If the document is currently locked by another live editor we wait
// in waitAuth until it unlocks (same as the real transport).
func CheckLive(url string) error {
	t := NewOnlyOfficeTransport(url, transport.DefaultConfig())
	info, err := t.fetchDocInfo(url, "yandexuid:doctor000")
	if err != nil {
		return err
	}

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0")
	headers.Set("Origin", info.Origin)
	headers.Set("Cookie", info.CookieStr)
	headers.Set("Host", info.Host)

	conn, _, err := dialer.DialContext(t.ctx, info.WsURL, headers)
	if err != nil {
		return fmt.Errorf("websocket dial: %w", err)
	}
	defer conn.Close()
	conn.SetReadLimit(maxWireMessageSize)

	session := &ooSession{Info: info, Conn: conn}
	return t.handshake(session)
}
