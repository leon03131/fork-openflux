// Package mail implements a carrier over the R7-Office (Mail.ru Cloud
// documents, an OnlyOffice fork) co-editing websocket that serves public
// cloud.mail.ru links.
//
// Config acquisition is a single authenticated-by-cookie API call:
//
//	GET  <public link>                       (collect cookies, esp. "oid")
//	POST <scheme://host>/api/v4/r7/edit      {"public":"<path w/o /public>",...}
//	     -> {"token":<JWT>, "api":"https://<host>/<version>",
//	         "document":{"key","fileType","permissions",...},
//	         "editorConfig":{"user":{"id":...}}}
//
// The websocket lives at wss://<api>/doc/<key>/c/?EIO=4&transport=websocket
// (the API version is already part of the returned api base URL).
//
// Data frames ride as "cursor" messages, same as the OnlyOffice carrier:
//
//	42["message",{"type":"cursor","cursor":"18;<base64 payload>"}]
//
// The server relays them to every other participant as
// {"type":"cursor","messages":[{"cursor":"18;<base64>","user":"<id+index>",
// "useridoriginal":"<id>"}]}. The sender never receives its own cursor
// back (excluded server-side, verified by live probing); as defense in
// depth we additionally drop messages whose useridoriginal matches the id
// the server assigned to us.
//
// Protocol quirks discovered by live probing (2026-09):
//   - The "public" field of the r7/edit request is the link path WITHOUT
//     the "/public" prefix ("/MLKF/6CEdaR5Qf"); anything else yields
//     400 {"error":"BAD/REQUEST"}.
//   - The auth message carries a dummy "token":"fghhfgsjdgfjs" while the
//     real JWT rides in "jwtOpen" (and the socket.io namespace connect).
//   - Co-editing lock semantics match OnlyOffice: when a second editor
//     joins, the server answers it with {"type":"waitAuth"} and notifies
//     the first participant via {"type":"connectState",...,
//     "waitAuth":true}; the holder must send {"type":"unLockDocument",
//     "unlock":true,...} or it is dropped with disconnectReason 4007.
//   - Before auth the server may send "license" and "waitAuth" messages;
//     both are normal.
//   - Engine.io ping "2" must be answered with "3" (~25s interval).
package mail

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/utils"
)

// docInfo is everything a websocket session needs, extracted from the
// r7/edit API response.
type docInfo struct {
	Token       string
	DocKey      string
	Origin      string
	WsURL       string
	UserID      string
	Permissions map[string]interface{}
	OpenCmd     map[string]interface{}
}

type mailSession struct {
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

func (s *mailSession) safeWrite(messageType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	// A wedged connection must not block writers forever.
	s.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	err := s.Conn.WriteMessage(messageType, data)
	s.Conn.SetWriteDeadline(time.Time{})
	return err
}

type MailTransport struct {
	*transport.BaseTransport

	url     string
	session *mailSession

	connectInFlight atomic.Int32
}

// MaxPayload is the raw message budget for the Mail carrier. Payloads are
// base64-wrapped into JSON cursor messages, so the wire size is ~1.37x
// (~90 KiB for 64 KiB); the server's EIO maxPayload is 100 MB, leaving an
// enormous margin.
func (t *MailTransport) MaxPayload() int { return 64 * 1024 }

func NewMailTransport(url string, config transport.TransportConfig) *MailTransport {
	return &MailTransport{
		BaseTransport: transport.NewBaseTransport(config),
		url:           url,
	}
}

func (t *MailTransport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	go t.keepAliveLoop()
	go t.writerLoop()
	t.connectToDoc(0)

	return nil
}

// Stop shuts the transport down and closes the active websocket so the
// read loop can actually exit (it would otherwise block in ReadMessage).
func (t *MailTransport) Stop() error {
	if err := t.BaseTransport.Stop(); err != nil {
		return err
	}
	t.Mu.RLock()
	session := t.session
	t.Mu.RUnlock()
	if session != nil && session.Conn != nil {
		session.Conn.Close()
	}
	return nil
}

func (t *MailTransport) Send(data []byte) error {
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
		t.RecordSend(len(data))
		return nil
	default:
		return fmt.Errorf("write queue full")
	}
}

func (t *MailTransport) connectToDoc(attempt int) {
	if !t.IsRunning() {
		return
	}
	// Only one connect sequence at a time; if another is in flight,
	// it owns the retry chain. The flag is held for the WHOLE
	// goroutine lifecycle (dial + auth + read loop), not just this call.
	if !t.connectInFlight.CompareAndSwap(0, 1) {
		return
	}

	utils.Debugf("[MAIL] connectToDoc attempt %d", attempt)

	go func() {
		defer t.connectInFlight.Store(0)
		t.Mu.Lock()
		existingSession := t.session
		t.Mu.Unlock()

		info, err := t.fetchDocInfo(t.url)
		if err != nil {
			utils.Debugf("[MAIL] fetchDocInfo failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}

		dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
		headers := http.Header{}
		headers.Set("User-Agent", "Mozilla/5.0")
		headers.Set("Origin", info.Origin)

		conn, _, err := dialer.Dial(info.WsURL, headers)
		if err != nil {
			utils.Debugf("[MAIL] WebSocket dial failed: %v", err)
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

		session := &mailSession{
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

		// EIO4 + socket.io + R7 auth handshake. Connected is reported
		// ONLY after auth result=1: Ready must mean the provider can
		// actually carry application payload.
		if err := t.handshake(session); err != nil {
			utils.Debugf("[MAIL] handshake failed: %v", err)
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
				utils.Debugf("[MAIL] Read error: %v", err)
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

// handshake performs EIO4 open -> socket.io namespace connect -> R7 auth,
// waiting for auth result=1. During the wait it keeps the connection
// alive (pongs) and honours the co-editing document lock
// (unLockDocument) so a peer waiting on us is not stuck.
func (t *MailTransport) handshake(s *mailSession) error {
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

	// 3. R7 auth. "token" is a dummy literal (verified live); the real
	// JWT rides in jwtOpen. permissions go AS IS from the config.
	authData := map[string]interface{}{
		"type": "auth", "docid": s.Info.DocKey, "token": "fghhfgsjdgfjs",
		"user": map[string]interface{}{
			"id": s.Info.UserID, "name": "",
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
	// in kind when we are the holder) or the server-side lock timer
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

func (t *MailTransport) writerLoop() {
	for t.IsRunning() {
		t.Mu.RLock()
		session := t.session
		t.Mu.RUnlock()

		if session == nil || session.Conn == nil {
			time.Sleep(50 * time.Millisecond)
			continue
		}

		select {
		case packet := <-session.WriteQueue:
			payload := base64.StdEncoding.EncodeToString(packet)
			msg := `42["message",{"type":"cursor","cursor":"18;` + payload + `"}]`

			if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
				utils.Debugf("[MAIL] Write error: %v", err)
				// A failed write means the connection is broken:
				// close it so the read loop wakes and reconnects.
				t.Mu.Lock()
				if t.session == session {
					t.SetConnected(false)
					session.Conn.Close()
				}
				t.Mu.Unlock()
			}
		case <-time.After(250 * time.Millisecond):
			// Periodic wake-up to re-check IsRunning and session.
		}
	}
}

// keepAliveLoop refreshes the R7 session idle timer (same OnlyOffice
// expire.sessionidle semantics as the onlyoffice carrier). The socket.io
// ping/pong ("2"/"3") is handled by the read loop.
func (t *MailTransport) keepAliveLoop() {
	ticker := time.NewTicker(t.GetConfig().KeepAliveInterval)
	defer ticker.Stop()
	extendMsg := `42["message",{"type":"extendSession","idletime":0}]`

	for t.IsRunning() {
		<-ticker.C
		t.Mu.RLock()
		session := t.session
		t.Mu.RUnlock()

		if session == nil || session.Conn == nil || !t.IsConnected() {
			continue
		}
		if err := session.safeWrite(websocket.TextMessage, []byte(extendMsg)); err != nil {
			utils.Debugf("[MAIL] extendSession failed: %v", err)
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

func (t *MailTransport) handleMessage(session *mailSession, text string) {
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
		// peer waits and we get dropped (disconnectReason 4007).
		// Sending this when we are NOT the holder is a server-side no-op.
		var cs struct {
			WaitAuth bool `json:"waitAuth"`
		}
		if err := json.Unmarshal(body, &cs); err == nil && cs.WaitAuth {
			utils.Debugf("[MAIL] peer waiting on document lock, releasing")
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
			payload, ok := decodeCursor(m.Cursor)
			if !ok {
				continue
			}
			t.RecordReceive(len(payload))
			t.CallReceive(payload)
		}
	case "expiredToken", "refreshToken":
		// The JWT is about to expire / has been rotated. Drop the
		// connection: the reconnect chain re-runs fetchDocInfo and
		// comes back with a fresh token.
		utils.Debugf("[MAIL] %s received, reconnecting with fresh config", head.Type)
		t.Mu.Lock()
		if t.session == session {
			t.SetConnected(false)
			session.Conn.Close()
		}
		t.Mu.Unlock()
	case "disconnectReason":
		// Server-initiated drop (lock timeout, idle, duplicate). The
		// socket close follows immediately; the read loop reconnects.
		utils.Debugf("[MAIL] disconnectReason: %s", truncForLog(text))
	}
}

// decodeCursor extracts the payload from a cursor string of the form
// "<index>;<base64>". Anything else (real editors' cursor positions)
// fails validation and is ignored.
func decodeCursor(cursor string) ([]byte, bool) {
	i := strings.IndexByte(cursor, ';')
	if i < 0 || i+1 >= len(cursor) {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(cursor[i+1:])
	if err != nil {
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
// is a dead connection: the server unlocks us only after its lock timer
// fires.
const authWaitTimeout = 45 * time.Second

// maxWireMessageSize bounds a single websocket message we are willing to
// buffer. Cursor batches carrying 64 KiB payloads stay far below this.
const maxWireMessageSize = 4 << 20 // 4 MiB

func (t *MailTransport) scheduleReconnect(attempt int) {
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

	utils.Debugf("[MAIL] Reconnect #%d in %v", attempt+1, delay)
	time.AfterFunc(delay, func() {
		t.connectToDoc(attempt + 1)
	})
}

// editConfigDoc is the typed subset of the /api/v4/r7/edit response that
// this transport depends on. Any provider schema change results in a
// validation error instead of a panic.
type editConfigDoc struct {
	Token        string `json:"token"`
	API          string `json:"api"` // e.g. "https://docs.datacloudmail.ru/2026.2.1.2268"
	DocumentType string `json:"documentType"`
	Document     struct {
		Key         string                 `json:"key"`
		FileType    string                 `json:"fileType"`
		URL         string                 `json:"url"`
		Title       string                 `json:"title"`
		Permissions map[string]interface{} `json:"permissions"`
	} `json:"document"`
	EditorConfig struct {
		Mode string `json:"mode"`
		User struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"user"`
	} `json:"editorConfig"`
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
		User           string `json:"user"`
		UserIDOriginal string `json:"useridoriginal"`
	} `json:"messages"`
}

// maxConfigPageSize bounds the public-link HTML page (defense in depth).
const maxConfigPageSize = 8 << 20 // 8 MiB

// maxEditResponseSize bounds the r7/edit JSON response.
const maxEditResponseSize = 4 << 20 // 4 MiB

// publicPath extracts the "public" request field from a cloud.mail.ru
// public link: the URL path without the "/public" prefix.
func publicPath(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("bad document URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("bad document URL scheme %q", u.Scheme)
	}
	p := strings.TrimSuffix(u.Path, "/")
	if !strings.HasPrefix(p, "/public/") {
		return "", fmt.Errorf("not a public link (path %q does not start with /public/)", u.Path)
	}
	return strings.TrimPrefix(p, "/public"), nil
}

func (t *MailTransport) fetchDocInfo(rawURL string) (docInfo, error) {
	pub, err := publicPath(rawURL)
	if err != nil {
		return docInfo{}, err
	}
	u, _ := url.Parse(rawURL) // already validated by publicPath
	apiBase := u.Scheme + "://" + u.Host

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return nil },
		Timeout:       30 * time.Second,
	}

	// Step 1: GET the public link to acquire the anonymous-session
	// cookies ("oid" is the important one).
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return docInfo{}, fmt.Errorf("bad document URL: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return docInfo{}, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxConfigPageSize))
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return docInfo{}, fmt.Errorf("document page returned HTTP %d", resp.StatusCode)
	}

	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}

	// Step 2: exchange the public path for an editor config + JWT.
	body := fmt.Sprintf(`{"public":%s,"platform":"desktop_web","x-email":"anonym"}`,
		mustJSONString(pub))
	req2, err := http.NewRequest("POST", apiBase+"/api/v4/r7/edit", strings.NewReader(body))
	if err != nil {
		return docInfo{}, err
	}
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	req2.Header.Set("Content-Type", "application/json")
	if len(cookies) > 0 {
		req2.Header.Set("Cookie", strings.Join(cookies, "; "))
	}
	resp2, err := client.Do(req2)
	if err != nil {
		return docInfo{}, err
	}
	defer resp2.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp2.Body, maxEditResponseSize))
	if err != nil {
		return docInfo{}, fmt.Errorf("read r7/edit response: %w", err)
	}
	if resp2.StatusCode != http.StatusOK {
		return docInfo{}, fmt.Errorf("r7/edit returned HTTP %d", resp2.StatusCode)
	}

	var config editConfigDoc
	if err := json.Unmarshal(raw, &config); err != nil {
		return docInfo{}, fmt.Errorf("r7/edit JSON: %w", err)
	}

	if config.Token == "" || config.API == "" || config.Document.Key == "" ||
		config.EditorConfig.User.ID == "" {
		return docInfo{}, fmt.Errorf("r7/edit response missing required fields (provider schema changed?)")
	}

	apiURL, err := url.Parse(config.API)
	if err != nil || apiURL.Host == "" {
		return docInfo{}, fmt.Errorf("r7/edit returned bad api URL (provider schema changed?)")
	}

	perms := config.Document.Permissions
	if perms == nil {
		perms = make(map[string]interface{})
	}

	openCmd := map[string]interface{}{
		"c":      "open",
		"id":     config.Document.Key,
		"userid": config.EditorConfig.User.ID,
		"format": config.Document.FileType,
		"lcid":   25,
	}
	// Optional fields: include only when the provider supplied them.
	if config.Document.URL != "" {
		openCmd["url"] = config.Document.URL
	}
	if config.Document.Title != "" {
		openCmd["title"] = config.Document.Title
	}

	return docInfo{
		Token:  config.Token,
		DocKey: config.Document.Key,
		Origin: apiURL.Scheme + "://" + apiURL.Host,
		WsURL: "wss://" + apiURL.Host + apiURL.Path +
			"/doc/" + config.Document.Key + "/c/?EIO=4&transport=websocket",
		UserID:      config.EditorConfig.User.ID,
		Permissions: perms,
		OpenCmd:     openCmd,
	}, nil
}

// mustJSONString marshals a string to a JSON string literal. Marshal of a
// plain string cannot fail; the helper exists to keep the call site tidy.
func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil { // unreachable for strings
		return `""`
	}
	return string(b)
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
func (t *MailTransport) Bounce() {
	t.Mu.RLock()
	s := t.session
	t.Mu.RUnlock()
	if s != nil && s.Conn != nil {
		s.Conn.Close()
	}
}

// CheckDoc verifies that the document URL is reachable and the r7/edit
// API returns a compatible editor config (used by `openflux doctor`).
func CheckDoc(url string) error {
	t := NewMailTransport(url, transport.DefaultConfig())
	_, err := t.fetchDocInfo(url)
	return err
}

// CheckLive goes further than CheckDoc: it dials the provider websocket
// and performs the full EIO4 + auth handshake, proving the server accepts
// us. If the document is currently locked by another live editor we wait
// in waitAuth until it unlocks (same as the real transport).
func CheckLive(url string) error {
	t := NewMailTransport(url, transport.DefaultConfig())
	info, err := t.fetchDocInfo(url)
	if err != nil {
		return err
	}

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	headers := http.Header{}
	headers.Set("User-Agent", "Mozilla/5.0")
	headers.Set("Origin", info.Origin)

	conn, _, err := dialer.Dial(info.WsURL, headers)
	if err != nil {
		return fmt.Errorf("websocket dial: %w", err)
	}
	defer conn.Close()
	conn.SetReadLimit(maxWireMessageSize)

	session := &mailSession{Info: info, Conn: conn}
	return t.handshake(session)
}
