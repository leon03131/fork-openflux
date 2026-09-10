package yandex

import (
	"crypto/sha256"
	"encoding/base64"
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

type YandexDocsInfo struct {
	CookieStr   string
	Token       string
	DocID       string
	UserID      string
	Origin      string
	Host        string
	WsURL       string
	Permissions map[string]interface{}
	OpenCmd     map[string]interface{}
}

type DocSession struct {
	Info       YandexDocsInfo
	Conn       *websocket.Conn
	WriteQueue chan []byte
	UserID     string
	writeMu    sync.Mutex
}

func (s *DocSession) safeWrite(messageType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	// A wedged connection must not block writers forever.
	s.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	err := s.Conn.WriteMessage(messageType, data)
	s.Conn.SetWriteDeadline(time.Time{})
	return err
}

type YandexDocsTransport struct {
	*transport.BaseTransport

	url     string
	session *DocSession

	userCounter atomic.Int32
	baseUserID  string

	sentEcho *dedupRing

	connectInFlight atomic.Int32
}

// dedupRingSize covers ~30s of echo latency at 130 msg/s.
const dedupRingSize = 4096

// dedupRing is a fixed-size ring of hashes of recently sent payloads,
// used to drop our own cursor messages if the server echoes them back
// (self-echo would otherwise burn the session's decrypt-failure budget).
type dedupRing struct {
	mu    sync.Mutex
	set   map[[32]byte]struct{}
	order [dedupRingSize][32]byte
	pos   int
}

func newDedupRing() *dedupRing {
	return &dedupRing{set: make(map[[32]byte]struct{}, dedupRingSize)}
}

func (r *dedupRing) add(h [32]byte) {
	r.mu.Lock()
	if old, ok := r.evictLocked(); ok {
		delete(r.set, old)
	}
	r.order[r.pos] = h
	r.set[h] = struct{}{}
	r.pos = (r.pos + 1) % dedupRingSize
	r.mu.Unlock()
}

func (r *dedupRing) evictLocked() ([32]byte, bool) {
	if len(r.set) < dedupRingSize {
		return [32]byte{}, false
	}
	return r.order[r.pos], true
}

func (r *dedupRing) contains(h [32]byte) bool {
	r.mu.Lock()
	_, ok := r.set[h]
	r.mu.Unlock()
	return ok
}

// MaxPayload is the raw message budget for the Yandex Docs carrier.
// Payloads are base64-wrapped into JSON cursor messages, so the wire size
// is ~4/3x; 24 KiB raw stays well within websocket message limits.
func (t *YandexDocsTransport) MaxPayload() int { return 24 * 1024 }

func NewYandexDocsTransport(url string, config transport.TransportConfig) *YandexDocsTransport {
	t := &YandexDocsTransport{
		BaseTransport: transport.NewBaseTransport(config),
		url:           url,
		sentEcho:      newDedupRing(),
	}
	t.baseUserID = randUserID()
	return t
}

func (t *YandexDocsTransport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	t.baseUserID = randUserID()
	go t.keepAliveLoop()
	t.connectToDoc(0)

	return nil
}

// Stop shuts the transport down and closes the active websocket so the
// read loop can actually exit (it would otherwise block in ReadMessage).
func (t *YandexDocsTransport) Stop() error {
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

func (t *YandexDocsTransport) Send(data []byte) error {
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

func (t *YandexDocsTransport) connectToDoc(attempt int) {
	if !t.IsRunning() {
		return
	}
	// Only one connect sequence at a time; if another is in flight,
	// it owns the retry chain. The flag is held for the WHOLE
	// goroutine lifecycle (dial + read loop), not just this call.
	if !t.connectInFlight.CompareAndSwap(0, 1) {
		return
	}

	utils.Debugf("[YDOCS] connectToDoc attempt %d", attempt)

	go func() {
		defer t.connectInFlight.Store(0)
		t.Mu.Lock()
		existingSession := t.session
		t.Mu.Unlock()

		var userID string
		if existingSession != nil {
			userID = existingSession.UserID
		} else {
			suffix := fmt.Sprintf("%03d", t.userCounter.Add(1)%1000)
			userID = t.baseUserID + suffix
		}

		info, err := t.fetchDocInfo(t.url, userID)
		if err != nil {
			utils.Debugf("[YDOCS] fetchDocInfo failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}

		dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
		headers := http.Header{}
		headers.Set("User-Agent", "Mozilla/5.0")
		headers.Set("Origin", info.Origin)
		headers.Set("Cookie", info.CookieStr)
		headers.Set("Host", info.Host)

		conn, _, err := dialer.Dial(info.WsURL, headers)
		if err != nil {
			utils.Debugf("[YDOCS] WebSocket dial failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}

		writeQueue := make(chan []byte, t.GetConfig().MaxQueueSize)
		if existingSession != nil {
			writeQueue = existingSession.WriteQueue
		}

		session := &DocSession{
			Info:       info,
			Conn:       conn,
			WriteQueue: writeQueue,
			UserID:     userID,
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

		// Auth must complete BEFORE we report Connected: Ready means the
		// provider transport can actually carry application payload.
		tokenJSON, _ := json.Marshal(info.Token)
		auth1 := fmt.Sprintf(`40{"token":%s}`, tokenJSON)
		if err := session.safeWrite(websocket.TextMessage, []byte(auth1)); err != nil {
			utils.Debugf("[YDOCS] auth write failed: %v", err)
			conn.Close()
			t.scheduleReconnect(attempt)
			return
		}

		authData := map[string]interface{}{
			"type": "auth", "docid": info.DocID, "token": "fghhfgsjdgfjs",
			"user": map[string]interface{}{"id": userID}, "editorType": 0,
			"lastOtherSaveTime": -1, "permissions": info.Permissions,
			"openCmd": info.OpenCmd, "coEditingMode": "fast", "jwtOpen": info.Token,
		}
		messagePart, _ := json.Marshal([]interface{}{"message", authData})
		if err := session.safeWrite(websocket.TextMessage, []byte(fmt.Sprintf("42%s", string(messagePart)))); err != nil {
			utils.Debugf("[YDOCS] auth write failed: %v", err)
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
		} else {
			go t.writerLoop()
		}

		establishedAt := time.Now()

		for t.IsRunning() {
			_, message, err := conn.ReadMessage()
			if err != nil {
				utils.Debugf("[YDOCS] Read error: %v", err)
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
			conn.SetReadDeadline(time.Now().Add(75 * time.Second))
			t.handleMessage(session, message)
		}
	}()
}

func (t *YandexDocsTransport) writerLoop() {
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
			t.sentEcho.add(sha256.Sum256([]byte(payload)))
			msg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, payload)

			if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
				utils.Debugf("[YDOCS] Write error: %v", err)
				// A failed write means the connection is broken:
				// close it so the read loop wakes and reconnects.
				// Frames in the queue survive for the next session
				// (legacy mode) or are dropped with the session (v2).
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

func (t *YandexDocsTransport) keepAliveLoop() {
	ticker := time.NewTicker(t.GetConfig().KeepAliveInterval)
	defer ticker.Stop()
	keepAliveMsg := `42["message",{"type":"cursor","cursor":"18;---KA---"}]`

	for t.IsRunning() {
		<-ticker.C
		t.Mu.Lock()
		session := t.session
		t.Mu.Unlock()

		if session != nil && session.Conn != nil {
			if err := session.safeWrite(websocket.TextMessage, []byte(keepAliveMsg)); err != nil {
				utils.Debugf("[YDOCS] Keep-alive failed: %v", err)
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
}

func (t *YandexDocsTransport) handleMessage(session *DocSession, data []byte) {
	text := string(data)

	if strings.Contains(text, "---KA---") {
		return
	}

	// Socket.IO ping - respond with pong (use safeWrite)
	if text == "2" {
		if session != nil && session.Conn != nil {
			session.safeWrite(websocket.TextMessage, []byte("3"))
		}
		return
	}
	if text == "3" {
		return
	}

	if strings.Contains(text, "saveChanges") || strings.Contains(text, "cursor") {
		base64Str := t.extractBase64String(text)
		if base64Str == "" {
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(base64Str)
		if err != nil {
			utils.Debugf("[YDOCS] Base64 decode error: %v", err)
			return
		}

		// Drop our own messages echoed back by the server.
		if t.sentEcho.contains(sha256.Sum256([]byte(base64Str))) {
			return
		}

		t.RecordReceive(len(decoded))
		t.CallReceive(decoded)
	}
}

func (t *YandexDocsTransport) extractBase64String(response string) string {
	if strings.Contains(response, "saveChanges") {
		marker := `"excelAdditionalInfo":"`
		left := strings.Index(response, marker) + len(marker)
		if left < len(marker) {
			return ""
		}
		right := strings.Index(response[left:], `"`)
		if right == -1 {
			return ""
		}
		return response[left : left+right]
	}

	matches := cursorRe.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// maxReconnectDelay caps the exponential reconnect backoff.
const maxReconnectDelay = 30 * time.Second

func (t *YandexDocsTransport) scheduleReconnect(attempt int) {
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

	utils.Debugf("[YDOCS] Reconnect #%d in %v", attempt+1, delay)
	time.AfterFunc(delay, func() {
		t.connectToDoc(attempt + 1)
	})
}

// clientConfigDoc is the typed subset of the Yandex Docs "client-config"
// JSON that this transport depends on. Any provider schema change results
// in a validation error instead of a panic.
type clientConfigDoc struct {
	OfficeActionData struct {
		BalancerURL  string `json:"balancer_url"`
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

// maxConfigPageSize bounds the HTML page we parse (defense in depth).
const maxConfigPageSize = 8 << 20 // 8 MiB

var (
	// (?s): the embedded JSON may span newlines.
	clientConfigRe = regexp.MustCompile(`(?s)<script[^>]*id="client-config"[^>]*>(.*?)</script>`)
	cursorRe       = regexp.MustCompile(`"cursor":"[^;]+;([^"]+)"`)
)

func (t *YandexDocsTransport) fetchDocInfo(url, userID string) (YandexDocsInfo, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return nil },
		Timeout:       30 * time.Second,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return YandexDocsInfo{}, fmt.Errorf("bad document URL: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return YandexDocsInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return YandexDocsInfo{}, fmt.Errorf("document page returned HTTP %d", resp.StatusCode)
	}

	htmlBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxConfigPageSize))
	if err != nil {
		return YandexDocsInfo{}, fmt.Errorf("read document page: %w", err)
	}
	html := string(htmlBytes)

	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}

	matches := clientConfigRe.FindStringSubmatch(html)
	if len(matches) < 2 {
		return YandexDocsInfo{}, fmt.Errorf("client-config script not found (provider schema changed?)")
	}

	var config clientConfigDoc
	if err := json.Unmarshal([]byte(matches[1]), &config); err != nil {
		return YandexDocsInfo{}, fmt.Errorf("client-config JSON: %w", err)
	}

	ec := config.OfficeActionData.EditorConfig
	if ec == nil {
		return YandexDocsInfo{}, fmt.Errorf("editor_config missing (legacy editor not enabled?)")
	}
	if ec.Token == "" || ec.Document.Key == "" || config.OfficeActionData.BalancerURL == "" {
		return YandexDocsInfo{}, fmt.Errorf("client-config missing required fields (provider schema changed?)")
	}

	balancerURL := config.OfficeActionData.BalancerURL
	host := strings.TrimPrefix(balancerURL, "https://")
	document := ec.Document

	perms := document.Permissions
	if perms == nil {
		perms = make(map[string]interface{})
	}

	return YandexDocsInfo{
		CookieStr:   strings.Join(cookies, "; "),
		Token:       ec.Token,
		DocID:       document.Key,
		Origin:      balancerURL,
		Host:        host,
		WsURL:       fmt.Sprintf("wss://%s/2024.1.1-375/doc/%s/c/?EIO=4&transport=websocket", host, document.Key),
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

func randUserID() string {
	return fmt.Sprintf("%010d", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(1000000000))
}

// CheckDoc verifies that the document URL is reachable and has a
// compatible client-config (used by `openflux doctor`).
func CheckDoc(url string) error {
	t := NewYandexDocsTransport(url, transport.DefaultConfig())
	_, err := t.fetchDocInfo(url, "doctor000")
	return err
}
