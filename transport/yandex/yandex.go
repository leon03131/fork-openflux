package yandex

import (
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
	return s.Conn.WriteMessage(messageType, data)
}

type YandexDocsTransport struct {
	*transport.BaseTransport

	url     string
	session *DocSession

	userCounter atomic.Int32
	baseUserID  string
}

func NewYandexDocsTransport(url string, config transport.TransportConfig) *YandexDocsTransport {
	t := &YandexDocsTransport{
		BaseTransport: transport.NewBaseTransport(config),
		url:           url,
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

	utils.Debugf("[YDOCS] connectToDoc attempt ...")

	go func() {
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

		// Re-check after the blocking dial: Stop() may have been called
		// while we were connecting.
		if !t.IsRunning() {
			conn.Close()
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

		t.Mu.Lock()
		t.session = session
		t.SetConnected(true)
		t.Mu.Unlock()

		// Close the superseded connection AFTER the new session is
		// installed: its read loop will error out, see it is no longer
		// the active session and exit without scheduling a reconnect.
		if existingSession != nil && existingSession.Conn != nil {
			existingSession.Conn.Close()
		} else {
			go t.writerLoop()
		}

		// Auth - use safeWrite
		tokenJSON, _ := json.Marshal(info.Token)
		auth1 := fmt.Sprintf(`40{"token":%s}`, tokenJSON)
		session.safeWrite(websocket.TextMessage, []byte(auth1))

		authData := map[string]interface{}{
			"type": "auth", "docid": info.DocID, "token": "fghhfgsjdgfjs",
			"user": map[string]interface{}{"id": userID}, "editorType": 0,
			"lastOtherSaveTime": -1, "permissions": info.Permissions,
			"openCmd": info.OpenCmd, "coEditingMode": "fast", "jwtOpen": info.Token,
		}
		messagePart, _ := json.Marshal([]interface{}{"message", authData})
		session.safeWrite(websocket.TextMessage, []byte(fmt.Sprintf("42%s", string(messagePart))))

		establishedAt := time.Now()

		for t.IsRunning() {
			_, message, err := conn.ReadMessage()
			if err != nil {
				utils.Debugf("[YDOCS] Read error: %v", err)
				// Only the active session's failure drives reconnects.
				t.Mu.RLock()
				current := t.session
				t.Mu.RUnlock()
				if current != session {
					return
				}
				t.SetConnected(false)
				// A session that lived long enough was healthy:
				// restart the backoff sequence.
				if time.Since(establishedAt) > 30*time.Second {
					attempt = 0
				}
				t.scheduleReconnect(attempt)
				return
			}
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
			msg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, payload)

			if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
				utils.Debugf("[YDOCS] Write error: %v", err)
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
				t.SetConnected(false)
				// Kill the connection so the read loop wakes up and
				// schedules a reconnect; otherwise the transport would
				// stay disconnected forever on a half-open socket.
				session.Conn.Close()
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

	re := regexp.MustCompile(`"cursor":"[^;]+;([^"]+)"`)
	matches := re.FindStringSubmatch(response)
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

var clientConfigRe = regexp.MustCompile(`<script[^>]*id="client-config"[^>]*>(.*?)</script>`)

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
