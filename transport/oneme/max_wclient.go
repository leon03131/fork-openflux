package oneme

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

const (
	WS_HOST     = "wss://ws-api.oneme.ru/websocket"
	RPC_VERSION = 11
	USER_AGENT  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
)

func NewMaxClient() *MaxClient {
	return &MaxClient{
		deviceID:      genUUID(),
		keepaliveStop: make(chan struct{}),
		closedCh:      make(chan struct{}),
	}
}

func (c *MaxClient) Connect() error {
	// Never hold c.mu across a blocking dial (it can take tens of
	// seconds) — Close and invoke must stay responsive.
	select {
	case <-c.closedCh:
		return fmt.Errorf("client closed")
	default:
	}
	header := http.Header{}
	header.Set("Origin", "https://web.max.ru")
	header.Set("User-Agent", USER_AGENT)
	conn, _, err := websocket.DefaultDialer.Dial(WS_HOST, header)
	if err != nil {
		return err
	}
	c.mu.Lock()
	select {
	case <-c.closedCh:
		c.mu.Unlock()
		conn.Close()
		return fmt.Errorf("client closed")
	default:
	}
	c.conn = conn
	c.mu.Unlock()
	c.dead.Store(false)
	go c.readLoop(conn)
	logInfo("[MAX] Connected")
	return nil
}

func (c *MaxClient) SetEventCallback(cb func(MaxPacket)) { c.onEvent = cb }

// readLoop reads from the given connection (captured, so a reconnect
// swapping c.conn cannot race with reads).
func (c *MaxClient) readLoop(conn *websocket.Conn) {
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			c.mu.Lock()
			current := c.conn == conn
			c.mu.Unlock()
			if current {
				logError("[MAX] connection lost: %v", err)
				c.dead.Store(true)
			}
			return
		}
		var packet MaxPacket
		if json.Unmarshal(message, &packet) != nil {
			continue
		}
		if ch, ok := c.pending.LoadAndDelete(int64(packet.Seq)); ok {
			ch.(chan MaxPacket) <- packet
		} else if c.onEvent != nil {
			c.onEvent(packet)
		}
	}
}

func (c *MaxClient) invoke(opcode int, payload map[string]interface{}) (*MaxPacket, error) {
	if c.dead.Load() {
		return nil, fmt.Errorf("main connection is dead")
	}
	seq := c.seq.Add(1)
	req := map[string]interface{}{"ver": RPC_VERSION, "cmd": 0, "seq": seq, "opcode": opcode, "payload": payload}
	data, _ := json.Marshal(req)
	ch := make(chan MaxPacket, 1)
	c.pending.Store(seq, ch)
	defer c.pending.Delete(seq)
	c.mu.Lock()
	conn := c.conn
	if conn == nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("not connected")
	}
	err := conn.WriteMessage(websocket.TextMessage, data)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case resp := <-ch:
		return &resp, nil
	case <-c.closedCh:
		return nil, fmt.Errorf("client closed")
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout")
	}
}

func (c *MaxClient) LoginByToken(token string) error {
	if _, err := c.invoke(6, map[string]interface{}{
		"userAgent": map[string]interface{}{
			"deviceType": "WEB", "locale": "ru_RU", "osVersion": "macOS",
			"deviceName": "vkmax Go", "appVersion": "25.9.15",
			"screen": "956x1470 2.0x", "timezone": "Asia/Vladivostok",
		},
		"deviceId": c.deviceID,
	}); err != nil {
		return fmt.Errorf("userAgent handshake: %w", err)
	}
	resp, err := c.invoke(19, map[string]interface{}{
		"interactive": true, "token": token, "chatsSync": 0,
		"contactsSync": 0, "presenceSync": 0, "draftsSync": 0, "chatsCount": 40,
	})
	if err != nil {
		return err
	}
	var payload map[string]interface{}
	json.Unmarshal(resp.Payload, &payload)
	if _, ok := payload["error"]; ok {
		return fmt.Errorf("login failed: %v", payload["error"])
	}
	c.loggedIn.Store(true)
	// Keepalive is started once per client; it survives reconnects
	// because it reads the current conn via invoke.
	c.keepaliveOnce.Do(func() { go c.keepalive() })
	logInfo("[MAX] logged in")
	return nil
}

// Supervise keeps the main websocket connection alive: when readLoop
// dies, it reconnects and re-logs-in with backoff until Close.
// The event callback (set via SetEventCallback) survives reconnects.
func (c *MaxClient) Supervise(token string) {
	for {
		select {
		case <-c.closedCh:
			return
		case <-time.After(2 * time.Second):
		}
		if !c.dead.Load() {
			continue
		}
		// Race guard: Close() during the 2s sleep.
		select {
		case <-c.closedCh:
			return
		default:
		}
		logInfo("[MAX] reconnecting main websocket...")
		c.mu.Lock()
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
		c.mu.Unlock()
		// Connect resets the dead flag on success.
		if err := c.Connect(); err != nil {
			logError("[MAX] reconnect failed: %v", err)
			continue
		}
		if err := c.LoginByToken(token); err != nil {
			// invoke aborts immediately once closedCh is closed, so a
			// login error during shutdown must not trigger a retry.
			select {
			case <-c.closedCh:
				return
			default:
			}
			logError("[MAX] re-login failed: %v", err)
			c.dead.Store(true)
			continue
		}
		logInfo("[MAX] reconnected")
	}
}

// Close terminates the client and all its goroutines.
func (c *MaxClient) Close() {
	c.closeOnce.Do(func() {
		close(c.keepaliveStop)
		close(c.closedCh)
		c.mu.Lock()
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
		c.mu.Unlock()
	})
}

// Check verifies MAX connectivity and credentials (used by
// `openflux doctor`).
func Check(token string) error {
	c := NewMaxClient()
	defer c.Close()
	if err := c.Connect(); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	if err := c.LoginByToken(token); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	return nil
}

func (c *MaxClient) keepalive() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.keepaliveStop:
			return
		case <-ticker.C:
			if c.loggedIn.Load() {
				c.invoke(1, map[string]interface{}{"interactive": false})
			}
		}
	}
}
