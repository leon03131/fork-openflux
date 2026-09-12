package transport

import (
	"sync"
	"sync/atomic"
	"time"
)

type TransportConfig struct {
	MaxReconnectAttempts int
	ReconnectDelay       time.Duration
	ReconnectMultiplier  float64
	MaxQueueSize         int
	KeepAliveInterval    time.Duration
}

// Transport is a message carrier. Semantics:
//
//   - Send(data) queues the message for delivery: nil means ACCEPTED into
//     the queue, NOT delivered. Actual write errors surface asynchronously
//     via disconnection (IsConnected=false → session teardown).
//   - Start is single-use: a second call must return an error, and restart
//     after Stop is unsupported.
//   - Receive callbacks arrive in order, never concurrently.
type Transport interface {
	Start() error
	Stop() error
	Send(data []byte) error
	Receive(callback func([]byte))
	IsConnected() bool
	// IsRunning reports whether Start was called and Stop has not.
	IsRunning() bool
	Stats() TransportStats
}

type TransportStats struct {
	BytesSent     uint64
	BytesReceived uint64
	PacketsSent   uint64
	PacketsRecv   uint64
	Reconnects    uint64
	Connected     bool
	Uptime        time.Duration
}

func DefaultConfig() TransportConfig {
	return TransportConfig{
		MaxReconnectAttempts: 999999,
		ReconnectDelay:       500 * time.Millisecond,
		ReconnectMultiplier:  1.5,
		MaxQueueSize:         1024,
		KeepAliveInterval:    10 * time.Second,
	}
}

type BaseTransport struct {
	config    TransportConfig
	running   atomic.Int32
	connected atomic.Int32
	stats     TransportStats
	startTime time.Time

	receiveCallback func([]byte)
	Mu              sync.RWMutex

	reconnectAttempts atomic.Int32
}

func NewBaseTransport(config TransportConfig) *BaseTransport {
	// Normalize obviously broken values instead of letting carriers
	// panic later (e.g. time.NewTicker panics on interval <= 0).
	if config.KeepAliveInterval <= 0 {
		config.KeepAliveInterval = 10 * time.Second
	}
	if config.MaxQueueSize <= 0 {
		config.MaxQueueSize = 1024
	}
	if config.ReconnectDelay <= 0 {
		config.ReconnectDelay = 500 * time.Millisecond
	}
	return &BaseTransport{
		config:    config,
		startTime: time.Now(),
	}
}

func (b *BaseTransport) Start() error {
	b.running.Store(1)
	return nil
}

func (b *BaseTransport) Stop() error {
	b.running.Store(0)
	b.connected.Store(0)
	return nil
}

func (b *BaseTransport) IsRunning() bool {
	return b.running.Load() == 1
}

func (b *BaseTransport) IsConnected() bool {
	return b.connected.Load() == 1
}

func (b *BaseTransport) SetConnected(connected bool) {
	if connected {
		b.connected.Store(1)
	} else {
		b.connected.Store(0)
	}
}

func (b *BaseTransport) Receive(callback func([]byte)) {
	b.Mu.Lock()
	defer b.Mu.Unlock()
	b.receiveCallback = callback
}

func (b *BaseTransport) CallReceive(data []byte) {
	b.Mu.RLock()
	cb := b.receiveCallback
	b.Mu.RUnlock()
	if cb != nil {
		cb(data)
	}
}

func (b *BaseTransport) Stats() TransportStats {
	return TransportStats{
		BytesSent:     atomic.LoadUint64(&b.stats.BytesSent),
		BytesReceived: atomic.LoadUint64(&b.stats.BytesReceived),
		PacketsSent:   atomic.LoadUint64(&b.stats.PacketsSent),
		PacketsRecv:   atomic.LoadUint64(&b.stats.PacketsRecv),
		Reconnects:    uint64(b.reconnectAttempts.Load()),
		Connected:     b.IsConnected(),
		Uptime:        time.Since(b.startTime),
	}
}

func (b *BaseTransport) RecordSend(bytes int) {
	atomic.AddUint64(&b.stats.BytesSent, uint64(bytes))
	atomic.AddUint64(&b.stats.PacketsSent, 1)
}

func (b *BaseTransport) RecordReceive(bytes int) {
	atomic.AddUint64(&b.stats.BytesReceived, uint64(bytes))
	atomic.AddUint64(&b.stats.PacketsRecv, 1)
}

func (b *BaseTransport) RecordReconnect() {
	b.reconnectAttempts.Add(1)
}

func (b *BaseTransport) GetConfig() TransportConfig {
	return b.config
}

// Bouncer is an optional Transport capability: force the underlying
// connection to drop and reconnect, giving the next session a clean
// channel. Used by the supervisor after a fatal session error.
type Bouncer interface {
	Bounce()
}
