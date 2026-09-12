// Package volga implements a carrier over the Yandex Documents NEW editor
// ("Volga") that serves public Yandex Disk documents. The document page's
// client-config carries an officeActionData block whose action_url trades
// the page token for a relay session on volga.yandex.ru plus a push
// subscription on push.yandex.ru (xiva).
//
// Volga protocol adapted from p1neappleXpress/OpenFlux (original author: p1neappleXpress). Adapted for OpenFlux v2 by leon03131.
//
// Data frames ride inside the Volga relay bundle: every bundle carries
// two editor ops (a textInsert + setCaret — the cover traffic that makes
// the server relay the bundle and keeps the editing session alive) and
// one opaque base64 blob. The blob is our own container:
//
//	blob = "OFX1<channelID>:" || repeated{ uint32be len || payload }
//
// channelID is derived deterministically from the document URL (first 8
// hex chars of sha256), so both tunnel ends compute it without
// negotiation. Because the blob always starts with the marker, the first
// 16 base64 chars are constant per document: foreign blobs (real editors'
// op payloads, stale garbage) are dropped by a cheap string comparison
// BEFORE base64 decoding, and again by a binary marker check after
// decoding (defense in depth), so they can never reach the session layer
// as a decrypt failure.
//
// Differences from the upstream reference implementation:
//   - single writer goroutine over a bounded queue (Send honestly reports
//     "queue full") instead of 2000 workers over a 1M-entry queue;
//   - 4-byte length prefix inside the blob (upstream uses 2 bytes, which
//     caps a frame at 64 KiB; our MaxPayload is 256 KiB);
//   - the OFX1 channel marker (upstream blobs are unmarked);
//   - re-authorization on 401/403 (upstream never re-authorizes);
//   - keepalive is a relay batch with zero data packets (the editor ops
//     are the activity that matters), so no poison byte is ever delivered
//     to the session layer.
//
// Note: the cover ops insert a literal "A" into the document per batch —
// that is the upstream-proven mechanics, use a dedicated document.
package volga

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/leon03131/fork-openflux/transport"
	"github.com/leon03131/fork-openflux/utils"
)

const (
	// maxPayloadSize is the raw message budget for the Volga carrier.
	// The relay accepts blobs up to ~5 MB; 256 KiB keeps batches small
	// and latency sane.
	maxPayloadSize = 256 * 1024

	// Batching (from the reference): coalescing packets into one relay
	// POST per batchSize packets / batchTimeout slashes HTTP request
	// rate under stream load.
	batchSize     = 20
	batchTimeout  = 2 * time.Millisecond
	batchMaxBytes = 1 << 20

	// maxBatchPackets bounds packets decoded from a single inbound blob
	// (untrusted input must not cause an allocation/callback storm).
	maxBatchPackets = 1024

	maxRedirects       = 10
	maxConfigPageSize  = 8 << 20 // 8 MiB bound on the HTML page we parse
	maxWireMessageSize = 8 << 20 // 8 MiB bound on a single ws message
	readDeadline       = 75 * time.Second

	authHTTPTimeout    = 30 * time.Second
	relayTimeout       = 30 * time.Second
	wsHandshakeTimeout = 10 * time.Second
	maxReconnectDelay  = 30 * time.Second
	doctorTimeout      = 60 * time.Second

	volgaUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:153.0) Gecko/20100101 Firefox/153.0"

	// volgaDocPath is the document node the cover ops reference (magic
	// constant from the upstream reference).
	volgaDocPath = "vyd:t/00000000000008"
)

// errAuthFailed marks relay/ws failures that call for re-authorization
// (expired token/sign) rather than a plain reconnect.
var errAuthFailed = errors.New("volga: auth rejected")

// (?s): the embedded JSON may span newlines.
var clientConfigRe = regexp.MustCompile(`(?s)<script[^>]*id="client-config"[^>]*>(.*?)</script>`)

// framePrefixFor derives the OFX1 protocol marker for a document URL.
// The channel id is deterministic (first 8 hex chars of sha256(url)), so
// the client and the exit — configured with the same document URL —
// compute the same marker without any negotiation.
func framePrefixFor(docURL string) string {
	sum := sha256.Sum256([]byte(docURL))
	return "OFX1" + hex.EncodeToString(sum[:])[:8] + ":"
}

// encodeBlob builds the blob binary: marker, then per packet a 4-byte
// big-endian length prefix followed by the payload.
func encodeBlob(marker []byte, batch [][]byte) []byte {
	total := len(marker)
	for _, p := range batch {
		total += 4 + len(p)
	}
	out := make([]byte, 0, total)
	out = append(out, marker...)
	var lenBuf [4]byte
	for _, p := range batch {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(p)))
		out = append(out, lenBuf[:]...)
		out = append(out, p...)
	}
	return out
}

// decodeBlob verifies the marker and splits the rest into packets.
// Returns nil for foreign blobs.
func decodeBlob(raw, marker []byte) [][]byte {
	if !bytes.HasPrefix(raw, marker) {
		return nil
	}
	return decodeBatch(raw[len(marker):])
}

// decodeBatch splits length-prefixed packets. Bounded and panic-free on
// adversarial input: truncated or oversized length prefixes stop the
// decode, zero-length packets are skipped.
func decodeBatch(data []byte) [][]byte {
	var packets [][]byte
	for len(data) >= 4 && len(packets) < maxBatchPackets {
		ln := binary.BigEndian.Uint32(data[:4])
		data = data[4:]
		if ln == 0 {
			continue
		}
		if ln > maxPayloadSize || uint64(ln) > uint64(len(data)) {
			break
		}
		packets = append(packets, data[:ln])
		data = data[ln:]
	}
	return packets
}

// volgaAuth is everything a relay/ws session needs, harvested from the
// document page and the action_url handshake. Token/Sign/CookieHeader
// are secrets: never log them.
type volgaAuth struct {
	Token        string
	RequestPath  string
	DocID        string
	UserID       int64
	UserIDStr    string
	Sign         string
	TS           string
	SessionID    string
	CookieHeader string
}

// authorize performs the Volga entry handshake: fetch the document page
// (following redirects manually), extract officeActionData/editorParams
// from the client-config script, POST action_url for the relay token and
// xiva credentials, then follow the redirect once to plant cookies.
func authorize(ctx context.Context, docURL string) (*volgaAuth, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("cookiejar: %w", err)
	}
	session := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: authHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var finalBody []byte
	var finalURL string
	currentURL := docURL

	for i := 0; i < maxRedirects; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", currentURL, nil)
		if err != nil {
			return nil, fmt.Errorf("bad URL %q: %w", currentURL, err)
		}
		req.Header.Set("User-Agent", volgaUserAgent)
		req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		if i > 0 {
			req.Header.Set("Referer", docURL)
		}

		resp, err := session.Do(req)
		if err != nil {
			return nil, fmt.Errorf("GET %s: %w", currentURL, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxConfigPageSize))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", currentURL, err)
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			if loc == "" {
				return nil, fmt.Errorf("redirect without Location from %s", currentURL)
			}
			base, err := url.Parse(currentURL)
			if err != nil {
				return nil, fmt.Errorf("parse URL %q: %w", currentURL, err)
			}
			ref, err := url.Parse(loc)
			if err != nil {
				return nil, fmt.Errorf("bad redirect Location from %s", currentURL)
			}
			currentURL = base.ResolveReference(ref).String()
			continue
		}

		finalBody = body
		finalURL = currentURL
		break
	}

	if finalBody == nil {
		return nil, fmt.Errorf("too many redirects from %s", docURL)
	}

	m := clientConfigRe.FindSubmatch(finalBody)
	if len(m) < 2 {
		return nil, fmt.Errorf("client-config script not found (provider schema changed?)")
	}

	// The client-config is untrusted input: UseNumber + comma-ok
	// accessors only, never panicking assertions.
	var cfg map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(m[1]))
	dec.UseNumber()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("client-config JSON: %w", err)
	}

	office, _ := cfg["officeActionData"].(map[string]interface{})
	if office == nil {
		return nil, fmt.Errorf("officeActionData missing (not a Volga document?)")
	}
	editor, _ := cfg["editorParams"].(map[string]interface{})

	actionURL := getStr(office, "action_url")
	accessToken := getStr(office, "access_token")
	if actionURL == "" || accessToken == "" {
		// .docx/.xlsx files are served by the OnlyOffice editor and
		// never carry the Volga action_url; say so explicitly instead
		// of a generic schema error.
		if et := getStr(office, "office_online_editor_type"); et == "only_office" {
			return nil, fmt.Errorf("document is served by the OnlyOffice editor (office_online_editor_type=only_office); use --transport onlyoffice")
		}
		return nil, fmt.Errorf("client-config missing action_url/access_token (provider schema changed?)")
	}
	utils.Debugf("[VOLGA] client-config ok: action_url=%s token=%d bytes ttl=%v",
		actionURL, len(accessToken), office["access_token_ttl"])

	form := url.Values{}
	form.Set("access_token", accessToken)
	form.Set("access_token_ttl", formatTTL(office["access_token_ttl"]))

	req2, err := http.NewRequestWithContext(ctx, "POST", actionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("bad action_url: %w", err)
	}
	req2.Header.Set("User-Agent", volgaUserAgent)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Origin", "https://disk.yandex.ru")
	req2.Header.Set("Referer", finalURL)
	req2.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req2.Header.Set("Accept-Language", "ru-RU,ru;q=0.9")
	req2.Header.Set("Upgrade-Insecure-Requests", "1")
	req2.Header.Set("Sec-Fetch-Dest", "iframe")
	req2.Header.Set("Sec-Fetch-Mode", "navigate")
	req2.Header.Set("Sec-Fetch-Site", "cross-site")

	resp2, err := session.Do(req2)
	if err != nil {
		return nil, fmt.Errorf("POST action_url: %w", err)
	}
	io.Copy(io.Discard, io.LimitReader(resp2.Body, 1<<20))
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("action_url returned status %d (expected 302)", resp2.StatusCode)
	}

	// The Location query carries token/request-path/json — secrets;
	// never log the URL.
	location := resp2.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("action_url redirect without Location")
	}
	if strings.Contains(location, "/document/error/") {
		return nil, fmt.Errorf("action_url redirected to /document/error/ (document unavailable or schema changed)")
	}

	locParsed, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("parse redirect Location: %w", err)
	}
	qs := locParsed.Query()

	jsonStr := qs.Get("json")
	if jsonStr == "" {
		return nil, fmt.Errorf("redirect Location missing json parameter")
	}
	var jsonData map[string]interface{}
	dec2 := json.NewDecoder(strings.NewReader(jsonStr))
	dec2.UseNumber()
	if err := dec2.Decode(&jsonData); err != nil {
		return nil, fmt.Errorf("redirect json: %w", err)
	}

	a := &volgaAuth{
		Token:       qs.Get("token"),
		RequestPath: qs.Get("request-path"),
		SessionID:   getStr(jsonData, "sessionId"),
		UserID:      jsonInt64(jsonData["userId"]),
		DocID:       getStr(editor, "idDoc"),
	}
	if xiva, ok := jsonData["xiva"].(map[string]interface{}); ok {
		a.Sign = getStr(xiva, "sign")
		a.TS = getStr(xiva, "ts")
		a.UserIDStr = getStr(xiva, "user")
	}

	// Follow the redirect once to plant the session cookies into the jar.
	req3, err := http.NewRequestWithContext(ctx, "GET", location, nil)
	if err != nil {
		return nil, fmt.Errorf("bad redirect Location: %w", err)
	}
	req3.Header.Set("User-Agent", volgaUserAgent)
	req3.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req3.Header.Set("Referer", actionURL)
	resp3, err := session.Do(req3)
	if err != nil {
		return nil, fmt.Errorf("GET redirect Location: %w", err)
	}
	io.Copy(io.Discard, io.LimitReader(resp3.Body, maxConfigPageSize))
	resp3.Body.Close()

	if a.Token == "" || a.RequestPath == "" || a.UserIDStr == "" || a.Sign == "" {
		// Report only which fields are missing, never their values.
		return nil, fmt.Errorf("incomplete auth: token=%v request-path=%v user=%v sign=%v",
			a.Token != "", a.RequestPath != "", a.UserIDStr != "", a.Sign != "")
	}

	// Collect the cookies for the RELAY url, not the document page: the
	// action_url handshake plants a session cookie (context-*) scoped to
	// the /session/main/<request-path>/ path, so jar.Cookies for the
	// /document/ URL silently misses it and the relay answers 401. (The
	// upstream reference survives this because its relay client carries
	// the whole jar, which applies path-scoped cookies per request.)
	cookieURL := locParsed
	if u, err := url.Parse(relayURLFor(a.RequestPath)); err == nil {
		cookieURL = u
	}
	var cookieParts []string
	for _, c := range jar.Cookies(cookieURL) {
		cookieParts = append(cookieParts, c.Name+"="+c.Value)
	}
	a.CookieHeader = strings.Join(cookieParts, "; ")

	utils.Debugf("[VOLGA] auth OK: user=%d rp=%s doc=%s", a.UserID, a.RequestPath, a.DocID)
	return a, nil
}

// getStr is a comma-ok string extractor for the untrusted client-config.
func getStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

// formatTTL renders access_token_ttl whatever its JSON type (the schema
// has been seen to vary).
func formatTTL(v interface{}) string {
	switch x := v.(type) {
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatInt(int64(x), 10)
	case string:
		return x
	case nil:
		return "0"
	default:
		return fmt.Sprintf("%v", x)
	}
}

// jsonInt64 is a comma-ok int extractor for untrusted JSON values.
func jsonInt64(v interface{}) int64 {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		if f, err := x.Float64(); err == nil {
			return int64(f)
		}
	case float64:
		return int64(x)
	case string:
		if i, err := strconv.ParseInt(x, 10, 64); err == nil {
			return i
		}
	}
	return 0
}

// sameUserID compares an untrusted incoming userId with ours.
func sameUserID(n json.Number, id int64) bool {
	if v, err := n.Int64(); err == nil {
		return v == id
	}
	if f, err := n.Float64(); err == nil {
		return int64(f) == id
	}
	return false
}

// idGen hands out the monotonically increasing bundle/op/local ids the
// relay protocol expects.
type idGen struct {
	bundleID atomic.Uint64
	seq      atomic.Uint64
	localID  atomic.Uint64
}

func (g *idGen) nextOpID(userID int64) string {
	return fmt.Sprintf("1-%d.%d", userID, g.seq.Add(1))
}

// relayURLFor builds the relay endpoint URL for a request-path.
func relayURLFor(requestPath string) string {
	return "https://volga.yandex.ru/session/main/" + requestPath + "/relay"
}

// sendRelayBatch POSTs one bundle (two cover ops + base64 blob) to the
// relay. 401/403 are reported as errAuthFailed so the caller can
// re-authorize instead of blindly retrying.
func sendRelayBatch(ctx context.Context, client *http.Client, auth *volgaAuth, frontier string, ids *idGen, blob []byte) error {
	opID := ids.nextOpID(auth.UserID)

	var frontierVal []interface{}
	if frontier != "" {
		frontierVal = []interface{}{frontier}
	} else {
		frontierVal = []interface{}{}
	}

	bundle := []interface{}{
		map[string]interface{}{
			"id":         opID,
			"frontier":   frontierVal,
			"undoable":   true,
			"actionName": "textInsert",
			"ops":        []interface{}{[]interface{}{"it", volgaDocPath, 0, "A"}},
			"sideEffect": false,
			"localId":    ids.localID.Add(1),
		},
		map[string]interface{}{
			"id":         ids.nextOpID(auth.UserID),
			"frontier":   []interface{}{opID},
			"undoable":   false,
			"actionName": "setCaret",
			"ops": []interface{}{
				[]interface{}{"us", auth.UserID, []interface{}{
					[]interface{}{
						[]interface{}{volgaDocPath, 0, -1},
						[]interface{}{volgaDocPath, 0, -1},
					},
				}},
			},
			"sideEffect": true,
			"localId":    ids.localID.Add(1),
		},
		base64.StdEncoding.EncodeToString(blob),
	}

	payload := map[string]interface{}{
		"message": map[string]interface{}{
			"bundleId": ids.bundleID.Add(1),
			"bundle":   bundle,
		},
		"targetUserId": nil,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal relay payload: %w", err)
	}

	reqURL := relayURLFor(auth.RequestPath)
	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build relay request: %w", err)
	}
	req.Header.Set("User-Agent", volgaUserAgent)
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://volga.yandex.ru")
	req.Header.Set("Referer", "https://volga.yandex.ru/document/?request-path="+auth.RequestPath)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if auth.CookieHeader != "" {
		req.Header.Set("Cookie", auth.CookieHeader)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("relay POST: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent:
		return nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("relay status %d: %w", resp.StatusCode, errAuthFailed)
	default:
		return fmt.Errorf("relay status %d", resp.StatusCode)
	}
}

// wsURLFor builds the xiva push subscription URL.
func wsURLFor(a *volgaAuth) string {
	v := url.Values{}
	v.Set("service", "volga")
	v.Set("user", a.UserIDStr)
	v.Set("sign", a.Sign)
	v.Set("ts", a.TS)
	v.Set("client", "web")
	v.Set("session", a.SessionID)
	v.Set("fetch_history", a.UserIDStr+":volga:0:1")
	v.Set("x_request_attempt", "0")
	return "wss://push.yandex.ru/v2/subscribe/websocket?" + v.Encode()
}

// dialWS opens the push websocket. The response is returned for status
// inspection on handshake failure.
func dialWS(ctx context.Context, auth *volgaAuth) (*websocket.Conn, *http.Response, error) {
	header := http.Header{}
	header.Set("User-Agent", volgaUserAgent)
	header.Set("Origin", "https://volga.yandex.ru")
	if auth.CookieHeader != "" {
		header.Set("Cookie", auth.CookieHeader)
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: wsHandshakeTimeout,
		ReadBufferSize:   1 << 20,
		WriteBufferSize:  64 << 10,
	}
	return dialer.DialContext(ctx, wsURLFor(auth), header)
}

type VolgaTransport struct {
	*transport.BaseTransport

	docURL string

	// ctx/cancel drive the whole transport lifecycle: cancel (called by
	// Stop) aborts an in-flight authorize/dial, pending reconnect timers
	// and all background loops.
	ctx    context.Context
	cancel context.CancelFunc

	// frameMarker is the OFX1 protocol marker identifying our blobs;
	// derived deterministically from the document URL so both tunnel
	// ends share it without negotiation. markerB64Prefix is the constant
	// 16-char base64 prefix of any blob carrying the marker (base64
	// encodes 3-byte groups, and the marker's first 12 bytes are fixed).
	frameMarker     []byte
	markerB64Prefix string

	relayClient *http.Client
	ids         idGen
	writeQueue  chan []byte

	// sendMu serializes relay POSTs (writer loop and keepalive) so
	// bundle/seq ids stay in order on the wire.
	sendMu sync.Mutex

	connectInFlight atomic.Int32

	// Guarded by Mu (BaseTransport):
	started     bool
	auth        *volgaAuth
	authInvalid bool
	frontier    string
	wsConn      *websocket.Conn
}

// MaxPayload is the raw message budget for the Volga carrier.
func (t *VolgaTransport) MaxPayload() int { return maxPayloadSize }

func NewVolgaTransport(docURL string, config transport.TransportConfig) *VolgaTransport {
	ctx, cancel := context.WithCancel(context.Background())
	marker := []byte(framePrefixFor(docURL))
	return &VolgaTransport{
		BaseTransport: transport.NewBaseTransport(config),
		docURL:        docURL,
		ctx:           ctx,
		cancel:        cancel,
		frameMarker:   marker,
		// base64 of the marker's first 12 bytes = first 16 chars of any
		// of our base64 blobs.
		markerB64Prefix: base64.StdEncoding.EncodeToString(marker[:12]),
		relayClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        32,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
				ForceAttemptHTTP2:   true,
			},
			Timeout: relayTimeout,
		},
	}
}

func (t *VolgaTransport) Start() error {
	t.Mu.Lock()
	if t.started {
		t.Mu.Unlock()
		return errors.New("volga: already started")
	}
	t.started = true
	t.Mu.Unlock()

	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	t.writeQueue = make(chan []byte, t.GetConfig().MaxQueueSize)

	go t.writerLoop()
	go t.keepAliveLoop()
	t.connectToDoc(0)

	return nil
}

// Stop shuts the transport down: it cancels the transport context
// (aborting any in-flight authorize/dial, pending reconnect timer and
// the background loops) and closes the active websocket so the read loop
// can actually exit (it would otherwise block in ReadMessage).
// Idempotent; restart after Stop is not supported.
func (t *VolgaTransport) Stop() error {
	if err := t.BaseTransport.Stop(); err != nil {
		return err
	}
	t.cancel()
	t.Mu.RLock()
	conn := t.wsConn
	t.Mu.RUnlock()
	if conn != nil {
		conn.Close()
	}
	return nil
}

// Send queues data for relay. nil means ACCEPTED into the bounded queue,
// not delivered; a full queue, an oversized/empty payload or a
// disconnected transport all return an honest error.
func (t *VolgaTransport) Send(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("volga: empty payload")
	}
	if len(data) > maxPayloadSize {
		return fmt.Errorf("volga: payload too large: %d > %d", len(data), maxPayloadSize)
	}
	if !t.IsConnected() {
		return fmt.Errorf("volga: transport not connected")
	}

	select {
	case t.writeQueue <- data:
		return nil
	default:
		return fmt.Errorf("volga: write queue full")
	}
}

// Bounce drops the current websocket; the reconnect chain rebuilds it
// (re-authorizing first if the auth was invalidated). Implements
// transport.Bouncer.
func (t *VolgaTransport) Bounce() {
	t.Mu.RLock()
	conn := t.wsConn
	t.Mu.RUnlock()
	if conn != nil {
		conn.Close()
	}
}

// invalidateAuth marks the current credentials dead and drops the
// websocket so the reconnect chain re-authorizes from scratch.
func (t *VolgaTransport) invalidateAuth() {
	t.Mu.Lock()
	t.authInvalid = true
	conn := t.wsConn
	t.Mu.Unlock()
	t.SetConnected(false)
	if conn != nil {
		conn.Close()
	}
}

// writerLoop is the single relay writer: it batches queued packets
// (batchSize packets / batchTimeout / batchMaxBytes, whichever fires
// first) and POSTs them. Batches survive an auth outage: they are held
// (and retried with the fresh credentials) instead of being silently
// dropped. RecordSend happens only after the relay actually accepted
// the batch.
func (t *VolgaTransport) writerLoop() {
	batch := make([][]byte, 0, batchSize)
	totalBytes := 0
	timer := time.NewTimer(batchTimeout)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	flush := func() {
		for len(batch) > 0 {
			t.Mu.RLock()
			auth, invalid := t.auth, t.authInvalid
			t.Mu.RUnlock()
			if auth == nil || invalid {
				// Not authorized yet (or being re-authorized):
				// hold the batch, Send-side backpressure applies
				// via the bounded queue.
				select {
				case <-time.After(200 * time.Millisecond):
					continue
				case <-t.ctx.Done():
					return
				}
			}

			err := t.sendBatchWith(auth, batch)
			switch {
			case err == nil:
				for _, p := range batch {
					t.RecordSend(len(p))
				}
				batch = batch[:0]
				totalBytes = 0
			case errors.Is(err, errAuthFailed):
				utils.Debugf("[VOLGA] relay auth failed, re-authorizing")
				t.invalidateAuth()
				select {
				case <-time.After(500 * time.Millisecond):
				case <-t.ctx.Done():
					return
				}
			default:
				// Non-auth failure (network, 5xx): the batch is
				// dropped and NOT counted; the loss surfaces to
				// the session layer like any carrier loss.
				utils.Debugf("[VOLGA] relay batch dropped: %v", err)
				batch = batch[:0]
				totalBytes = 0
			}
		}
	}

	for {
		select {
		case pkt := <-t.writeQueue:
			batch = append(batch, pkt)
			totalBytes += len(pkt)
			if len(batch) >= batchSize || totalBytes >= batchMaxBytes {
				flush()
			} else if len(batch) == 1 {
				timer.Reset(batchTimeout)
			}
		case <-timer.C:
			flush()
		case <-t.ctx.Done():
			return
		}
	}
}

// keepAliveLoop POSTs an ops-only bundle (zero data packets) every
// KeepAliveInterval so the editing session and the push subscription
// stay alive. The blob carries only the marker, so the peer decodes it
// to zero packets and delivers nothing.
func (t *VolgaTransport) keepAliveLoop() {
	ticker := time.NewTicker(t.GetConfig().KeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
		case <-t.ctx.Done():
			return
		}

		if !t.IsConnected() {
			continue
		}
		t.Mu.RLock()
		auth, invalid := t.auth, t.authInvalid
		t.Mu.RUnlock()
		if auth == nil || invalid {
			continue
		}
		if err := t.sendBatchWith(auth, nil); err != nil {
			if errors.Is(err, errAuthFailed) {
				utils.Debugf("[VOLGA] keepalive auth failed, re-authorizing")
				t.invalidateAuth()
			} else {
				utils.Debugf("[VOLGA] keepalive failed: %v", err)
			}
		}
	}
}

func (t *VolgaTransport) sendBatchWith(auth *volgaAuth, batch [][]byte) error {
	blob := encodeBlob(t.frameMarker, batch)
	t.Mu.RLock()
	frontier := t.frontier
	t.Mu.RUnlock()
	t.sendMu.Lock()
	defer t.sendMu.Unlock()
	return sendRelayBatch(t.ctx, t.relayClient, auth, frontier, &t.ids, blob)
}

// connectToDoc owns one connect sequence end to end: (re-)authorize if
// needed, dial the push websocket, then run the read loop until failure.
// Only one sequence is in flight at a time.
func (t *VolgaTransport) connectToDoc(attempt int) {
	if !t.IsRunning() {
		return
	}
	// If another connect is in flight, it owns the retry chain. The
	// flag is held for the WHOLE goroutine lifecycle.
	if !t.connectInFlight.CompareAndSwap(0, 1) {
		return
	}

	utils.Debugf("[VOLGA] connectToDoc attempt %d", attempt)

	go func() {
		defer t.connectInFlight.Store(0)

		t.Mu.RLock()
		auth, invalid := t.auth, t.authInvalid
		t.Mu.RUnlock()

		if auth == nil || invalid {
			newAuth, err := authorize(t.ctx, t.docURL)
			if err != nil {
				if t.ctx.Err() != nil {
					return // Stop() fired mid-authorize
				}
				utils.Debugf("[VOLGA] authorize failed: %v", err)
				t.scheduleReconnect(attempt)
				return
			}
			// Re-check under the same critical section that installs
			// the auth: Stop() may have fired during the fetch.
			t.Mu.Lock()
			if !t.IsRunning() {
				t.Mu.Unlock()
				return
			}
			t.auth, t.authInvalid = newAuth, false
			t.Mu.Unlock()
			auth = newAuth
		}

		conn, resp, err := dialWS(t.ctx, auth)
		if err != nil {
			if t.ctx.Err() != nil {
				return // Stop() fired mid-dial
			}
			if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
				utils.Debugf("[VOLGA] WS handshake rejected: status %d", resp.StatusCode)
				t.invalidateAuth()
			} else {
				utils.Debugf("[VOLGA] WS dial failed: %v", err)
			}
			t.scheduleReconnect(attempt)
			return
		}
		// Bound inbound frames (defense in depth).
		conn.SetReadLimit(maxWireMessageSize)

		t.Mu.Lock()
		if !t.IsRunning() {
			t.Mu.Unlock()
			conn.Close()
			return
		}
		old := t.wsConn
		t.wsConn = conn
		t.Mu.Unlock()

		// Close the superseded connection AFTER the new one is
		// installed: its read loop will error out, see it is no
		// longer current and exit without scheduling a reconnect.
		if old != nil {
			old.Close()
		}

		t.SetConnected(true)
		utils.Debugf("[VOLGA] WS connected (user=%d)", auth.UserID)
		establishedAt := time.Now()

		conn.SetReadDeadline(time.Now().Add(readDeadline))
		for t.IsRunning() {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				utils.Debugf("[VOLGA] WS read error: %v", err)
				// Only the current connection's failure drives
				// reconnects; the staleness check and the state
				// change must be atomic.
				t.Mu.Lock()
				current := t.wsConn == conn
				if current {
					t.SetConnected(false)
					conn.Close()
				}
				t.Mu.Unlock()
				if !current {
					return
				}
				// A connection that lived long enough was healthy:
				// restart the backoff sequence.
				if time.Since(establishedAt) > 30*time.Second {
					attempt = 0
				}
				t.scheduleReconnect(attempt)
				return
			}
			// Any inbound message proves the connection is alive.
			conn.SetReadDeadline(time.Now().Add(readDeadline))
			t.handleWSMessage(auth, msg)
		}
	}()
}

func (t *VolgaTransport) scheduleReconnect(attempt int) {
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

	utils.Debugf("[VOLGA] Reconnect #%d in %v", attempt+1, delay)
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

// handleWSMessage parses the push envelope {"operation","message"} and
// the inner {"t","userId","bundle","message"} frame. All fields are
// untrusted; anything malformed is dropped silently.
func (t *VolgaTransport) handleWSMessage(auth *volgaAuth, raw []byte) {
	var envelope struct {
		Operation string `json:"operation"`
		Message   string `json:"message"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return
	}
	if envelope.Operation != "SESSION" && envelope.Operation != "WORKER" {
		return
	}
	if envelope.Message == "" {
		return
	}

	var inner struct {
		T       string          `json:"t"`
		UserID  json.Number     `json:"userId"`
		Bundle  json.RawMessage `json:"bundle"`
		Message json.RawMessage `json:"message"`
	}
	if err := json.Unmarshal([]byte(envelope.Message), &inner); err != nil {
		return
	}

	// Our own bundles come back through the push channel; drop them.
	if sameUserID(inner.UserID, auth.UserID) {
		return
	}

	switch inner.T {
	case "relay":
		var rel struct {
			Bundle []json.RawMessage `json:"bundle"`
		}
		if err := json.Unmarshal(inner.Message, &rel); err != nil {
			return
		}
		for _, item := range rel.Bundle {
			t.handleBundleItem(item)
		}
	case "exchange":
		t.handleBundle(inner.Bundle)
	}
}

func (t *VolgaTransport) handleBundle(raw json.RawMessage) {
	var asArray []json.RawMessage
	if err := json.Unmarshal(raw, &asArray); err == nil {
		for _, item := range asArray {
			t.handleBundleItem(item)
		}
		return
	}

	var asObject struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil {
		for _, item := range asObject.Value {
			t.handleBundleItem(item)
		}
	}
}

func (t *VolgaTransport) handleBundleItem(raw json.RawMessage) {
	// Op objects carry the OT frontier we must quote in our next op.
	var asObj struct {
		ID     string `json:"id"`
		Action string `json:"actionName"`
	}
	if err := json.Unmarshal(raw, &asObj); err == nil && asObj.Action != "" {
		if asObj.ID != "" {
			t.Mu.Lock()
			t.frontier = asObj.ID
			t.Mu.Unlock()
		}
		return
	}

	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil {
		t.handleBlobString(asStr)
	}
}

// handleBlobString filters and decodes a base64 blob from a bundle.
// Foreign blobs are dropped by the cheap prefix check BEFORE base64
// decoding, then by the binary marker check after it; packets are
// delivered in order.
func (t *VolgaTransport) handleBlobString(s string) {
	if !strings.HasPrefix(s, t.markerB64Prefix) {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return
	}
	for _, p := range decodeBlob(raw, t.frameMarker) {
		t.RecordReceive(len(p))
		t.CallReceive(p)
	}
}

// CheckDoc verifies that the document URL authorizes cleanly (page
// fetch, client-config, action_url handshake). Used by `openflux doctor`.
func CheckDoc(docURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), doctorTimeout)
	defer cancel()
	_, err := authorize(ctx, docURL)
	return err
}

// CheckLive goes further than CheckDoc: it proves the write path (a
// relay POST with an ops-only bundle) and the read path (the push
// websocket handshake). Note the relay POST, like any bundle, carries
// the cover textInsert op.
func CheckLive(docURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), doctorTimeout)
	defer cancel()

	auth, err := authorize(ctx, docURL)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: relayTimeout}
	var ids idGen
	marker := []byte(framePrefixFor(docURL))
	if err := sendRelayBatch(ctx, client, auth, "", &ids, encodeBlob(marker, nil)); err != nil {
		return fmt.Errorf("relay POST: %w", err)
	}

	conn, _, err := dialWS(ctx, auth)
	if err != nil {
		return fmt.Errorf("websocket subscribe: %w", err)
	}
	conn.Close()
	return nil
}
