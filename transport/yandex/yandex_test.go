package yandex

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/leon03131/fork-openflux/transport"
)

func TestExtractBase64String(t *testing.T) {
	tr := NewYandexDocsTransport("http://example.invalid", transport.DefaultConfig())

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "cursor message",
			input: `42["message",{"type":"cursor","cursor":"18;aGVsbG8="}]`,
			want:  "aGVsbG8=",
		},
		{
			name:  "cursor with long session prefix",
			input: `"cursor":"0000000018;QUJDREVGRw=="`,
			want:  "QUJDREVGRw==",
		},
		{
			name:  "saveChanges marker",
			input: `42["message",{"type":"saveChanges","excelAdditionalInfo":"U0FWRUQ=","changes":[]}]`,
			want:  "U0FWRUQ=",
		},
		{
			name:  "saveChanges without marker",
			input: `42["message",{"type":"saveChanges","changes":[]}]`,
			want:  "",
		},
		{
			name:  "saveChanges marker without closing quote",
			input: `{"type":"saveChanges","excelAdditionalInfo":"truncated`,
			want:  "",
		},
		{
			name:  "garbage",
			input: "hello, this is not a protocol message",
			want:  "",
		},
		{
			name:  "empty",
			input: "",
			want:  "",
		},
		{
			name:  "cursor without payload",
			input: `"cursor":"18;"`,
			want:  "",
		},
		{
			name:  "cursor without semicolon",
			input: `"cursor":"aGVsbG8="`,
			want:  "",
		},
		{
			// The regex requires no whitespace after the colon.
			name:  "cursor with space after colon not matched",
			input: `"cursor": "18;abc"`,
			want:  "",
		},
		{
			// The prefix cannot contain ';'; everything after the first
			// ';' up to the closing quote is taken as the payload.
			name:  "cursor with extra semicolons",
			input: `"cursor":"18;20;cGF5bG9hZA=="`,
			want:  "20;cGF5bG9hZA==",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tr.extractBase64String(tt.input); got != tt.want {
				t.Errorf("extractBase64String(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDedupRingAddContains(t *testing.T) {
	r := newDedupRing()
	h1 := sha256.Sum256([]byte("payload-1"))
	h2 := sha256.Sum256([]byte("payload-2"))
	h3 := sha256.Sum256([]byte("payload-3"))

	if r.contains(h1) {
		t.Fatal("empty ring must not contain anything")
	}

	r.add(h1)
	r.add(h2)
	if !r.contains(h1) || !r.contains(h2) {
		t.Fatal("added hashes must be contained in the ring")
	}
	if r.contains(h3) {
		t.Fatal("ring must not contain a hash that was never added")
	}

	// Adding the same hash again keeps it present.
	r.add(h1)
	if !r.contains(h1) {
		t.Fatal("re-added hash must be contained in the ring")
	}
}

func TestDedupRingEviction(t *testing.T) {
	r := newDedupRing()
	h := func(i uint64) [32]byte {
		var b [32]byte
		binary.LittleEndian.PutUint64(b[:8], i)
		return b
	}

	// Fill the ring to capacity: every entry must be retrievable.
	for i := uint64(0); i < dedupRingSize; i++ {
		r.add(h(i))
	}
	if got := len(r.set); got != dedupRingSize {
		t.Fatalf("ring holds %d entries, capacity is %d", got, dedupRingSize)
	}
	for i := uint64(0); i < dedupRingSize; i++ {
		if !r.contains(h(i)) {
			t.Fatalf("hash %d missing from a full ring", i)
		}
	}

	// One more entry evicts the oldest one; capacity stays fixed.
	r.add(h(dedupRingSize))
	if r.contains(h(0)) {
		t.Error("oldest hash was not evicted after overflow")
	}
	if !r.contains(h(1)) {
		t.Error("second-oldest hash must still be present")
	}
	if !r.contains(h(dedupRingSize)) {
		t.Error("newest hash missing after overflow")
	}
	if got := len(r.set); got != dedupRingSize {
		t.Fatalf("ring holds %d entries after overflow, capacity is %d", got, dedupRingSize)
	}

	// Rotate the whole ring: only the last dedupRingSize entries survive.
	for i := uint64(dedupRingSize + 1); i < 2*dedupRingSize; i++ {
		r.add(h(i))
	}
	if r.contains(h(1)) {
		t.Error("stale hash survived a full ring rotation")
	}
	if !r.contains(h(2*dedupRingSize - 1)) {
		t.Error("most recent hash missing after full rotation")
	}
	if got := len(r.set); got != dedupRingSize {
		t.Fatalf("ring holds %d entries after full rotation, capacity is %d", got, dedupRingSize)
	}
}

// configJSON renders a client-config document for fetchDocInfo tests.
func configJSON(editorType, officeType, balancerURL, editorConfig string) string {
	return fmt.Sprintf(`{"officeActionData":{`+
		`"balancer_url":%q,`+
		`"office_online_editor_type":%q,`+
		`"officeType":%q,`+
		`"editor_config":%s}}`,
		balancerURL, editorType, officeType, editorConfig)
}

const legacyEditorConfig = `{"token":"test-token-123","document":{` +
	`"key":"doc-key-456",` +
	`"url":"https://example.com/doc.docx",` +
	`"title":"Test Doc",` +
	`"fileType":"docx",` +
	`"permissions":{"edit":true,"read":true}}}`

func configPage(config string) string {
	return `<!DOCTYPE html><html><head>` +
		`<script id="client-config" type="application/json">` + config + `</script>` +
		`</head><body></body></html>`
}

func TestFetchDocInfoLegacySuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "yandexuid", Value: "cookie-123"})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, configPage(configJSON("desktop", "legacy", "https://example.com", legacyEditorConfig)))
	}))
	defer srv.Close()

	tr := NewYandexDocsTransport(srv.URL, transport.DefaultConfig())
	info, err := tr.fetchDocInfo(srv.URL, "user0000001")
	if err != nil {
		t.Fatalf("fetchDocInfo: %v", err)
	}

	if info.Token != "test-token-123" {
		t.Errorf("Token = %q, want %q", info.Token, "test-token-123")
	}
	if info.DocID != "doc-key-456" {
		t.Errorf("DocID = %q, want %q", info.DocID, "doc-key-456")
	}
	if info.Origin != "https://example.com" {
		t.Errorf("Origin = %q, want %q", info.Origin, "https://example.com")
	}
	if info.Host != "example.com" {
		t.Errorf("Host = %q, want %q", info.Host, "example.com")
	}
	wantWs := "wss://example.com/2024.1.1-375/doc/doc-key-456/c/?EIO=4&transport=websocket"
	if info.WsURL != wantWs {
		t.Errorf("WsURL = %q, want %q", info.WsURL, wantWs)
	}
	if !strings.Contains(info.CookieStr, "yandexuid=cookie-123") {
		t.Errorf("CookieStr = %q, want it to contain %q", info.CookieStr, "yandexuid=cookie-123")
	}
	if got := info.Permissions["edit"]; got != true {
		t.Errorf("Permissions[edit] = %v, want true", got)
	}
	if info.OpenCmd["c"] != "open" || info.OpenCmd["id"] != "doc-key-456" ||
		info.OpenCmd["userid"] != "user0000001" || info.OpenCmd["format"] != "docx" {
		t.Errorf("unexpected OpenCmd: %v", info.OpenCmd)
	}
}

func TestFetchDocInfoErrors(t *testing.T) {
	legacy := configJSON("desktop", "legacy", "https://example.com", legacyEditorConfig)

	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{
			name:    "only_office editor type",
			body:    configPage(configJSON("only_office", "legacy", "https://example.com", legacyEditorConfig)),
			wantErr: "OnlyOffice",
		},
		{
			name:    "onlyoffice balancer",
			body:    configPage(configJSON("desktop", "legacy", "https://onlyoffice.example.com", legacyEditorConfig)),
			wantErr: "OnlyOffice",
		},
		{
			name:    "missing editor_config",
			body:    configPage(configJSON("desktop", "legacy", "https://example.com", "null")),
			wantErr: "editor_config missing",
		},
		{
			name:    "missing required fields",
			body:    configPage(configJSON("desktop", "legacy", "https://example.com", `{"token":"","document":{"key":""}}`)),
			wantErr: "missing required fields",
		},
		{
			name:    "no client-config script",
			body:    `<!DOCTYPE html><html><body>nothing here</body></html>`,
			wantErr: "client-config script not found",
		},
		{
			name:    "invalid config JSON",
			body:    configPage("{this is not json"),
			wantErr: "client-config JSON",
		},
		{
			name:    "http error status",
			status:  http.StatusInternalServerError,
			body:    configPage(legacy),
			wantErr: "HTTP 500",
		},
		{
			name:    "valid legacy config still works",
			body:    configPage(legacy),
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := tt.status
			if status == 0 {
				status = http.StatusOK
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(status)
				fmt.Fprint(w, tt.body)
			}))
			defer srv.Close()

			tr := NewYandexDocsTransport(srv.URL, transport.DefaultConfig())
			_, err := tr.fetchDocInfo(srv.URL, "user0000001")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("fetchDocInfo: unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("fetchDocInfo: expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("fetchDocInfo: error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}
