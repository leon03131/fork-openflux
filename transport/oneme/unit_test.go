package oneme

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/pierrec/lz4/v4"
)

func TestRedactEndpointToken(t *testing.T) {
	endpoint := "https://example.com/ws2?userId=user42&entityType=USER&token=SECRET-TOKEN-123&platform=WEB&clientType=ONE_ME"
	redacted := redactEndpointToken(endpoint)

	if strings.Contains(redacted, "SECRET-TOKEN-123") {
		t.Fatalf("redacted endpoint still leaks the token: %s", redacted)
	}

	u, err := url.Parse(redacted)
	if err != nil {
		t.Fatalf("redacted endpoint is not a valid URL: %v", err)
	}
	q := u.Query()
	if got := q.Get("token"); got != "***" {
		t.Errorf("token param = %q, want %q", got, "***")
	}

	// Every other query parameter and the URL base must stay intact.
	orig, err := url.Parse(endpoint)
	if err != nil {
		t.Fatalf("test endpoint does not parse: %v", err)
	}
	for _, key := range []string{"userId", "entityType", "platform", "clientType"} {
		if got, want := q.Get(key), orig.Query().Get(key); got != want {
			t.Errorf("param %s changed: got %q, want %q", key, got, want)
		}
	}
	if u.Scheme != orig.Scheme || u.Host != orig.Host || u.Path != orig.Path {
		t.Errorf("endpoint base changed: %s", redacted)
	}
}

func TestRedactEndpointTokenNoToken(t *testing.T) {
	endpoint := "https://example.com/ws2?userId=user42"
	redacted := redactEndpointToken(endpoint)

	u, err := url.Parse(redacted)
	if err != nil {
		t.Fatalf("redacted endpoint is not a valid URL: %v", err)
	}
	if u.Query().Has("token") {
		t.Errorf("token param appeared out of nowhere: %s", redacted)
	}
	if got := u.Query().Get("userId"); got != "user42" {
		t.Errorf("userId = %q, want %q", got, "user42")
	}
}

func TestRedactEndpointTokenBrokenURL(t *testing.T) {
	// Unparseable input must not panic and must be clearly marked.
	for _, bad := range []string{"://no-scheme", "http://exa\x7fmple/"} {
		if got := redactEndpointToken(bad); got != "(unparseable endpoint)" {
			t.Errorf("redactEndpointToken(%q) = %q, want %q", bad, got, "(unparseable endpoint)")
		}
	}
}

// uuidV4Re is the canonical RFC 4122 v4 UUID layout genUUID must produce.
var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestGenUUIDFormat(t *testing.T) {
	for i := 0; i < 100; i++ {
		if id := genUUID(); !uuidV4Re.MatchString(id) {
			t.Fatalf("genUUID() = %q, not an RFC 4122 v4 UUID", id)
		}
	}
}

func TestGenUUIDUnique(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := genUUID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate UUID at iteration %d: %s", i, id)
		}
		seen[id] = struct{}{}
	}
}

// makeVCP builds a syntactically valid vcp blob: 3-digit decompressed
// size prefix, one separator byte, base64(lz4(payload)).
func makeVCP(t *testing.T, payload string) string {
	t.Helper()
	buf := make([]byte, lz4.CompressBlockBound(len(payload)))
	n, err := lz4.CompressBlock([]byte(payload), buf, nil)
	if err != nil {
		t.Fatalf("lz4.CompressBlock: %v", err)
	}
	return fmt.Sprintf("%03d|%s", len(payload), base64.StdEncoding.EncodeToString(buf[:n]))
}

func TestDecodeCallDetailsValid(t *testing.T) {
	const payload = `{"conversationId":"conv-1","type":"CALL"}`
	got, err := decodeCallDetails(makeVCP(t, payload))
	if err != nil {
		t.Fatalf("decodeCallDetails: %v", err)
	}
	if got != payload {
		t.Errorf("decodeCallDetails round trip = %q, want %q", got, payload)
	}
}

func TestDecodeCallDetailsInvalid(t *testing.T) {
	// A well-formed lz4 block whose payload is larger than the
	// declared size must fail (destination buffer too small).
	buf := make([]byte, lz4.CompressBlockBound(len("hello")))
	n, err := lz4.CompressBlock([]byte("hello"), buf, nil)
	if err != nil {
		t.Fatalf("lz4.CompressBlock: %v", err)
	}
	undersized := fmt.Sprintf("002|%s", base64.StdEncoding.EncodeToString(buf[:n]))

	tests := []struct {
		name string
		vcp  string
	}{
		{"empty", ""},
		{"shorter than size prefix", "005"},
		{"non-numeric size", "abc|AAAA"},
		{"zero size", "000|AAAA"},
		{"negative size", "-12|AAAA"},
		{"base64 garbage", "005|!!!not-base64!!!"},
		{"valid base64 but not lz4", "005|aGVsbG8="},
		{"declared size smaller than payload", undersized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if out, err := decodeCallDetails(tt.vcp); err == nil {
				t.Fatalf("decodeCallDetails(%q) succeeded with %q, want error", tt.vcp, out)
			}
		})
	}
}

// TestDecodeCallDetailsEmptyPayload pins the current lenient behaviour:
// a well-formed prefix with an empty payload decodes to an empty string
// without an error, because lz4.UncompressBlock returns (0, nil) for an
// empty source. Callers must be ready to reject empty call details.
func TestDecodeCallDetailsEmptyPayload(t *testing.T) {
	out, err := decodeCallDetails("005|")
	if err != nil {
		t.Fatalf("decodeCallDetails(\"005|\") = %v, want nil error", err)
	}
	if out != "" {
		t.Fatalf("decodeCallDetails(\"005|\") = %q, want empty string", out)
	}
}
