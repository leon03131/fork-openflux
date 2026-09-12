// Package ydetect probes a Yandex document URL and determines which
// editor backend serves it: volga (new Yandex editor) or onlyoffice.
// The legacy editor is gone provider-side and is not offered.
package ydetect

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"time"
)

const (
	BackendVolga      = "volga"
	BackendOnlyOffice = "onlyoffice"
)

var clientConfigRe = regexp.MustCompile(`(?s)<script[^>]*id="client-config"[^>]*>(.*?)</script>`)

// Probe fetches the document page (following redirects) and classifies
// the editor backend.
func Probe(docURL string) (string, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest("GET", docURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch document page: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}

	m := clientConfigRe.FindSubmatch(body)
	if len(m) < 2 {
		return "", fmt.Errorf("client-config not found")
	}
	cfg := string(m[1])

	// Volga markers come from officeActionData; OnlyOffice from officeType.
	hasActionURL := regexp.MustCompile(`"action_url"\s*:\s*"[^"]+"`).MatchString(cfg)
	hasAccessToken := regexp.MustCompile(`"access_token"\s*:\s*"[^"]+"`).MatchString(cfg)
	if hasActionURL && hasAccessToken {
		return BackendVolga, nil
	}
	if regexp.MustCompile(`"office_online_editor_type"\s*:\s*"only_office"`).MatchString(cfg) ||
		regexp.MustCompile(`"officeType"\s*:\s*"only_office"`).MatchString(cfg) {
		return BackendOnlyOffice, nil
	}
	return "", fmt.Errorf("unknown Yandex editor backend (neither volga nor onlyoffice markers found)")
}
