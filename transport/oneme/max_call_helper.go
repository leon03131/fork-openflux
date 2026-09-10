package oneme

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/pierrec/lz4/v4"
)

// maxVCPSize bounds the decompressed call-details blob (untrusted input).
const maxVCPSize = 1 << 20 // 1 MiB

func decodeCallDetails(vcp string) (string, error) {
	if len(vcp) < 4 {
		return "", fmt.Errorf("vcp too short")
	}
	var size int
	if _, err := fmt.Sscanf(vcp[:3], "%d", &size); err != nil {
		return "", fmt.Errorf("bad vcp size: %w", err)
	}
	if size <= 0 || size > maxVCPSize {
		return "", fmt.Errorf("bad vcp size %d", size)
	}
	decoded, err := base64.StdEncoding.DecodeString(vcp[4:])
	if err != nil {
		return "", err
	}
	decompressed := make([]byte, size)
	n, err := lz4.UncompressBlock(decoded, decompressed)
	if err != nil {
		return "", err
	}
	return string(decompressed[:n]), nil
}

func craftEndpoint(convID, jsonConfig string) string {
	var config WebRTCConfig
	json.Unmarshal([]byte(jsonConfig), &config)
	baseURL := config.WebsocketEndpoint
	if len(baseURL) > 4 {
		baseURL = baseURL[:len(baseURL)-4]
	}
	userID := config.TurnUsername
	for i := len(config.TurnUsername) - 1; i >= 0; i-- {
		if config.TurnUsername[i] == ':' {
			userID = config.TurnUsername[i+1:]
			break
		}
	}
	return fmt.Sprintf("%s/ws2?userId=%s&entityType=USER&deviceIdx=0&conversationId=%s&token=%s&platform=WEB&appVersion=1.1&version=5&device=browser&capabilities=2A03F&clientType=ONE_ME&tgt=accept",
		baseURL, userID, convID, config.Token)
}

// redactEndpointToken masks the token query parameter for logging.
func redactEndpointToken(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "(unparseable endpoint)"
	}
	q := u.Query()
	if q.Has("token") {
		q.Set("token", "***")
	}
	u.RawQuery = q.Encode()
	return u.String()
}
