package mail

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzParseEvent feeds untrusted socket.io frames into the event
// envelope parser. Rule: never panic; a failed parse returns zero
// values; a successful parse returns a non-empty JSON body.
func FuzzParseEvent(f *testing.F) {
	f.Add(`42["message",{"type":"cursor","cursor":"18;OFX1deadbeef:aGVsbG8="}]`)
	f.Add(`42["message",{"type":"auth","result":1}]`)
	f.Add(`42["message",{"type":"connectState","waitAuth":true}]`)
	f.Add(`0{"sid":"abc","pingInterval":25000}`)
	f.Add("2")
	f.Add("")
	f.Add("42[")
	f.Add(`42["message"]`)
	f.Add(`42[1,2]`)
	f.Add(`42["message",{}]extra`)
	f.Add("garbage-not-json")
	f.Fuzz(func(t *testing.T, text string) {
		ev, body, ok := parseEvent(text)
		if !ok {
			if ev != "" || body != nil {
				t.Fatalf("parseEvent(%q) = (%q, %v, false), want zero values", text, ev, body)
			}
			return
		}
		if len(body) == 0 {
			t.Fatalf("parseEvent(%q): ok with empty body", text)
		}
	})
}

// FuzzDecodeCursor feeds untrusted cursor strings into the OFX1 marker
// filter + base64 extractor. Rule: never panic; a rejected cursor
// returns a nil payload; an accepted payload is non-empty and survives
// an encode/decode roundtrip byte-identically.
func FuzzDecodeCursor(f *testing.F) {
	const prefix = "OFX1deadbeef:"
	f.Add("18;OFX1deadbeef:aGVsbG8=", prefix)         // valid frame
	f.Add("18;OFX1cafebabe:aGVsbG8=", prefix)         // foreign channel marker
	f.Add("18;OFX1deadbeef:!!!not-base64!!!", prefix) // broken base64
	f.Add("OFX1deadbeef:aGVsbG8=", prefix)            // missing cursor index
	f.Add("", prefix)
	f.Add(";", prefix)
	f.Add("18;", prefix)
	f.Fuzz(func(t *testing.T, cursor, framePrefix string) {
		payload, ok := decodeCursor(cursor, framePrefix)
		if !ok {
			if payload != nil {
				t.Fatalf("decodeCursor(%q, %q) = (%v, false), want nil payload", cursor, framePrefix, payload)
			}
			return
		}
		if len(payload) == 0 {
			t.Fatalf("decodeCursor(%q, %q): ok with empty payload", cursor, framePrefix)
		}
		again, ok2 := decodeCursor(encodeCursor(framePrefix, payload), framePrefix)
		if !ok2 || !bytes.Equal(again, payload) {
			t.Fatalf("roundtrip mismatch: decodeCursor(encodeCursor(%q, %x)) = (%x, %v)",
				framePrefix, payload, again, ok2)
		}
	})
}

// FuzzPublicPath feeds untrusted URLs into the public-link path
// extractor (the "public" field of the r7/edit request). Rule: never
// panic; an error result carries an empty path; a successful result
// always starts with a slash.
func FuzzPublicPath(f *testing.F) {
	f.Add("https://cloud.mail.ru/public/MLKF/6CEdaR5Qf")
	f.Add("https://cloud.mail.ru/public/A/b?x=1#frag")
	f.Add("http://cloud.mail.ru/public/ABC")
	f.Add("https://cloud.mail.ru/private/ABC")
	f.Add("ftp://cloud.mail.ru/public/ABC")
	f.Add("://bad")
	f.Add("")
	f.Add("https://cloud.mail.ru/public/")
	f.Fuzz(func(t *testing.T, rawURL string) {
		p, err := publicPath(rawURL)
		if err != nil {
			if p != "" {
				t.Fatalf("publicPath(%q) = (%q, %v): non-empty path on error", rawURL, p, err)
			}
			return
		}
		if !strings.HasPrefix(p, "/") {
			t.Fatalf("publicPath(%q) = %q, want leading slash", rawURL, p)
		}
	})
}
