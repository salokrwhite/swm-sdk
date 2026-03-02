package swmsdk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"github.com/google/uuid"
)

func canonicalQuery(raw url.Values) string {
	if len(raw) == 0 {
		return ""
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		values := append([]string{}, raw[key]...)
		sort.Strings(values)
		escapedKey := url.QueryEscape(key)
		escapedKey = strings.ReplaceAll(escapedKey, "+", "%20")
		escapedKey = strings.ReplaceAll(escapedKey, "*", "%2A")
		for _, value := range values {
			escapedValue := url.QueryEscape(value)
			escapedValue = strings.ReplaceAll(escapedValue, "+", "%20")
			escapedValue = strings.ReplaceAll(escapedValue, "*", "%2A")
			parts = append(parts, escapedKey+"="+escapedValue)
		}
	}
	return strings.Join(parts, "&")
}

func bodySHA256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func signHMACHex(secret string, canonical string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func extractJWTSubject(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	segment := parts[1]
	payload, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return ""
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return ""
	}
	if sub, ok := parsed["sub"].(string); ok {
		return strings.TrimSpace(sub)
	}
	if uid, ok := parsed["uid"].(string); ok {
		return strings.TrimSpace(uid)
	}
	return ""
}

func (c *Client) signRequestHeaders(req *http.Request, body []byte, secret string, identity string, includeAppID bool) {
	now := time.Now().Unix()
	nonce := uuid.NewString()
	canonical := strings.Join([]string{
		strings.ToUpper(req.Method),
		req.URL.Path,
		canonicalQuery(req.URL.Query()),
		bodySHA256Hex(body),
		strconv.FormatInt(now, 10),
		nonce,
		identity,
	}, "\n")
	signature := signHMACHex(secret, canonical)
	req.Header.Set(signHeaderTimestamp, strconv.FormatInt(now, 10))
	req.Header.Set(signHeaderNonce, nonce)
	req.Header.Set(signHeaderSignature, signature)
	req.Header.Set(signHeaderVersion, signVersionV1)
	if includeAppID {
		req.Header.Set(signHeaderAppID, c.AppID)
	}
}

func (c *Client) signAuthRequestHeaders(req *http.Request, body []byte) error {
	sub := extractJWTSubject(c.AuthToken)
	if sub == "" {
		return fmt.Errorf("invalid auth token subject")
	}
	c.signRequestHeaders(req, body, c.AuthToken, sub, false)
	return nil
}

