package swmsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func (c *Client) doRequest(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	resp, _, err := c.doRequestCapturingNonce(ctx, method, path, body)
	return resp, err
}

// doRequestCapturingNonce is doRequest but also returns the X-Nonce that was sent
// on the successful attempt, so callers can verify a server response is bound to
// that challenge.
func (c *Client) doRequestCapturingNonce(ctx context.Context, method, path string, body []byte) (*http.Response, string, error) {
	if strings.TrimSpace(c.AppID) == "" || strings.TrimSpace(c.AppSecret) == "" {
		return nil, "", fmt.Errorf("app_id and app_secret required")
	}
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		nonce := c.signRequestHeaders(req, body, c.AppSecret, c.AppID, true)
		resp, err := c.HTTPClient.Do(req)
		if err == nil {
			return resp, nonce, nil
		}
		lastErr = err
		time.Sleep(c.Backoff * time.Duration(1<<attempt))
	}
	return nil, "", lastErr
}

// verifyResponseAuthz reads the response body, extracts the authz envelope, and
// enforces it (no-op when RequireAuthz is false). Used by endpoints whose body is
// otherwise ignored (heartbeat/events/feedback).
func (c *Client) verifyResponseAuthz(resp *http.Response, nonce string) error {
	if !c.RequireAuthz {
		return nil
	}
	var parsed struct {
		Authz *AuthzEnvelope `json:"authz"`
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &parsed)
	return c.verifyAuthz(parsed.Authz, nonce)
}
