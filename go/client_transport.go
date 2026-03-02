package swmsdk

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (c *Client) doRequest(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	if strings.TrimSpace(c.AppID) == "" || strings.TrimSpace(c.AppSecret) == "" {
		return nil, fmt.Errorf("app_id and app_secret required")
	}
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
		if len(body) > 0 {
			req.Header.Set("Content-Type", "application/json")
		}
		c.signRequestHeaders(req, body, c.AppSecret, c.AppID, true)
		resp, err := c.HTTPClient.Do(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		time.Sleep(c.Backoff * time.Duration(1<<attempt))
	}
	return nil, lastErr
}

