package swmsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (c *Client) ensureAuthToken() error {
	if strings.TrimSpace(c.AuthToken) == "" {
		return fmt.Errorf("auth token required, call SetAuthToken first")
	}
	return nil
}

func (c *Client) doAuthRequest(ctx context.Context, method, path string, query url.Values, body io.Reader, contentType string) (*http.Response, error) {
	if err := c.ensureAuthToken(); err != nil {
		return nil, err
	}
	fullURL := c.BaseURL + path
	if query != nil && len(query) > 0 {
		fullURL += "?" + query.Encode()
	}

	var bodyBytes []byte
	var err error
	if body != nil {
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return nil, err
		}
	}

	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(bodyBytes))
		req.Header.Set("Authorization", "Bearer "+c.AuthToken)
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if err := c.signAuthRequestHeaders(req, bodyBytes); err != nil {
			return nil, err
		}
		resp, reqErr := c.HTTPClient.Do(req)
		if reqErr == nil {
			return resp, nil
		}
		lastErr = reqErr
		time.Sleep(c.Backoff * time.Duration(1<<attempt))
	}
	return nil, lastErr
}

func parseErrorResponse(resp *http.Response) error {
	if resp.StatusCode < 300 {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var errBody apiErrorBody
	if json.Unmarshal(body, &errBody) == nil && strings.TrimSpace(errBody.Error) != "" {
		return fmt.Errorf("api request failed: %s (%s)", errBody.Error, resp.Status)
	}
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = resp.Status
	}
	return fmt.Errorf("api request failed: %s", msg)
}

func decodeJSONResponse[T any](resp *http.Response) (T, error) {
	var out T
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return out, parseErrorResponse(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, err
	}
	return out, nil
}

func (c *Client) doAuthJSON(ctx context.Context, method, path string, query url.Values, payload interface{}) (*http.Response, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	return c.doAuthRequest(ctx, method, path, query, body, "application/json")
}

