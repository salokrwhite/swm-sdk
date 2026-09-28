package swm

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (c *Client) sendWebOperation(
	ctx context.Context,
	method, path string,
	body []byte,
	operation operationClass,
	credentials *debugCredentials,
	watchToken, requestID string,
) (protocolResponse, error) {
	if err := c.checkOpen(); err != nil {
		return protocolResponse{}, err
	}
	if !c.clock.isInitialized() {
		if err := c.refreshTrustedTime(ctx); err != nil {
			return protocolResponse{}, err
		}
	}
	session, err := c.ensureSession()
	if err != nil {
		return protocolResponse{}, err
	}
	uri, err := c.buildWebURL(path)
	if err != nil {
		return protocolResponse{}, err
	}
	policy := policyFor(operation)
	started := time.Now()
	var lastError error
	for attempt := 0; attempt <= policy.retries; attempt++ {
		response, err := c.sendWebAttempt(ctx, method, uri, body, session, credentials, watchToken, requestID, policy)
		if err == nil {
			if response.status >= 200 && response.status < 400 {
				return response, nil
			}
			if isTransientStatus(response.status) && attempt < policy.retries {
				delay := parseRetryAfter(response.headers)
				if delay <= 0 {
					delay = backoff(policy, attempt)
				}
				if !canWait(policy, started, delay, attempt) {
					return response, nil
				}
				if err := sleepContext(ctx, delay); err != nil {
					return protocolResponse{}, err
				}
				continue
			}
			return response, nil
		}
		lastError = err
		if attempt >= policy.retries {
			break
		}
		if err := sleepContext(ctx, backoff(policy, attempt)); err != nil {
			return protocolResponse{}, err
		}
	}
	return protocolResponse{}, wrapError(KindNetwork, string(operation), lastError)
}

func (c *Client) sendWebAttempt(
	ctx context.Context,
	method string,
	uri *url.URL,
	body []byte,
	session string,
	credentials *debugCredentials,
	watchToken, requestID string,
	policy requestPolicy,
) (protocolResponse, error) {
	requestContext := ctx
	cancel := func() {}
	if policy.timeout > 0 {
		requestContext, cancel = context.WithTimeout(ctx, policy.timeout)
	}
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, method, uri.String(), bytes.NewReader(body))
	if err != nil {
		return protocolResponse{}, wrapError(KindNetwork, "web request", err)
	}
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	proof, err := c.createDPoP(method, uri.String(), session, body)
	if err != nil {
		return protocolResponse{}, err
	}
	request.Header.Set(headerSession, session)
	request.Header.Set(headerDPoP, proof)
	if credentials != nil {
		timestamp := strconv.FormatInt(c.clock.nowUnixSeconds(), 10)
		nonce, err := randomUUID()
		if err != nil {
			return protocolResponse{}, err
		}
		signature := createDebugHMAC(
			credentials.ClientSecret,
			method,
			uri.EscapedPath(),
			body,
			timestamp,
			nonce,
			credentials.ClientID,
		)
		request.Header.Set("X-Client-ID", credentials.ClientID)
		request.Header.Set("X-Timestamp", timestamp)
		request.Header.Set("X-Nonce", nonce)
		request.Header.Set("X-Signature-Version", "1")
		request.Header.Set("X-Signature", signature)
	}
	if watchToken != "" {
		request.Header.Set("X-Debug-Watch-Token", watchToken)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return protocolResponse{}, wrapError(KindNetwork, "web request", err)
	}
	defer response.Body.Close()
	responseBody, err := readBounded(response.Body, 4*1024*1024, requestContext)
	if err != nil {
		return protocolResponse{}, wrapError(KindProtocol, "web response", err)
	}
	return protocolResponse{
		status:  response.StatusCode,
		body:    responseBody,
		headers: response.Header.Clone(),
	}, nil
}

func (c *Client) sendWebPublic(
	ctx context.Context,
	path string,
	body []byte,
	operation operationClass,
) (protocolResponse, error) {
	if err := c.checkOpen(); err != nil {
		return protocolResponse{}, err
	}
	uri, err := c.buildWebURL(path)
	if err != nil {
		return protocolResponse{}, err
	}
	policy := policyFor(operation)
	started := time.Now()
	var lastError error
	for attempt := 0; attempt <= policy.retries; attempt++ {
		requestContext := ctx
		cancel := func() {}
		if policy.timeout > 0 {
			requestContext, cancel = context.WithTimeout(ctx, policy.timeout)
		}
		request, err := http.NewRequestWithContext(requestContext, http.MethodPost, uri.String(), bytes.NewReader(body))
		if err != nil {
			cancel()
			return protocolResponse{}, wrapError(KindNetwork, "public web request", err)
		}
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
		response, err := c.http.Do(request)
		if err == nil {
			responseBody, readErr := readBounded(response.Body, 4*1024*1024, requestContext)
			_ = response.Body.Close()
			cancel()
			if readErr != nil {
				return protocolResponse{}, wrapError(KindProtocol, "public web response", readErr)
			}
			result := protocolResponse{
				status:  response.StatusCode,
				body:    responseBody,
				headers: response.Header.Clone(),
			}
			if (result.status >= 200 && result.status < 400) ||
				!isTransientStatus(result.status) ||
				attempt >= policy.retries {
				return result, nil
			}
			if err := sleepContext(ctx, backoff(policy, attempt)); err != nil {
				return protocolResponse{}, err
			}
			continue
		}
		cancel()
		lastError = err
		if attempt >= policy.retries || !canWait(policy, started, backoff(policy, attempt), attempt) {
			break
		}
		if err := sleepContext(ctx, backoff(policy, attempt)); err != nil {
			return protocolResponse{}, err
		}
	}
	return protocolResponse{}, wrapError(KindNetwork, "public web request", lastError)
}

func (c *Client) openDebugEventStream(
	ctx context.Context,
	credentials debugCredentials,
	requestID, watchToken string,
) (*http.Response, string, error) {
	if !c.clock.isInitialized() {
		if err := c.refreshTrustedTime(ctx); err != nil {
			return nil, "", err
		}
	}
	session, err := c.ensureSession()
	if err != nil {
		return nil, "", err
	}
	path := "/api/v1/client/debug-requests/" + url.PathEscape(requestID) + "/events"
	uri, err := c.buildWebURL(path)
	if err != nil {
		return nil, "", err
	}
	nonce, err := randomUUID()
	if err != nil {
		return nil, "", err
	}
	timestamp := strconv.FormatInt(c.clock.nowUnixSeconds(), 10)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, uri.String(), nil)
	if err != nil {
		return nil, "", wrapError(KindNetwork, "debug stream", err)
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("X-Client-ID", credentials.ClientID)
	request.Header.Set("X-Timestamp", timestamp)
	request.Header.Set("X-Nonce", nonce)
	request.Header.Set("X-Signature-Version", "1")
	request.Header.Set(
		"X-Signature",
		createDebugHMAC(credentials.ClientSecret, http.MethodGet, uri.EscapedPath(), nil, timestamp, nonce, credentials.ClientID),
	)
	request.Header.Set("X-Debug-Watch-Token", watchToken)
	proof, err := c.createDPoP(http.MethodGet, uri.String(), session, nil)
	if err != nil {
		return nil, "", err
	}
	request.Header.Set(headerSession, session)
	request.Header.Set(headerDPoP, proof)
	response, err := c.http.Do(request)
	if err != nil {
		return nil, "", wrapError(KindNetwork, "debug stream", err)
	}
	return response, nonce, nil
}

func createDebugHMAC(secret, method, path string, body []byte, timestamp, nonce, clientID string) string {
	canonical := strings.Join([]string{
		method,
		path,
		"",
		sha256Hex(body),
		timestamp,
		nonce,
		clientID,
	}, "\n")
	return hmacSHA256Hex(secret, canonical)
}
