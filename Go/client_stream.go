package swm

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"iter"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// WatchUpdates yields verified update-stream events and reconnects according
// to options. A terminal error is yielded once before the sequence ends.
func (c *Client) WatchUpdates(ctx context.Context, options UpdateStreamOptions) iter.Seq2[UpdateEvent, error] {
	if options.ReconnectBackoff <= 0 {
		options.ReconnectBackoff = 1500 * time.Millisecond
	}
	if options.ReconnectMaxBackoff <= 0 {
		options.ReconnectMaxBackoff = 20 * time.Second
	}
	return func(yield func(UpdateEvent, error) bool) {
		if err := c.checkOpen(); err != nil {
			yield(UpdateEvent{}, err)
			return
		}
		attempt := 0
		for {
			if ctx == nil {
				ctx = context.Background()
			}
			err := c.readUpdateStreamOnce(ctx, options, func(event UpdateEvent) bool {
				return yield(event, nil)
			})
			if err == nil || errors.Is(err, errStreamStopped) {
				return
			}
			if !options.Reconnect || !shouldReconnectUpdate(err) {
				yield(UpdateEvent{}, err)
				return
			}
			baseDelay := options.ReconnectBackoff
			if attempt > 0 {
				baseDelay = cycleRetryDelay(attempt)
			}
			delay := baseDelay
			if delay > options.ReconnectMaxBackoff {
				delay = options.ReconnectMaxBackoff
			}
			if options.Jitter {
				half := int64(delay / 2)
				if half > 0 {
					delay += time.Duration(rand.Int63n(half))
				}
			}
			attempt++
			if err := sleepContext(ctx, delay); err != nil {
				return
			}
		}
	}
}

var errStreamStopped = errors.New("stream stopped")

func (c *Client) readUpdateStreamOnce(
	ctx context.Context,
	options UpdateStreamOptions,
	yield func(UpdateEvent) bool,
) error {
	query := url.Values{}
	query.Set("device_id", c.DeviceID())
	query.Set("channel_code", c.options.Channel)
	query.Set("platform", c.options.Platform)
	query.Set("arch", c.options.Arch)
	currentVersion := options.CurrentVersion
	if currentVersion == "" {
		currentVersion = c.options.Version
	}
	query.Set("current_version", currentVersion)
	versionCode := options.VersionCode
	if versionCode == nil {
		versionCode = c.options.VersionCode
	}
	if versionCode != nil {
		query.Set("version_code", strconv.Itoa(*versionCode))
	}
	streamURL, err := c.buildURL("/api/client/updates/stream", query)
	if err != nil {
		return err
	}
	response, requestNonce, err := c.openUpdateStream(ctx, streamURL)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := readBounded(response.Body, 4*1024*1024, ctx)
		return c.throwIfError(protocolResponse{
			status:  response.StatusCode,
			body:    body,
			headers: response.Header.Clone(),
		})
	}
	reader := bufio.NewReaderSize(response.Body, 64*1024)
	eventName := ""
	eventID := ""
	dataLines := make([]string, 0, 2)
	authzVerified := false
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil && len(line) == 0 {
			if errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
				return readErr
			}
			if !authzVerified {
				return newError(KindUnauthorized, "update stream", "authz_invalid", "update stream closed before authorization")
			}
			return newError(KindNetwork, "update stream", "stream_closed", "update stream closed by server")
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if strings.HasPrefix(line, ":") {
			continue
		}
		if line == "" {
			event, verified, err := c.parseSSEMessage(eventName, eventID, dataLines, requestNonce, authzVerified)
			eventName = ""
			eventID = ""
			dataLines = dataLines[:0]
			if err != nil {
				if errors.Is(err, errAuthzExpired) {
					c.clearSession()
					return newError(KindSession, "update stream", "authz_session_expired", "update stream authorization expired")
				}
				return err
			}
			if verified {
				authzVerified = true
			}
			if event != nil && !yield(*event) {
				return errStreamStopped
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "event:"):
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "id:"):
			eventID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		case strings.HasPrefix(line, "data:"):
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
}

func (c *Client) parseSSEMessage(
	eventName, eventID string,
	dataLines []string,
	requestNonce string,
	authzVerified bool,
) (*UpdateEvent, bool, error) {
	if len(dataLines) == 0 || strings.EqualFold(eventName, "connected") {
		return nil, false, nil
	}
	data := []byte(strings.Join(dataLines, "\n"))
	if strings.EqualFold(eventName, "authz_expired") ||
		strings.EqualFold(eventName, "authz-expired") {
		return nil, false, errAuthzExpired
	}
	if strings.EqualFold(eventName, "authz") {
		_, err := c.verifyAuthz(protocolResponse{
			status:  http.StatusOK,
			body:    data,
			nonce:   requestNonce,
			headers: http.Header{},
		}, requestNonce)
		if err != nil {
			return nil, false, err
		}
		return nil, true, nil
	}
	if !authzVerified {
		return nil, false, nil
	}
	verifiedData, err := c.verifyAuthz(protocolResponse{
		status:  http.StatusOK,
		body:    data,
		nonce:   requestNonce,
		headers: http.Header{},
	}, requestNonce)
	if err != nil {
		return nil, false, err
	}
	var event UpdateEvent
	if err := json.Unmarshal(verifiedData, &event); err != nil {
		return nil, false, wrapError(KindProtocol, "update stream event", err)
	}
	if event.ID == "" {
		event.ID = eventID
	}
	if event.EventType == "" {
		event.EventType = eventName
	}
	return &event, true, nil
}

var errAuthzExpired = errors.New("authz expired")

func (c *Client) openUpdateStream(ctx context.Context, streamURL *url.URL) (*http.Response, string, error) {
	if !c.clock.isInitialized() {
		if err := c.refreshTrustedTime(ctx); err != nil {
			return nil, "", err
		}
	}
	session, err := c.ensureSession()
	if err != nil {
		return nil, "", err
	}
	nonce, err := randomUUID()
	if err != nil {
		return nil, "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, streamURL.String(), nil)
	if err != nil {
		return nil, "", wrapError(KindNetwork, "update stream", err)
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set(headerAppID, c.options.AppID)
	request.Header.Set(headerTimestamp, strconv.FormatInt(c.clock.nowUnixSeconds(), 10))
	request.Header.Set(headerNonce, nonce)
	request.Header.Set(headerCapability, "v3")
	request.Header.Set(headerReleaseID, c.options.ReleaseID)
	request.Header.Set(headerClientVersion, c.options.Version)
	request.Header.Set(headerVersionCode, versionCodeString(c.options.VersionCode))
	proof, err := c.createDPoP(http.MethodGet, streamURL.String(), session, nil)
	if err != nil {
		return nil, "", err
	}
	request.Header.Set(headerSession, session)
	request.Header.Set(headerDPoP, proof)
	response, err := c.http.Do(request)
	if err != nil {
		return nil, "", wrapError(KindNetwork, "update stream", err)
	}
	return response, nonce, nil
}

func shouldReconnectUpdate(err error) bool {
	if err == nil {
		return true
	}
	var sdkErr *Error
	if !errors.As(err, &sdkErr) {
		return true
	}
	switch sdkErr.Kind {
	case KindDeviceBlocked, KindUnsupportedVersion, KindUpdateRegionBlocked,
		KindUnauthorized, KindIntegrity:
		return false
	default:
		return true
	}
}

func cycleRetryDelay(attempt int) time.Duration {
	delays := []time.Duration{1500 * time.Millisecond, 3 * time.Second, 6 * time.Second, 20 * time.Second}
	if attempt < 1 {
		return delays[0]
	}
	if attempt >= len(delays) {
		return delays[len(delays)-1]
	}
	return delays[attempt]
}
