package swmsdk

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (c *Client) StartUpdateStream(ctx context.Context, options UpdateStreamOptions, onEvent func(UpdatePushEvent)) (*UpdateWatchHandle, error) {
	if strings.TrimSpace(c.AppID) == "" || strings.TrimSpace(c.AppSecret) == "" {
		return nil, fmt.Errorf("app_id and app_secret required")
	}
	opts := options
	if strings.TrimSpace(opts.ChannelCode) == "" {
		opts.ChannelCode = strings.TrimSpace(c.Channel)
	}
	if strings.TrimSpace(opts.Platform) == "" {
		opts.Platform = strings.TrimSpace(c.Platform)
	}
	if strings.TrimSpace(opts.Arch) == "" {
		opts.Arch = strings.TrimSpace(c.Arch)
	}
	if strings.TrimSpace(opts.DeviceID) == "" {
		opts.DeviceID = strings.TrimSpace(c.DeviceID)
	}
	if strings.TrimSpace(opts.ChannelCode) == "" || strings.TrimSpace(opts.Platform) == "" || strings.TrimSpace(opts.Arch) == "" || strings.TrimSpace(opts.DeviceID) == "" {
		return nil, fmt.Errorf("channel_code/platform/arch/device_id required")
	}
	if opts.ReconnectBackoff <= 0 {
		opts.ReconnectBackoff = 1500 * time.Millisecond
	}
	if opts.ReconnectMaxBackoff <= 0 {
		opts.ReconnectMaxBackoff = 20 * time.Second
	}
	if !opts.Reconnect {
		opts.Reconnect = true
	}
	if !opts.Jitter {
		opts.Jitter = true
	}

	wctx := ctx
	if wctx == nil {
		wctx = context.Background()
	}
	childCtx, cancel := context.WithCancel(wctx)

	go c.consumeUpdateStream(childCtx, opts, onEvent)
	return &UpdateWatchHandle{cancel: cancel}, nil
}

func (c *Client) WatchUpdates(ctx context.Context, options UpdateStreamOptions, onUpdateAvailable func(UpdateCheckResponse)) (*UpdateWatchHandle, error) {
	checkCtx := ctx
	if checkCtx == nil {
		checkCtx = context.Background()
	}
	return c.StartUpdateStream(ctx, options, func(evt UpdatePushEvent) {
		if strings.EqualFold(strings.TrimSpace(evt.EventType), ControlEventShutdown) {
			return
		}
		resp, err := c.CheckUpdate(checkCtx, options.CurrentVersion, options.VersionCode)
		if err != nil {
			if options.OnError != nil {
				options.OnError(err)
			}
			return
		}
		if resp.UpdateAvailable && onUpdateAvailable != nil {
			onUpdateAvailable(resp)
		}
	})
}

func (c *Client) consumeUpdateStream(ctx context.Context, options UpdateStreamOptions, onEvent func(UpdatePushEvent)) {
	backoff := options.ReconnectBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		status, err := c.connectAndReadSSE(ctx, options, onEvent)
		if err != nil && options.OnError != nil {
			options.OnError(err)
		}
		if errors.Is(err, ErrDeviceBlocked) {
			return
		}
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return
		}
		if !options.Reconnect {
			return
		}

		wait := backoff
		if options.Jitter {
			wait += time.Duration(rand.Int63n(int64(wait / 2)))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		backoff *= 2
		if backoff > options.ReconnectMaxBackoff {
			backoff = options.ReconnectMaxBackoff
		}
	}
}

func (c *Client) connectAndReadSSE(ctx context.Context, options UpdateStreamOptions, onEvent func(UpdatePushEvent)) (int, error) {
	streamURL, err := url.Parse(c.BaseURL + "/api/client/updates/stream")
	if err != nil {
		return 0, err
	}
	q := streamURL.Query()
	q.Set("device_id", options.DeviceID)
	q.Set("channel_code", options.ChannelCode)
	q.Set("platform", options.Platform)
	q.Set("arch", options.Arch)
	if strings.TrimSpace(options.CurrentVersion) != "" {
		q.Set("current_version", strings.TrimSpace(options.CurrentVersion))
	}
	if options.VersionCode != nil {
		q.Set("version_code", strconv.Itoa(*options.VersionCode))
	}
	streamURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, streamURL.String(), nil)
	if err != nil {
		return 0, err
	}
	c.signRequestHeaders(req, nil, c.AppSecret, c.AppID, true)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return resp.StatusCode, parseAPIErrorResponse(resp)
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024), 1024*1024)

	eventName := ""
	eventID := ""
	var dataLines []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, ":") {
			continue
		}
		if line == "" {
			if len(dataLines) == 0 {
				eventName = ""
				continue
			}
			if eventName == "" {
				eventName = "message"
			}
			payload := strings.Join(dataLines, "\n")
			if eventName != "connected" && payload != "" {
				var evt UpdatePushEvent
				if err := json.Unmarshal([]byte(payload), &evt); err == nil {
					if evt.ID == "" {
						evt.ID = eventID
					}
					if evt.EventType == "" {
						evt.EventType = eventName
					}
					if (eventName == ControlEventShutdown || evt.EventType == ControlEventShutdown) && options.OnControlEvent != nil {
						options.OnControlEvent(ControlEvent{
							Type:     ControlEventShutdown,
							DeviceID: evt.DeviceID,
							Reason:   evt.Reason,
						})
					}
					if onEvent != nil {
						onEvent(evt)
					}
				}
			}
			eventName = ""
			eventID = ""
			dataLines = dataLines[:0]
			continue
		}
		if strings.HasPrefix(line, "event:") {
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			continue
		}
		if strings.HasPrefix(line, "id:") {
			eventID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		return resp.StatusCode, err
	}
	return resp.StatusCode, nil
}

