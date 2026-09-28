package swm

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// ReportEvent submits one analytics event.
func (c *Client) ReportEvent(ctx context.Context, eventName string, properties map[string]any) error {
	return c.ReportEvents(ctx, []Event{{
		EventName:  eventName,
		EventTime:  time.Now().UTC(),
		Properties: properties,
	}})
}

// ReportEvents submits one or more analytics events.
func (c *Client) ReportEvents(ctx context.Context, events []Event) error {
	if err := c.checkOpen(); err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	normalized := make([]Event, 0, len(events))
	for _, event := range events {
		if strings.TrimSpace(event.EventName) == "" {
			return newError(KindValidation, "events", "event_name_required", "event_name is required")
		}
		if event.DeviceID == "" {
			event.DeviceID = c.DeviceID()
		}
		if event.ChannelCode == "" {
			event.ChannelCode = c.options.Channel
		}
		if event.EventTime.IsZero() {
			event.EventTime = time.Now().UTC()
		}
		if event.Attributes == nil {
			event.Attributes = map[string]any{}
		}
		normalized = append(normalized, event)
	}
	var body []byte
	var err error
	if len(normalized) == 1 {
		body, err = json.Marshal(normalized[0])
	} else {
		body, err = json.Marshal(struct {
			Events []Event `json:"events"`
		}{Events: normalized})
	}
	if err != nil {
		return wrapError(KindProtocol, "events", err)
	}
	var ignored json.RawMessage
	return c.sendAndVerify(ctx, protocolRequest{
		operation:          opEvents,
		method:             http.MethodPost,
		path:               "/api/client/events",
		body:               body,
		encryptBody:        true,
		requireSession:     true,
		requireTrustedTime: true,
		requireOnlineKey:   true,
	}, &ignored)
}
