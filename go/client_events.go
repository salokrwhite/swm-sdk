package swmsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (c *Client) ReportEvent(ctx context.Context, eventName string, props map[string]interface{}) error {
	event := Event{
		DeviceID:    c.DeviceID,
		EventName:   eventName,
		EventTime:   time.Now(),
		ChannelCode: c.Channel,
		Properties:  props,
		Attributes:  c.Attributes,
	}
	body, _ := json.Marshal(event)
	resp, err := c.doRequest(ctx, http.MethodPost, "/api/client/events", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return parseAPIErrorResponse(resp)
	}
	return nil
}

func (c *Client) ReportHeartbeat(ctx context.Context, appVersion string) error {
	if strings.TrimSpace(c.DeviceID) == "" {
		return fmt.Errorf("device_id required")
	}
	payload := map[string]interface{}{
		"device_id": c.DeviceID,
	}
	if c.Channel != "" {
		payload["channel_code"] = c.Channel
	}
	if appVersion != "" {
		payload["app_version"] = appVersion
	}
	if c.Platform != "" {
		payload["platform"] = c.Platform
	}
	if c.Arch != "" {
		payload["arch"] = c.Arch
	}
	if c.Attributes != nil && len(c.Attributes) > 0 {
		payload["attributes"] = c.Attributes
	}
	body, _ := json.Marshal(payload)
	resp, err := c.doRequest(ctx, http.MethodPost, "/api/client/heartbeat", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return parseAPIErrorResponse(resp)
	}
	return nil
}

func (c *Client) ReportEvents(ctx context.Context, events []Event) error {
	payload := map[string]interface{}{
		"events":  events,
	}
	body, _ := json.Marshal(payload)
	resp, err := c.doRequest(ctx, http.MethodPost, "/api/client/events", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return parseAPIErrorResponse(resp)
	}
	return nil
}

func (c *Client) ReportFeedback(ctx context.Context, content string, rating *int, contact string, attachments []string, metadata map[string]interface{}) error {
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("content required")
	}
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	_ = writer.WriteField("device_id", c.DeviceID)
	if c.Channel != "" {
		_ = writer.WriteField("channel_code", c.Channel)
	}
	if rating != nil {
		_ = writer.WriteField("rating", strconv.Itoa(*rating))
	}
	_ = writer.WriteField("content", content)
	if contact != "" {
		_ = writer.WriteField("contact", contact)
	}

	combined := map[string]interface{}{}
	for k, v := range metadata {
		combined[k] = v
	}
	if len(c.Attributes) > 0 {
		if _, ok := combined["attributes"]; !ok {
			combined["attributes"] = c.Attributes
		}
	}
	if v, ok := combined["app_version"].(string); ok && v != "" {
		_ = writer.WriteField("app_version", v)
	}
	if len(combined) > 0 {
		if payload, err := json.Marshal(combined); err == nil {
			_ = writer.WriteField("metadata", string(payload))
		}
	}

	for _, filePath := range attachments {
		filePath = strings.TrimSpace(filePath)
		if filePath == "" {
			continue
		}
		file, err := os.Open(filePath)
		if err != nil {
			return err
		}
		func() {
			defer file.Close()
			part, err := writer.CreateFormFile("attachments", filepath.Base(filePath))
			if err != nil {
				return
			}
			_, _ = io.Copy(part, file)
		}()
	}

	_ = writer.Close()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/client/feedback", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	c.signRequestHeaders(req, buf.Bytes(), c.AppSecret, c.AppID, true)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return parseAPIErrorResponse(resp)
	}
	return nil
}

