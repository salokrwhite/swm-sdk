package swm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	maximumFeedbackPayload     = 32 * 1024 * 1024
	maximumFeedbackAttachments = 3
	maximumAttachmentBytes     = 5 * 1024 * 1024
)

// SubmitFeedback uploads multipart feedback.
func (c *Client) SubmitFeedback(ctx context.Context, request FeedbackRequest) (FeedbackResult, error) {
	if err := c.checkOpen(); err != nil {
		return FeedbackResult{}, err
	}
	if strings.TrimSpace(request.Content) == "" {
		return FeedbackResult{}, newError(KindValidation, "feedback", "feedback_content_required", "feedback content is required")
	}
	if request.Rating != nil && (*request.Rating < 1 || *request.Rating > 5) {
		return FeedbackResult{}, newError(KindValidation, "feedback", "feedback_rating_invalid", "feedback rating must be between 1 and 5")
	}
	body, contentType, err := c.buildFeedbackPayload(request)
	if err != nil {
		return FeedbackResult{}, err
	}
	var result FeedbackResult
	if err := c.sendAndVerify(ctx, protocolRequest{
		operation:          opFeedback,
		method:             http.MethodPost,
		path:               "/api/client/feedback",
		body:               body,
		contentType:        contentType,
		encryptBody:        true,
		requireSession:     true,
		requireTrustedTime: true,
		requireOnlineKey:   true,
	}, &result); err != nil {
		return FeedbackResult{}, err
	}
	return result, nil
}

func (c *Client) buildFeedbackPayload(request FeedbackRequest) ([]byte, string, error) {
	if len(request.AttachmentPaths) > maximumFeedbackAttachments {
		return nil, "", newError(KindValidation, "feedback", "feedback_attachments_limit", "feedback supports at most 3 attachments")
	}
	var buffer bytes.Buffer
	writer := multipart.NewWriter(&buffer)
	writeField := func(name, value string) error {
		return writer.WriteField(name, value)
	}
	if err := writeField("device_id", c.DeviceID()); err != nil {
		return nil, "", wrapError(KindProtocol, "feedback", err)
	}
	if err := writeField("channel_code", c.options.Channel); err != nil {
		return nil, "", wrapError(KindProtocol, "feedback", err)
	}
	if err := writeField("content", request.Content); err != nil {
		return nil, "", wrapError(KindProtocol, "feedback", err)
	}
	if request.Rating != nil {
		if err := writeField("rating", strconv.Itoa(*request.Rating)); err != nil {
			return nil, "", wrapError(KindProtocol, "feedback", err)
		}
	}
	if request.Contact != "" {
		if err := writeField("contact", request.Contact); err != nil {
			return nil, "", wrapError(KindProtocol, "feedback", err)
		}
	}
	appVersion := request.AppVersion
	if appVersion == "" {
		appVersion = c.options.Version
	}
	if appVersion != "" {
		if err := writeField("app_version", appVersion); err != nil {
			return nil, "", wrapError(KindProtocol, "feedback", err)
		}
	}
	if len(request.Metadata) > 0 {
		metadata, err := json.Marshal(request.Metadata)
		if err != nil {
			return nil, "", wrapError(KindProtocol, "feedback metadata", err)
		}
		if err := writeField("metadata", string(metadata)); err != nil {
			return nil, "", wrapError(KindProtocol, "feedback", err)
		}
	}
	for _, path := range request.AttachmentPaths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, "", wrapError(KindValidation, "feedback attachment", err)
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, "", wrapError(KindValidation, "feedback attachment", err)
		}
		if info.Size() > maximumAttachmentBytes {
			_ = file.Close()
			return nil, "", newError(KindValidation, "feedback attachment", "feedback_attachment_too_large", "feedback attachment exceeds 5 MiB")
		}
		if int64(buffer.Len())+info.Size() > maximumFeedbackPayload {
			_ = file.Close()
			return nil, "", newError(KindValidation, "feedback", "feedback_payload_too_large", "feedback payload exceeds 32 MiB")
		}
		part, err := writer.CreateFormFile("attachments", filepath.Base(path))
		if err != nil {
			_ = file.Close()
			return nil, "", wrapError(KindProtocol, "feedback attachment", err)
		}
		if _, err := ioCopyContext(part, file); err != nil {
			_ = file.Close()
			return nil, "", wrapError(KindProtocol, "feedback attachment", err)
		}
		_ = file.Close()
	}
	if err := writer.Close(); err != nil {
		return nil, "", wrapError(KindProtocol, "feedback", err)
	}
	if buffer.Len() > maximumFeedbackPayload {
		return nil, "", newError(KindValidation, "feedback", "feedback_payload_too_large", "feedback payload exceeds 32 MiB")
	}
	return buffer.Bytes(), writer.FormDataContentType(), nil
}

func ioCopyContext(destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 128*1024)
	var written int64
	for {
		count, readErr := source.Read(buffer)
		if count > 0 {
			writtenCount, writeErr := destination.Write(buffer[:count])
			written += int64(writtenCount)
			if writeErr != nil {
				return written, writeErr
			}
		}
		if readErr == io.EOF {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
	}
}
