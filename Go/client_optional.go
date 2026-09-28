package swm

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"strings"
	"unicode/utf8"
)

// ResolveFirmwareIdentity performs a first-party firmware metadata lookup.
func (c *Client) ResolveFirmwareIdentity(ctx context.Context, metadata map[string]string) (json.RawMessage, error) {
	allowed := map[string]struct{}{
		"ota_target_version": {},
		"version_name":       {},
		"post_build":         {},
		"oplus_rom_version":  {},
		"android_version":    {},
		"post_sdk_level":     {},
	}
	normalized := make(map[string]string)
	for key, value := range metadata {
		if _, ok := allowed[key]; !ok || value == "" {
			continue
		}
		if len(value) > 512 {
			return nil, newError(KindValidation, "firmware identity", "firmware_metadata_invalid", "firmware metadata field is invalid: "+key)
		}
		normalized[key] = value
	}
	if len(normalized) == 0 {
		return nil, newError(KindValidation, "firmware identity", "firmware_metadata_required", "firmware metadata must contain at least one supported field")
	}
	body, err := json.Marshal(normalized)
	if err != nil {
		return nil, wrapError(KindProtocol, "firmware identity", err)
	}
	response, err := c.sendWebOperation(
		ctx, http.MethodPost, "/api/v1/device-models/resolve", body,
		opFirmwareIdentity, nil, "", "",
	)
	if err != nil {
		return nil, err
	}
	if err := c.throwIfError(response); err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), response.body...), nil
}

type debugEnrollWireRequest struct {
	Ticket     string `json:"ticket"`
	AppID      string `json:"app_id"`
	ReleaseID  string `json:"release_id"`
	SessionID  string `json:"session_id"`
	PCID       string `json:"pcid"`
	AppVersion string `json:"app_version"`
}

type debugEnrollWireResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ExpiresAt    int64  `json:"expires_at"`
}

type debugCreateWireRequest struct {
	SessionID  string `json:"session_id"`
	PCID       string `json:"pcid"`
	AppVersion string `json:"app_version"`
	Note       string `json:"note"`
}

type debugCreateWireResponse struct {
	RequestID  string `json:"request_id"`
	WatchToken string `json:"watch_token"`
	ExpiresAt  int64  `json:"expires_at"`
}

// CreateDebugRequest creates a one-time debug approval workflow.
func (c *Client) CreateDebugRequest(ctx context.Context, note string) (DebugRequestTicket, error) {
	if utf8.RuneCountInString(note) < 2 || utf8.RuneCountInString(note) > 200 {
		return DebugRequestTicket{}, newError(KindValidation, "debug request", "debug_note_invalid", "debug note must contain 2 to 200 characters")
	}
	sessionBytes, err := randomBytes(32)
	if err != nil {
		return DebugRequestTicket{}, err
	}
	sessionID := base64URLEncode(sessionBytes)
	enrollment, err := c.RequestEnrollmentTicket(ctx, "debug")
	if err != nil {
		return DebugRequestTicket{}, err
	}
	enrollBody, err := json.Marshal(debugEnrollWireRequest{
		Ticket:     enrollment.Ticket,
		AppID:      c.options.AppID,
		ReleaseID:  c.options.ReleaseID,
		SessionID:  sessionID,
		PCID:       c.DeviceID(),
		AppVersion: c.options.Version,
	})
	if err != nil {
		return DebugRequestTicket{}, wrapError(KindProtocol, "debug enrollment", err)
	}
	enrollResponse, err := c.sendWebPublic(ctx, "/api/v1/client/debug-enroll", enrollBody, opDebugProtocol)
	if err != nil {
		return DebugRequestTicket{}, err
	}
	if err := c.throwIfError(enrollResponse); err != nil {
		return DebugRequestTicket{}, err
	}
	var enrolled debugEnrollWireResponse
	if err := json.Unmarshal(enrollResponse.body, &enrolled); err != nil {
		return DebugRequestTicket{}, wrapError(KindProtocol, "debug enrollment", err)
	}
	now := c.clock.nowUnixSeconds()
	if enrolled.ClientID == "" || enrolled.ClientSecret == "" ||
		enrolled.ExpiresAt <= now || enrolled.ExpiresAt > now+5*60+5 {
		return DebugRequestTicket{}, newError(KindProtocol, "debug enrollment", "debug_enrollment_invalid", "debug enrollment response is invalid")
	}
	credentials := debugCredentials{
		ClientID:     enrolled.ClientID,
		ClientSecret: enrolled.ClientSecret,
		ExpiresAt:    enrolled.ExpiresAt,
	}
	createBody, err := json.Marshal(debugCreateWireRequest{
		SessionID:  sessionID,
		PCID:       c.DeviceID(),
		AppVersion: c.options.Version,
		Note:       note,
	})
	if err != nil {
		return DebugRequestTicket{}, wrapError(KindProtocol, "debug request", err)
	}
	createResponse, err := c.sendWebOperation(
		ctx, http.MethodPost, "/api/v1/client/debug-requests", createBody,
		opDebugProtocol, &credentials, "", "",
	)
	if err != nil {
		return DebugRequestTicket{}, err
	}
	if err := c.throwIfError(createResponse); err != nil {
		return DebugRequestTicket{}, err
	}
	var created debugCreateWireResponse
	if err := json.Unmarshal(createResponse.body, &created); err != nil {
		return DebugRequestTicket{}, wrapError(KindProtocol, "debug request", err)
	}
	if !isUUID(created.RequestID) || created.WatchToken == "" ||
		created.ExpiresAt <= now || created.ExpiresAt > now+5*60+5 {
		return DebugRequestTicket{}, newError(KindProtocol, "debug request", "debug_create_invalid", "debug create response is invalid")
	}
	return DebugRequestTicket{
		RequestID:   created.RequestID,
		WatchToken:  created.WatchToken,
		ExpiresAt:   created.ExpiresAt,
		credentials: credentials,
		sessionID:   sessionID,
	}, nil
}

// CancelDebugRequest cancels a pending debug request.
func (c *Client) CancelDebugRequest(ctx context.Context, ticket DebugRequestTicket) error {
	if ticket.RequestID == "" || ticket.WatchToken == "" || ticket.credentials.ClientID == "" {
		return newError(KindValidation, "debug cancel", "debug_ticket_invalid", "debug ticket is incomplete")
	}
	path := "/api/v1/client/debug-requests/" + ticket.RequestID + "/cancel"
	response, err := c.sendWebOperation(
		ctx, http.MethodPost, path, nil,
		opDebugProtocol, &ticket.credentials, ticket.WatchToken, ticket.RequestID,
	)
	if err != nil {
		return err
	}
	return c.throwIfError(response)
}

// WatchDebugRequest yields verified debug decisions until a terminal state.
func (c *Client) WatchDebugRequest(
	ctx context.Context,
	ticket DebugRequestTicket,
) iter.Seq2[DebugDecisionEvent, error] {
	return func(yield func(DebugDecisionEvent, error) bool) {
		if ticket.RequestID == "" || ticket.WatchToken == "" ||
			ticket.credentials.ClientID == "" || ticket.sessionID == "" {
			yield(DebugDecisionEvent{}, newError(KindValidation, "debug watch", "debug_ticket_invalid", "debug ticket is incomplete"))
			return
		}
		response, requestNonce, err := c.openDebugEventStream(
			ctx,
			ticket.credentials,
			ticket.RequestID,
			ticket.WatchToken,
		)
		if err != nil {
			yield(DebugDecisionEvent{}, err)
			return
		}
		defer response.Body.Close()
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			body, _ := readBounded(response.Body, 4*1024*1024, ctx)
			yield(DebugDecisionEvent{}, c.throwIfError(protocolResponse{
				status:  response.StatusCode,
				body:    body,
				headers: response.Header.Clone(),
			}))
			return
		}
		reader := bufio.NewReaderSize(response.Body, 64*1024)
		eventName := ""
		dataLines := make([]string, 0, 2)
		expectedSessionHash := sha256Hex([]byte(ticket.sessionID))
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil && len(line) == 0 {
				if errors.Is(readErr, context.Canceled) || errors.Is(readErr, context.DeadlineExceeded) {
					yield(DebugDecisionEvent{}, wrapError(KindTimeout, "debug watch", readErr))
				}
				return
			}
			line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
			if strings.HasPrefix(line, ":") {
				continue
			}
			if line == "" {
				if len(dataLines) > 0 &&
					(eventName == "debug-request-state" || eventName == "debug_request_state") {
					decision, terminal, err := c.decodeDebugDecision(
						requestNonce,
						ticket.RequestID,
						expectedSessionHash,
						[]byte(strings.Join(dataLines, "\n")),
					)
					if err != nil {
						yield(DebugDecisionEvent{}, err)
						return
					}
					if !yield(decision, nil) {
						return
					}
					if terminal {
						return
					}
				}
				eventName = ""
				dataLines = dataLines[:0]
				continue
			}
			switch {
			case strings.HasPrefix(line, "event:"):
				eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
	}
}

func (c *Client) decodeDebugDecision(
	requestNonce, expectedRequestID, expectedSessionHash string,
	carrier []byte,
) (DebugDecisionEvent, bool, error) {
	data, err := c.verifyAuthz(protocolResponse{
		status:  http.StatusOK,
		body:    carrier,
		nonce:   requestNonce,
		headers: http.Header{},
	}, requestNonce)
	if err != nil {
		return DebugDecisionEvent{}, false, err
	}
	var payload struct {
		Version       string `json:"version"`
		RequestID     string `json:"request_id"`
		SessionIDHash string `json:"session_id_hash"`
		Status        string `json:"status"`
		Reason        string `json:"reason"`
		ExpiresAt     int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return DebugDecisionEvent{}, false, wrapError(KindProtocol, "debug decision", err)
	}
	if payload.Version != "debug_decision_v1" ||
		payload.RequestID != expectedRequestID ||
		!strings.EqualFold(payload.SessionIDHash, expectedSessionHash) ||
		(payload.Status != "pending" && payload.Status != "approved" &&
			payload.Status != "rejected" && payload.Status != "cancelled") ||
		payload.ExpiresAt <= 0 {
		return DebugDecisionEvent{}, false, newError(KindProtocol, "debug decision", "debug_decision_invalid", "debug decision payload is invalid")
	}
	decision := DebugDecisionEvent{
		State:  payload.Status,
		Reason: payload.Reason,
	}
	if payload.Status == "approved" {
		decision.AuthorizationExpiresAt = payload.ExpiresAt
	}
	terminal := payload.Status == "approved" ||
		payload.Status == "rejected" ||
		payload.Status == "cancelled"
	return decision, terminal, nil
}
