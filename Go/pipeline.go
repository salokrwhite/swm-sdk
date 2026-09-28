package swm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type operationClass string

const (
	opTrustedTime            operationClass = "trusted_time"
	opOnlineKeyManifest      operationClass = "online_key_manifest"
	opUpdateCheck            operationClass = "update_check"
	opHeartbeat              operationClass = "heartbeat"
	opEvents                 operationClass = "events"
	opFeedback               operationClass = "feedback"
	opEnrollmentTicket       operationClass = "enrollment_ticket"
	opDeviceKeyRotation      operationClass = "device_key_rotation"
	opOperationAuthorization operationClass = "operation_authorization"
	opOperationGrantConsume  operationClass = "operation_grant_consume"
	opDownload               operationClass = "download"
	opUpdateStream           operationClass = "update_stream"
	opFirmwareIdentity       operationClass = "firmware_identity"
	opDebugProtocol          operationClass = "debug_protocol"
	opDebugStream            operationClass = "debug_stream"
)

type requestPolicy struct {
	timeout    time.Duration
	retries    int
	backoff    time.Duration
	backoffMax time.Duration
	deadline   time.Duration
}

func policyFor(operation operationClass) requestPolicy {
	switch operation {
	case opTrustedTime:
		return requestPolicy{10 * time.Second, 2, time.Second, 4 * time.Second, 40 * time.Second}
	case opOnlineKeyManifest:
		return requestPolicy{10 * time.Second, 2, time.Second, 4 * time.Second, 40 * time.Second}
	case opUpdateCheck:
		return requestPolicy{15 * time.Second, 2, 1500 * time.Millisecond, 6 * time.Second, 60 * time.Second}
	case opHeartbeat:
		return requestPolicy{8 * time.Second, 2, time.Second, 4 * time.Second, 30 * time.Second}
	case opOperationAuthorization:
		return requestPolicy{10 * time.Second, 2, time.Second, 4 * time.Second, 36 * time.Second}
	case opOperationGrantConsume:
		return requestPolicy{10 * time.Second, 1, time.Second, 2 * time.Second, 24 * time.Second}
	case opEvents:
		return requestPolicy{8 * time.Second, 1, time.Second, 2 * time.Second, 20 * time.Second}
	case opFeedback:
		return requestPolicy{10 * time.Second, 1, time.Second, 2 * time.Second, 24 * time.Second}
	case opEnrollmentTicket, opDeviceKeyRotation:
		return requestPolicy{10 * time.Second, 1, time.Second, 2 * time.Second, 24 * time.Second}
	case opDownload:
		return requestPolicy{30 * time.Second, 2, 2 * time.Second, 8 * time.Second, 0}
	case opUpdateStream:
		return requestPolicy{30 * time.Second, 0, 0, 0, 0}
	case opFirmwareIdentity, opDebugProtocol:
		return requestPolicy{8 * time.Second, 1, 500 * time.Millisecond, time.Second, 20 * time.Second}
	case opDebugStream:
		return requestPolicy{8 * time.Second, 1, 500 * time.Millisecond, time.Second, 20 * time.Second}
	default:
		return requestPolicy{8 * time.Second, 1, time.Second, 2 * time.Second, 20 * time.Second}
	}
}

type protocolRequest struct {
	operation          operationClass
	method             string
	path               string
	query              url.Values
	body               []byte
	encryptBody        bool
	requireSession     bool
	requireTrustedTime bool
	requireOnlineKey   bool
	contentType        string
	dpopResource       string
}

type protocolResponse struct {
	status  int
	body    []byte
	nonce   string
	headers http.Header
}

func (c *Client) send(ctx context.Context, request protocolRequest) (protocolResponse, error) {
	if c == nil {
		return protocolResponse{}, newError(KindConfiguration, "request", "client_missing", "client is nil")
	}
	if err := c.checkOpen(); err != nil {
		return protocolResponse{}, err
	}
	if request.requireTrustedTime && !c.clock.isInitialized() {
		if err := c.refreshTrustedTime(ctx); err != nil {
			return protocolResponse{}, err
		}
	}
	if request.requireOnlineKey {
		if err := c.refreshOnlineKeys(ctx, false); err != nil {
			return protocolResponse{}, err
		}
	}
	if request.requireSession {
		if _, err := c.ensureSession(); err != nil {
			return protocolResponse{}, err
		}
	}
	policy := policyFor(request.operation)
	started := time.Now()
	var lastTransport error
	for attempt := 0; attempt <= policy.retries; attempt++ {
		if err := ctx.Err(); err != nil {
			return protocolResponse{}, wrapError(KindTimeout, string(request.operation), err)
		}
		if policy.deadline > 0 &&
			time.Since(started)+policy.timeout > policy.deadline {
			break
		}
		response, err := c.sendAttempt(ctx, request, policy)
		if err == nil {
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
		lastTransport = err
		if ctx.Err() != nil {
			return protocolResponse{}, wrapError(KindTimeout, string(request.operation), ctx.Err())
		}
		if attempt >= policy.retries {
			break
		}
		delay := backoff(policy, attempt)
		if !canWait(policy, started, delay, attempt) {
			break
		}
		if err := sleepContext(ctx, delay); err != nil {
			return protocolResponse{}, err
		}
	}
	if lastTransport != nil {
		if errors.Is(lastTransport, context.DeadlineExceeded) {
			return protocolResponse{}, wrapError(KindTimeout, string(request.operation), lastTransport)
		}
		return protocolResponse{}, wrapError(KindNetwork, string(request.operation), lastTransport)
	}
	return protocolResponse{}, newError(KindTimeout, string(request.operation), "request_deadline", "request deadline exceeded")
}

func (c *Client) sendAttempt(ctx context.Context, request protocolRequest, policy requestPolicy) (protocolResponse, error) {
	uri, err := c.buildURL(request.path, request.query)
	if err != nil {
		return protocolResponse{}, err
	}
	var timestamp string
	if request.requireTrustedTime {
		timestamp = strconv.FormatInt(c.clock.nowUnixSeconds(), 10)
		if timestamp == "0" {
			return protocolResponse{}, newError(KindClock, string(request.operation), "clock_unavailable", "trusted time is unavailable")
		}
	} else {
		timestamp = strconv.FormatInt(time.Now().Unix(), 10)
	}
	nonce, err := randomUUID()
	if err != nil {
		return protocolResponse{}, err
	}
	headers := http.Header{}
	headers.Set(headerAppID, c.options.AppID)
	headers.Set(headerTimestamp, timestamp)
	headers.Set(headerNonce, nonce)
	headers.Set(headerCapability, "v3")
	headers.Set(headerReleaseID, c.options.ReleaseID)
	headers.Set(headerClientVersion, c.options.Version)
	headers.Set(headerVersionCode, versionCodeString(c.options.VersionCode))
	body := request.body
	session := ""
	if request.requireSession {
		session, err = c.ensureSession()
		if err != nil {
			return protocolResponse{}, err
		}
		headers.Set(headerSession, session)
	}
	if request.requireOnlineKey {
		key, err := c.getCurrentKey()
		if err != nil {
			return protocolResponse{}, err
		}
		dpopResource := request.dpopResource
		if dpopResource == "" {
			dpopResource = uri.String()
		}
		proof, err := c.createDPoP(request.method, dpopResource, session, body)
		if err != nil {
			return protocolResponse{}, err
		}
		headers.Set(headerDPoP, proof)
		if request.encryptBody {
			encrypted, err := encryptRequestBody(
				request.method,
				uri.EscapedPath(),
				canonicalQuery(uri.Query()),
				mustParseInt64(timestamp),
				nonce,
				c.options.AppID,
				c.options.ReleaseID,
				c.options.Version,
				c.options.VersionCode,
				key.keyID,
				key.publicKey,
				body,
			)
			if err != nil {
				return protocolResponse{}, err
			}
			body = encrypted
			headers.Set(headerBodyEnc, "x25519-aes-gcm-v1")
			headers.Set(headerOnlineKeyID, key.keyID)
		}
	}
	httpRequest, err := http.NewRequestWithContext(ctx, request.method, uri.String(), bytes.NewReader(body))
	if err != nil {
		return protocolResponse{}, wrapError(KindNetwork, string(request.operation), err)
	}
	httpRequest.Header = headers
	if len(body) > 0 {
		contentType := request.contentType
		if contentType == "" {
			contentType = "application/json; charset=utf-8"
		}
		httpRequest.Header.Set("Content-Type", contentType)
	}
	requestContext := ctx
	cancel := func() {}
	if policy.timeout > 0 {
		requestContext, cancel = context.WithTimeout(ctx, policy.timeout)
	}
	defer cancel()
	httpRequest = httpRequest.WithContext(requestContext)
	response, err := c.http.Do(httpRequest)
	if err != nil {
		return protocolResponse{}, wrapError(KindNetwork, string(request.operation), err)
	}
	defer response.Body.Close()
	responseBody, err := readBounded(response.Body, 16*1024*1024, requestContext)
	if err != nil {
		return protocolResponse{}, wrapError(KindProtocol, string(request.operation), err)
	}
	return protocolResponse{
		status:  response.StatusCode,
		body:    responseBody,
		nonce:   nonce,
		headers: response.Header.Clone(),
	}, nil
}

func (c *Client) sendAndVerify(ctx context.Context, request protocolRequest, output any) error {
	response, err := c.send(ctx, request)
	if err != nil {
		return err
	}
	if err := c.throwIfError(response); err != nil {
		return err
	}
	data, err := c.verifyAuthz(response, response.nonce)
	if err != nil {
		return err
	}
	if output == nil {
		return nil
	}
	if err := json.Unmarshal(data, output); err != nil {
		return wrapError(KindProtocol, string(request.operation), err)
	}
	return nil
}

func (c *Client) verifyAuthz(response protocolResponse, requestNonce string) ([]byte, error) {
	var carrier authzV3Carrier
	if err := json.Unmarshal(response.body, &carrier); err != nil {
		return nil, newError(KindProtocol, "authz", "authz_carrier_invalid", "Authz v3 carrier is invalid")
	}
	if len(carrier.Data) == 0 || carrier.Authz.Signature == "" {
		return nil, newError(KindProtocol, "authz", "authz_carrier_missing", "Authz v3 carrier is missing data or authz")
	}
	envelope := carrier.Authz
	now := c.clock.nowUnixSeconds()
	if envelope.Version != "authz_v3" ||
		envelope.Decision != "allow" ||
		envelope.ReleaseID != c.options.ReleaseID ||
		envelope.DeviceID != c.DeviceID() ||
		envelope.Nonce != requestNonce ||
		envelope.KeyID == "" ||
		envelope.IssuedAt <= 0 ||
		envelope.ExpiresAt <= envelope.IssuedAt ||
		envelope.ExpiresAt-envelope.IssuedAt > 900 ||
		envelope.IssuedAt > now+120 ||
		envelope.ExpiresAt < now-120 {
		return nil, newError(KindUnauthorized, "authz", "authz_invalid", "Authz v3 response identity or lifetime is invalid")
	}
	key := c.findKey(envelope.KeyID)
	if key == nil {
		return nil, newError(KindUnauthorized, "authz", "authz_invalid", "Authz v3 response key is unknown")
	}
	if !strings.EqualFold(envelope.DataSHA256, sha256Hex(carrier.Data)) {
		return nil, newError(KindIntegrity, "authz", "authz_data_mismatch", "Authz v3 response data hash is invalid")
	}
	canonical := strings.Join([]string{
		"authz_v3",
		"app_id:" + c.options.AppID,
		"release_id:" + envelope.ReleaseID,
		"device_id:" + envelope.DeviceID,
		"nonce:" + envelope.Nonce,
		"decision:" + envelope.Decision,
		"reason:" + envelope.Reason,
		"data_sha256:" + envelope.DataSHA256,
		"session:" + envelope.Session,
		"issued_at:" + strconv.FormatInt(envelope.IssuedAt, 10),
		"expires_at:" + strconv.FormatInt(envelope.ExpiresAt, 10),
		"key_id:" + envelope.KeyID,
	}, "\n")
	valid, err := verifyEd25519(key.publicKey, []byte(canonical), envelope.Signature)
	if err != nil || !valid {
		return nil, newError(KindIntegrity, "authz", "authz_signature_invalid", "Authz v3 response signature is invalid")
	}
	if envelope.Session != "" {
		c.mu.Lock()
		c.session = envelope.Session
		c.sessionExpiresAt = envelope.ExpiresAt
		c.mu.Unlock()
	}
	c.noteServerVerifiedInteraction()
	return carrier.Data, nil
}

func (c *Client) throwIfError(response protocolResponse) error {
	if response.status >= 200 && response.status < 300 {
		return nil
	}
	bodyText := string(response.body)
	code := ""
	message := http.StatusText(response.status)
	minimumVersion := ""
	failureAction := IntegrityShutdownClient
	var root serviceErrorEnvelope
	if err := json.Unmarshal(response.body, &root); err == nil {
		if len(root.Error) > 0 {
			var nested serviceError
			if err := json.Unmarshal(root.Error, &nested); err == nil && nested.Code != "" {
				code = nested.Code
				if nested.Message != "" {
					message = nested.Message
				}
				minimumVersion = nested.MinimumSupportedVersion
				switch nested.FailureAction {
				case "deny_operations":
					failureAction = IntegrityDenyOperations
				}
			} else {
				var flat string
				if err := json.Unmarshal(root.Error, &flat); err == nil && flat != "" {
					message = flat
					if looksLikeCode(flat) {
						code = flat
					}
				}
			}
		} else if root.Code != "" {
			code = root.Code
			if root.Message != "" {
				message = root.Message
			}
		}
	}
	if code == "" && looksLikeCode(message) {
		code = message
	}
	switch {
	case strings.EqualFold(code, "device_blocked"):
		return &Error{Kind: KindDeviceBlocked, StatusCode: response.status, Code: code, Message: message, ResponseBody: bodyText}
	case strings.EqualFold(code, "client_version_unsupported"):
		return &Error{Kind: KindUnsupportedVersion, StatusCode: response.status, Code: code, Message: message, MinimumSupportedVersion: minimumVersion, ResponseBody: bodyText}
	case strings.EqualFold(code, "update_region_blocked"):
		return &Error{Kind: KindUpdateRegionBlocked, StatusCode: response.status, Code: code, Message: message, ResponseBody: bodyText}
	case strings.EqualFold(code, "feedback_disabled"):
		return &Error{Kind: KindFeedbackDisabled, StatusCode: response.status, Code: code, Message: message, ResponseBody: bodyText}
	case strings.HasPrefix(code, "release_integrity_"):
		return &Error{Kind: KindIntegrity, StatusCode: response.status, Code: code, Message: message, FailureAction: failureAction, ResponseBody: bodyText}
	case strings.HasPrefix(code, "operation_auth_") || strings.HasPrefix(code, "operation_grant_"):
		return &Error{Kind: KindOperationAuthorization, StatusCode: response.status, Code: code, Message: message, ResponseBody: bodyText}
	case response.status == http.StatusTooManyRequests:
		return &Error{Kind: KindRateLimit, StatusCode: response.status, Code: code, Message: message, RetryAfter: parseRetryAfter(response.headers), ResponseBody: bodyText}
	case response.status == http.StatusUnauthorized:
		return &Error{Kind: KindSession, StatusCode: response.status, Code: code, Message: message, ResponseBody: bodyText}
	case response.status == http.StatusForbidden:
		return &Error{Kind: KindUnauthorized, StatusCode: response.status, Code: code, Message: message, ResponseBody: bodyText}
	case response.status >= 400 && response.status < 500:
		return &Error{Kind: KindValidation, StatusCode: response.status, Code: code, Message: message, ResponseBody: bodyText}
	default:
		return &Error{Kind: KindAPI, StatusCode: response.status, Code: code, Message: message, ResponseBody: bodyText}
	}
}

func (c *Client) createDPoP(method, absoluteURL, sessionBinding string, body []byte) (string, error) {
	identity, err := c.ensureIdentity()
	if err != nil {
		return "", err
	}
	now := c.clock.nowUnixSeconds()
	if now <= 0 {
		return "", newError(KindClock, "DPoP", "clock_unavailable", "trusted time is unavailable")
	}
	jti, err := randomUUID()
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]string{
		"alg": "ES256",
		"kid": identity.keyID,
		"typ": "swm-dpop+jwt",
	})
	if err != nil {
		return "", wrapError(KindCryptographic, "DPoP", err)
	}
	payload, err := json.Marshal(map[string]any{
		"app_id":      c.options.AppID,
		"ath":         base64URLEncode(sha256Bytes([]byte(sessionBinding))),
		"body_sha256": sha256Hex(body),
		"channel":     c.options.Channel,
		"device_id":   c.DeviceID(),
		"exp":         now + 60,
		"htm":         strings.ToUpper(method),
		"htu":         absoluteURL,
		"iat":         now,
		"install_id":  identity.installID,
		"jti":         jti,
		"pcid":        c.DeviceID(),
		"release_id":  c.options.ReleaseID,
	})
	if err != nil {
		return "", wrapError(KindCryptographic, "DPoP", err)
	}
	signingInput := base64URLEncode(header) + "." + base64URLEncode(payload)
	digest := sha256Bytes([]byte(signingInput))
	signature, err := identity.signDigest(digest)
	if err != nil {
		return "", err
	}
	if len(signature) != 64 {
		return "", newError(KindCryptographic, "DPoP", "signature_invalid", "DPoP signer returned an invalid signature length")
	}
	return signingInput + "." + base64URLEncode(signature), nil
}

func (c *Client) refreshTrustedTime(ctx context.Context) error {
	started := time.Now()
	response, err := c.send(ctx, protocolRequest{
		operation: opTrustedTime,
		method:    http.MethodGet,
		path:      "/api/client/time",
	})
	received := time.Now()
	if err != nil {
		return err
	}
	if err := c.throwIfError(response); err != nil {
		return err
	}
	var manifest serverTimeManifest
	if err := json.Unmarshal(response.body, &manifest); err != nil {
		return wrapError(KindClock, "server time", err)
	}
	if manifest.ManifestVersion != "server_time_v1" ||
		manifest.AppID != c.options.AppID ||
		manifest.ReleaseID != c.options.ReleaseID ||
		manifest.Nonce != response.nonce ||
		manifest.RootTrustKeyID != c.options.RootTrustKeyID ||
		manifest.Signature == "" ||
		manifest.ServerTimeMS <= 0 ||
		manifest.ExpiresAtMS <= manifest.ServerTimeMS ||
		manifest.ExpiresAtMS-manifest.ServerTimeMS > 60000 {
		return newError(KindClock, "server time", "server_time_invalid", "signed server time identity or lifetime is invalid")
	}
	canonical := strings.Join([]string{
		"server_time_v1",
		"app_id:" + manifest.AppID,
		"release_id:" + manifest.ReleaseID,
		"nonce:" + manifest.Nonce,
		"server_time_ms:" + strconv.FormatInt(manifest.ServerTimeMS, 10),
		"expires_at_ms:" + strconv.FormatInt(manifest.ExpiresAtMS, 10),
		"root_trust_key_id:" + manifest.RootTrustKeyID,
	}, "\n")
	valid, err := verifyEd25519(c.options.RootTrustPublicKey, []byte(canonical), manifest.Signature)
	if err != nil || !valid {
		return newError(KindClock, "server time", "server_time_signature_invalid", "signed server time signature is invalid")
	}
	if err := c.clock.setAuthoritativeTime(manifest.ServerTimeMS, started, received); err != nil {
		return err
	}
	c.noteServerVerifiedInteraction()
	return nil
}

func (c *Client) refreshOnlineKeys(ctx context.Context, force bool) error {
	if !force && c.hasFreshOnlineKey() {
		return nil
	}
	c.keyRefreshMu.Lock()
	defer c.keyRefreshMu.Unlock()
	if !force && c.hasFreshOnlineKey() {
		return nil
	}
	if !c.clock.isInitialized() {
		if err := c.refreshTrustedTime(ctx); err != nil {
			if c.canUseCurrentKeyAfterRefreshFailure() {
				return nil
			}
			return err
		}
	}
	response, err := c.send(ctx, protocolRequest{
		operation:          opOnlineKeyManifest,
		method:             http.MethodGet,
		path:               "/api/client/key-manifest",
		requireTrustedTime: true,
	})
	if err != nil {
		if c.canUseCurrentKeyAfterRefreshFailure() {
			return nil
		}
		return err
	}
	if err := c.throwIfError(response); err != nil {
		if isTransientStatus(response.status) && c.canUseCurrentKeyAfterRefreshFailure() {
			return nil
		}
		return err
	}
	var manifest onlineKeyManifest
	if err := json.Unmarshal(response.body, &manifest); err != nil {
		return wrapError(KindIntegrity, "online key", err)
	}
	if manifest.ManifestVersion != "online_key_manifest_v1" ||
		manifest.Purpose != "online_body" ||
		manifest.AppID != c.options.AppID ||
		manifest.ReleaseID != c.options.ReleaseID ||
		manifest.RootTrustKeyID != c.options.RootTrustKeyID ||
		manifest.KeyID == "" ||
		manifest.PublicKey == "" ||
		manifest.RootTrustSignature == "" ||
		manifest.IssuedAt <= 0 ||
		manifest.RefreshAfter <= manifest.IssuedAt ||
		manifest.RefreshAfter-manifest.IssuedAt > 30*24*60*60 {
		return newError(KindIntegrity, "online key", "online_key_manifest_invalid", "online key manifest identity or lifetime is invalid")
	}
	now := c.clock.nowUnixSeconds()
	if manifest.IssuedAt > now+120 || manifest.RefreshAfter < now-120 {
		return newError(KindIntegrity, "online key", "online_key_manifest_invalid", "online key manifest is outside its accepted lifetime")
	}
	canonical := strings.Join([]string{
		manifest.ManifestVersion,
		"purpose:" + manifest.Purpose,
		"app_id:" + manifest.AppID,
		"release_id:" + manifest.ReleaseID,
		"key_id:" + manifest.KeyID,
		"public_key:" + manifest.PublicKey,
		"root_trust_key_id:" + manifest.RootTrustKeyID,
		"issued_at:" + strconv.FormatInt(manifest.IssuedAt, 10),
		"refresh_after:" + strconv.FormatInt(manifest.RefreshAfter, 10),
	}, "\n")
	valid, err := verifyEd25519(c.options.RootTrustPublicKey, []byte(canonical), manifest.RootTrustSignature)
	if err != nil || !valid {
		return newError(KindIntegrity, "online key", "online_key_manifest_invalid", "online key manifest root signature is invalid")
	}
	return c.installKey(protocolKey{
		keyID:        manifest.KeyID,
		publicKey:    manifest.PublicKey,
		issuedAt:     manifest.IssuedAt,
		refreshAfter: manifest.RefreshAfter,
	})
}

func (c *Client) hasFreshOnlineKey() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.currentKey != nil && c.clock.isInitialized() &&
		c.clock.nowUnixSeconds() < c.currentKey.refreshAfter-300
}

func (c *Client) canUseCurrentKeyAfterRefreshFailure() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.currentKey != nil && c.clock.isInitialized() &&
		c.clock.nowUnixSeconds() < c.currentKey.refreshAfter
}

func (c *Client) getCurrentKey() (*protocolKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.currentKey == nil {
		return nil, newError(KindSession, "online key", "authz_key_required", "online authorization key is unavailable")
	}
	if c.clock.isInitialized() && c.clock.nowUnixSeconds() >= c.currentKey.refreshAfter {
		return nil, newError(KindSession, "online key", "authz_key_expired", "online authorization key has expired")
	}
	copy := *c.currentKey
	return &copy, nil
}

func (c *Client) findKey(keyID string) *protocolKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.currentKey != nil && c.currentKey.keyID == keyID {
		copy := *c.currentKey
		return &copy
	}
	for index := len(c.previousKeys) - 1; index >= 0; index-- {
		if c.previousKeys[index].keyID == keyID {
			copy := c.previousKeys[index]
			return &copy
		}
	}
	return nil
}

func (c *Client) installKey(next protocolKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.currentKey != nil && c.currentKey.keyID == next.keyID {
		if c.currentKey.publicKey != next.publicKey {
			return newError(KindIntegrity, "online key", "online_key_manifest_invalid", "online key id was rebound to different key material")
		}
		updated := next
		c.currentKey = &updated
		return nil
	}
	for index := range c.previousKeys {
		if c.previousKeys[index].keyID == next.keyID {
			if c.previousKeys[index].publicKey != next.publicKey {
				return newError(KindIntegrity, "online key", "online_key_manifest_invalid", "online key id was rebound to different key material")
			}
			c.previousKeys = append(c.previousKeys[:index], c.previousKeys[index+1:]...)
			break
		}
	}
	if c.currentKey != nil {
		c.previousKeys = append(c.previousKeys, *c.currentKey)
		for len(c.previousKeys) > 4 {
			c.previousKeys = c.previousKeys[1:]
		}
	}
	updated := next
	c.currentKey = &updated
	return nil
}

func (c *Client) buildURL(path string, query url.Values) (*url.URL, error) {
	if c == nil || c.baseURL == nil {
		return nil, newError(KindConfiguration, "request", "base_url_missing", "base URL is unavailable")
	}
	result := *c.baseURL
	result.Path = path
	result.RawPath = ""
	result.RawQuery = query.Encode()
	return &result, nil
}

func (c *Client) buildWebURL(path string) (*url.URL, error) {
	if c == nil || c.webURL == nil {
		return nil, newError(KindConfiguration, "request", "web_url_missing", "web base URL is unavailable")
	}
	result := *c.webURL
	result.Path = path
	result.RawPath = ""
	result.RawQuery = ""
	return &result, nil
}

func (c *Client) checkOpen() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return newError(KindConfiguration, "client", "client_closed", "client is closed")
	}
	return nil
}

func isTransientStatus(status int) bool {
	return status == 408 || status == 429 || status == 500 || status == 502 || status == 503 || status == 504
}

func backoff(policy requestPolicy, attempt int) time.Duration {
	if policy.backoff <= 0 {
		return 0
	}
	delay := policy.backoff << min(attempt, 16)
	maximum := policy.backoffMax
	if maximum < policy.backoff {
		maximum = policy.backoff
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func canWait(policy requestPolicy, started time.Time, delay time.Duration, attempt int) bool {
	if attempt >= policy.retries {
		return false
	}
	if policy.deadline <= 0 {
		return true
	}
	return time.Since(started)+delay+policy.timeout <= policy.deadline
}

func parseRetryAfter(headers http.Header) time.Duration {
	value := strings.TrimSpace(headers.Get("Retry-After"))
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		delay := time.Until(date)
		if delay < 0 {
			return 0
		}
		return delay
	}
	return 0
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return wrapError(KindTimeout, "request", ctx.Err())
	case <-timer.C:
		return nil
	}
}

func readBounded(reader io.ReadCloser, maximum int64, ctx context.Context) ([]byte, error) {
	var buffer bytes.Buffer
	chunk := make([]byte, 32*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		count, err := reader.Read(chunk)
		if count > 0 {
			if int64(buffer.Len()+count) > maximum {
				return nil, newError(KindProtocol, "response", "response_too_large", "response body exceeds the accepted limit")
			}
			_, _ = buffer.Write(chunk[:count])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return buffer.Bytes(), nil
}

func looksLikeCode(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func mustParseInt64(value string) int64 {
	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		panic(err)
	}
	return number
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
