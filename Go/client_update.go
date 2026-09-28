package swm

import (
	"context"
	"encoding/json"
	"net/http"
)

// CheckUpdateOptions controls update checks.
type CheckUpdateOptions struct {
	UserID     string
	Attributes map[string]any
}

// HeartbeatOptions controls heartbeat reporting.
type HeartbeatOptions struct {
	AppVersion string
	UserID     string
	Attributes map[string]any
}

// RefreshOnlineKeys forces a fresh root-verified online authorization key
// manifest. Normal requests refresh the key automatically as needed.
func (c *Client) RefreshOnlineKeys(ctx context.Context) error {
	if err := c.checkOpen(); err != nil {
		return err
	}
	return c.refreshOnlineKeys(ctx, true)
}

// CheckUpdate performs a signed update check and establishes a session.
func (c *Client) CheckUpdate(ctx context.Context, options *CheckUpdateOptions) (UpdateInfo, error) {
	if err := c.checkOpen(); err != nil {
		return UpdateInfo{}, err
	}
	if options == nil {
		options = &CheckUpdateOptions{}
	}
	evidence, err := c.host.getEvidence(ctx)
	if err != nil {
		return UpdateInfo{}, err
	}
	challenge := ""
	for attempt := 0; attempt < 2; attempt++ {
		deviceAuth, err := c.createDeviceAuth(challenge)
		if err != nil {
			return UpdateInfo{}, err
		}
		payload := updateCheckWireRequest{
			ChannelCode:              c.options.Channel,
			CurrentVersion:           c.options.Version,
			VersionCode:              c.options.VersionCode,
			Platform:                 c.options.Platform,
			Arch:                     c.options.Arch,
			DeviceID:                 c.DeviceID(),
			UserID:                   options.UserID,
			Attributes:               options.Attributes,
			DeviceAuth:               deviceAuth,
			IntegrityState:           evidence.IntegrityState,
			IntegrityFailureCode:     evidence.IntegrityFailureCode,
			IntegrityEvidenceVersion: evidence.EvidenceVersion,
			IntegrityManifestSHA256:  evidence.ManifestSHA256,
			IntegrityFiles:           evidence.Files,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return UpdateInfo{}, wrapError(KindProtocol, "update check", err)
		}
		response, err := c.send(ctx, protocolRequest{
			operation:          opUpdateCheck,
			method:             http.MethodPost,
			path:               "/api/client/update-check",
			body:               body,
			encryptBody:        true,
			requireTrustedTime: true,
			requireOnlineKey:   true,
		})
		if err != nil {
			return UpdateInfo{}, err
		}
		if response.status == http.StatusPreconditionRequired && attempt == 0 {
			var challengeResponse deviceRegistrationChallenge
			if err := json.Unmarshal(response.body, &challengeResponse); err != nil {
				return UpdateInfo{}, wrapError(KindProtocol, "update check registration challenge", err)
			}
			if challengeResponse.Challenge == "" ||
				challengeResponse.ExpiresAt <= c.clock.nowUnixSeconds() {
				return UpdateInfo{}, newError(KindProtocol, "update check registration challenge", "registration_challenge_invalid", "device registration challenge is missing or expired")
			}
			challenge = challengeResponse.Challenge
			continue
		}
		if err := c.throwIfError(response); err != nil {
			return UpdateInfo{}, err
		}
		data, err := c.verifyAuthz(response, response.nonce)
		if err != nil {
			return UpdateInfo{}, err
		}
		var update UpdateInfo
		if err := json.Unmarshal(data, &update); err != nil {
			return UpdateInfo{}, wrapError(KindProtocol, "update check", err)
		}
		c.setHostIntegrityPolicy(update.HostIntegrityRequired)
		if err := verifyUpdateArtifact(update, c.options); err != nil {
			return UpdateInfo{}, err
		}
		return update, nil
	}
	return UpdateInfo{}, newError(KindProtocol, "update check", "registration_challenge_exhausted", "device registration challenge retry was exhausted")
}

// ReportHeartbeat reports liveness and refreshes the Authz v3 session.
func (c *Client) ReportHeartbeat(ctx context.Context, options *HeartbeatOptions) (HeartbeatResult, error) {
	if err := c.checkOpen(); err != nil {
		return HeartbeatResult{}, err
	}
	if options == nil {
		options = &HeartbeatOptions{}
	}
	evidence, err := c.host.getEvidence(ctx)
	if err != nil {
		return HeartbeatResult{}, err
	}
	if c.hostIntegrityRequired() && evidence.IntegrityState != "verified" {
		code := evidence.IntegrityFailureCode
		if code == "" {
			code = "host_manifest_missing"
		}
		return HeartbeatResult{}, &Error{
			Kind:          KindIntegrity,
			Op:            "heartbeat",
			Code:          code,
			Message:       "host integrity evidence is required for heartbeat",
			FailureAction: c.failureAction(),
		}
	}
	appVersion := options.AppVersion
	if appVersion == "" {
		appVersion = c.options.Version
	}
	payload := heartbeatWireRequest{
		DeviceID:                 c.DeviceID(),
		ChannelCode:              c.options.Channel,
		AppVersion:               appVersion,
		Platform:                 c.options.Platform,
		Arch:                     c.options.Arch,
		UserID:                   options.UserID,
		Attributes:               options.Attributes,
		IntegrityEvidenceVersion: evidence.EvidenceVersion,
		IntegrityManifestSHA256:  evidence.ManifestSHA256,
		IntegrityFiles:           evidence.Files,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return HeartbeatResult{}, wrapError(KindProtocol, "heartbeat", err)
	}
	var result HeartbeatResult
	if err := c.sendAndVerify(ctx, protocolRequest{
		operation:          opHeartbeat,
		method:             http.MethodPost,
		path:               "/api/client/heartbeat",
		body:               body,
		encryptBody:        true,
		requireSession:     true,
		requireTrustedTime: true,
		requireOnlineKey:   true,
	}, &result); err != nil {
		return HeartbeatResult{}, err
	}
	return result, nil
}

func (c *Client) setHostIntegrityPolicy(required bool) {
	c.mu.Lock()
	c.hostPolicyRequired = required
	c.mu.Unlock()
	c.host.storePolicy(required)
}

func (c *Client) hostIntegrityRequired() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hostPolicyRequired
}

func (c *Client) failureAction() IntegrityFailureAction {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastFailureAction
}
