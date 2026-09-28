package swm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
)

// RequestEnrollmentTicket requests a short-lived first-party enrollment ticket.
func (c *Client) RequestEnrollmentTicket(ctx context.Context, audience string) (EnrollmentTicket, error) {
	if err := c.checkOpen(); err != nil {
		return EnrollmentTicket{}, err
	}
	audience = strings.ToLower(strings.TrimSpace(audience))
	if audience == "" {
		return EnrollmentTicket{}, newError(KindValidation, "enrollment", "enrollment_audience_required", "enrollment audience is required")
	}
	body, err := json.Marshal(map[string]string{"audience": audience})
	if err != nil {
		return EnrollmentTicket{}, wrapError(KindProtocol, "enrollment", err)
	}
	var result EnrollmentTicket
	if err := c.sendAndVerify(ctx, protocolRequest{
		operation:          opEnrollmentTicket,
		method:             http.MethodPost,
		path:               "/api/client/enrollment-ticket",
		body:               body,
		encryptBody:        true,
		requireSession:     true,
		requireTrustedTime: true,
		requireOnlineKey:   true,
	}, &result); err != nil {
		return EnrollmentTicket{}, err
	}
	return result, nil
}

type deviceKeyRotationWireRequest struct {
	NewDeviceAuth deviceAuthRegistration `json:"new_device_auth"`
	NewKeyProof   string                 `json:"new_key_proof,omitempty"`
}

type deviceKeyRotationChallenge struct {
	Challenge   string `json:"challenge"`
	ExpiresAt   int64  `json:"expires_at"`
	ProofDigest string `json:"proof_digest"`
}

type deviceKeyRotationWireResponse struct {
	Rotated        bool   `json:"rotated"`
	RegistrationID string `json:"registration_id"`
	InstallID      string `json:"install_id"`
	KeyID          string `json:"key_id"`
}

// RotateDeviceKey replaces the device CNG key and commits the new metadata
// only after the server accepts the rotation.
func (c *Client) RotateDeviceKey(ctx context.Context) (DeviceKeyRotationResult, error) {
	if err := c.checkOpen(); err != nil {
		return DeviceKeyRotationResult{}, err
	}
	if !c.clock.isInitialized() {
		if err := c.refreshTrustedTime(ctx); err != nil {
			return DeviceKeyRotationResult{}, err
		}
	}
	if err := c.refreshOnlineKeys(ctx, false); err != nil {
		return DeviceKeyRotationResult{}, err
	}
	if _, err := c.ensureSession(); err != nil {
		return DeviceKeyRotationResult{}, err
	}
	pending, err := createPendingIdentity(c.options.AppID, c.store)
	if err != nil {
		return DeviceKeyRotationResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			pending.deletePending()
		}
	}()
	challenge := ""
	proofDigest := ""
	for attempt := 0; attempt < 2; attempt++ {
		deviceAuth, err := c.createDeviceAuthFor(pending, challenge)
		if err != nil {
			return DeviceKeyRotationResult{}, err
		}
		wire := deviceKeyRotationWireRequest{NewDeviceAuth: deviceAuth}
		if challenge != "" && proofDigest != "" {
			digest, err := hex.DecodeString(proofDigest)
			if err != nil || len(digest) != 32 {
				return DeviceKeyRotationResult{}, newError(KindProtocol, "key rotation", "proof_digest_invalid", "device key rotation proof digest is invalid")
			}
			signature, err := pending.signDigest(digest)
			if err != nil {
				return DeviceKeyRotationResult{}, err
			}
			wire.NewKeyProof = base64URLEncode(signature)
		}
		body, err := json.Marshal(wire)
		if err != nil {
			return DeviceKeyRotationResult{}, wrapError(KindProtocol, "key rotation", err)
		}
		response, err := c.send(ctx, protocolRequest{
			operation:          opDeviceKeyRotation,
			method:             http.MethodPost,
			path:               "/api/client/device-key/rotate",
			body:               body,
			encryptBody:        true,
			requireSession:     true,
			requireTrustedTime: true,
			requireOnlineKey:   true,
		})
		if err != nil {
			return DeviceKeyRotationResult{}, err
		}
		if response.status == http.StatusPreconditionRequired && attempt == 0 {
			var challengeResponse deviceKeyRotationChallenge
			if err := json.Unmarshal(response.body, &challengeResponse); err != nil {
				return DeviceKeyRotationResult{}, wrapError(KindProtocol, "key rotation challenge", err)
			}
			if challengeResponse.Challenge == "" || challengeResponse.ProofDigest == "" ||
				challengeResponse.ExpiresAt <= c.clock.nowUnixSeconds() {
				return DeviceKeyRotationResult{}, newError(KindProtocol, "key rotation challenge", "rotation_challenge_invalid", "device key rotation challenge is invalid")
			}
			challenge = challengeResponse.Challenge
			proofDigest = challengeResponse.ProofDigest
			continue
		}
		if err := c.throwIfError(response); err != nil {
			return DeviceKeyRotationResult{}, err
		}
		var result deviceKeyRotationWireResponse
		if err := json.Unmarshal(response.body, &result); err != nil {
			return DeviceKeyRotationResult{}, wrapError(KindProtocol, "key rotation", err)
		}
		if !result.Rotated || !isUUID(result.RegistrationID) ||
			result.InstallID != pending.installID || result.KeyID != pending.keyID {
			return DeviceKeyRotationResult{}, newError(KindProtocol, "key rotation", "rotation_response_invalid", "device key rotation response is invalid")
		}
		if err := pending.commitPending(); err != nil {
			return DeviceKeyRotationResult{}, err
		}
		committed = true
		c.mu.Lock()
		previous := c.identity
		c.identity = pending
		c.offline = nil
		c.session = ""
		c.sessionExpiresAt = 0
		c.mu.Unlock()
		if previous != nil {
			previous.close()
		}
		return DeviceKeyRotationResult{
			RegistrationID: result.RegistrationID,
			InstallID:      pending.installID,
			KeyID:          pending.keyID,
			DeviceID:       pending.deviceID,
		}, nil
	}
	return DeviceKeyRotationResult{}, newError(KindProtocol, "key rotation", "rotation_challenge_exhausted", "device key rotation challenge retry was exhausted")
}
