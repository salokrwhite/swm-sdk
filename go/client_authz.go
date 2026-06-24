package swmsdk

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// APIErrorCodeAuthzInvalid is returned when a required authorization verdict is
	// missing, malformed, expired, or fails signature/binding checks.
	APIErrorCodeAuthzInvalid = "authz_invalid"
	// APIErrorCodeAuthzDenied is returned when the (authenticated) verdict is a deny.
	APIErrorCodeAuthzDenied = "authz_denied"
)

// AuthzEnvelope is the server-signed device-authorization verdict embedded in
// client responses. It mirrors backend internal/auth.AuthzEnvelope. The client
// verifies it with an embedded public key, so a fake/offline server cannot forge
// an "allow".
type AuthzEnvelope struct {
	Decision  string `json:"decision"`
	Nonce     string `json:"nonce"`
	DeviceID  string `json:"device_id"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	KeyID     string `json:"key_id"`
	Reason    string `json:"reason,omitempty"`
	Signature string `json:"signature"`
}

// AuthzError indicates a required authorization verdict was missing or invalid
// (the caller should fail closed). Code is one of APIErrorCodeAuthz*.
type AuthzError struct {
	Code    string
	Message string
}

func (e *AuthzError) Error() string {
	if e == nil {
		return "authz error"
	}
	return e.Code + ": " + e.Message
}

// authzCanonical must match backend internal/auth.authzCanonical byte-for-byte.
func authzCanonical(appID string, env *AuthzEnvelope) string {
	return strings.Join([]string{
		"authz_v1",
		"app_id:" + appID,
		"device_id:" + env.DeviceID,
		"nonce:" + env.Nonce,
		"decision:" + env.Decision,
		"reason:" + env.Reason,
		"issued_at:" + strconv.FormatInt(env.IssuedAt, 10),
		"expires_at:" + strconv.FormatInt(env.ExpiresAt, 10),
		"key_id:" + env.KeyID,
	}, "\n")
}

// decodeKeyMaterial accepts hex (preferred when it parses) or base64.
func decodeKeyMaterial(value string) ([]byte, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil, fmt.Errorf("empty key material")
	}
	if len(v)%2 == 0 {
		if b, err := hex.DecodeString(v); err == nil {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(v); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("key material is neither valid hex nor base64")
}

// verifyAuthz enforces a server authorization verdict. No-op when RequireAuthz is
// false. Otherwise the envelope must be present, bound to requestNonce and this
// device, unexpired, and signed by an embedded public key for its key_id, with
// decision "allow"; any failure returns an *AuthzError so callers fail closed.
// Order matters: signature is verified before the decision is honored, so a
// forged "deny" cannot be used to probe behavior.
func (c *Client) verifyAuthz(env *AuthzEnvelope, requestNonce string) error {
	if !c.RequireAuthz {
		return nil
	}
	if env == nil {
		return &AuthzError{APIErrorCodeAuthzInvalid, "authorization missing"}
	}
	if requestNonce == "" || env.Nonce != requestNonce {
		return &AuthzError{APIErrorCodeAuthzInvalid, "authorization nonce mismatch"}
	}
	if env.DeviceID != c.DeviceID {
		return &AuthzError{APIErrorCodeAuthzInvalid, "authorization device mismatch"}
	}
	skew := int64(c.AuthzClockSkewSeconds)
	if skew <= 0 {
		skew = 120
	}
	now := time.Now().Unix()
	if env.ExpiresAt <= 0 || now > env.ExpiresAt+skew {
		return &AuthzError{APIErrorCodeAuthzInvalid, "authorization expired"}
	}
	pubEncoded, ok := c.AuthzPublicKeys[env.KeyID]
	if !ok || strings.TrimSpace(pubEncoded) == "" {
		return &AuthzError{APIErrorCodeAuthzInvalid, "authorization key unknown: " + env.KeyID}
	}
	if strings.TrimSpace(env.Signature) == "" {
		return &AuthzError{APIErrorCodeAuthzInvalid, "authorization signature missing"}
	}
	pub, err := decodeKeyMaterial(pubEncoded)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return &AuthzError{APIErrorCodeAuthzInvalid, "authorization public key invalid"}
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(env.Signature))
	if err != nil {
		sig, err = decodeKeyMaterial(env.Signature)
		if err != nil {
			return &AuthzError{APIErrorCodeAuthzInvalid, "authorization signature invalid encoding"}
		}
	}
	msg := []byte(authzCanonical(c.AppID, env))
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return &AuthzError{APIErrorCodeAuthzInvalid, "authorization signature invalid"}
	}
	if env.Decision != "allow" {
		reason := strings.TrimSpace(env.Reason)
		if reason == "" {
			reason = "access denied"
		}
		return &AuthzError{APIErrorCodeAuthzDenied, "authorization denied: " + reason}
	}
	return nil
}
