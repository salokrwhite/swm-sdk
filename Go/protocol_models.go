package swm

import "encoding/json"

type hardwareEvidenceWire struct {
	Version       uint32 `json:"version"`
	ComponentMask uint32 `json:"component_mask"`
	AggregateHash string `json:"aggregate_hash"`
}

type deviceAuthRegistration struct {
	InstallID        string               `json:"install_id"`
	KeyID            string               `json:"key_id"`
	KeyThumbprint    string               `json:"key_thumbprint"`
	PublicKeySEC1    string               `json:"public_key_sec1"`
	CredentialVer    string               `json:"credential_version"`
	Challenge        string               `json:"challenge,omitempty"`
	HardwareEvidence hardwareEvidenceWire `json:"hardware_evidence"`
}

type updateCheckWireRequest struct {
	ChannelCode              string                 `json:"channel_code"`
	CurrentVersion           string                 `json:"current_version"`
	VersionCode              *int                   `json:"version_code,omitempty"`
	Platform                 string                 `json:"platform"`
	Arch                     string                 `json:"arch"`
	DeviceID                 string                 `json:"device_id"`
	UserID                   string                 `json:"user_id,omitempty"`
	Attributes               map[string]any         `json:"attributes,omitempty"`
	DeviceAuth               deviceAuthRegistration `json:"device_auth"`
	IntegrityState           string                 `json:"integrity_state,omitempty"`
	IntegrityFailureCode     string                 `json:"integrity_failure_code,omitempty"`
	IntegrityEvidenceVersion uint32                 `json:"integrity_evidence_version,omitempty"`
	IntegrityManifestSHA256  string                 `json:"integrity_manifest_sha256,omitempty"`
	IntegrityFiles           map[string]string      `json:"integrity_files,omitempty"`
}

type heartbeatWireRequest struct {
	DeviceID                 string            `json:"device_id"`
	ChannelCode              string            `json:"channel_code,omitempty"`
	AppVersion               string            `json:"app_version,omitempty"`
	Platform                 string            `json:"platform,omitempty"`
	Arch                     string            `json:"arch,omitempty"`
	UserID                   string            `json:"user_id,omitempty"`
	Attributes               map[string]any    `json:"attributes,omitempty"`
	IntegrityEvidenceVersion uint32            `json:"integrity_evidence_version,omitempty"`
	IntegrityManifestSHA256  string            `json:"integrity_manifest_sha256,omitempty"`
	IntegrityFiles           map[string]string `json:"integrity_files,omitempty"`
}

type deviceRegistrationChallenge struct {
	Challenge string `json:"challenge"`
	ExpiresAt int64  `json:"expires_at"`
}

type serverTimeManifest struct {
	ManifestVersion string `json:"manifest_version"`
	AppID           string `json:"app_id"`
	ReleaseID       string `json:"release_id"`
	Nonce           string `json:"nonce"`
	ServerTimeMS    int64  `json:"server_time_ms"`
	ExpiresAtMS     int64  `json:"expires_at_ms"`
	RootTrustKeyID  string `json:"root_trust_key_id"`
	Signature       string `json:"signature"`
}

type onlineKeyManifest struct {
	ManifestVersion    string `json:"manifest_version"`
	Purpose            string `json:"purpose"`
	AppID              string `json:"app_id"`
	ReleaseID          string `json:"release_id"`
	KeyID              string `json:"key_id"`
	PublicKey          string `json:"public_key"`
	RootTrustKeyID     string `json:"root_trust_key_id"`
	RootTrustSignature string `json:"root_trust_signature"`
	IssuedAt           int64  `json:"issued_at"`
	RefreshAfter       int64  `json:"refresh_after"`
}

type authzV3Envelope struct {
	Version    string `json:"version"`
	Decision   string `json:"decision"`
	ReleaseID  string `json:"release_id"`
	DeviceID   string `json:"device_id"`
	Nonce      string `json:"nonce"`
	DataSHA256 string `json:"data_sha256"`
	Session    string `json:"session,omitempty"`
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
	KeyID      string `json:"key_id"`
	Reason     string `json:"reason,omitempty"`
	Signature  string `json:"signature"`
}

type authzV3Carrier struct {
	Data  json.RawMessage `json:"data"`
	Authz authzV3Envelope `json:"authz"`
}

type serviceErrorEnvelope struct {
	Error   json.RawMessage `json:"error"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
}

type serviceError struct {
	Code                    string `json:"code"`
	Message                 string `json:"message"`
	MinimumSupportedVersion string `json:"minimum_supported_version"`
	FailureAction           string `json:"failure_action"`
}
