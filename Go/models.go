package swm

import (
	"context"
	"encoding/json"
	"time"
)

// CloudState describes the current authorization session state.
type CloudState string

const (
	CloudUnavailable      CloudState = "unavailable"
	CloudAuthorizing      CloudState = "authorizing"
	CloudAvailable        CloudState = "available"
	CloudExpired          CloudState = "expired"
	CloudRevoked          CloudState = "revoked"
	CloudIntegrityFailure CloudState = "integrity_failure"
	CloudTimeSyncFailure  CloudState = "time_sync_failure"
	CloudOfflineLocked    CloudState = "offline_locked"
)

// HardwareEvidence is sent during device registration.
type HardwareEvidence struct {
	Version       uint32 `json:"version"`
	ComponentMask uint32 `json:"component_mask"`
	AggregateHash string `json:"aggregate_hash"`
}

// IntegrityEvidence is produced by the built-in scanner or a custom provider.
type IntegrityEvidence struct {
	IntegrityState       string            `json:"integrity_state,omitempty"`
	IntegrityFailureCode string            `json:"integrity_failure_code,omitempty"`
	EvidenceVersion      uint32            `json:"integrity_evidence_version,omitempty"`
	ManifestSHA256       string            `json:"integrity_manifest_sha256,omitempty"`
	Files                map[string]string `json:"integrity_files,omitempty"`
}

// IntegrityEvidenceContext is passed to a custom evidence provider.
type IntegrityEvidenceContext struct {
	AppID        string
	ReleaseID    string
	Version      string
	VersionCode  *int
	Arch         string
	PackageRoot  string
	ManifestPath string
}

// IntegrityEvidenceProvider can replace the built-in RIM2 scanner.
type IntegrityEvidenceProvider interface {
	GetEvidence(context.Context, IntegrityEvidenceContext) (IntegrityEvidence, error)
}

// MaintenanceInfo describes a scheduled maintenance window.
type MaintenanceInfo struct {
	Enabled bool   `json:"enabled"`
	StartAt string `json:"start_at,omitempty"`
	Message string `json:"message,omitempty"`
	Active  bool   `json:"active"`
}

// UpdateInfo is the verified update-check response.
type UpdateInfo struct {
	UpdateAvailable          bool             `json:"update_available"`
	Mandatory                bool             `json:"mandatory"`
	HeartbeatIntervalSeconds int              `json:"heartbeat_interval_seconds"`
	OpenInBrowser            bool             `json:"open_in_browser"`
	DeliveryMethod           string           `json:"delivery_method,omitempty"`
	ReleaseID                string           `json:"release_id,omitempty"`
	Version                  string           `json:"version,omitempty"`
	VersionCode              *int             `json:"version_code,omitempty"`
	Notes                    string           `json:"notes,omitempty"`
	DownloadURL              string           `json:"download_url,omitempty"`
	ChecksumSHA256           string           `json:"checksum_sha256,omitempty"`
	Signature                string           `json:"signature,omitempty"`
	ManifestKeyID            string           `json:"manifest_key_id,omitempty"`
	ManifestPublicKey        string           `json:"manifest_public_key,omitempty"`
	RootTrustKeyID           string           `json:"root_trust_key_id,omitempty"`
	RootTrustSignature       string           `json:"root_trust_signature,omitempty"`
	ArtifactFileName         string           `json:"artifact_file_name,omitempty"`
	ArtifactPlatform         string           `json:"artifact_platform,omitempty"`
	ArtifactArch             string           `json:"artifact_arch,omitempty"`
	AuthzProtocol            string           `json:"authz_protocol,omitempty"`
	HostIntegrityRequired    bool             `json:"host_integrity_required"`
	Size                     int64            `json:"size"`
	RollbackAllowed          bool             `json:"rollback_allowed"`
	Maintenance              *MaintenanceInfo `json:"maintenance,omitempty"`
}

// HeartbeatResult is the verified heartbeat response.
type HeartbeatResult struct {
	OK          bool             `json:"ok"`
	ServerTime  *time.Time       `json:"server_time,omitempty"`
	Maintenance *MaintenanceInfo `json:"maintenance,omitempty"`
}

// FeedbackRequest contains user feedback and optional local attachments.
type FeedbackRequest struct {
	Content         string
	Rating          *int
	Contact         string
	AppVersion      string
	AttachmentPaths []string
	Metadata        map[string]any
}

// FeedbackResult is returned after feedback submission.
type FeedbackResult struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
}

// EnrollmentTicket is a short-lived ticket for a first-party audience.
type EnrollmentTicket struct {
	Ticket    string `json:"ticket"`
	ExpiresAt int64  `json:"expires_at"`
	Audience  string `json:"audience"`
}

// DeviceKeyRotationResult describes a committed key rotation.
type DeviceKeyRotationResult struct {
	RegistrationID string
	InstallID      string
	KeyID          string
	DeviceID       string
}

// OperationAuthorizationRequest is caller-defined operation intent.
type OperationAuthorizationRequest struct {
	Operation          string
	Plan               []byte
	StepCount          uint32
	TotalBytes         uint64
	ConsumerModule     string
	ConsumerChallenge  []byte
	HostExecutablePath string
	ConsumerModulePath string
}

// OperationGrant is a signed operation authorization.
type OperationGrant struct {
	Schema                  string `json:"schema"`
	AppID                   string `json:"app_id"`
	ReleaseID               string `json:"release_id"`
	DeviceID                string `json:"device_id"`
	DeviceKeyID             string `json:"device_key_id"`
	KeyThumbprint           string `json:"key_thumbprint"`
	DevicePublicKey         string `json:"device_public_key"`
	AuthzPublicKey          string `json:"authz_public_key"`
	AuthzKeyID              string `json:"authz_key_id"`
	AuthzRootTrustKeyID     string `json:"authz_root_trust_key_id"`
	AuthzRootTrustSignature string `json:"authz_root_trust_signature"`
	Session                 string `json:"session"`
	GrantID                 string `json:"grant_id"`
	Operation               string `json:"operation"`
	PlanSHA256              string `json:"plan_sha256"`
	StepCount               uint32 `json:"step_count"`
	TotalBytes              uint64 `json:"total_bytes"`
	IssuedAt                int64  `json:"issued_at"`
	ExpiresAt               int64  `json:"expires_at"`
	ConsumerChallenge       string `json:"consumer_challenge"`
	IntegrityManifestSHA256 string `json:"integrity_manifest_sha256,omitempty"`
	HostExeSHA256           string `json:"host_exe_sha256,omitempty"`
	ConsumerModule          string `json:"consumer_module"`
	ConsumerModuleSHA256    string `json:"consumer_module_sha256,omitempty"`
}

// OperationConsumptionReceipt is the one-time consumption result.
type OperationConsumptionReceipt struct {
	Schema                  string `json:"schema"`
	GrantID                 string `json:"grant_id"`
	Operation               string `json:"operation"`
	PlanSHA256              string `json:"plan_sha256"`
	StepCount               uint32 `json:"step_count"`
	TotalBytes              uint64 `json:"total_bytes"`
	ConsumerChallenge       string `json:"consumer_challenge"`
	ConsumedAt              int64  `json:"consumed_at"`
	ExpiresAt               int64  `json:"expires_at"`
	IntegrityManifestSHA256 string `json:"integrity_manifest_sha256,omitempty"`
	HostExeSHA256           string `json:"host_exe_sha256,omitempty"`
	ConsumerModule          string `json:"consumer_module"`
	ConsumerModuleSHA256    string `json:"consumer_module_sha256,omitempty"`
}

// Event is one analytics event submitted by the caller.
type Event struct {
	DeviceID    string         `json:"device_id,omitempty"`
	EventName   string         `json:"event_name"`
	EventTime   time.Time      `json:"event_time"`
	ChannelCode string         `json:"channel_code,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
	Attributes  map[string]any `json:"attributes,omitempty"`
}

// UpdateEvent is one verified server-sent update event.
type UpdateEvent struct {
	ID                 string     `json:"id,omitempty"`
	EventType          string     `json:"event_type,omitempty"`
	OrgID              string     `json:"org_id,omitempty"`
	AppID              string     `json:"app_id,omitempty"`
	DeviceID           string     `json:"device_id,omitempty"`
	ChannelCode        string     `json:"channel_code,omitempty"`
	Platform           string     `json:"platform,omitempty"`
	Arch               string     `json:"arch,omitempty"`
	ReleaseID          string     `json:"release_id,omitempty"`
	PublishedAt        *time.Time `json:"published_at,omitempty"`
	Reason             string     `json:"reason,omitempty"`
	Message            string     `json:"message,omitempty"`
	MaintenanceStartAt *time.Time `json:"maintenance_start_at,omitempty"`
}

// UpdateStreamOptions controls update SSE reconnect behavior.
type UpdateStreamOptions struct {
	CurrentVersion      string
	VersionCode         *int
	Reconnect           bool
	ReconnectBackoff    time.Duration
	ReconnectMaxBackoff time.Duration
	Jitter              bool
}

// DefaultUpdateStreamOptions returns the production defaults.
func DefaultUpdateStreamOptions() UpdateStreamOptions {
	return UpdateStreamOptions{
		Reconnect:           true,
		ReconnectBackoff:    1500 * time.Millisecond,
		ReconnectMaxBackoff: 20 * time.Second,
		Jitter:              true,
	}
}

// DebugRequestTicket identifies an approved-debug workflow.
type DebugRequestTicket struct {
	RequestID  string
	WatchToken string
	ExpiresAt  int64

	credentials debugCredentials
	sessionID   string
}

// DebugDecisionEvent is one verified administrator decision.
type DebugDecisionEvent struct {
	State                  string
	Reason                 string
	AuthorizationExpiresAt int64
}

type debugCredentials struct {
	ClientID     string
	ClientSecret string
	ExpiresAt    int64
}

// ProgressFunc is invoked as a download advances.
type ProgressFunc func(downloaded, total int64)

// JSON is a convenience alias for callers handling extension response data.
type JSON = json.RawMessage
