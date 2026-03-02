package swmsdk

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	ControlEventShutdown = "device_shutdown"
	APIErrorCodeDeviceBlocked = "device_blocked"
	signHeaderAppID      = "X-App-Id"
	signHeaderTimestamp  = "X-Timestamp"
	signHeaderNonce      = "X-Nonce"
	signHeaderSignature  = "X-Signature"
	signHeaderVersion    = "X-Sign-Version"
	signVersionV1        = "v1"
)

var ErrDeviceBlocked = errors.New("device blocked")

type Client struct {
	BaseURL    string
	AppID      string
	AppSecret  string
	AuthToken  string
	Channel    string
	Platform   string
	Arch       string
	DeviceID   string
	Attributes map[string]interface{}
	PublicKey  string
	VerifySignature bool
	Retries    int
	Backoff    time.Duration
	HTTPClient *http.Client
}

type UpdateCheckRequest struct {
	ChannelCode    string `json:"channel_code"`
	CurrentVersion string `json:"current_version"`
	VersionCode    *int   `json:"version_code,omitempty"`
	Platform       string `json:"platform"`
	Arch           string `json:"arch"`
	DeviceID       string `json:"device_id"`
	UserID         string `json:"user_id,omitempty"`
	Attributes     map[string]interface{} `json:"attributes,omitempty"`
}

type UpdateCheckResponse struct {
	UpdateAvailable bool   `json:"update_available"`
	Mandatory       bool   `json:"mandatory"`
	HeartbeatIntervalSeconds int `json:"heartbeat_interval_seconds"`
	OpenInBrowser   bool   `json:"open_in_browser"`
	DeliveryMethod  string `json:"delivery_method"`
	ReleaseID       string `json:"release_id"`
	Version         string `json:"version"`
	Notes           string `json:"notes"`
	DownloadURL     string `json:"download_url"`
	ChecksumSHA256  string `json:"checksum_sha256"`
	Signature       string `json:"signature"`
	Size            int64  `json:"size"`
	RollbackAllowed bool   `json:"rollback_allowed"`
	ReleaseNotesURL string `json:"release_notes_url"`
}

type Event struct {
	DeviceID    string                 `json:"device_id"`
	EventName   string                 `json:"event_name"`
	EventTime   time.Time              `json:"event_time"`
	ChannelCode string                 `json:"channel_code"`
	Properties  map[string]interface{} `json:"properties"`
	Attributes  map[string]interface{} `json:"attributes,omitempty"`
}

type UpdatePushEvent struct {
	ID          string    `json:"id"`
	EventType   string    `json:"event_type"`
	OrgID       string    `json:"org_id"`
	AppID       string    `json:"app_id"`
	DeviceID    string    `json:"device_id,omitempty"`
	ChannelCode string    `json:"channel_code"`
	Platform    string    `json:"platform"`
	Arch        string    `json:"arch"`
	ReleaseID   string    `json:"release_id"`
	PublishedAt time.Time `json:"published_at"`
	Reason      string    `json:"reason"`
}

type ControlEvent struct {
	Type     string
	DeviceID string
	Reason   string
}

type UpdateStreamOptions struct {
	ChannelCode          string
	Platform             string
	Arch                 string
	DeviceID             string
	CurrentVersion       string
	VersionCode          *int
	Reconnect            bool
	ReconnectBackoff     time.Duration
	ReconnectMaxBackoff  time.Duration
	Jitter               bool
	OnError              func(error)
	OnControlEvent       func(ControlEvent)
}

type UpdateWatchHandle struct {
	cancel context.CancelFunc
}

func (h *UpdateWatchHandle) Stop() {
	if h == nil || h.cancel == nil {
		return
	}
	h.cancel()
}

func New(baseURL, appID, appSecret string) *Client {
	return &Client{
		BaseURL: baseURL,
		AppID:   appID,
		AppSecret: appSecret,
		Attributes: map[string]interface{}{},
		Retries: 2,
		Backoff: 500 * time.Millisecond,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) SetAuthToken(token string) {
	c.AuthToken = strings.TrimSpace(token)
}

