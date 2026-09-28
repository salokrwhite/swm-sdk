package swm

import (
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/salokrwhite/swm-sdk/Go/v2/internal/winapi"
)

const (
	headerAppID         = "X-App-Id"
	headerTimestamp     = "X-Timestamp"
	headerNonce         = "X-Nonce"
	headerCapability    = "X-Authz-Capability"
	headerReleaseID     = "X-Client-Release-Id"
	headerClientVersion = "X-Client-Version"
	headerVersionCode   = "X-Client-Version-Code"
	headerSession       = "X-SWM-Session"
	headerDPoP          = "X-SWM-DPoP"
	headerBodyEnc       = "X-SWM-Body-Enc"
	headerOnlineKeyID   = "X-SWM-Online-Key-Id"
)

type protocolKey struct {
	keyID        string
	publicKey    string
	issuedAt     int64
	refreshAfter int64
}

// Client is a concurrent-safe Software Web Manager client.
type Client struct {
	options Options
	baseURL *url.URL
	webURL  *url.URL
	http    *http.Client
	store   *stateStore
	clock   *trustedClock
	host    *hostIntegrityManager

	identity           *deviceIdentity
	hardware           *winapi.HardwareEvidence
	offline            *offlineBudgetState
	session            string
	sessionExpiresAt   int64
	currentKey         *protocolKey
	previousKeys       []protocolKey
	hostPolicyRequired bool
	lastFailureAction  IntegrityFailureAction
	closed             bool

	mu           sync.Mutex
	keyRefreshMu sync.Mutex
}

// NewClient validates options and initializes the Windows client.
func NewClient(options Options) (*Client, error) {
	validated, base, web, err := validateOptions(options)
	if err != nil {
		return nil, err
	}
	if !winapi.Supported() {
		return nil, newError(
			KindUnsupportedPlatform, "new client", "unsupported_platform",
			"SWM SDK requires Windows x86 or x64")
	}
	store, err := newStateStore(validated.AppID, validated.StorageDirectory)
	if err != nil {
		return nil, err
	}
	client := &Client{
		options:           validated,
		baseURL:           base,
		webURL:            web,
		store:             store,
		clock:             &trustedClock{},
		lastFailureAction: IntegrityShutdownClient,
		http: &http.Client{
			Transport: validated.Transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	client.host = newHostIntegrityManager(validated, store)
	if required, ok := client.host.readCachedPolicy(); ok {
		client.hostPolicyRequired = required
	}
	return client, nil
}

// Close releases the persisted CNG key handle. It does not delete the key.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.identity != nil {
		c.identity.close()
	}
	return nil
}

// DeviceID returns the configured or generated device identifier.
func (c *Client) DeviceID() string {
	if c == nil {
		return ""
	}
	if strings.TrimSpace(c.options.DeviceID) != "" {
		return strings.TrimSpace(c.options.DeviceID)
	}
	identity, err := c.ensureIdentity()
	if err != nil {
		return ""
	}
	return identity.deviceID
}

// InstallID returns the local installation identifier.
func (c *Client) InstallID() string {
	identity, err := c.ensureIdentity()
	if err != nil {
		return ""
	}
	return identity.installID
}

// DeviceKeyID returns the CNG key identifier.
func (c *Client) DeviceKeyID() string {
	identity, err := c.ensureIdentity()
	if err != nil {
		return ""
	}
	return identity.keyID
}

// KeyThumbprint returns the base64url SHA-256 thumbprint of the SEC1 key.
func (c *Client) KeyThumbprint() string {
	identity, err := c.ensureIdentity()
	if err != nil {
		return ""
	}
	return identity.keyThumbprint
}

// SessionToken returns the current Authz v3 session token.
func (c *Client) SessionToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

// SessionExpiresAt returns the current session expiry in Unix seconds.
func (c *Client) SessionExpiresAt() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionExpiresAt
}

// CloudState reports whether the client currently has a usable session.
func (c *Client) CloudState() CloudState {
	if c == nil {
		return CloudUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.clock.isInitialized() {
		return CloudUnavailable
	}
	if c.session == "" || c.sessionExpiresAt <= c.clock.nowUnixSeconds() {
		if c.sessionExpiresAt > 0 {
			return CloudExpired
		}
		return CloudUnavailable
	}
	return CloudAvailable
}

func (c *Client) ensureIdentity() (*deviceIdentity, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, newError(KindIdentity, "identity", "client_closed", "client is closed")
	}
	if c.identity != nil {
		return c.identity, nil
	}
	identity, err := loadOrCreateIdentity(c.options.AppID, c.store)
	if err != nil {
		return nil, err
	}
	c.identity = identity
	return identity, nil
}

func (c *Client) ensureOfflineBudget() *offlineBudgetState {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.offline == nil && c.identity != nil {
		c.offline = newOfflineBudget(c.store, c.identity.installID, c.identity.keyThumbprint)
	}
	return c.offline
}

func (c *Client) isOfflineBudgetLocked() bool {
	identity, err := c.ensureIdentity()
	if err != nil {
		return true
	}
	c.mu.Lock()
	if c.offline == nil {
		c.offline = newOfflineBudget(c.store, identity.installID, identity.keyThumbprint)
	}
	offline := c.offline
	c.mu.Unlock()
	return offline.isLocked(c.clock)
}

func (c *Client) noteServerVerifiedInteraction() {
	if c == nil || c.store == nil {
		return
	}
	now := c.clock.nowUnixMilliseconds()
	if now <= 0 {
		return
	}
	identity, err := c.ensureIdentity()
	if err != nil {
		return
	}
	c.mu.Lock()
	if c.offline == nil {
		c.offline = newOfflineBudget(c.store, identity.installID, identity.keyThumbprint)
	}
	offline := c.offline
	c.mu.Unlock()
	offline.noteVerifiedInteraction(now)
}

func (c *Client) ensureSession() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == "" || c.sessionExpiresAt <= c.clock.nowUnixSeconds() {
		c.session = ""
		c.sessionExpiresAt = 0
		return "", newError(KindSession, "session", "authz_session_invalid", "authorization session is missing or expired")
	}
	return c.session, nil
}

func (c *Client) clearSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.session = ""
	c.sessionExpiresAt = 0
}

func (c *Client) hasValidSession() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock.nowUnixSeconds()
	return c.session != "" && c.sessionExpiresAt > now
}

func (c *Client) createDeviceAuth(challenge string) (deviceAuthRegistration, error) {
	identity, err := c.ensureIdentity()
	if err != nil {
		return deviceAuthRegistration{}, err
	}
	return c.createDeviceAuthFor(identity, challenge)
}

func (c *Client) createDeviceAuthFor(identity *deviceIdentity, challenge string) (deviceAuthRegistration, error) {
	hardware, err := c.hardwareEvidence()
	if err != nil {
		return deviceAuthRegistration{}, err
	}
	return deviceAuthRegistration{
		InstallID:     identity.installID,
		KeyID:         identity.keyID,
		KeyThumbprint: identity.keyThumbprint,
		PublicKeySEC1: base64URLEncode(identity.publicKeySEC1),
		CredentialVer: "device_credential_v2",
		Challenge:     challenge,
		HardwareEvidence: hardwareEvidenceWire{
			Version:       hardware.Version,
			ComponentMask: hardware.ComponentMask,
			AggregateHash: hardware.AggregateHash,
		},
	}, nil
}

func (c *Client) hardwareEvidence() (winapi.HardwareEvidence, error) {
	c.mu.Lock()
	if c.hardware != nil {
		value := *c.hardware
		c.mu.Unlock()
		return value, nil
	}
	c.mu.Unlock()
	value, err := winapi.CollectHardwareEvidence(c.options.AppID)
	if err != nil {
		return winapi.HardwareEvidence{}, wrapError(KindIdentity, "hardware evidence", err)
	}
	c.mu.Lock()
	if c.hardware == nil {
		valueCopy := value
		c.hardware = &valueCopy
	}
	result := *c.hardware
	c.mu.Unlock()
	return result, nil
}
