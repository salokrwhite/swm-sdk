package swm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// HostIntegrityOptions configures local RIM2 scanning.
type HostIntegrityOptions struct {
	Enabled          bool
	PackageRoot      string
	ManifestPath     string
	EvidenceProvider IntegrityEvidenceProvider
}

// Options configures a Client.
type Options struct {
	BaseURL            string
	WebBaseURL         string
	AppID              string
	ReleaseID          string
	Version            string
	VersionCode        *int
	RootTrustKeyID     string
	RootTrustPublicKey string
	Channel            string
	Platform           string
	Arch               string
	DeviceID           string
	StorageDirectory   string
	AllowInsecureHTTP  bool
	Transport          http.RoundTripper
	HostIntegrity      HostIntegrityOptions
}

func validateOptions(opts Options) (Options, *url.URL, *url.URL, error) {
	if strings.TrimSpace(opts.AppID) == "" ||
		strings.TrimSpace(opts.ReleaseID) == "" ||
		strings.TrimSpace(opts.Version) == "" ||
		strings.TrimSpace(opts.RootTrustKeyID) == "" ||
		strings.TrimSpace(opts.RootTrustPublicKey) == "" {
		return opts, nil, nil, newError(
			KindConfiguration, "new client", "configuration_invalid",
			"BaseURL, AppID, ReleaseID, Version, RootTrustKeyID and RootTrustPublicKey are required")
	}
	opts.AppID = strings.TrimSpace(opts.AppID)
	opts.ReleaseID = strings.TrimSpace(opts.ReleaseID)
	opts.Version = strings.TrimSpace(opts.Version)
	opts.RootTrustKeyID = strings.TrimSpace(opts.RootTrustKeyID)
	opts.RootTrustPublicKey = strings.TrimSpace(opts.RootTrustPublicKey)
	if !isUUID(opts.AppID) || !isUUID(opts.ReleaseID) {
		return opts, nil, nil, newError(
			KindConfiguration, "new client", "configuration_invalid",
			"AppID and ReleaseID must be UUID values")
	}
	base, err := parseServiceURL(opts.BaseURL, opts.AllowInsecureHTTP)
	if err != nil {
		return opts, nil, nil, err
	}
	webRaw := opts.WebBaseURL
	if strings.TrimSpace(webRaw) == "" {
		webRaw = opts.BaseURL
	}
	web, err := parseServiceURL(webRaw, opts.AllowInsecureHTTP)
	if err != nil {
		return opts, nil, nil, err
	}
	key, err := decodeKeyMaterial(opts.RootTrustPublicKey)
	if err != nil || len(key) != 32 {
		return opts, nil, nil, newError(
			KindConfiguration, "new client", "root_trust_key_invalid",
			"RootTrustPublicKey must be a 32-byte Ed25519 public key")
	}
	opts.Channel = strings.TrimSpace(opts.Channel)
	if opts.Channel == "" {
		opts.Channel = "stable"
	}
	opts.Platform = strings.ToLower(strings.TrimSpace(opts.Platform))
	if opts.Platform == "" {
		opts.Platform = "windows"
	}
	opts.Arch = normalizeArch(opts.Arch)
	if opts.Arch == "" {
		opts.Arch = normalizeArch(runtime.GOARCH)
	}
	if opts.Arch != "x86" && opts.Arch != "x64" {
		return opts, nil, nil, newError(
			KindConfiguration, "new client", "architecture_invalid",
			"Arch must be x86 or x64")
	}
	if opts.Platform != "windows" {
		return opts, nil, nil, newError(
			KindConfiguration, "new client", "platform_invalid",
			"Platform must be windows")
	}
	if opts.HostIntegrity.ManifestPath == "" {
		opts.HostIntegrity.ManifestPath = "release-integrity.v2"
	}
	if filepath.IsAbs(opts.HostIntegrity.ManifestPath) {
		return opts, nil, nil, newError(
			KindConfiguration, "new client", "manifest_path_invalid",
			"HostIntegrity.ManifestPath must be package-relative")
	}
	if _, err := safeRelativePath(opts.HostIntegrity.ManifestPath); err != nil {
		return opts, nil, nil, err
	}
	if opts.Transport == nil {
		opts.Transport = http.DefaultTransport
	}
	return opts, base, web, nil
}

func parseServiceURL(raw string, allowInsecure bool) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" ||
		(parsed.Scheme != "https" && !(allowInsecure && parsed.Scheme == "http")) {
		return nil, newError(
			KindConfiguration, "new client", "base_url_invalid",
			"BaseURL and WebBaseURL must be absolute HTTPS URLs")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed, nil
}

func normalizeArch(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "386", "i386", "x86", "win-x86":
		return "x86"
	case "amd64", "x64", "win-x64":
		return "x64"
	default:
		return ""
	}
}

func isUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' ||
		value[18] != '-' || value[23] != '-' {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func safeRelativePath(value string) (string, error) {
	normalized := strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if normalized == "" || strings.HasPrefix(normalized, "/") ||
		strings.Contains(normalized, ":") || strings.ContainsRune(normalized, 0) {
		return "", newError(KindIntegrity, "path", "host_unsafe_path", "integrity path is unsafe")
	}
	for _, part := range strings.Split(normalized, "/") {
		if part == "" || part == "." || part == ".." {
			return "", newError(KindIntegrity, "path", "host_unsafe_path", "integrity path is unsafe")
		}
	}
	return normalized, nil
}

func defaultStorageDirectory(appID string) (string, error) {
	local := os.Getenv("LOCALAPPDATA")
	if strings.TrimSpace(local) == "" {
		var err error
		local, err = os.UserCacheDir()
		if err != nil {
			return "", wrapError(KindIdentity, "storage", err)
		}
	}
	hash := sha256Hex([]byte(appID))
	return filepath.Join(local, "SwmSdk", hash[:12]), nil
}

type integrityProviderFunc func(context.Context, IntegrityEvidenceContext) (IntegrityEvidence, error)

func (f integrityProviderFunc) GetEvidence(ctx context.Context, info IntegrityEvidenceContext) (IntegrityEvidence, error) {
	return f(ctx, info)
}

var _ IntegrityEvidenceProvider = integrityProviderFunc(nil)

func formatErrorf(kind ErrorKind, op, format string, args ...any) *Error {
	return newError(kind, op, "", fmt.Sprintf(format, args...))
}
