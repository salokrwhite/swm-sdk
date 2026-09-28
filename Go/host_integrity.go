package swm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/salokrwhite/swm-sdk/Go/v2/internal/rim2"
)

type hostIntegrityManager struct {
	options  Options
	store    *stateStore
	mu       sync.Mutex
	manifest *rim2.Manifest
	root     string
}

func newHostIntegrityManager(options Options, store *stateStore) *hostIntegrityManager {
	return &hostIntegrityManager{options: options, store: store}
}

func (m *hostIntegrityManager) readCachedPolicy() (bool, bool) {
	plaintext, ok := m.store.readProtected(integrityPolicyFile)
	if !ok {
		return false, false
	}
	defer zero(plaintext)
	parts := strings.Split(string(plaintext), "\n")
	if len(parts) < 5 ||
		parts[0] != "SwmSdkIntegrityPolicyV1" ||
		parts[2] != m.options.AppID ||
		parts[3] != m.options.ReleaseID ||
		parts[4] != versionCodeString(m.options.VersionCode) {
		return false, false
	}
	switch parts[1] {
	case "1":
		return true, true
	case "0":
		return false, true
	default:
		return false, false
	}
}

func (m *hostIntegrityManager) storePolicy(required bool) {
	if cached, ok := m.readCachedPolicy(); ok && cached == required {
		return
	}
	text := strings.Join([]string{
		"SwmSdkIntegrityPolicyV1",
		boolString(required),
		m.options.AppID,
		m.options.ReleaseID,
		versionCodeString(m.options.VersionCode),
		strconv.FormatInt(timeNowUnixMilliseconds(), 10),
	}, "\n") + "\n"
	_ = m.store.writeProtected(integrityPolicyFile, []byte(text))
}

func (m *hostIntegrityManager) getEvidence(ctx context.Context) (IntegrityEvidence, error) {
	if provider := m.options.HostIntegrity.EvidenceProvider; provider != nil {
		root, err := m.packageRoot()
		if err != nil {
			return IntegrityEvidence{}, err
		}
		return provider.GetEvidence(ctx, IntegrityEvidenceContext{
			AppID:        m.options.AppID,
			ReleaseID:    m.options.ReleaseID,
			Version:      m.options.Version,
			VersionCode:  m.options.VersionCode,
			Arch:         m.options.Arch,
			PackageRoot:  root,
			ManifestPath: m.options.HostIntegrity.ManifestPath,
		})
	}
	if !m.options.HostIntegrity.Enabled {
		return IntegrityEvidence{}, nil
	}
	manifest, err := m.loadManifest(ctx)
	if err != nil {
		code := "host_integrity_internal_error"
		var rimErr *rim2.Error
		if errors.As(err, &rimErr) && rimErr.Code != "" {
			code = rimErr.Code
		} else if errors.Is(err, os.ErrPermission) || errors.Is(err, io.EOF) {
			code = "host_file_io_failed"
		}
		return IntegrityEvidence{
			IntegrityState:       "failed",
			IntegrityFailureCode: code,
		}, nil
	}
	root, err := m.packageRoot()
	if err != nil {
		return IntegrityEvidence{IntegrityState: "failed", IntegrityFailureCode: "host_file_io_failed"}, nil
	}
	files := make(map[string]string, len(manifest.Files))
	for _, file := range manifest.Files {
		fullPath, err := resolvePackagePath(root, file.Path)
		if err != nil {
			return IntegrityEvidence{IntegrityState: "failed", IntegrityFailureCode: "host_unsafe_path"}, nil
		}
		hash, err := hashFile(fullPath, ctx)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return IntegrityEvidence{IntegrityState: "failed", IntegrityFailureCode: "host_file_io_failed"}, nil
		}
		files[strings.ToLower(file.Path)] = hex.EncodeToString(hash)
	}
	return IntegrityEvidence{
		IntegrityState:  "verified",
		EvidenceVersion: 2,
		ManifestSHA256:  manifest.ManifestSHA256,
		Files:           files,
	}, nil
}

func (m *hostIntegrityManager) getRequiredEvidence(ctx context.Context) (IntegrityEvidence, error) {
	evidence, err := m.getEvidence(ctx)
	if err != nil {
		return IntegrityEvidence{}, err
	}
	if evidence.IntegrityState == "failed" {
		return IntegrityEvidence{}, newError(
			KindIntegrity, "host integrity",
			evidence.IntegrityFailureCode,
			"host integrity validation failed")
	}
	return evidence, nil
}

func (m *hostIntegrityManager) resolveOperationHashes(
	hostPath, modulePath string,
	ctx context.Context,
) (string, string, error) {
	if strings.TrimSpace(hostPath) == "" || strings.TrimSpace(modulePath) == "" {
		return "", "", newError(
			KindValidation, "operation authorization",
			"operation_auth_invalid_request",
			"HostExecutablePath and ConsumerModulePath are required")
	}
	hostHash, err := hashFile(hostPath, ctx)
	if err != nil {
		return "", "", wrapError(KindValidation, "operation host hash", err)
	}
	moduleHash, err := hashFile(modulePath, ctx)
	if err != nil {
		return "", "", wrapError(KindValidation, "operation module hash", err)
	}
	return hex.EncodeToString(hostHash), hex.EncodeToString(moduleHash), nil
}

func (m *hostIntegrityManager) loadManifest(ctx context.Context) (*rim2.Manifest, error) {
	root, err := m.packageRoot()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.manifest != nil && m.root == root {
		return m.manifest, nil
	}
	manifestPath, err := resolvePackagePath(root, m.options.HostIntegrity.ManifestPath)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	manifest, err := rim2.ParseAndVerify(
		raw,
		m.options.AppID,
		m.options.ReleaseID,
		m.options.Version,
		m.options.VersionCode,
		m.options.Arch,
		m.options.RootTrustKeyID,
		m.options.RootTrustPublicKey,
	)
	if err != nil {
		return nil, err
	}
	m.manifest = manifest
	m.root = root
	return manifest, nil
}

func (m *hostIntegrityManager) currentManifestSHA256() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.manifest == nil {
		return ""
	}
	return m.manifest.ManifestSHA256
}

func (m *hostIntegrityManager) packageRoot() (string, error) {
	root := m.options.HostIntegrity.PackageRoot
	if strings.TrimSpace(root) == "" {
		executable, err := os.Executable()
		if err != nil {
			return "", wrapError(KindIntegrity, "package root", err)
		}
		root = filepath.Dir(executable)
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", wrapError(KindIntegrity, "package root", err)
	}
	return filepath.Clean(absolute), nil
}

func resolvePackagePath(root, relative string) (string, error) {
	normalized, err := safeRelativePath(relative)
	if err != nil {
		return "", err
	}
	rootAbsolute, err := filepath.Abs(root)
	if err != nil {
		return "", wrapError(KindIntegrity, "package path", err)
	}
	path := filepath.Join(rootAbsolute, filepath.FromSlash(normalized))
	relativeToRoot, err := filepath.Rel(rootAbsolute, path)
	if err != nil || relativeToRoot == ".." ||
		strings.HasPrefix(relativeToRoot, ".."+string(filepath.Separator)) {
		return "", newError(KindIntegrity, "package path", "host_unsafe_path", "integrity path escapes the package root")
	}
	return path, nil
}

func hashFile(path string, ctx context.Context) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, 128*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		count, readErr := file.Read(buffer)
		if count > 0 {
			_, _ = hash.Write(buffer[:count])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	return hash.Sum(nil), nil
}

func versionCodeString(value *int) string {
	if value == nil {
		return ""
	}
	return strconv.Itoa(*value)
}

func boolString(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
