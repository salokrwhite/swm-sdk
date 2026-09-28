package swm

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVerifyAuthzV3AndSessionUpdate(t *testing.T) {
	const (
		appID     = "00000000-0000-0000-0000-000000000201"
		releaseID = "00000000-0000-0000-0000-000000000202"
		deviceID  = "device-201"
		nonce     = "00000000-0000-0000-0000-000000000203"
		keyID     = "key-201"
	)
	seed := bytes.Repeat([]byte{0x11}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	client := &Client{
		options: Options{
			AppID:     appID,
			ReleaseID: releaseID,
			DeviceID:  deviceID,
		},
		clock: &trustedClock{},
		currentKey: &protocolKey{
			keyID:        keyID,
			publicKey:    hex.EncodeToString(publicKey),
			issuedAt:     1,
			refreshAfter: 9999999999,
		},
	}
	now := time.Now()
	if err := client.clock.setAuthoritativeTime(now.UnixMilli(), now, now); err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"ok":true}`)
	envelope := authzV3Envelope{
		Version:    "authz_v3",
		Decision:   "allow",
		ReleaseID:  releaseID,
		DeviceID:   deviceID,
		Nonce:      nonce,
		DataSHA256: sha256Hex(data),
		Session:    "session-201",
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(10 * time.Minute).Unix(),
		KeyID:      keyID,
	}
	canonical := strings.Join([]string{
		"authz_v3",
		"app_id:" + appID,
		"release_id:" + releaseID,
		"device_id:" + deviceID,
		"nonce:" + nonce,
		"decision:allow",
		"reason:",
		"data_sha256:" + envelope.DataSHA256,
		"session:" + envelope.Session,
		"issued_at:" + strconv.FormatInt(envelope.IssuedAt, 10),
		"expires_at:" + strconv.FormatInt(envelope.ExpiresAt, 10),
		"key_id:" + keyID,
	}, "\n")
	envelope.Signature = base64URLEncode(ed25519.Sign(privateKey, []byte(canonical)))
	carrier, err := json.Marshal(map[string]any{
		"data":  json.RawMessage(data),
		"authz": envelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := client.verifyAuthz(protocolResponse{
		status:  http.StatusOK,
		body:    carrier,
		nonce:   nonce,
		headers: http.Header{},
	}, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if string(verified) != string(data) {
		t.Fatalf("verified data mismatch: %s", verified)
	}
	if client.SessionToken() != "session-201" {
		t.Fatalf("session was not updated: %q", client.SessionToken())
	}

	carrier, err = json.Marshal(map[string]any{
		"data":  json.RawMessage(`{"ok":false}`),
		"authz": envelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.verifyAuthz(protocolResponse{
		status:  http.StatusOK,
		body:    carrier,
		nonce:   nonce,
		headers: http.Header{},
	}, nonce); err == nil {
		t.Fatal("tampered Authz v3 data was accepted")
	}
}

func TestArtifactVerification(t *testing.T) {
	rootSeed := bytes.Repeat([]byte{0x22}, ed25519.SeedSize)
	rootPrivate := ed25519.NewKeyFromSeed(rootSeed)
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	signerSeed := bytes.Repeat([]byte{0x33}, ed25519.SeedSize)
	signerPrivate := ed25519.NewKeyFromSeed(signerSeed)
	signerPublic := signerPrivate.Public().(ed25519.PublicKey)
	update := UpdateInfo{
		UpdateAvailable:       true,
		ReleaseID:             "00000000-0000-0000-0000-000000000301",
		Version:               "1.2.3",
		DownloadURL:           "https://example.test/api/client/artifacts/00000000-0000-0000-0000-000000000302/download?ticket=x",
		ChecksumSHA256:        strings.Repeat("a", 64),
		ManifestKeyID:         "manifest-301",
		ManifestPublicKey:     hex.EncodeToString(signerPublic),
		RootTrustKeyID:        "root-301",
		ArtifactFileName:      "app.zip",
		ArtifactPlatform:      "windows",
		ArtifactArch:          "x64",
		Size:                  1234,
		HostIntegrityRequired: false,
	}
	rootCanonical := strings.Join([]string{
		"root_trust_manifest_v1",
		"app_id:00000000-0000-0000-0000-000000000303",
		"signer_key_id:root-301",
		"key_id:manifest-301",
		"public_key:" + update.ManifestPublicKey,
	}, "\n")
	update.RootTrustSignature = base64URLEncode(ed25519.Sign(rootPrivate, []byte(rootCanonical)))
	artifactCanonical := strings.Join([]string{
		"artifact_manifest_v1",
		"release_id:" + update.ReleaseID,
		"release_version:" + update.Version,
		"version_code:",
		"platform:windows",
		"arch:x64",
		"size:1234",
		"sha256:" + update.ChecksumSHA256,
		"key_id:" + update.ManifestKeyID,
	}, "\n")
	update.Signature = base64URLEncode(ed25519.Sign(signerPrivate, []byte(artifactCanonical)))
	options := Options{
		AppID:              "00000000-0000-0000-0000-000000000303",
		RootTrustKeyID:     "root-301",
		RootTrustPublicKey: hex.EncodeToString(rootPublic),
		Arch:               "x64",
	}
	if err := verifyUpdateArtifact(update, options); err != nil {
		t.Fatal(err)
	}
	if err := verifyDownloadArtifact(update, update.ChecksumSHA256); err != nil {
		t.Fatal(err)
	}
	if err := verifyDownloadArtifact(update, strings.Repeat("b", 64)); err == nil {
		t.Fatal("checksum mismatch was accepted")
	}
}

func TestThrowIfErrorMappings(t *testing.T) {
	client := &Client{}
	err := client.throwIfError(protocolResponse{
		status:  http.StatusForbidden,
		body:    []byte(`{"error":{"code":"device_blocked","message":"blocked"}}`),
		headers: http.Header{},
	})
	if !errors.Is(err, ErrDeviceBlocked) {
		t.Fatalf("device_blocked did not map to sentinel: %v", err)
	}
	err = client.throwIfError(protocolResponse{
		status:  http.StatusTooManyRequests,
		body:    []byte(`{"error":"rate_limited"}`),
		headers: http.Header{"Retry-After": []string{"3"}},
	})
	var sdkErr *Error
	if !errors.As(err, &sdkErr) || sdkErr.Kind != KindRateLimit || sdkErr.RetryAfter != 3*time.Second {
		t.Fatalf("unexpected rate-limit error: %#v", err)
	}
}

func TestRandomUUIDShape(t *testing.T) {
	value, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	if !isUUID(value) || value[14] != '4' {
		t.Fatalf("invalid UUIDv4: %q", value)
	}
}
