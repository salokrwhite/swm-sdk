//go:build windows && (amd64 || 386)

package swm

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCheckUpdateEndToEnd(t *testing.T) {
	const (
		appID     = "00000000-0000-0000-0000-000000000401"
		releaseID = "00000000-0000-0000-0000-000000000402"
		keyID     = "online-key-401"
	)
	rootPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	onlineSeed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	onlinePrivate := ed25519.NewKeyFromSeed(onlineSeed)
	onlinePublic := onlinePrivate.Public().(ed25519.PublicKey)
	onlineX25519 := x25519PrivateFromSeed(onlineSeed)

	options := Options{
		BaseURL:            "https://swm.example.test",
		AppID:              appID,
		ReleaseID:          releaseID,
		Version:            "1.0.0",
		RootTrustKeyID:     "root-401",
		RootTrustPublicKey: hex.EncodeToString(rootPublic),
		Channel:            "stable",
		StorageDirectory:   t.TempDir(),
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			switch request.URL.Path {
			case "/api/client/time":
				return jsonResponse(t, serverTimeBody(t, request, appID, releaseID, rootPrivate)), nil
			case "/api/client/key-manifest":
				return jsonResponse(t, onlineKeyBody(t, appID, releaseID, keyID, onlinePublic, rootPrivate)), nil
			case "/api/client/update-check":
				timestamp, err := strconv.ParseInt(request.Header.Get(headerTimestamp), 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				requestBody, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				plaintext, err := decryptBodyForTest(
					requestBody,
					onlineX25519,
					onlinePublic,
					keyID,
					request.Method,
					request.URL,
					timestamp,
					request.Header.Get(headerNonce),
					appID,
					releaseID,
					"1.0.0",
					nil,
				)
				if err != nil {
					t.Fatal(err)
				}
				var updateRequest updateCheckWireRequest
				if err := json.Unmarshal(plaintext, &updateRequest); err != nil {
					t.Fatal(err)
				}
				updateData := []byte(`{"update_available":false,"heartbeat_interval_seconds":30}`)
				carrier := signedAuthzCarrier(
					t,
					appID,
					releaseID,
					updateRequest.DeviceID,
					request.Header.Get(headerNonce),
					"sdk-test-session",
					updateData,
					keyID,
					onlinePrivate,
				)
				return jsonResponse(t, carrier), nil
			default:
				t.Fatalf("unexpected endpoint: %s", request.URL.Path)
				return nil, nil
			}
		}),
	}
	client, err := NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	identity, err := client.ensureIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer identity.key.Delete()

	update, err := client.CheckUpdate(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if update.UpdateAvailable || update.HeartbeatIntervalSeconds != 30 {
		t.Fatalf("unexpected update response: %#v", update)
	}
	if client.SessionToken() != "sdk-test-session" || client.CloudState() != CloudAvailable {
		t.Fatalf("session state not established: token=%q state=%s", client.SessionToken(), client.CloudState())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func jsonResponse(t *testing.T, body []byte) *http.Response {
	t.Helper()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func serverTimeBody(
	t *testing.T,
	request *http.Request,
	appID, releaseID string,
	rootPrivate ed25519.PrivateKey,
) []byte {
	t.Helper()
	now := time.Now().UnixMilli()
	body := serverTimeManifest{
		ManifestVersion: "server_time_v1",
		AppID:           appID,
		ReleaseID:       releaseID,
		Nonce:           request.Header.Get(headerNonce),
		ServerTimeMS:    now,
		ExpiresAtMS:     now + 30000,
		RootTrustKeyID:  "root-401",
	}
	canonical := strings.Join([]string{
		"server_time_v1",
		"app_id:" + body.AppID,
		"release_id:" + body.ReleaseID,
		"nonce:" + body.Nonce,
		"server_time_ms:" + strconv.FormatInt(body.ServerTimeMS, 10),
		"expires_at_ms:" + strconv.FormatInt(body.ExpiresAtMS, 10),
		"root_trust_key_id:" + body.RootTrustKeyID,
	}, "\n")
	body.Signature = base64URLEncode(ed25519.Sign(rootPrivate, []byte(canonical)))
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func onlineKeyBody(
	t *testing.T,
	appID, releaseID, keyID string,
	publicKey ed25519.PublicKey,
	rootPrivate ed25519.PrivateKey,
) []byte {
	t.Helper()
	now := time.Now().Unix()
	body := onlineKeyManifest{
		ManifestVersion: "online_key_manifest_v1",
		Purpose:         "online_body",
		AppID:           appID,
		ReleaseID:       releaseID,
		KeyID:           keyID,
		PublicKey:       hex.EncodeToString(publicKey),
		RootTrustKeyID:  "root-401",
		IssuedAt:        now - 1,
		RefreshAfter:    now + 3600,
	}
	canonical := strings.Join([]string{
		body.ManifestVersion,
		"purpose:" + body.Purpose,
		"app_id:" + body.AppID,
		"release_id:" + body.ReleaseID,
		"key_id:" + body.KeyID,
		"public_key:" + body.PublicKey,
		"root_trust_key_id:" + body.RootTrustKeyID,
		"issued_at:" + strconv.FormatInt(body.IssuedAt, 10),
		"refresh_after:" + strconv.FormatInt(body.RefreshAfter, 10),
	}, "\n")
	body.RootTrustSignature = base64URLEncode(ed25519.Sign(rootPrivate, []byte(canonical)))
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decryptBodyForTest(
	sealed []byte,
	xPrivate *ecdh.PrivateKey,
	onlinePublic ed25519.PublicKey,
	keyID, method string,
	resource *url.URL,
	timestamp int64,
	nonce, appID, releaseID, version string,
	versionCode *int,
) ([]byte, error) {
	if len(sealed) < 32+12+16 {
		return nil, io.ErrUnexpectedEOF
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(sealed[:32])
	if err != nil {
		return nil, err
	}
	shared, err := xPrivate.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	contextValue := strings.Join([]string{
		bodyEncryptionLabel,
		"app_id:" + appID,
		"release_id:" + releaseID,
		"key_id:" + keyID,
		"public_key:" + hex.EncodeToString(onlinePublic),
	}, "\n")
	salt := sha256Bytes([]byte(contextValue))
	info := contextValue + "\nephemeral_public:" + base64URLEncode(sealed[:32])
	key, err := hkdf.Key(sha256.New, shared, salt, info, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := buildBodyEncryptionAAD(
		method,
		resource.EscapedPath(),
		canonicalQuery(resource.Query()),
		timestamp,
		nonce,
		appID,
		releaseID,
		version,
		versionCode,
		keyID,
	)
	return aead.Open(nil, sealed[32:44], sealed[44:], []byte(aad))
}

func signedAuthzCarrier(
	t *testing.T,
	appID, releaseID, deviceID, nonce, session string,
	data []byte,
	keyID string,
	privateKey ed25519.PrivateKey,
) []byte {
	t.Helper()
	now := time.Now().Unix()
	envelope := authzV3Envelope{
		Version:    "authz_v3",
		Decision:   "allow",
		ReleaseID:  releaseID,
		DeviceID:   deviceID,
		Nonce:      nonce,
		DataSHA256: sha256Hex(data),
		Session:    session,
		IssuedAt:   now,
		ExpiresAt:  now + 600,
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
		"session:" + session,
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
	return carrier
}
