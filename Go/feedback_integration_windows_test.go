//go:build windows && (amd64 || 386)

package swm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSubmitFeedbackEndToEnd(t *testing.T) {
	const (
		appID      = "00000000-0000-0000-0000-000000000701"
		releaseID  = "00000000-0000-0000-0000-000000000702"
		keyID      = "online-key-701"
		sessionID  = "sdk-feedback-session"
		feedbackID = "00000000-0000-0000-0000-000000000703"
	)
	rootPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	rootPublic := rootPrivate.Public().(ed25519.PublicKey)
	onlineSeed := bytes.Repeat([]byte{0x52}, ed25519.SeedSize)
	onlinePrivate := ed25519.NewKeyFromSeed(onlineSeed)
	onlinePublic := onlinePrivate.Public().(ed25519.PublicKey)
	onlineX25519 := x25519PrivateFromSeed(onlineSeed)

	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
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
			encryptedBody, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := decryptBodyForTest(
				encryptedBody,
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
			carrier := signedAuthzCarrier(
				t,
				appID,
				releaseID,
				updateRequest.DeviceID,
				request.Header.Get(headerNonce),
				sessionID,
				[]byte(`{"update_available":false,"heartbeat_interval_seconds":30}`),
				keyID,
				onlinePrivate,
			)
			return jsonResponse(t, carrier), nil
		case "/api/client/feedback":
			mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
			if err != nil {
				t.Fatal(err)
			}
			if mediaType != "multipart/form-data" || parameters["boundary"] == "" {
				t.Fatalf("unexpected feedback content type: %s", request.Header.Get("Content-Type"))
			}
			timestamp, err := strconv.ParseInt(request.Header.Get(headerTimestamp), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			encryptedBody, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			plaintext, err := decryptBodyForTest(
				encryptedBody,
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
			fields, files := parseFeedbackMultipartForTest(t, plaintext, parameters["boundary"])
			if fields["content"] != "feedback content" ||
				fields["rating"] != "5" ||
				fields["contact"] != "user@example.com" ||
				fields["app_version"] != "1.2.3" ||
				fields["metadata"] != `{"os":"windows"}` {
				t.Fatalf("unexpected feedback fields: %#v", fields)
			}
			if string(files["screen.txt"]) != "attachment body" {
				t.Fatalf("unexpected feedback attachment: %#v", files)
			}
			responseData := []byte(`{"ok":true,"id":"` + feedbackID + `"}`)
			carrier := signedAuthzCarrier(
				t,
				appID,
				releaseID,
				fields["device_id"],
				request.Header.Get(headerNonce),
				sessionID,
				responseData,
				keyID,
				onlinePrivate,
			)
			return jsonResponse(t, carrier), nil
		default:
			t.Fatalf("unexpected endpoint: %s", request.URL.Path)
			return nil, nil
		}
	})

	client, err := NewClient(Options{
		BaseURL:            "https://swm.example.test",
		AppID:              appID,
		ReleaseID:          releaseID,
		Version:            "1.0.0",
		RootTrustKeyID:     "root-401",
		RootTrustPublicKey: hex.EncodeToString(rootPublic),
		Channel:            "stable",
		StorageDirectory:   t.TempDir(),
		Transport:          transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	identity, err := client.ensureIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer identity.key.Delete()

	if _, err := client.CheckUpdate(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := client.RefreshOnlineKeys(context.Background()); err != nil {
		t.Fatal(err)
	}

	attachmentPath := filepath.Join(t.TempDir(), "screen.txt")
	if err := os.WriteFile(attachmentPath, []byte("attachment body"), 0o600); err != nil {
		t.Fatal(err)
	}
	rating := 5
	result, err := client.SubmitFeedback(context.Background(), FeedbackRequest{
		Content:         "feedback content",
		Rating:          &rating,
		Contact:         "user@example.com",
		AppVersion:      "1.2.3",
		AttachmentPaths: []string{attachmentPath},
		Metadata:        map[string]any{"os": "windows"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.ID != feedbackID {
		t.Fatalf("unexpected feedback result: %#v", result)
	}
}

func parseFeedbackMultipartForTest(
	t *testing.T,
	body []byte,
	boundary string,
) (map[string]string, map[string][]byte) {
	t.Helper()
	fields := make(map[string]string)
	files := make(map[string][]byte)
	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		value, err := io.ReadAll(part)
		_ = part.Close()
		if err != nil {
			t.Fatal(err)
		}
		name := part.FormName()
		if part.FileName() != "" {
			files[part.FileName()] = value
		} else if strings.TrimSpace(name) != "" {
			fields[name] = string(value)
		}
	}
	return fields, files
}
