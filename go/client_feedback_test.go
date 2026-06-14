package swmsdk

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestReportFeedbackUploadsMultipart(t *testing.T) {
	var sawAttachment bool
	var sawMetadata bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/client/feedback" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			t.Fatalf("parse multipart: %v", err)
		}
		if got := strings.TrimSpace(r.FormValue("content")); got != "hello feedback" {
			t.Fatalf("content = %q", got)
		}
		if got := strings.TrimSpace(r.FormValue("device_id")); got != "device-1" {
			t.Fatalf("device_id = %q", got)
		}
		if got := strings.TrimSpace(r.FormValue("rating")); got != "5" {
			t.Fatalf("rating = %q", got)
		}
		if strings.Contains(r.FormValue("metadata"), `"app_version":"1.0.0"`) {
			sawMetadata = true
		}
		if files := r.MultipartForm.File["attachments"]; len(files) == 1 && files[0].Filename != "" {
			sawAttachment = true
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	tmp, err := os.CreateTemp("", "feedback-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	_, _ = tmp.WriteString("attachment")
	_ = tmp.Close()

	client := New(server.URL, "app-id", "secret")
	client.DeviceID = "device-1"
	rating := 5
	err = client.ReportFeedback(context.Background(), "hello feedback", &rating, "user@example.local", []string{tmp.Name()}, map[string]interface{}{
		"app_version": "1.0.0",
	})
	if err != nil {
		t.Fatalf("ReportFeedback returned error: %v", err)
	}
	if !sawAttachment {
		t.Fatal("expected attachment part")
	}
	if !sawMetadata {
		t.Fatal("expected metadata part")
	}
}

func TestReportFeedbackDisabledError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"feedback_disabled","message":"feedback disabled"}}`))
	}))
	defer server.Close()

	client := New(server.URL, "app-id", "secret")
	client.DeviceID = "device-1"
	err := client.ReportFeedback(context.Background(), "hello feedback", nil, "", nil, nil)
	if !errors.Is(err, ErrFeedbackDisabled) {
		t.Fatalf("expected ErrFeedbackDisabled, got %v", err)
	}
}
