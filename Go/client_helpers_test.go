package swm

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalQueryAndDownloadURLValidation(t *testing.T) {
	if got := canonicalQuery(mustQuery("b=two&a=one&a=zero")); got != "a=one&a=zero&b=two" {
		t.Fatalf("canonical query mismatch: %s", got)
	}
	client := &Client{
		baseURL: mustURL("https://swm.example.test"),
	}
	_, err := client.validateDownloadURL(
		"https://swm.example.test/api/client/artifacts/00000000-0000-0000-0000-000000000601/download?ticket=t",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.validateDownloadURL("https://evil.example/api/client/artifacts/00000000-0000-0000-0000-000000000601/download?ticket=t"); err == nil {
		t.Fatal("foreign download origin was accepted")
	}
}

func mustQuery(raw string) url.Values {
	parsed, _ := url.Parse("https://example.test/?" + raw)
	return parsed.Query()
}

func mustURL(raw string) *url.URL {
	parsed, _ := url.Parse(raw)
	return parsed
}

func TestFeedbackLimitsAndPlaceholder(t *testing.T) {
	client := &Client{options: Options{
		DeviceID: "device-601",
		Channel:  "stable",
		Version:  "1.0.0",
	}}
	_, _, err := client.buildFeedbackPayload(FeedbackRequest{
		Content:         "hello",
		AttachmentPaths: []string{"a", "b", "c", "d"},
	})
	if err == nil || !strings.Contains(err.Error(), "at most 3") {
		t.Fatalf("expected attachment limit error, got %v", err)
	}
	path := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, contentType, err := client.buildFeedbackPayload(FeedbackRequest{
		Content:         "hello",
		AttachmentPaths: []string{path},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(contentType, "multipart/form-data; boundary=") {
		t.Fatalf("unexpected content type: %s", contentType)
	}
	if !strings.Contains(string(body), "name=\"content\"") ||
		!strings.Contains(string(body), "name=\"attachments\"") {
		t.Fatal("feedback multipart did not contain expected fields")
	}
}
