package swmsdk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
)

func (c *Client) UploadArtifact(ctx context.Context, releaseID string, opt UploadArtifactOptions) (map[string]interface{}, error) {
	if strings.TrimSpace(opt.Platform) == "" || strings.TrimSpace(opt.Arch) == "" || strings.TrimSpace(opt.FileType) == "" {
		return nil, fmt.Errorf("platform, arch, file_type required")
	}
	file, err := os.Open(opt.FilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("platform", opt.Platform)
	_ = writer.WriteField("arch", opt.Arch)
	_ = writer.WriteField("file_type", opt.FileType)
	if strings.TrimSpace(opt.Signature) != "" {
		_ = writer.WriteField("signature", opt.Signature)
	}
	if opt.Replace {
		_ = writer.WriteField("replace", "true")
	}

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, filepath.Base(opt.FilePath)))
	h.Set("Content-Type", "application/octet-stream")
	part, err := writer.CreatePart(h)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	resp, err := c.doAuthRequest(ctx, http.MethodPost, "/api/releases/"+releaseID+"/artifacts", nil, &body, writer.FormDataContentType())
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[map[string]map[string]interface{}](resp)
	if err != nil {
		return nil, err
	}
	return out["artifact"], nil
}

func (c *Client) ListArtifacts(ctx context.Context, releaseID string) ([]map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodGet, "/api/releases/"+releaseID+"/artifacts", nil, nil)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[listResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) GetArtifactDownloadURL(ctx context.Context, artifactID string) (string, error) {
	if err := c.ensureAuthToken(); err != nil {
		return "", err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/artifacts/"+artifactID+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+c.AuthToken)
	if err := c.signAuthRequestHeaders(req, nil); err != nil {
		return "", err
	}

	hc := *c.HTTPClient
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location == "" {
			return "", fmt.Errorf("missing redirect location")
		}
		return location, nil
	}
	if resp.StatusCode >= 300 {
		return "", parseErrorResponse(resp)
	}
	return "", fmt.Errorf("unexpected status %s, expected redirect", resp.Status)
}

