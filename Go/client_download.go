package swm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DownloadUpdate downloads and verifies a signed update package with Range
// continuation.
func (c *Client) DownloadUpdate(
	ctx context.Context,
	update UpdateInfo,
	destination string,
	progress ProgressFunc,
) error {
	if err := c.checkOpen(); err != nil {
		return err
	}
	if !update.UpdateAvailable || update.OpenInBrowser {
		return newError(KindValidation, "download", "download_unavailable", "update does not contain a downloadable package")
	}
	if strings.TrimSpace(destination) == "" {
		return newError(KindValidation, "download", "destination_required", "destination path is required")
	}
	downloadURL, err := c.validateDownloadURL(update.DownloadURL)
	if err != nil {
		return err
	}
	fullDestination, err := filepath.Abs(destination)
	if err != nil {
		return wrapError(KindValidation, "download", err)
	}
	if err := os.MkdirAll(filepath.Dir(fullDestination), 0o700); err != nil {
		return wrapError(KindValidation, "download", err)
	}
	partial := fullDestination + ".part"
	policy := policyFor(opDownload)
	var lastError error
	for attempt := 0; attempt <= policy.retries; attempt++ {
		if err := c.downloadRange(ctx, downloadURL, partial, update.Size, progress); err == nil {
			lastError = nil
			break
		} else {
			lastError = err
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
		}
		if attempt >= policy.retries {
			break
		}
		if err := sleepContext(ctx, backoff(policy, attempt)); err != nil {
			return err
		}
	}
	if lastError != nil {
		return wrapError(KindNetwork, "download", lastError)
	}
	file, err := os.Open(partial)
	if err != nil {
		return wrapError(KindValidation, "download", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		_ = file.Close()
		return wrapError(KindValidation, "download", err)
	}
	_ = file.Close()
	actual := hex.EncodeToString(hasher.Sum(nil))
	if err := verifyDownloadArtifact(update, actual); err != nil {
		_ = os.Remove(partial)
		return err
	}
	if err := os.Remove(fullDestination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return wrapError(KindValidation, "download", err)
	}
	if err := os.Rename(partial, fullDestination); err != nil {
		return wrapError(KindValidation, "download", err)
	}
	return nil
}

func (c *Client) downloadRange(
	ctx context.Context,
	downloadURL *url.URL,
	partialPath string,
	totalSize int64,
	progress ProgressFunc,
) error {
	var existing int64
	if info, err := os.Stat(partialPath); err == nil {
		existing = info.Size()
	}
	if totalSize > 0 && existing > totalSize {
		_ = os.Remove(partialPath)
		existing = 0
	}
	initial, err := c.sendDownloadRequest(ctx, downloadURL, existing, true)
	if err != nil {
		return err
	}
	response := initial
	if initial.StatusCode >= 300 && initial.StatusCode < 400 {
		location, err := initial.Location()
		_ = initial.Body.Close()
		if err != nil {
			return newError(KindProtocol, "download", "download_redirect_invalid", "artifact download redirect is missing a location")
		}
		storageURL := location
		if !storageURL.IsAbs() {
			storageURL = downloadURL.ResolveReference(location)
		}
		if storageURL.Scheme != "https" && !c.options.AllowInsecureHTTP {
			return newError(KindNetwork, "download", "storage_https_required", "storage redirect must use HTTPS")
		}
		response, err = c.sendStorageRequest(ctx, storageURL, existing)
		if err != nil {
			return err
		}
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024*1024))
		return c.throwIfError(protocolResponse{
			status:  response.StatusCode,
			body:    body,
			headers: response.Header.Clone(),
		})
	}
	appendMode := existing > 0 && response.StatusCode == http.StatusPartialContent
	if !appendMode {
		existing = 0
	}
	expectedTotal := int64(0)
	if contentRange := response.Header.Get("Content-Range"); contentRange != "" {
		if slash := strings.LastIndex(contentRange, "/"); slash >= 0 {
			expectedTotal, _ = strconv.ParseInt(strings.TrimSpace(contentRange[slash+1:]), 10, 64)
		}
	}
	if expectedTotal <= 0 && response.ContentLength >= 0 {
		expectedTotal = existing + response.ContentLength
	}
	flags := os.O_CREATE | os.O_WRONLY
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	target, err := os.OpenFile(partialPath, flags, 0o600)
	if err != nil {
		return wrapError(KindValidation, "download", err)
	}
	if progress != nil {
		progress(existing, expectedTotal)
	}
	written := existing
	buffer := make([]byte, 128*1024)
	for {
		if err := ctx.Err(); err != nil {
			_ = target.Close()
			return err
		}
		count, readErr := response.Body.Read(buffer)
		if count > 0 {
			writtenCount, writeErr := target.Write(buffer[:count])
			written += int64(writtenCount)
			if writeErr != nil {
				_ = target.Close()
				return writeErr
			}
			if progress != nil {
				progress(written, expectedTotal)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = target.Close()
			return readErr
		}
	}
	if err := target.Sync(); err != nil {
		_ = target.Close()
		return err
	}
	if err := target.Close(); err != nil {
		return err
	}
	if expectedTotal > 0 && written != expectedTotal {
		return newError(KindProtocol, "download", "download_length_mismatch", fmt.Sprintf("download length mismatch: %d != %d", written, expectedTotal))
	}
	return nil
}

func (c *Client) sendDownloadRequest(
	ctx context.Context,
	downloadURL *url.URL,
	rangeStart int64,
	signed bool,
) (*http.Response, error) {
	if signed && !c.clock.isInitialized() {
		if err := c.refreshTrustedTime(ctx); err != nil {
			return nil, err
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return nil, wrapError(KindNetwork, "download", err)
	}
	if rangeStart > 0 {
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-", rangeStart))
	}
	if signed {
		session, err := c.ensureSession()
		if err != nil {
			return nil, err
		}
		proof, err := c.createDPoP(http.MethodGet, downloadURL.String(), session, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set(headerSession, session)
		request.Header.Set(headerDPoP, proof)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, wrapError(KindNetwork, "download", err)
	}
	return response, nil
}

func (c *Client) sendStorageRequest(
	ctx context.Context,
	storageURL *url.URL,
	rangeStart int64,
) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, storageURL.String(), nil)
	if err != nil {
		return nil, wrapError(KindNetwork, "download", err)
	}
	if rangeStart > 0 {
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-", rangeStart))
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, wrapError(KindNetwork, "download", err)
	}
	return response, nil
}

func (c *Client) validateDownloadURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !parsed.IsAbs() ||
		parsed.Scheme != c.baseURL.Scheme ||
		!strings.EqualFold(parsed.Hostname(), c.baseURL.Hostname()) ||
		effectivePort(parsed) != effectivePort(c.baseURL) {
		return nil, newError(KindIntegrity, "download", "download_url_invalid", "download URL is not bound to the configured SWM origin")
	}
	segments := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	if len(segments) != 5 ||
		segments[0] != "api" ||
		segments[1] != "client" ||
		segments[2] != "artifacts" ||
		!isUUID(segments[3]) ||
		segments[4] != "download" ||
		!strings.Contains(parsed.RawQuery, "ticket=") {
		return nil, newError(KindIntegrity, "download", "download_url_invalid", "download URL does not match the fixed artifact ticket route")
	}
	return parsed, nil
}

func effectivePort(value *url.URL) string {
	if value == nil {
		return ""
	}
	if port := value.Port(); port != "" {
		return port
	}
	switch strings.ToLower(value.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}
