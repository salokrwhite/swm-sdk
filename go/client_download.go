package swmsdk

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func (c *Client) Download(ctx context.Context, url, destPath, checksum, signature string, progress func(written int64, total int64)) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	h := sha256.New()
	writer := io.MultiWriter(out, h)
	var written int64
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			wn, werr := writer.Write(buf[:n])
			written += int64(wn)
			if werr != nil {
				return werr
			}
			if progress != nil {
				progress(written, resp.ContentLength)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	if checksum != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if got != checksum {
			return fmt.Errorf("checksum mismatch: %s != %s", got, checksum)
		}
	}
	if c.VerifySignature && signature != "" && checksum != "" {
		if err := c.verifySignature(checksum, signature); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) verifySignature(checksumHex, signature string) error {
	if c.PublicKey == "" {
		return nil
	}
	pubBytes, err := decodeBase64OrHex(c.PublicKey)
	if err != nil {
		return err
	}
	sig, err := decodeBase64OrHex(signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), []byte(checksumHex), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func decodeBase64OrHex(input string) ([]byte, error) {
	if input == "" {
		return nil, fmt.Errorf("empty key")
	}
	if b, err := base64.StdEncoding.DecodeString(input); err == nil {
		return b, nil
	}
	if b, err := hex.DecodeString(input); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("invalid key encoding")
}

