package swmsdk

import (
	"context"
	"encoding/json"
	"net/http"
)

func (c *Client) CheckUpdate(ctx context.Context, currentVersion string, versionCode *int) (UpdateCheckResponse, error) {
	req := UpdateCheckRequest{
		ChannelCode:    c.Channel,
		CurrentVersion: currentVersion,
		VersionCode:    versionCode,
		Platform:       c.Platform,
		Arch:           c.Arch,
		DeviceID:       c.DeviceID,
		Attributes:     c.Attributes,
	}
	body, _ := json.Marshal(req)
	resp, err := c.doRequest(ctx, http.MethodPost, "/api/client/update-check", body)
	if err != nil {
		return UpdateCheckResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return UpdateCheckResponse{}, parseAPIErrorResponse(resp)
	}
	var out UpdateCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return UpdateCheckResponse{}, err
	}
	if c.VerifySignature && out.Signature != "" && out.ChecksumSHA256 != "" {
		if err := c.verifySignature(out.ChecksumSHA256, out.Signature); err != nil {
			return UpdateCheckResponse{}, err
		}
	}
	return out, nil
}

