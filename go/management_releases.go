package swmsdk

import (
	"context"
	"net/http"
)

func (c *Client) ListReleases(ctx context.Context, appID string) ([]map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodGet, "/api/apps/"+appID+"/releases", nil, nil)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[listResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) CreateRelease(ctx context.Context, appID string, payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPost, "/api/apps/"+appID+"/releases", nil, payload)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[releaseResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Release, nil
}

func (c *Client) UpdateRelease(ctx context.Context, releaseID string, payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPatch, "/api/releases/"+releaseID, nil, payload)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[releaseResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Release, nil
}

func (c *Client) DeleteRelease(ctx context.Context, releaseID string) error {
	resp, err := c.doAuthJSON(ctx, http.MethodDelete, "/api/releases/"+releaseID, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) SubmitRelease(ctx context.Context, releaseID, note string) error {
	return c.reviewReleaseAction(ctx, releaseID, "submit", note)
}

func (c *Client) ApproveRelease(ctx context.Context, releaseID, note string) error {
	return c.reviewReleaseAction(ctx, releaseID, "approve", note)
}

func (c *Client) RejectRelease(ctx context.Context, releaseID, note string) error {
	return c.reviewReleaseAction(ctx, releaseID, "reject", note)
}

func (c *Client) reviewReleaseAction(ctx context.Context, releaseID, action, note string) error {
	payload := map[string]interface{}{"note": note}
	resp, err := c.doAuthJSON(ctx, http.MethodPost, "/api/releases/"+releaseID+"/"+action, nil, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) PublishRelease(ctx context.Context, releaseID string, payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPost, "/api/releases/"+releaseID+"/publish", nil, payload)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[releaseChannelResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.ReleaseChannel, nil
}

func (c *Client) RollbackRelease(ctx context.Context, releaseID string, payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPost, "/api/releases/"+releaseID+"/rollback", nil, payload)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[releaseChannelResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.ReleaseChannel, nil
}

func (c *Client) RevokeRelease(ctx context.Context, releaseID string) error {
	resp, err := c.doAuthJSON(ctx, http.MethodPost, "/api/releases/"+releaseID+"/revoke", nil, map[string]interface{}{})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return parseErrorResponse(resp)
	}
	return nil
}

