package swmsdk

import (
	"context"
	"net/http"
)

func (c *Client) ListAppSecrets(ctx context.Context, appID string) ([]map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodGet, "/api/apps/"+appID+"/app-secrets", nil, nil)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[listResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) CreateAppSecret(ctx context.Context, appID string, payload map[string]interface{}) (*AppSecretCreateResponse, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPost, "/api/apps/"+appID+"/app-secrets", nil, payload)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[AppSecretCreateResponse](resp)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RevokeAppSecret(ctx context.Context, keyID string) error {
	resp, err := c.doAuthJSON(ctx, http.MethodDelete, "/api/app-secrets/"+keyID, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return parseErrorResponse(resp)
	}
	return nil
}

