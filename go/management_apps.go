package swmsdk

import (
	"context"
	"net/http"
)

func (c *Client) GetApp(ctx context.Context, appID string) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodGet, "/api/apps/"+appID, nil, nil)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[appResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.App, nil
}

func (c *Client) UpdateApp(ctx context.Context, appID string, payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPatch, "/api/apps/"+appID, nil, payload)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[appResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.App, nil
}

func (c *Client) ListChannels(ctx context.Context, appID string) ([]map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodGet, "/api/apps/"+appID+"/channels", nil, nil)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[listResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) CreateChannel(ctx context.Context, appID string, payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPost, "/api/apps/"+appID+"/channels", nil, payload)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[channelResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Channel, nil
}

func (c *Client) ListAppMembers(ctx context.Context, appID string) ([]map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodGet, "/api/apps/"+appID+"/members", nil, nil)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[listResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) AddAppMember(ctx context.Context, appID string, payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPost, "/api/apps/"+appID+"/members", nil, payload)
	if err != nil {
		return nil, err
	}
	return decodeJSONResponse[map[string]interface{}](resp)
}

