package swmsdk

import (
	"context"
	"net/http"
)

func (c *Client) ListReleaseTemplates(ctx context.Context) ([]map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodGet, "/api/release-templates", nil, nil)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[listResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) CreateReleaseTemplate(ctx context.Context, payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPost, "/api/release-templates", nil, payload)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[templateResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Template, nil
}

func (c *Client) UpdateReleaseTemplate(ctx context.Context, templateID string, payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPatch, "/api/release-templates/"+templateID, nil, payload)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[templateResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Template, nil
}

func (c *Client) DeleteReleaseTemplate(ctx context.Context, templateID string) error {
	resp, err := c.doAuthJSON(ctx, http.MethodDelete, "/api/release-templates/"+templateID, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return parseErrorResponse(resp)
	}
	return nil
}

func (c *Client) SetReleaseTemplate(ctx context.Context, releaseID, templateID string) (map[string]interface{}, error) {
	payload := map[string]interface{}{"template_id": templateID}
	resp, err := c.doAuthJSON(ctx, http.MethodPatch, "/api/releases/"+releaseID+"/template", nil, payload)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[releaseResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Release, nil
}

