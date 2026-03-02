package swmsdk

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

func (c *Client) ListReleaseChannels(ctx context.Context, appID string) ([]map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodGet, "/api/apps/"+appID+"/release-channels", nil, nil)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[listResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) CreateReleaseChannel(ctx context.Context, appID string, payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPost, "/api/apps/"+appID+"/release-channels", nil, payload)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[releaseChannelResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.ReleaseChannel, nil
}

func (c *Client) UpdateReleaseChannel(ctx context.Context, releaseChannelID string, payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPatch, "/api/release-channels/"+releaseChannelID, nil, payload)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[releaseChannelResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.ReleaseChannel, nil
}

func (c *Client) GetReleaseChannelMetrics(ctx context.Context, appID, releaseChannelID, from, to string) (map[string]interface{}, error) {
	query := url.Values{}
	if strings.TrimSpace(from) != "" {
		query.Set("from", from)
	}
	if strings.TrimSpace(to) != "" {
		query.Set("to", to)
	}
	resp, err := c.doAuthJSON(ctx, http.MethodGet, "/api/apps/"+appID+"/release-channels/"+releaseChannelID+"/metrics", query, nil)
	if err != nil {
		return nil, err
	}
	return decodeJSONResponse[map[string]interface{}](resp)
}

func (c *Client) GetAppRegionRules(ctx context.Context, appID string) (interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodGet, "/api/apps/"+appID+"/region-rules", nil, nil)
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[appRegionRulesResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.RegionRules, nil
}

func (c *Client) UpdateAppRegionRules(ctx context.Context, appID string, rules interface{}) (interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodPatch, "/api/apps/"+appID+"/region-rules", nil, map[string]interface{}{"region_rules": rules})
	if err != nil {
		return nil, err
	}
	out, err := decodeJSONResponse[appRegionRulesResponse](resp)
	if err != nil {
		return nil, err
	}
	return out.RegionRules, nil
}

func (c *Client) ListGeoRegions(ctx context.Context) (map[string]interface{}, error) {
	resp, err := c.doAuthJSON(ctx, http.MethodGet, "/api/geo/regions", nil, nil)
	if err != nil {
		return nil, err
	}
	return decodeJSONResponse[map[string]interface{}](resp)
}

func (c *Client) ResolveGeo(ctx context.Context, ip string) (map[string]interface{}, error) {
	query := url.Values{}
	query.Set("ip", ip)
	resp, err := c.doAuthJSON(ctx, http.MethodGet, "/api/geo/resolve", query, nil)
	if err != nil {
		return nil, err
	}
	return decodeJSONResponse[map[string]interface{}](resp)
}

