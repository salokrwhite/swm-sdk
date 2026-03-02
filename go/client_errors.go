package swmsdk

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func parseAPIErrorResponse(resp *http.Response) error {
	if resp == nil {
		return fmt.Errorf("request failed")
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		return fmt.Errorf("request failed: %s", resp.Status)
	}

	type errorPayload struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	type errorBody struct {
		Error json.RawMessage `json:"error"`
	}

	var parsed errorBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("request failed: %s", resp.Status)
	}
	if len(parsed.Error) == 0 {
		return fmt.Errorf("request failed: %s", resp.Status)
	}

	var nested errorPayload
	if err := json.Unmarshal(parsed.Error, &nested); err == nil && strings.TrimSpace(nested.Code) != "" {
		if strings.EqualFold(strings.TrimSpace(nested.Code), APIErrorCodeDeviceBlocked) {
			return ErrDeviceBlocked
		}
		if strings.TrimSpace(nested.Message) != "" {
			return fmt.Errorf("%s: %s", nested.Code, nested.Message)
		}
		return fmt.Errorf("%s", nested.Code)
	}

	var flat string
	if err := json.Unmarshal(parsed.Error, &flat); err == nil && strings.TrimSpace(flat) != "" {
		return fmt.Errorf("%s", strings.TrimSpace(flat))
	}

	return fmt.Errorf("request failed: %s", resp.Status)
}

