package swmsdk

type listResponse struct {
	Items []map[string]interface{} `json:"items"`
}

type appResponse struct {
	App map[string]interface{} `json:"app"`
}

type channelResponse struct {
	Channel map[string]interface{} `json:"channel"`
}

type releaseResponse struct {
	Release map[string]interface{} `json:"release"`
}

type releaseChannelResponse struct {
	ReleaseChannel map[string]interface{} `json:"release_channel"`
}

type templateResponse struct {
	Template map[string]interface{} `json:"template"`
}

type AppSecretCreateResponse struct {
	AppSecret string                 `json:"app_secret"`
	Item      map[string]interface{} `json:"item"`
	AppID     string                 `json:"app_id"`
}

type appRegionRulesResponse struct {
	RegionRules interface{} `json:"region_rules"`
}

type apiErrorBody struct {
	Error string `json:"error"`
}

type UploadArtifactOptions struct {
	Platform  string
	Arch      string
	FileType  string
	FilePath  string
	Signature string
	Replace   bool
}

