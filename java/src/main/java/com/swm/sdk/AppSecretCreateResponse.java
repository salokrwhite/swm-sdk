package com.swm.sdk;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

public final class AppSecretCreateResponse {
    @JsonProperty("app_secret")
    private String appSecret;

    @JsonProperty("item")
    private Map<String, Object> item;

    @JsonProperty("app_id")
    private String appId;

    public String getAppSecret() {
        return appSecret;
    }

    public Map<String, Object> getItem() {
        return item;
    }

    public String getAppId() {
        return appId;
    }
}
