package com.swm.sdk;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.LinkedHashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public final class UpdateCheckRequest {
    @JsonProperty("channel_code")
    private String channelCode;

    @JsonProperty("current_version")
    private String currentVersion;

    @JsonProperty("version_code")
    private Integer versionCode;

    @JsonProperty("platform")
    private String platform;

    @JsonProperty("arch")
    private String arch;

    @JsonProperty("device_id")
    private String deviceId;

    @JsonProperty("user_id")
    private String userId;

    @JsonProperty("attributes")
    private Map<String, Object> attributes = new LinkedHashMap<>();

    public String getChannelCode() {
        return channelCode;
    }

    public UpdateCheckRequest setChannelCode(String channelCode) {
        this.channelCode = channelCode;
        return this;
    }

    public String getCurrentVersion() {
        return currentVersion;
    }

    public UpdateCheckRequest setCurrentVersion(String currentVersion) {
        this.currentVersion = currentVersion;
        return this;
    }

    public Integer getVersionCode() {
        return versionCode;
    }

    public UpdateCheckRequest setVersionCode(Integer versionCode) {
        this.versionCode = versionCode;
        return this;
    }

    public String getPlatform() {
        return platform;
    }

    public UpdateCheckRequest setPlatform(String platform) {
        this.platform = platform;
        return this;
    }

    public String getArch() {
        return arch;
    }

    public UpdateCheckRequest setArch(String arch) {
        this.arch = arch;
        return this;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public UpdateCheckRequest setDeviceId(String deviceId) {
        this.deviceId = deviceId;
        return this;
    }

    public String getUserId() {
        return userId;
    }

    public UpdateCheckRequest setUserId(String userId) {
        this.userId = userId;
        return this;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public UpdateCheckRequest setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
        return this;
    }
}
