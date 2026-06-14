package com.swm.sdk;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

public final class UpdatePushEvent {
    @JsonProperty("id")
    private String id;

    @JsonProperty("event_type")
    private String eventType;

    @JsonProperty("org_id")
    private String orgId;

    @JsonProperty("app_id")
    private String appId;

    @JsonProperty("device_id")
    private String deviceId;

    @JsonProperty("channel_code")
    private String channelCode;

    @JsonProperty("platform")
    private String platform;

    @JsonProperty("arch")
    private String arch;

    @JsonProperty("release_id")
    private String releaseId;

    @JsonProperty("published_at")
    private Instant publishedAt;

    @JsonProperty("reason")
    private String reason;

    @JsonProperty("message")
    private String message;

    @JsonProperty("maintenance_start_at")
    private Instant maintenanceStartAt;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getOrgId() {
        return orgId;
    }

    public String getAppId() {
        return appId;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getChannelCode() {
        return channelCode;
    }

    public String getPlatform() {
        return platform;
    }

    public String getArch() {
        return arch;
    }

    public String getReleaseId() {
        return releaseId;
    }

    public Instant getPublishedAt() {
        return publishedAt;
    }

    public String getReason() {
        return reason;
    }

    public String getMessage() {
        return message;
    }

    public Instant getMaintenanceStartAt() {
        return maintenanceStartAt;
    }
}
