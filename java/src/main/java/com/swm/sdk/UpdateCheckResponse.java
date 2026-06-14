package com.swm.sdk;

import com.fasterxml.jackson.annotation.JsonProperty;

public final class UpdateCheckResponse {
    @JsonProperty("update_available")
    private boolean updateAvailable;

    @JsonProperty("mandatory")
    private boolean mandatory;

    @JsonProperty("heartbeat_interval_seconds")
    private int heartbeatIntervalSeconds;

    @JsonProperty("open_in_browser")
    private boolean openInBrowser;

    @JsonProperty("delivery_method")
    private String deliveryMethod;

    @JsonProperty("release_id")
    private String releaseId;

    @JsonProperty("version")
    private String version;

    @JsonProperty("notes")
    private String notes;

    @JsonProperty("download_url")
    private String downloadUrl;

    @JsonProperty("checksum_sha256")
    private String checksumSha256;

    @JsonProperty("signature")
    private String signature;

    @JsonProperty("size")
    private long size;

    @JsonProperty("rollback_allowed")
    private boolean rollbackAllowed;

    @JsonProperty("maintenance")
    private Maintenance maintenance;

    public boolean isUpdateAvailable() {
        return updateAvailable;
    }

    public Maintenance getMaintenance() {
        return maintenance;
    }

    public boolean isMandatory() {
        return mandatory;
    }

    public int getHeartbeatIntervalSeconds() {
        return heartbeatIntervalSeconds;
    }

    public boolean isOpenInBrowser() {
        return openInBrowser;
    }

    public String getDeliveryMethod() {
        return deliveryMethod;
    }

    public String getReleaseId() {
        return releaseId;
    }

    public String getVersion() {
        return version;
    }

    public String getNotes() {
        return notes;
    }

    public String getDownloadUrl() {
        return downloadUrl;
    }

    public String getChecksumSha256() {
        return checksumSha256;
    }

    public String getSignature() {
        return signature;
    }

    public long getSize() {
        return size;
    }

    public boolean isRollbackAllowed() {
        return rollbackAllowed;
    }
}
