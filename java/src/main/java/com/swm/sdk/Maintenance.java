package com.swm.sdk;

import com.fasterxml.jackson.annotation.JsonProperty;

public final class Maintenance {
    @JsonProperty("enabled")
    private boolean enabled;

    @JsonProperty("start_at")
    private String startAt;

    @JsonProperty("message")
    private String message;

    @JsonProperty("active")
    private boolean active;

    public boolean isEnabled() {
        return enabled;
    }

    public String getStartAt() {
        return startAt;
    }

    public String getMessage() {
        return message;
    }

    public boolean isActive() {
        return active;
    }
}
