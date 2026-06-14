package com.swm.sdk;

import java.time.Instant;

public final class ControlEvent {
    private String type;
    private String deviceId;
    private String reason;
    private String message;
    private Instant startAt;

    public String getType() {
        return type;
    }

    public ControlEvent setType(String type) {
        this.type = type;
        return this;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public ControlEvent setDeviceId(String deviceId) {
        this.deviceId = deviceId;
        return this;
    }

    public String getReason() {
        return reason;
    }

    public ControlEvent setReason(String reason) {
        this.reason = reason;
        return this;
    }

    public String getMessage() {
        return message;
    }

    public ControlEvent setMessage(String message) {
        this.message = message;
        return this;
    }

    public Instant getStartAt() {
        return startAt;
    }

    public ControlEvent setStartAt(Instant startAt) {
        this.startAt = startAt;
        return this;
    }
}
