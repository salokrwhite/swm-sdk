package com.swm.sdk;

import java.time.Duration;
import java.util.function.Consumer;

public final class UpdateStreamOptions {
    private String channelCode;
    private String platform;
    private String arch;
    private String deviceId;
    private String currentVersion;
    private Integer versionCode;
    private boolean reconnect = true;
    private Duration reconnectBackoff = Duration.ofMillis(1500);
    private Duration reconnectMaxBackoff = Duration.ofSeconds(20);
    private boolean jitter = true;
    private Consumer<Throwable> onError;
    private Consumer<ControlEvent> onControlEvent;

    public String getChannelCode() {
        return channelCode;
    }

    public UpdateStreamOptions setChannelCode(String channelCode) {
        this.channelCode = channelCode;
        return this;
    }

    public String getPlatform() {
        return platform;
    }

    public UpdateStreamOptions setPlatform(String platform) {
        this.platform = platform;
        return this;
    }

    public String getArch() {
        return arch;
    }

    public UpdateStreamOptions setArch(String arch) {
        this.arch = arch;
        return this;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public UpdateStreamOptions setDeviceId(String deviceId) {
        this.deviceId = deviceId;
        return this;
    }

    public String getCurrentVersion() {
        return currentVersion;
    }

    public UpdateStreamOptions setCurrentVersion(String currentVersion) {
        this.currentVersion = currentVersion;
        return this;
    }

    public Integer getVersionCode() {
        return versionCode;
    }

    public UpdateStreamOptions setVersionCode(Integer versionCode) {
        this.versionCode = versionCode;
        return this;
    }

    public boolean isReconnect() {
        return reconnect;
    }

    public UpdateStreamOptions setReconnect(boolean reconnect) {
        this.reconnect = reconnect;
        return this;
    }

    public Duration getReconnectBackoff() {
        return reconnectBackoff;
    }

    public UpdateStreamOptions setReconnectBackoff(Duration reconnectBackoff) {
        this.reconnectBackoff = reconnectBackoff;
        return this;
    }

    public Duration getReconnectMaxBackoff() {
        return reconnectMaxBackoff;
    }

    public UpdateStreamOptions setReconnectMaxBackoff(Duration reconnectMaxBackoff) {
        this.reconnectMaxBackoff = reconnectMaxBackoff;
        return this;
    }

    public boolean isJitter() {
        return jitter;
    }

    public UpdateStreamOptions setJitter(boolean jitter) {
        this.jitter = jitter;
        return this;
    }

    public Consumer<Throwable> getOnError() {
        return onError;
    }

    public UpdateStreamOptions setOnError(Consumer<Throwable> onError) {
        this.onError = onError;
        return this;
    }

    public Consumer<ControlEvent> getOnControlEvent() {
        return onControlEvent;
    }

    public UpdateStreamOptions setOnControlEvent(Consumer<ControlEvent> onControlEvent) {
        this.onControlEvent = onControlEvent;
        return this;
    }
}
