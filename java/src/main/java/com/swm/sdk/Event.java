package com.swm.sdk;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Event {
    @JsonProperty("device_id")
    private String deviceId;

    @JsonProperty("event_name")
    private String eventName;

    @JsonProperty("event_time")
    private Instant eventTime = Instant.now();

    @JsonProperty("channel_code")
    private String channelCode;

    @JsonProperty("properties")
    private Map<String, Object> properties = new LinkedHashMap<>();

    @JsonProperty("attributes")
    private Map<String, Object> attributes = new LinkedHashMap<>();

    public String getDeviceId() {
        return deviceId;
    }

    public Event setDeviceId(String deviceId) {
        this.deviceId = deviceId;
        return this;
    }

    public String getEventName() {
        return eventName;
    }

    public Event setEventName(String eventName) {
        this.eventName = eventName;
        return this;
    }

    public Instant getEventTime() {
        return eventTime;
    }

    public Event setEventTime(Instant eventTime) {
        this.eventTime = eventTime;
        return this;
    }

    public String getChannelCode() {
        return channelCode;
    }

    public Event setChannelCode(String channelCode) {
        this.channelCode = channelCode;
        return this;
    }

    public Map<String, Object> getProperties() {
        return properties;
    }

    public Event setProperties(Map<String, Object> properties) {
        this.properties = properties;
        return this;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public Event setAttributes(Map<String, Object> attributes) {
        this.attributes = attributes;
        return this;
    }
}
