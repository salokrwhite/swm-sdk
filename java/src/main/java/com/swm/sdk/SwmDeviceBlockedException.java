package com.swm.sdk;

public final class SwmDeviceBlockedException extends SwmApiException {
    public SwmDeviceBlockedException(int statusCode, String message) {
        super(statusCode, Client.API_ERROR_CODE_DEVICE_BLOCKED, message);
    }
}
