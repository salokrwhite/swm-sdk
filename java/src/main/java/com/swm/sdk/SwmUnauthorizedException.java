package com.swm.sdk;

public final class SwmUnauthorizedException extends SwmApiException {
    public SwmUnauthorizedException(int statusCode, String errorCode, String message) {
        super(statusCode, errorCode, message);
    }
}
