package com.swm.sdk;

public final class SwmValidationException extends SwmApiException {
    public SwmValidationException(int statusCode, String errorCode, String message) {
        super(statusCode, errorCode, message);
    }
}
