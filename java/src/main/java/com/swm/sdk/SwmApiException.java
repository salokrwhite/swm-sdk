package com.swm.sdk;

public class SwmApiException extends RuntimeException {
    private final int statusCode;
    private final String errorCode;

    public SwmApiException(int statusCode, String errorCode, String message) {
        super(message);
        this.statusCode = statusCode;
        this.errorCode = errorCode;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
