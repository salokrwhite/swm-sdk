package com.swm.sdk;

public final class SwmFeedbackDisabledException extends SwmApiException {
    public SwmFeedbackDisabledException(int statusCode, String message) {
        super(statusCode, Client.API_ERROR_CODE_FEEDBACK_DISABLED, message);
    }
}
