package com.swm.sdk;

public final class SwmUpdateRegionBlockedException extends SwmApiException {
    public SwmUpdateRegionBlockedException(int statusCode, String message) {
        super(statusCode, Client.API_ERROR_CODE_UPDATE_REGION_BLOCKED, message);
    }
}
