package com.swm.sdk;

/**
 * Base runtime exception for SDK failures.
 */
public class SwmException extends RuntimeException {
    public enum Kind {
        CONFIGURATION,
        VALIDATION,
        NETWORK,
        TIMEOUT,
        CLOCK,
        PROTOCOL,
        CRYPTOGRAPHIC,
        IDENTITY,
        UNAUTHORIZED,
        SESSION,
        DEVICE_BLOCKED,
        UNSUPPORTED_VERSION,
        UPDATE_REGION_BLOCKED,
        FEEDBACK_DISABLED,
        INTEGRITY,
        OPERATION_AUTHORIZATION,
        OFFLINE_BUDGET,
        RATE_LIMIT,
        API
    }

    private final Kind kind;
    private final int statusCode;
    private final String serviceCode;
    private final String responseBody;

    public SwmException(Kind kind, int statusCode, String serviceCode, String message) {
        this(kind, statusCode, serviceCode, message, "");
    }

    public SwmException(Kind kind, int statusCode, String serviceCode, String message,
                        String responseBody) {
        super(message);
        this.kind = kind;
        this.statusCode = statusCode;
        this.serviceCode = serviceCode == null ? "" : serviceCode;
        this.responseBody = responseBody == null ? "" : responseBody;
    }

    public SwmException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
        this.statusCode = 0;
        this.serviceCode = "";
        this.responseBody = "";
    }

    public Kind kind() {
        return kind;
    }

    public int statusCode() {
        return statusCode;
    }

    public String serviceCode() {
        return serviceCode;
    }

    public String responseBody() {
        return responseBody;
    }

    public static final class Configuration extends SwmException {
        public Configuration(String message) { super(Kind.CONFIGURATION, 0, "", message); }
    }

    public static final class Validation extends SwmException {
        public Validation(String message) { super(Kind.VALIDATION, 0, "", message); }
    }

    public static final class Network extends SwmException {
        public Network(String message, Throwable cause) { super(Kind.NETWORK, message, cause); }
    }

    public static final class Timeout extends SwmException {
        public Timeout(String message) { super(Kind.TIMEOUT, 0, "", message); }
    }

    public static final class Clock extends SwmException {
        public Clock(String message) { super(Kind.CLOCK, 0, "", message); }
    }

    public static final class Protocol extends SwmException {
        public Protocol(String message) { super(Kind.PROTOCOL, 0, "", message); }
    }

    public static final class Cryptographic extends SwmException {
        public Cryptographic(String message, Throwable cause) {
            super(Kind.CRYPTOGRAPHIC, message, cause);
        }
    }

    public static final class Identity extends SwmException {
        public Identity(String message, Throwable cause) { super(Kind.IDENTITY, message, cause); }
    }

    public static final class Session extends SwmException {
        public Session(int statusCode, String code, String message) {
            super(Kind.SESSION, statusCode, code, message);
        }
    }

    public static final class Integrity extends SwmException {
        public Integrity(int statusCode, String code, String message, String body) {
            super(Kind.INTEGRITY, statusCode, code, message, body);
        }
    }

    public static final class OperationAuthorization extends SwmException {
        public OperationAuthorization(int statusCode, String code, String message) {
            super(Kind.OPERATION_AUTHORIZATION, statusCode, code, message);
        }
    }

    public static final class OfflineBudget extends SwmException {
        public OfflineBudget(String message) {
            super(Kind.OFFLINE_BUDGET, 0, "offline_budget_exceeded", message);
        }
    }
}
