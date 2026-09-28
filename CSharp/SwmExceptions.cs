namespace SwmSdk;

public class SwmException : Exception
{
    public SwmException(string message) : base(message)
    {
    }

    public SwmException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

public sealed class SwmConfigurationException : SwmException
{
    public SwmConfigurationException(string message) : base(message)
    {
    }
}

public class SwmApiException : SwmException
{
    public int StatusCode { get; }
    public string? ErrorCode { get; }
    public string? ResponseBody { get; }
    public IntegrityFailureAction? FailureAction { get; }

    public SwmApiException(
        int statusCode,
        string? errorCode,
        string message,
        string? responseBody = null,
        IntegrityFailureAction? failureAction = null)
        : base(message)
    {
        StatusCode = statusCode;
        ErrorCode = errorCode;
        ResponseBody = responseBody;
        FailureAction = failureAction;
    }
}

public sealed class SwmNetworkException : SwmException
{
    public SwmNetworkException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

public sealed class SwmTimeoutException : SwmException
{
    public SwmTimeoutException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

public sealed class SwmProtocolException : SwmException
{
    public SwmProtocolException(string message) : base(message)
    {
    }
}

public sealed class SwmCryptographicException : SwmException
{
    public SwmCryptographicException(string message, Exception? innerException = null)
        : base(message, innerException ?? new InvalidOperationException(message))
    {
    }
}

public sealed class SwmIdentityException : SwmException
{
    public SwmIdentityException(string message, Exception? innerException = null)
        : base(message, innerException ?? new InvalidOperationException(message))
    {
    }
}

public sealed class SwmClockException : SwmException
{
    public SwmClockException(string message) : base(message)
    {
    }
}

public sealed class SwmSessionException : SwmApiException
{
    public SwmSessionException(int statusCode, string? errorCode, string message, string? responseBody = null)
        : base(statusCode, errorCode, message, responseBody)
    {
    }
}

public sealed class SwmValidationException : SwmApiException
{
    public SwmValidationException(
        int statusCode,
        string? errorCode,
        string message,
        string? responseBody = null)
        : base(statusCode, errorCode, message, responseBody)
    {
    }
}

public sealed class SwmRateLimitException : SwmApiException
{
    public TimeSpan? RetryAfter { get; }

    public SwmRateLimitException(
        int statusCode,
        string message,
        TimeSpan? retryAfter,
        string? responseBody = null)
        : base(statusCode, null, message, responseBody)
    {
        RetryAfter = retryAfter;
    }
}

public class SwmUnauthorizedException : SwmApiException
{
    public SwmUnauthorizedException(int statusCode, string? errorCode, string message, string? responseBody = null)
        : base(statusCode, errorCode, message, responseBody)
    {
    }
}

public sealed class SwmDeviceBlockedException : SwmApiException
{
    public const string Code = "device_blocked";

    public SwmDeviceBlockedException(int statusCode, string message, string? responseBody = null)
        : base(statusCode, Code, message, responseBody)
    {
    }
}

public sealed class SwmUnsupportedVersionException : SwmUnauthorizedException
{
    public const string Code = "client_version_unsupported";

    public string MinimumSupportedVersion { get; }

    public SwmUnsupportedVersionException(
        int statusCode,
        string message,
        string? minimumSupportedVersion,
        string? responseBody = null)
        : base(statusCode, Code, message, responseBody)
    {
        MinimumSupportedVersion = minimumSupportedVersion ?? string.Empty;
    }
}

public sealed class SwmUpdateRegionBlockedException : SwmApiException
{
    public const string Code = "update_region_blocked";

    public SwmUpdateRegionBlockedException(int statusCode, string message, string? responseBody = null)
        : base(statusCode, Code, message, responseBody)
    {
    }
}

public sealed class SwmFeedbackDisabledException : SwmApiException
{
    public const string Code = "feedback_disabled";

    public SwmFeedbackDisabledException(int statusCode, string message, string? responseBody = null)
        : base(statusCode, Code, message, responseBody)
    {
    }
}

public sealed class SwmIntegrityException : SwmApiException
{
    public SwmIntegrityException(
        int statusCode,
        string errorCode,
        string message,
        IntegrityFailureAction failureAction,
        string? responseBody = null)
        : base(statusCode, errorCode, message, responseBody, failureAction)
    {
    }
}

public sealed class SwmOperationAuthorizationException : SwmApiException
{
    public SwmOperationAuthorizationException(
        int statusCode,
        string? errorCode,
        string message,
        string? responseBody = null)
        : base(statusCode, errorCode, message, responseBody)
    {
    }
}

public sealed class SwmOfflineBudgetException : SwmApiException
{
    public SwmOfflineBudgetException(string message)
        : base(401, "offline_budget_exceeded", message)
    {
    }
}
