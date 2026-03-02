using System.Text.Json;

namespace SwmSdk;

public class SwmApiException : Exception
{
    public int StatusCode { get; }
    public string? ErrorCode { get; }

    public SwmApiException(int statusCode, string? errorCode, string message) : base(message)
    {
        StatusCode = statusCode;
        ErrorCode = errorCode;
    }
}

public sealed class SwmDeviceBlockedException : SwmApiException
{
    public SwmDeviceBlockedException(int statusCode, string message) : base(statusCode, Client.ApiErrorCodeDeviceBlocked, message)
    {
    }
}

public sealed class SwmUnauthorizedException : SwmApiException
{
    public SwmUnauthorizedException(int statusCode, string? errorCode, string message) : base(statusCode, errorCode, message)
    {
    }
}

public sealed class SwmValidationException : SwmApiException
{
    public SwmValidationException(int statusCode, string? errorCode, string message) : base(statusCode, errorCode, message)
    {
    }
}

internal static class SwmErrorParser
{
    public static async Task ThrowIfErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken = default)
    {
        if ((int)response.StatusCode < 300)
        {
            return;
        }

        var statusCode = (int)response.StatusCode;
        var raw = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        var message = response.ReasonPhrase ?? "request failed";
        string? code = null;

        if (!string.IsNullOrWhiteSpace(raw))
        {
            try
            {
                using var doc = JsonDocument.Parse(raw);
                if (doc.RootElement.TryGetProperty("error", out var err))
                {
                    if (err.ValueKind == JsonValueKind.String)
                    {
                        message = err.GetString() ?? message;
                    }
                    else if (err.ValueKind == JsonValueKind.Object)
                    {
                        if (err.TryGetProperty("code", out var codeNode) && codeNode.ValueKind == JsonValueKind.String)
                        {
                            code = codeNode.GetString();
                        }
                        if (err.TryGetProperty("message", out var msgNode) && msgNode.ValueKind == JsonValueKind.String)
                        {
                            message = msgNode.GetString() ?? message;
                        }
                        else if (!string.IsNullOrWhiteSpace(code))
                        {
                            message = code!;
                        }
                    }
                }
                else
                {
                    message = raw;
                }
            }
            catch
            {
                message = raw;
            }
        }

        if (string.Equals(code, Client.ApiErrorCodeDeviceBlocked, StringComparison.OrdinalIgnoreCase))
        {
            throw new SwmDeviceBlockedException(statusCode, message);
        }

        if (statusCode == 401 || statusCode == 403)
        {
            throw new SwmUnauthorizedException(statusCode, code, message);
        }

        if (statusCode >= 400 && statusCode < 500)
        {
            throw new SwmValidationException(statusCode, code, message);
        }

        throw new SwmApiException(statusCode, code, message);
    }
}
