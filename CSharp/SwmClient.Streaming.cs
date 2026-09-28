using System.Text;
using SwmSdk.Internal;

namespace SwmSdk;

public sealed partial class SwmClient
{
    public async IAsyncEnumerable<UpdatePushEvent> WatchUpdatesAsync(
        UpdateStreamOptions options,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(options);
        var attempt = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            Exception? failure = null;
            var enumerator = ReadUpdateStreamOnceAsync(options, cancellationToken).GetAsyncEnumerator(cancellationToken);
            try
            {
                while (true)
                {
                    bool hasNext;
                    try
                    {
                        hasNext = await enumerator.MoveNextAsync().ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        failure = ex;
                        break;
                    }
                    if (!hasNext)
                    {
                        break;
                    }
                    yield return enumerator.Current;
                }
            }
            finally
            {
                await enumerator.DisposeAsync().ConfigureAwait(false);
            }

            if (failure == null)
            {
                yield break;
            }
            if (!options.Reconnect ||
                failure is SwmDeviceBlockedException or
                    SwmUpdateRegionBlockedException or
                    SwmUnauthorizedException or
                    SwmUnsupportedVersionException or
                    SwmIntegrityException)
            {
                throw failure;
            }
            var baseDelay = attempt == 0
                ? options.ReconnectBackoff
                : TimeSpan.FromMilliseconds(RequestPolicies.CycleRetryDelayMilliseconds(
                    SwmOperationClass.UpdateStream,
                    attempt));
            var maximum = options.ReconnectMaxBackoff <= TimeSpan.Zero
                ? TimeSpan.FromSeconds(20)
                : options.ReconnectMaxBackoff;
            var delay = baseDelay <= TimeSpan.Zero ? TimeSpan.FromMilliseconds(1500) : baseDelay;
            if (delay > maximum)
            {
                delay = maximum;
            }
            if (options.Jitter)
            {
                var jitter = Random.Shared.Next(0, Math.Max(1, (int)(delay.TotalMilliseconds / 2)));
                delay += TimeSpan.FromMilliseconds(jitter);
            }
            attempt++;
            await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
        }
    }

    private async IAsyncEnumerable<UpdatePushEvent> ReadUpdateStreamOnceAsync(
        UpdateStreamOptions options,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var query = new Dictionary<string, string?>
        {
            ["device_id"] = DeviceId,
            ["channel_code"] = _options.Channel,
            ["platform"] = _options.Platform,
            ["arch"] = _options.Arch,
            ["current_version"] = options.CurrentVersion ?? _options.Version,
            ["version_code"] = (options.VersionCode ?? _options.VersionCode)?.ToString(
                System.Globalization.CultureInfo.InvariantCulture)
        };
        var queryString = string.Join(
            "&",
            query.Where(pair => !string.IsNullOrWhiteSpace(pair.Value))
                .Select(pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value!)}"));
        var streamUrl = new Uri(
            _options.BaseUri.GetLeftPart(UriPartial.Authority) + "/api/client/updates/stream?" + queryString);

        var (response, requestNonce) = await _pipeline.SendUpdateStreamAsync(streamUrl, cancellationToken)
            .ConfigureAwait(false);
        using (response)
        {
            if ((int)response.StatusCode is < 200 or >= 300)
            {
                var body = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                _pipeline.ThrowIfError(new ProtocolResponse(
                    (int)response.StatusCode,
                    body,
                    string.Empty,
                    response.Headers.ToDictionary(
                        pair => pair.Key,
                        pair => pair.Value.ToArray(),
                        StringComparer.OrdinalIgnoreCase)));
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false);
            var message = new SseMessage();
            var authzVerified = false;
            while (!cancellationToken.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (line == null)
                {
                    if (!authzVerified)
                    {
                        throw new SwmUnauthorizedException(401, "authz_invalid", "update stream closed before authorization");
                    }
                    throw new IOException("update stream closed by server");
                }
                if (line.StartsWith(':'))
                {
                    continue;
                }
                if (line.Length == 0)
                {
                    var parsed = ParseSseMessage(message, requestNonce, authzVerified);
                    message = new SseMessage();
                    if (parsed.AuthzVerified)
                    {
                        authzVerified = true;
                    }
                    if (parsed.Event != null)
                    {
                        yield return parsed.Event;
                    }
                    continue;
                }
                if (line.StartsWith("event:", StringComparison.OrdinalIgnoreCase))
                {
                    message.EventName = line[6..].Trim();
                }
                else if (line.StartsWith("id:", StringComparison.OrdinalIgnoreCase))
                {
                    message.EventId = line[3..].Trim();
                }
                else if (line.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                {
                    if (message.Data.Length > 0)
                    {
                        message.Data.Append('\n');
                    }
                    message.Data.Append(line[5..].Trim());
                }
            }
        }
    }

    private ParsedSseMessage ParseSseMessage(SseMessage message, string requestNonce, bool authzVerified)
    {
        if (message.Data.Length == 0 ||
            string.Equals(message.EventName, "connected", StringComparison.OrdinalIgnoreCase))
        {
            return default;
        }
        var payload = Encoding.UTF8.GetBytes(message.Data.ToString());
        if (string.Equals(message.EventName, "authz_expired", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(message.EventName, "authz-expired", StringComparison.OrdinalIgnoreCase))
        {
            _pipeline.ClearSession();
            throw new SwmSessionException(401, "authz_session_expired", "update stream authorization expired");
        }
        if (string.Equals(message.EventName, "authz", StringComparison.OrdinalIgnoreCase))
        {
            _pipeline.VerifyAuthz<System.Text.Json.JsonElement>(
                new ProtocolResponse(200, payload, requestNonce, EmptyHeaders),
                requestNonce);
            return new ParsedSseMessage(null, true);
        }
        if (!authzVerified)
        {
            return default;
        }
        var evt = _pipeline.VerifyAuthz<UpdatePushEvent>(
            new ProtocolResponse(200, payload, requestNonce, EmptyHeaders),
            requestNonce);
        if (string.IsNullOrWhiteSpace(evt.Id))
        {
            evt.Id = message.EventId;
        }
        if (string.IsNullOrWhiteSpace(evt.EventType))
        {
            evt.EventType = message.EventName;
        }
        return new ParsedSseMessage(evt, true);
    }

    private static readonly IReadOnlyDictionary<string, string[]> EmptyHeaders =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

    private sealed class SseMessage
    {
        public string EventName { get; set; } = string.Empty;
        public string EventId { get; set; } = string.Empty;
        public StringBuilder Data { get; } = new();
    }

    private readonly record struct ParsedSseMessage(UpdatePushEvent? Event, bool AuthzVerified);
}
