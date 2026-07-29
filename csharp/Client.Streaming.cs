using System.Text;
using System.Text.Json;

namespace SwmSdk;

public partial class Client
{
    private sealed class SseMessage
    {
        public string EventName { get; set; } = string.Empty;
        public string EventId { get; set; } = string.Empty;
        public StringBuilder Data { get; } = new();
    }

    public UpdateWatchHandle StartUpdateStream(UpdateStreamOptions options, Action<UpdatePushEvent> onEvent, CancellationToken cancellationToken = default)
    {
        var channel = string.IsNullOrWhiteSpace(options.ChannelCode) ? Channel : options.ChannelCode!;
        var platform = string.IsNullOrWhiteSpace(options.Platform) ? Platform : options.Platform!;
        var arch = string.IsNullOrWhiteSpace(options.Arch) ? Arch : options.Arch!;
        var deviceId = string.IsNullOrWhiteSpace(options.DeviceId) ? DeviceId : options.DeviceId!;

        if (string.IsNullOrWhiteSpace(channel) || string.IsNullOrWhiteSpace(platform) || string.IsNullOrWhiteSpace(arch) || string.IsNullOrWhiteSpace(deviceId))
        {
            throw new SwmValidationException(400, null, "channel_code/platform/arch/device_id required");
        }

        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _ = Task.Run(async () =>
        {
            var backoff = options.ReconnectBackoff <= TimeSpan.Zero ? TimeSpan.FromMilliseconds(1500) : options.ReconnectBackoff;
            var maxBackoff = options.ReconnectMaxBackoff <= TimeSpan.Zero ? TimeSpan.FromSeconds(20) : options.ReconnectMaxBackoff;
            if (maxBackoff < backoff)
            {
                maxBackoff = backoff;
            }
            var random = new Random();

            while (!cts.IsCancellationRequested)
            {
                try
                {
                    await ConnectAndReadSseAsync(channel, platform, arch, deviceId, options, onEvent, cts.Token).ConfigureAwait(false);
                    return;
                }
                catch (Exception ex)
                {
                    options.OnError?.Invoke(ex);
                    if (ex is SwmDeviceBlockedException || ex is SwmUpdateRegionBlockedException || ex is SwmUnauthorizedException)
                    {
                        return;
                    }
                    if (!options.Reconnect || cts.IsCancellationRequested)
                    {
                        return;
                    }

                    var wait = backoff;
                    if (options.Jitter)
                    {
                        var extra = random.Next(0, Math.Max(1, (int)wait.TotalMilliseconds / 2));
                        wait += TimeSpan.FromMilliseconds(extra);
                    }
                    await Task.Delay(wait, cts.Token).ConfigureAwait(false);
                    var next = TimeSpan.FromMilliseconds(backoff.TotalMilliseconds * 2);
                    backoff = next > maxBackoff ? maxBackoff : next;
                }
            }
        }, cts.Token);

        return new UpdateWatchHandle(cts);
    }

    public UpdateWatchHandle WatchUpdates(UpdateStreamOptions options, Action<UpdateCheckResponse> onUpdateAvailable, CancellationToken cancellationToken = default)
    {
        return StartUpdateStream(options, evt =>
        {
            if (string.Equals(evt.EventType, ControlEventShutdown, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }
            _ = Task.Run(async () =>
            {
                try
                {
                    var resp = await CheckUpdateAsync(options.CurrentVersion ?? string.Empty, options.VersionCode, cancellationToken: cancellationToken).ConfigureAwait(false);
                    if (resp.UpdateAvailable)
                    {
                        onUpdateAvailable(resp);
                    }
                }
                catch (Exception ex)
                {
                    options.OnError?.Invoke(ex);
                }
            }, cancellationToken);
        }, cancellationToken);
    }

    private async Task ConnectAndReadSseAsync(
        string channel,
        string platform,
        string arch,
        string deviceId,
        UpdateStreamOptions options,
        Action<UpdatePushEvent> onEvent,
        CancellationToken cancellationToken)
    {
		RequireV3SecurityProfile();
		if (string.IsNullOrWhiteSpace(SessionToken) || SessionExpiresAt <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
		{
			throw InvalidAuthz("authorization session missing or expired for update stream");
		}

        var query = new Dictionary<string, string?>
        {
            ["device_id"] = deviceId,
            ["channel_code"] = channel,
            ["platform"] = platform,
            ["arch"] = arch,
            ["current_version"] = options.CurrentVersion
        };
        if (options.VersionCode.HasValue)
        {
            query["version_code"] = options.VersionCode.Value.ToString();
        }

        var qs = string.Join("&", query.Where(kv => !string.IsNullOrWhiteSpace(kv.Value))
            .Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value!)}"));
        var url = $"{BaseUrl}/api/client/updates/stream{(string.IsNullOrWhiteSpace(qs) ? string.Empty : "?" + qs)}";

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.ParseAdd("text/event-stream");
        var nonce = SignClientRequest(req, Array.Empty<byte>());
        using var res = await HttpClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(res, cancellationToken).ConfigureAwait(false);

        using var stream = await res.Content.ReadAsStreamAsync().ConfigureAwait(false);
        using var reader = new StreamReader(stream);
        var message = new SseMessage();
		var authzVerified = false;
        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync().ConfigureAwait(false);
            if (line == null)
            {
				throw new IOException("update stream closed by server");
            }
            if (line.StartsWith(":", StringComparison.Ordinal))
            {
                continue;
            }
            if (line.Length == 0)
            {
                FlushMessage(message, options, onEvent, nonce, ref authzVerified);
                message = new SseMessage();
                continue;
            }
            if (line.StartsWith("event:", StringComparison.OrdinalIgnoreCase))
            {
                message.EventName = line.Substring(6).Trim();
                continue;
            }
            if (line.StartsWith("id:", StringComparison.OrdinalIgnoreCase))
            {
                message.EventId = line.Substring(3).Trim();
                continue;
            }
            if (line.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
            {
                if (message.Data.Length > 0)
                {
                    message.Data.Append('\n');
                }
                message.Data.Append(line.Substring(5).Trim());
            }
        }

		if (!authzVerified && !cancellationToken.IsCancellationRequested)
        {
            throw new SwmUnauthorizedException(401, ApiErrorCodeAuthzInvalid, "authorization missing from update stream");
        }
    }

    private void FlushMessage(
        SseMessage message,
        UpdateStreamOptions options,
        Action<UpdatePushEvent> onEvent,
        string requestNonce,
        ref bool authzVerified)
    {
        if (message.Data.Length == 0)
        {
            return;
        }
        if (string.Equals(message.EventName, "connected", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var payload = message.Data.ToString();
		if (string.Equals(message.EventName, "authz_expired", StringComparison.OrdinalIgnoreCase) ||
			string.Equals(message.EventName, "authz-expired", StringComparison.OrdinalIgnoreCase))
		{
			throw new SwmUnauthorizedException(401, ApiErrorCodeAuthzInvalid, "authorization session expired");
		}
        if (string.Equals(message.EventName, "authz", StringComparison.OrdinalIgnoreCase))
        {
			var authzCarrier = JsonSerializer.Deserialize(payload, SwmJsonContext.Default.AuthzV3Carrier)
				?? throw InvalidAuthz("stream authorization missing");
			VerifyAuthzV3OrThrow(authzCarrier.Authz, requestNonce, Encoding.UTF8.GetBytes(authzCarrier.Data.GetRawText()));
            authzVerified = true;
            return;
        }

        if (!authzVerified)
        {
            return;
        }

		var carrier = JsonSerializer.Deserialize(payload, SwmJsonContext.Default.AuthzV3Carrier)
			?? throw InvalidAuthz("signed stream event missing");
		var rawData = Encoding.UTF8.GetBytes(carrier.Data.GetRawText());
		VerifyAuthzV3OrThrow(carrier.Authz, requestNonce, rawData);
		payload = carrier.Data.GetRawText();
		var evt = JsonSerializer.Deserialize(payload, SwmJsonContext.Default.UpdatePushEvent);
        if (evt == null)
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(evt.Id))
        {
            evt.Id = message.EventId;
        }
        if (string.IsNullOrWhiteSpace(evt.EventType))
        {
            evt.EventType = message.EventName;
        }

        if (string.Equals(evt.EventType, ControlEventShutdown, StringComparison.OrdinalIgnoreCase))
        {
            options.OnControlEvent?.Invoke(new ControlEvent
            {
                Type = ControlEventShutdown,
                DeviceId = evt.DeviceId,
                Reason = evt.Reason
            });
        }
        if (string.Equals(evt.EventType, ControlEventMaintenanceScheduled, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(evt.EventType, ControlEventMaintenanceCancelled, StringComparison.OrdinalIgnoreCase))
        {
            options.OnControlEvent?.Invoke(new ControlEvent
            {
                Type = evt.EventType!,
                Reason = evt.Reason,
                Message = evt.Message,
                StartAt = evt.MaintenanceStartAt
            });
        }
        onEvent(evt);
    }
}
