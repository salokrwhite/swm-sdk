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
        SignClientRequest(req, Array.Empty<byte>());
        using var res = await HttpClient.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        await SwmErrorParser.ThrowIfErrorAsync(res, cancellationToken).ConfigureAwait(false);

        using var stream = await res.Content.ReadAsStreamAsync().ConfigureAwait(false);
        using var reader = new StreamReader(stream);
        var message = new SseMessage();
        while (!reader.EndOfStream && !cancellationToken.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync().ConfigureAwait(false);
            if (line == null)
            {
                continue;
            }
            if (line.StartsWith(":", StringComparison.Ordinal))
            {
                continue;
            }
            if (line.Length == 0)
            {
                await FlushMessageAsync(message, options, onEvent).ConfigureAwait(false);
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
    }

    private static Task FlushMessageAsync(SseMessage message, UpdateStreamOptions options, Action<UpdatePushEvent> onEvent)
    {
        if (message.Data.Length == 0)
        {
            return Task.CompletedTask;
        }
        if (string.Equals(message.EventName, "connected", StringComparison.OrdinalIgnoreCase))
        {
            return Task.CompletedTask;
        }

        var payload = message.Data.ToString();
        var evt = JsonSerializer.Deserialize(payload, SwmJsonContext.Default.UpdatePushEvent);
        if (evt == null)
        {
            return Task.CompletedTask;
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
        onEvent(evt);
        return Task.CompletedTask;
    }
}
