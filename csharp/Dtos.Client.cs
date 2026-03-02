using System.Text.Json;
using System.Text.Json.Serialization;

namespace SwmSdk;

public sealed class UpdateCheckRequest
{
    [JsonPropertyName("channel_code")]
    public string ChannelCode { get; set; } = string.Empty;

    [JsonPropertyName("current_version")]
    public string CurrentVersion { get; set; } = string.Empty;

    [JsonPropertyName("version_code")]
    public int? VersionCode { get; set; }

    [JsonPropertyName("platform")]
    public string Platform { get; set; } = string.Empty;

    [JsonPropertyName("arch")]
    public string Arch { get; set; } = string.Empty;

    [JsonPropertyName("device_id")]
    public string DeviceId { get; set; } = string.Empty;

    [JsonPropertyName("user_id")]
    public string? UserId { get; set; }

    [JsonPropertyName("attributes")]
    public Dictionary<string, JsonElement> Attributes { get; set; } = new();
}

public sealed class UpdateCheckResponse
{
    [JsonPropertyName("update_available")]
    public bool UpdateAvailable { get; set; }

    [JsonPropertyName("mandatory")]
    public bool Mandatory { get; set; }

    [JsonPropertyName("heartbeat_interval_seconds")]
    public int HeartbeatIntervalSeconds { get; set; }

    [JsonPropertyName("open_in_browser")]
    public bool OpenInBrowser { get; set; }

    [JsonPropertyName("delivery_method")]
    public string? DeliveryMethod { get; set; }

    [JsonPropertyName("release_id")]
    public string? ReleaseId { get; set; }

    [JsonPropertyName("version")]
    public string? Version { get; set; }

    [JsonPropertyName("notes")]
    public string? Notes { get; set; }

    [JsonPropertyName("download_url")]
    public string? DownloadUrl { get; set; }

    [JsonPropertyName("checksum_sha256")]
    public string? ChecksumSha256 { get; set; }

    [JsonPropertyName("signature")]
    public string? Signature { get; set; }

    [JsonPropertyName("size")]
    public long Size { get; set; }

    [JsonPropertyName("rollback_allowed")]
    public bool RollbackAllowed { get; set; }

    [JsonPropertyName("release_notes_url")]
    public string? ReleaseNotesUrl { get; set; }
}

public sealed class EventIngestItem
{
    [JsonPropertyName("device_id")]
    public string DeviceId { get; set; } = string.Empty;

    [JsonPropertyName("event_name")]
    public string EventName { get; set; } = string.Empty;

    [JsonPropertyName("event_time")]
    public DateTime EventTime { get; set; } = DateTime.UtcNow;

    [JsonPropertyName("channel_code")]
    public string ChannelCode { get; set; } = string.Empty;

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement> Properties { get; set; } = new();

    [JsonPropertyName("attributes")]
    public Dictionary<string, JsonElement> Attributes { get; set; } = new();
}

public sealed class HeartbeatRequest
{
    [JsonPropertyName("device_id")]
    public string DeviceId { get; set; } = string.Empty;

    [JsonPropertyName("channel_code")]
    public string? ChannelCode { get; set; }

    [JsonPropertyName("app_version")]
    public string? AppVersion { get; set; }

    [JsonPropertyName("platform")]
    public string? Platform { get; set; }

    [JsonPropertyName("arch")]
    public string? Arch { get; set; }

    [JsonPropertyName("user_id")]
    public string? UserId { get; set; }

    [JsonPropertyName("attributes")]
    public Dictionary<string, JsonElement>? Attributes { get; set; }
}

public sealed class EventBatchRequest
{
    [JsonPropertyName("events")]
    public List<EventIngestItem> Events { get; set; } = new();
}

public sealed class UpdatePushEvent
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }

    [JsonPropertyName("event_type")]
    public string? EventType { get; set; }

    [JsonPropertyName("org_id")]
    public string? OrgId { get; set; }

    [JsonPropertyName("app_id")]
    public string? AppId { get; set; }

    [JsonPropertyName("device_id")]
    public string? DeviceId { get; set; }

    [JsonPropertyName("channel_code")]
    public string? ChannelCode { get; set; }

    [JsonPropertyName("platform")]
    public string? Platform { get; set; }

    [JsonPropertyName("arch")]
    public string? Arch { get; set; }

    [JsonPropertyName("release_id")]
    public string? ReleaseId { get; set; }

    [JsonPropertyName("published_at")]
    public DateTime? PublishedAt { get; set; }

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }
}

public sealed class ControlEvent
{
    public string Type { get; set; } = string.Empty;
    public string? DeviceId { get; set; }
    public string? Reason { get; set; }
}

public sealed class UpdateStreamOptions
{
    public string? ChannelCode { get; set; }
    public string? Platform { get; set; }
    public string? Arch { get; set; }
    public string? DeviceId { get; set; }
    public string? CurrentVersion { get; set; }
    public int? VersionCode { get; set; }
    public bool Reconnect { get; set; } = true;
    public TimeSpan ReconnectBackoff { get; set; } = TimeSpan.FromMilliseconds(1500);
    public TimeSpan ReconnectMaxBackoff { get; set; } = TimeSpan.FromSeconds(20);
    public bool Jitter { get; set; } = true;
    public Action<Exception>? OnError { get; set; }
    public Action<ControlEvent>? OnControlEvent { get; set; }
}

public sealed class UpdateWatchHandle : IDisposable
{
    private readonly CancellationTokenSource _cts;

    internal UpdateWatchHandle(CancellationTokenSource cts)
    {
        _cts = cts;
    }

    public void Stop() => _cts.Cancel();

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
    }
}

internal sealed class GenericOkResponse
{
    [JsonExtensionData]
    public Dictionary<string, JsonElement>? Data { get; set; }
}
