using System.Text.Json;
using System.Text.Json.Serialization;

namespace SwmSdk;

public enum SwmCloudState
{
    Unavailable,
    Authorizing,
    Available,
    Expired,
    Revoked,
    IntegrityFailure,
    TimeSyncFailure,
    OfflineLocked
}

public enum IntegrityFailureAction
{
    DenyOperations,
    ShutdownClient
}

public sealed class DeviceAuthRegistration
{
    [JsonPropertyName("install_id")]
    public string InstallId { get; set; } = string.Empty;

    [JsonPropertyName("key_id")]
    public string KeyId { get; set; } = string.Empty;

    [JsonPropertyName("key_thumbprint")]
    public string KeyThumbprint { get; set; } = string.Empty;

    [JsonPropertyName("public_key_sec1")]
    public string PublicKeySec1 { get; set; } = string.Empty;

    [JsonPropertyName("credential_version")]
    public string CredentialVersion { get; set; } = "device_credential_v2";

    [JsonPropertyName("challenge")]
    public string? Challenge { get; set; }

    [JsonPropertyName("hardware_evidence")]
    public HardwareEvidence HardwareEvidence { get; set; } = new();
}

public sealed class HardwareEvidence
{
    [JsonPropertyName("version")]
    public uint Version { get; set; } = 2;

    [JsonPropertyName("component_mask")]
    public uint ComponentMask { get; set; }

    [JsonPropertyName("aggregate_hash")]
    public string AggregateHash { get; set; } = string.Empty;
}

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

    [JsonPropertyName("device_auth")]
    public DeviceAuthRegistration DeviceAuth { get; set; } = new();

    [JsonPropertyName("integrity_state")]
    public string? IntegrityState { get; set; }

    [JsonPropertyName("integrity_failure_code")]
    public string? IntegrityFailureCode { get; set; }

    [JsonPropertyName("integrity_manifest_sha256")]
    public string? IntegrityManifestSha256 { get; set; }

    [JsonPropertyName("integrity_evidence_version")]
    public uint? IntegrityEvidenceVersion { get; set; }

    [JsonPropertyName("integrity_files")]
    public Dictionary<string, string>? IntegrityFiles { get; set; }
}

public sealed class DeviceRegistrationChallengeResponse
{
    [JsonPropertyName("challenge")]
    public string? Challenge { get; set; }

    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }
}

public sealed class DeviceKeyRotationResult
{
    public required string RegistrationId { get; init; }
    public required string InstallId { get; init; }
    public required string KeyId { get; init; }
    public required string DeviceId { get; init; }
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

    [JsonPropertyName("version_code")]
    public int? VersionCode { get; set; }

    [JsonPropertyName("notes")]
    public string? Notes { get; set; }

    [JsonPropertyName("download_url")]
    public string? DownloadUrl { get; set; }

    [JsonPropertyName("checksum_sha256")]
    public string? ChecksumSha256 { get; set; }

    [JsonPropertyName("signature")]
    public string? Signature { get; set; }

    [JsonPropertyName("manifest_key_id")]
    public string? ManifestKeyId { get; set; }

    [JsonPropertyName("manifest_public_key")]
    public string? ManifestPublicKey { get; set; }

    [JsonPropertyName("root_trust_key_id")]
    public string? RootTrustKeyId { get; set; }

    [JsonPropertyName("root_trust_signature")]
    public string? RootTrustSignature { get; set; }

    [JsonPropertyName("artifact_file_name")]
    public string? ArtifactFileName { get; set; }

    [JsonPropertyName("artifact_platform")]
    public string? ArtifactPlatform { get; set; }

    [JsonPropertyName("artifact_arch")]
    public string? ArtifactArch { get; set; }

    [JsonPropertyName("authz_protocol")]
    public string? AuthzProtocol { get; set; }

    [JsonPropertyName("host_integrity_required")]
    public bool HostIntegrityRequired { get; set; }

    [JsonPropertyName("size")]
    public long Size { get; set; }

    [JsonPropertyName("rollback_allowed")]
    public bool RollbackAllowed { get; set; }

    [JsonPropertyName("maintenance")]
    public MaintenanceInfo? Maintenance { get; set; }
}

public sealed class MaintenanceInfo
{
    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; }

    [JsonPropertyName("start_at")]
    public string? StartAt { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    [JsonPropertyName("active")]
    public bool Active { get; set; }
}

public sealed record HeartbeatResult(
    bool Ok,
    DateTimeOffset? ServerTime,
    MaintenanceInfo? Maintenance);

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

    [JsonPropertyName("integrity_evidence_version")]
    public uint? IntegrityEvidenceVersion { get; set; }

    [JsonPropertyName("integrity_manifest_sha256")]
    public string? IntegrityManifestSha256 { get; set; }

    [JsonPropertyName("integrity_files")]
    public Dictionary<string, string>? IntegrityFiles { get; set; }
}

public sealed class HeartbeatResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    [JsonPropertyName("server_time")]
    public DateTimeOffset? ServerTime { get; set; }

    [JsonPropertyName("maintenance")]
    public MaintenanceInfo? Maintenance { get; set; }
}

public sealed class EventIngestItem
{
    [JsonPropertyName("device_id")]
    public string DeviceId { get; set; } = string.Empty;

    [JsonPropertyName("event_name")]
    public string EventName { get; set; } = string.Empty;

    [JsonPropertyName("event_time")]
    public DateTimeOffset EventTime { get; set; } = DateTimeOffset.UtcNow;

    [JsonPropertyName("channel_code")]
    public string ChannelCode { get; set; } = string.Empty;

    [JsonPropertyName("properties")]
    public Dictionary<string, JsonElement> Properties { get; set; } = new();

    [JsonPropertyName("attributes")]
    public Dictionary<string, JsonElement> Attributes { get; set; } = new();
}

public sealed class EventBatchRequest
{
    [JsonPropertyName("events")]
    public List<EventIngestItem> Events { get; set; } = new();
}

public sealed class EnrollmentTicketRequest
{
    [JsonPropertyName("audience")]
    public string Audience { get; set; } = string.Empty;
}

public sealed class EnrollmentTicketResponse
{
    [JsonPropertyName("ticket")]
    public string Ticket { get; set; } = string.Empty;

    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }

    [JsonPropertyName("audience")]
    public string Audience { get; set; } = string.Empty;
}

public sealed class IntegrityEvidence
{
    [JsonPropertyName("integrity_state")]
    public string? IntegrityState { get; set; }

    [JsonPropertyName("integrity_failure_code")]
    public string? IntegrityFailureCode { get; set; }

    [JsonPropertyName("integrity_evidence_version")]
    public uint? EvidenceVersion { get; set; }

    [JsonPropertyName("integrity_manifest_sha256")]
    public string? ManifestSha256 { get; set; }

    [JsonPropertyName("integrity_files")]
    public Dictionary<string, string>? Files { get; set; }

    public static IntegrityEvidence Verified(string manifestSha256, Dictionary<string, string> files) =>
        new()
        {
            IntegrityState = "verified",
            EvidenceVersion = 2,
            ManifestSha256 = manifestSha256,
            Files = files
        };

    public static IntegrityEvidence Failed(string code) =>
        new()
        {
            IntegrityState = "failed",
            IntegrityFailureCode = code
        };
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
    public DateTimeOffset? PublishedAt { get; set; }

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    [JsonPropertyName("maintenance_start_at")]
    public DateTimeOffset? MaintenanceStartAt { get; set; }
}

public sealed class UpdateStreamOptions
{
    public string? CurrentVersion { get; init; }
    public int? VersionCode { get; init; }
    public bool Reconnect { get; init; } = true;
    public TimeSpan ReconnectBackoff { get; init; } = TimeSpan.FromMilliseconds(1500);
    public TimeSpan ReconnectMaxBackoff { get; init; } = TimeSpan.FromSeconds(20);
    public bool Jitter { get; init; } = true;
}

public sealed class FeedbackRequest
{
    public required string Content { get; init; }
    public int? Rating { get; init; }
    public string? Contact { get; init; }
    public string? AppVersion { get; init; }
    public IReadOnlyList<string> AttachmentPaths { get; init; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, object?>? Metadata { get; init; }
}

public sealed class FeedbackResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    [JsonPropertyName("id")]
    public Guid Id { get; set; }
}

public sealed class DebugRequestTicket
{
    public required string RequestId { get; init; }
    public required string WatchToken { get; init; }
    public required long ExpiresAt { get; init; }
    internal DebugCredentials? Credentials { get; init; }
    internal string? SessionId { get; init; }
}

public sealed class DebugDecisionEvent
{
    public required string State { get; init; }
    public string? Reason { get; init; }
    public long AuthorizationExpiresAt { get; init; }
}

internal sealed class DebugCredentials
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public long ExpiresAt { get; set; }
}

internal sealed class DeviceKeyRotationRequest
{
    [JsonPropertyName("new_device_auth")]
    public DeviceAuthRegistration NewDeviceAuth { get; set; } = new();

    [JsonPropertyName("new_key_proof")]
    public string? NewKeyProof { get; set; }
}

internal sealed class DeviceKeyRotationChallengeResponse
{
    [JsonPropertyName("challenge")]
    public string? Challenge { get; set; }

    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }

    [JsonPropertyName("proof_digest")]
    public string? ProofDigest { get; set; }
}

internal sealed class DeviceKeyRotationResponse
{
    [JsonPropertyName("rotated")]
    public bool Rotated { get; set; }

    [JsonPropertyName("registration_id")]
    public string? RegistrationId { get; set; }

    [JsonPropertyName("install_id")]
    public string? InstallId { get; set; }

    [JsonPropertyName("key_id")]
    public string? KeyId { get; set; }
}

internal sealed class DebugEnrollRequest
{
    [JsonPropertyName("ticket")]
    public string Ticket { get; set; } = string.Empty;

    [JsonPropertyName("app_id")]
    public string AppId { get; set; } = string.Empty;

    [JsonPropertyName("release_id")]
    public string ReleaseId { get; set; } = string.Empty;

    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = string.Empty;

    [JsonPropertyName("pcid")]
    public string Pcid { get; set; } = string.Empty;

    [JsonPropertyName("app_version")]
    public string AppVersion { get; set; } = string.Empty;
}

internal sealed class DebugEnrollResponse
{
    [JsonPropertyName("client_id")]
    public string? ClientId { get; set; }

    [JsonPropertyName("client_secret")]
    public string? ClientSecret { get; set; }

    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }
}

internal sealed class DebugCreateRequest
{
    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = string.Empty;

    [JsonPropertyName("pcid")]
    public string Pcid { get; set; } = string.Empty;

    [JsonPropertyName("app_version")]
    public string AppVersion { get; set; } = string.Empty;

    [JsonPropertyName("note")]
    public string Note { get; set; } = string.Empty;
}

internal sealed class DebugCreateResponse
{
    [JsonPropertyName("request_id")]
    public string? RequestId { get; set; }

    [JsonPropertyName("watch_token")]
    public string? WatchToken { get; set; }

    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }
}
