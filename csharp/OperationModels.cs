using System.Text.Json.Serialization;

namespace SwmSdk;

public sealed class OperationAuthorizationRequest
{
    public required string Operation { get; init; }
    public required ReadOnlyMemory<byte> Plan { get; init; }
    public required uint StepCount { get; init; }
    public ulong TotalBytes { get; init; }
    public required string ConsumerModule { get; init; }
    public byte[]? ConsumerChallenge { get; init; }
    public string? HostExecutablePath { get; init; }
    public string? ConsumerModulePath { get; init; }
}

public sealed class OperationGrant
{
    [JsonPropertyName("schema")]
    public string Schema { get; set; } = string.Empty;

    [JsonPropertyName("app_id")]
    public string AppId { get; set; } = string.Empty;

    [JsonPropertyName("release_id")]
    public string ReleaseId { get; set; } = string.Empty;

    [JsonPropertyName("device_id")]
    public string DeviceId { get; set; } = string.Empty;

    [JsonPropertyName("device_key_id")]
    public string DeviceKeyId { get; set; } = string.Empty;

    [JsonPropertyName("key_thumbprint")]
    public string KeyThumbprint { get; set; } = string.Empty;

    [JsonPropertyName("device_public_key")]
    public string DevicePublicKey { get; set; } = string.Empty;

    [JsonPropertyName("authz_public_key")]
    public string AuthzPublicKey { get; set; } = string.Empty;

    [JsonPropertyName("authz_key_id")]
    public string AuthzKeyId { get; set; } = string.Empty;

    [JsonPropertyName("authz_root_trust_key_id")]
    public string AuthzRootTrustKeyId { get; set; } = string.Empty;

    [JsonPropertyName("authz_root_trust_signature")]
    public string AuthzRootTrustSignature { get; set; } = string.Empty;

    [JsonPropertyName("session")]
    public string Session { get; set; } = string.Empty;

    [JsonPropertyName("grant_id")]
    public string GrantId { get; set; } = string.Empty;

    [JsonPropertyName("operation")]
    public string Operation { get; set; } = string.Empty;

    [JsonPropertyName("plan_sha256")]
    public string PlanSha256 { get; set; } = string.Empty;

    [JsonPropertyName("step_count")]
    public uint StepCount { get; set; }

    [JsonPropertyName("total_bytes")]
    public ulong TotalBytes { get; set; }

    [JsonPropertyName("issued_at")]
    public long IssuedAt { get; set; }

    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }

    [JsonPropertyName("consumer_challenge")]
    public string ConsumerChallenge { get; set; } = string.Empty;

    [JsonPropertyName("integrity_manifest_sha256")]
    public string? IntegrityManifestSha256 { get; set; }

    [JsonPropertyName("host_exe_sha256")]
    public string? HostExeSha256 { get; set; }

    [JsonPropertyName("consumer_module")]
    public string ConsumerModule { get; set; } = string.Empty;

    [JsonPropertyName("consumer_module_sha256")]
    public string? ConsumerModuleSha256 { get; set; }
}

public sealed class OperationConsumptionReceipt
{
    [JsonPropertyName("schema")]
    public string Schema { get; set; } = string.Empty;

    [JsonPropertyName("grant_id")]
    public string GrantId { get; set; } = string.Empty;

    [JsonPropertyName("operation")]
    public string Operation { get; set; } = string.Empty;

    [JsonPropertyName("plan_sha256")]
    public string PlanSha256 { get; set; } = string.Empty;

    [JsonPropertyName("step_count")]
    public uint StepCount { get; set; }

    [JsonPropertyName("total_bytes")]
    public ulong TotalBytes { get; set; }

    [JsonPropertyName("consumer_challenge")]
    public string ConsumerChallenge { get; set; } = string.Empty;

    [JsonPropertyName("consumed_at")]
    public long ConsumedAt { get; set; }

    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }

    [JsonPropertyName("integrity_manifest_sha256")]
    public string? IntegrityManifestSha256 { get; set; }

    [JsonPropertyName("host_exe_sha256")]
    public string? HostExeSha256 { get; set; }

    [JsonPropertyName("consumer_module")]
    public string ConsumerModule { get; set; } = string.Empty;

    [JsonPropertyName("consumer_module_sha256")]
    public string? ConsumerModuleSha256 { get; set; }
}

internal sealed class OperationAuthorizationWireRequest
{
    [JsonPropertyName("schema")]
    public string Schema { get; set; } = string.Empty;

    [JsonPropertyName("operation")]
    public string Operation { get; set; } = string.Empty;

    [JsonPropertyName("plan_sha256")]
    public string PlanSha256 { get; set; } = string.Empty;

    [JsonPropertyName("step_count")]
    public uint StepCount { get; set; }

    [JsonPropertyName("total_bytes")]
    public ulong TotalBytes { get; set; }

    [JsonPropertyName("consumer_challenge")]
    public string ConsumerChallenge { get; set; } = string.Empty;

    [JsonPropertyName("integrity_manifest_sha256")]
    public string? IntegrityManifestSha256 { get; set; }

    [JsonPropertyName("host_exe_sha256")]
    public string? HostExeSha256 { get; set; }

    [JsonPropertyName("consumer_module")]
    public string ConsumerModule { get; set; } = string.Empty;

    [JsonPropertyName("consumer_module_sha256")]
    public string? ConsumerModuleSha256 { get; set; }
}

internal sealed class OperationConsumeWireRequest
{
    [JsonPropertyName("schema")]
    public string Schema { get; set; } = "operation_grant_consume_v2";

    [JsonPropertyName("grant_id")]
    public string GrantId { get; set; } = string.Empty;

    [JsonPropertyName("operation")]
    public string Operation { get; set; } = string.Empty;

    [JsonPropertyName("plan_sha256")]
    public string PlanSha256 { get; set; } = string.Empty;

    [JsonPropertyName("step_count")]
    public uint StepCount { get; set; }

    [JsonPropertyName("total_bytes")]
    public ulong TotalBytes { get; set; }

    [JsonPropertyName("consumer_challenge")]
    public string ConsumerChallenge { get; set; } = string.Empty;

    [JsonPropertyName("issued_at")]
    public long IssuedAt { get; set; }

    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }

    [JsonPropertyName("integrity_manifest_sha256")]
    public string? IntegrityManifestSha256 { get; set; }

    [JsonPropertyName("host_exe_sha256")]
    public string? HostExeSha256 { get; set; }

    [JsonPropertyName("consumer_module")]
    public string ConsumerModule { get; set; } = string.Empty;

    [JsonPropertyName("consumer_module_sha256")]
    public string? ConsumerModuleSha256 { get; set; }
}
