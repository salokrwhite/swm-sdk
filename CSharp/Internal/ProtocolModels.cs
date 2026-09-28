using System.Text.Json;
using System.Text.Json.Serialization;

namespace SwmSdk.Internal;

internal sealed class ServerTimeManifest
{
    [JsonPropertyName("manifest_version")]
    public string? ManifestVersion { get; set; }

    [JsonPropertyName("app_id")]
    public string? AppId { get; set; }

    [JsonPropertyName("release_id")]
    public string? ReleaseId { get; set; }

    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; }

    [JsonPropertyName("server_time_ms")]
    public long ServerTimeMs { get; set; }

    [JsonPropertyName("expires_at_ms")]
    public long ExpiresAtMs { get; set; }

    [JsonPropertyName("root_trust_key_id")]
    public string? RootTrustKeyId { get; set; }

    [JsonPropertyName("signature")]
    public string? Signature { get; set; }
}

internal sealed class OnlineKeyManifest
{
    [JsonPropertyName("manifest_version")]
    public string? ManifestVersion { get; set; }

    [JsonPropertyName("purpose")]
    public string? Purpose { get; set; }

    [JsonPropertyName("app_id")]
    public string? AppId { get; set; }

    [JsonPropertyName("release_id")]
    public string? ReleaseId { get; set; }

    [JsonPropertyName("key_id")]
    public string? KeyId { get; set; }

    [JsonPropertyName("public_key")]
    public string? PublicKey { get; set; }

    [JsonPropertyName("root_trust_key_id")]
    public string? RootTrustKeyId { get; set; }

    [JsonPropertyName("root_trust_signature")]
    public string? RootTrustSignature { get; set; }

    [JsonPropertyName("issued_at")]
    public long IssuedAt { get; set; }

    [JsonPropertyName("refresh_after")]
    public long RefreshAfter { get; set; }
}

internal sealed class AuthzV3Envelope
{
    [JsonPropertyName("version")]
    public string? Version { get; set; }

    [JsonPropertyName("decision")]
    public string? Decision { get; set; }

    [JsonPropertyName("release_id")]
    public string? ReleaseId { get; set; }

    [JsonPropertyName("device_id")]
    public string? DeviceId { get; set; }

    [JsonPropertyName("nonce")]
    public string? Nonce { get; set; }

    [JsonPropertyName("data_sha256")]
    public string? DataSha256 { get; set; }

    [JsonPropertyName("session")]
    public string? Session { get; set; }

    [JsonPropertyName("issued_at")]
    public long IssuedAt { get; set; }

    [JsonPropertyName("expires_at")]
    public long ExpiresAt { get; set; }

    [JsonPropertyName("key_id")]
    public string? KeyId { get; set; }

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    [JsonPropertyName("signature")]
    public string? Signature { get; set; }
}

internal sealed class AuthzV3Carrier
{
    [JsonPropertyName("data")]
    public JsonElement Data { get; set; }

    [JsonPropertyName("authz")]
    public AuthzV3Envelope? Authz { get; set; }
}

internal sealed class ServiceErrorEnvelope
{
    [JsonPropertyName("error")]
    public ServiceError? Error { get; set; }

    [JsonPropertyName("code")]
    public string? Code { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }
}

internal sealed class ServiceError
{
    [JsonPropertyName("code")]
    public string? Code { get; set; }

    [JsonPropertyName("message")]
    public string? Message { get; set; }

    [JsonPropertyName("minimum_supported_version")]
    public string? MinimumSupportedVersion { get; set; }

    [JsonPropertyName("failure_action")]
    public string? FailureAction { get; set; }
}

internal sealed record ProtocolKey(
    string KeyId,
    string PublicKey,
    long IssuedAt,
    long RefreshAfter);

internal sealed record ProtocolResponse(
    int StatusCode,
    byte[] Body,
    string RequestNonce,
    IReadOnlyDictionary<string, string[]> Headers);

internal sealed record ProtocolRequest(
    HttpMethod Method,
    string Path,
    SwmOperationClass Operation,
    byte[]? Body,
    bool EncryptBody,
    bool RequireSession,
    bool RequireTrustedTime,
    bool RequireOnlineKey,
    string? ContentType = "application/json; charset=utf-8",
    string? Query = null,
    string? DpopResource = null);
