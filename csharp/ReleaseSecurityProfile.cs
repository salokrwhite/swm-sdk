#nullable enable
namespace SwmSdk;

public sealed class ReleaseSecurityProfile
{
    public string ReleaseId { get; }
    public string Version { get; }
    public int? VersionCode { get; }
    public string Protocol { get; }
    public string KeyId { get; }
    public string PublicKey { get; }

    public ReleaseSecurityProfile(string releaseId, string version, int? versionCode, string protocol, string keyId, string publicKey)
    {
        ReleaseId = releaseId?.Trim() ?? string.Empty;
        Version = version?.Trim() ?? string.Empty;
        VersionCode = versionCode;
        Protocol = protocol?.Trim().ToLowerInvariant() ?? string.Empty;
        KeyId = keyId?.Trim() ?? string.Empty;
        PublicKey = publicKey?.Trim() ?? string.Empty;
    }
}
