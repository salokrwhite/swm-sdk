using System.Runtime.InteropServices;

namespace SwmSdk;

public sealed class SwmClientOptions
{
    public required string BaseUrl { get; init; }
    public string? WebBaseUrl { get; init; }
    public required string AppId { get; init; }
    public required string ReleaseId { get; init; }
    public required string Version { get; init; }
    public int? VersionCode { get; init; }
    public required string RootTrustKeyId { get; init; }
    public required string RootTrustPublicKey { get; init; }
    public string Channel { get; init; } = "stable";
    public string Platform { get; init; } = "windows";
    public string Arch { get; init; } = RuntimeInformation.ProcessArchitecture == Architecture.X86 ? "x86" : "x64";
    public string? DeviceId { get; init; }
    public string? StorageDirectory { get; init; }
    public bool AllowInsecureHttp { get; init; }
    public HttpMessageHandler? HttpMessageHandler { get; init; }
    public HostIntegrityOptions HostIntegrity { get; init; } = new();

    internal Uri BaseUri
    {
        get
        {
            if (!Uri.TryCreate(BaseUrl.TrimEnd('/') + "/", UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttps && !(AllowInsecureHttp && uri.Scheme == Uri.UriSchemeHttp)))
            {
                throw new SwmConfigurationException("BaseUrl must be an absolute HTTPS URL");
            }
            return uri;
        }
    }

    internal Uri WebBaseUri
    {
        get
        {
            var raw = string.IsNullOrWhiteSpace(WebBaseUrl) ? BaseUrl : WebBaseUrl;
            if (!Uri.TryCreate(raw.TrimEnd('/') + "/", UriKind.Absolute, out var uri) ||
                (uri.Scheme != Uri.UriSchemeHttps && !(AllowInsecureHttp && uri.Scheme == Uri.UriSchemeHttp)))
            {
                throw new SwmConfigurationException("WebBaseUrl must be an absolute HTTPS URL");
            }
            return uri;
        }
    }
}

public sealed class HostIntegrityOptions
{
    public bool Enabled { get; init; }
    public string? PackageRoot { get; init; }
    public string ManifestPath { get; init; } = "release-integrity.v2";
    public IIntegrityEvidenceProvider? EvidenceProvider { get; init; }
}

public interface IIntegrityEvidenceProvider
{
    ValueTask<IntegrityEvidence> GetEvidenceAsync(
        IntegrityEvidenceContext context,
        CancellationToken cancellationToken = default);
}

public sealed class IntegrityEvidenceContext
{
    public required string AppId { get; init; }
    public required string ReleaseId { get; init; }
    public required string Version { get; init; }
    public int? VersionCode { get; init; }
    public required string Arch { get; init; }
    public required string PackageRoot { get; init; }
    public required string ManifestPath { get; init; }
}
