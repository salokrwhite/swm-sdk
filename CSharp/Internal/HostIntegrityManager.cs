using System.Security.Cryptography;

namespace SwmSdk.Internal;

internal sealed class HostIntegrityManager
{
    private const string PolicyCacheFile = "integrity-policy.bin";
    private readonly SwmClientOptions _options;
    private readonly StateStore _store;
    private Rim2Manifest? _manifest;
    private string? _packageRoot;

    public HostIntegrityManager(SwmClientOptions options, StateStore store)
    {
        _options = options;
        _store = store;
    }

    public bool? ReadCachedPolicy()
    {
        if (!_store.TryReadProtected(PolicyCacheFile, out var plaintext))
        {
            return null;
        }
        try
        {
            var text = System.Text.Encoding.UTF8.GetString(plaintext);
            var lines = text.Split('\n');
            if (lines.Length < 5 ||
                lines[0] != "SwmSdkIntegrityPolicyV1" ||
                lines[2] != _options.AppId ||
                lines[3] != _options.ReleaseId ||
                lines[4] != (_options.VersionCode?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty))
            {
                return null;
            }
            return lines[1] switch
            {
                "1" => true,
                "0" => false,
                _ => null
            };
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public void StorePolicy(bool required)
    {
        if (ReadCachedPolicy() == required)
        {
            return;
        }
        var text = string.Join(
            "\n",
            "SwmSdkIntegrityPolicyV1",
            required ? "1" : "0",
            _options.AppId,
            _options.ReleaseId,
            _options.VersionCode?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(System.Globalization.CultureInfo.InvariantCulture));
        var plaintext = System.Text.Encoding.UTF8.GetBytes(text + "\n");
        try
        {
            _store.WriteProtected(PolicyCacheFile, plaintext);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async Task<IntegrityEvidence?> GetEvidenceAsync(CancellationToken cancellationToken = default)
    {
        var integrity = _options.HostIntegrity;
        if (integrity.EvidenceProvider != null)
        {
            var root = GetPackageRoot();
            return await integrity.EvidenceProvider.GetEvidenceAsync(new IntegrityEvidenceContext
            {
                AppId = _options.AppId,
                ReleaseId = _options.ReleaseId,
                Version = _options.Version,
                VersionCode = _options.VersionCode,
                Arch = _options.Arch,
                PackageRoot = root,
                ManifestPath = integrity.ManifestPath
            }, cancellationToken).ConfigureAwait(false);
        }
        if (!integrity.Enabled)
        {
            return null;
        }
        try
        {
            var manifest = await LoadManifestAsync(cancellationToken).ConfigureAwait(false);
            var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var file in manifest.Files)
            {
                var fullPath = ResolveSafePath(GetPackageRoot(), file.Path);
                var info = new FileInfo(fullPath);
                if (!info.Exists || (ulong)info.Length != file.Size)
                {
                    throw new SwmIntegrityException(
                        0,
                        "host_bundle_incomplete",
                        $"protected file is missing or has the wrong size: {file.Path}",
                        IntegrityFailureAction.ShutdownClient);
                }
                var hash = await HashFileAsync(fullPath, cancellationToken).ConfigureAwait(false);
                if (!CryptographicOperations.FixedTimeEquals(hash, file.Sha256))
                {
                    throw new SwmIntegrityException(
                        0,
                        "host_executable_mismatch",
                        $"protected file hash mismatch: {file.Path}",
                        IntegrityFailureAction.ShutdownClient);
                }
                files[NormalizeRelativePath(file.Path)] = Convert.ToHexString(hash).ToLowerInvariant();
            }
            return IntegrityEvidence.Verified(manifest.ManifestSha256, files);
        }
        catch (Exception ex) when (ex is SwmIntegrityException or IOException or UnauthorizedAccessException or CryptographicException)
        {
            var code = ex is SwmIntegrityException integrityException
                ? integrityException.ErrorCode ?? "host_integrity_internal_error"
                : "host_file_io_failed";
            return IntegrityEvidence.Failed(code);
        }
    }

    public async Task<IntegrityEvidence?> GetRequiredEvidenceAsync(CancellationToken cancellationToken = default)
    {
        var evidence = await GetEvidenceAsync(cancellationToken).ConfigureAwait(false);
        if (evidence?.IntegrityState == "failed")
        {
            throw new SwmIntegrityException(
                0,
                evidence.IntegrityFailureCode ?? "host_integrity_internal_error",
                "host integrity validation failed",
                IntegrityFailureAction.ShutdownClient);
        }
        return evidence;
    }

    public async Task<(string HostExecutableSha256, string ConsumerModuleSha256)> ResolveOperationHashesAsync(
        OperationAuthorizationRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.HostExecutablePath) ||
            string.IsNullOrWhiteSpace(request.ConsumerModulePath))
        {
            throw new SwmValidationException(
                0,
                "operation_auth_invalid_request",
                "HostExecutablePath and ConsumerModulePath are required for host-bound operation authorization");
        }
        var hostHash = await HashFileAsync(Path.GetFullPath(request.HostExecutablePath), cancellationToken)
            .ConfigureAwait(false);
        var moduleHash = await HashFileAsync(Path.GetFullPath(request.ConsumerModulePath), cancellationToken)
            .ConfigureAwait(false);
        return (Convert.ToHexString(hostHash).ToLowerInvariant(), Convert.ToHexString(moduleHash).ToLowerInvariant());
    }

    public string? CurrentManifestSha256 => _manifest?.ManifestSha256;

    private async Task<Rim2Manifest> LoadManifestAsync(CancellationToken cancellationToken)
    {
        var root = GetPackageRoot();
        var manifestPath = ResolveSafePath(root, _options.HostIntegrity.ManifestPath);
        if (_manifest != null && string.Equals(_packageRoot, root, StringComparison.OrdinalIgnoreCase))
        {
            return _manifest;
        }
        var raw = await File.ReadAllBytesAsync(manifestPath, cancellationToken).ConfigureAwait(false);
        _manifest = Rim2Parser.ParseAndVerify(
            raw,
            _options.AppId,
            _options.ReleaseId,
            _options.Version,
            _options.VersionCode,
            _options.Arch,
            _options.RootTrustKeyId,
            _options.RootTrustPublicKey);
        _packageRoot = root;
        return _manifest;
    }

    private string GetPackageRoot()
    {
        if (!string.IsNullOrWhiteSpace(_options.HostIntegrity.PackageRoot))
        {
            return Path.GetFullPath(_options.HostIntegrity.PackageRoot);
        }
        return AppContext.BaseDirectory;
    }

    private static string ResolveSafePath(string root, string relativePath)
    {
        var normalized = NormalizeRelativePath(relativePath);
        var rootFull = Path.GetFullPath(root)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
            Path.DirectorySeparatorChar;
        var path = Path.GetFullPath(Path.Combine(rootFull, normalized.Replace('/', Path.DirectorySeparatorChar)));
        if (!path.StartsWith(rootFull, StringComparison.OrdinalIgnoreCase))
        {
            throw new SwmIntegrityException(
                0,
                "host_unsafe_path",
                "integrity path escapes the package root",
                IntegrityFailureAction.ShutdownClient);
        }
        return path;
    }

    private static string NormalizeRelativePath(string value)
    {
        var normalized = value.Trim().Replace('\\', '/');
        if (normalized.Length == 0 || normalized.StartsWith('/') ||
            normalized.Contains(':') ||
            normalized.Split('/').Any(part => part is "" or "." or ".."))
        {
            throw new SwmIntegrityException(
                0,
                "host_unsafe_path",
                "integrity path is unsafe",
                IntegrityFailureAction.ShutdownClient);
        }
        return normalized;
    }

    private static async Task<byte[]> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
    }
}
