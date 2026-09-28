using System.Globalization;
using System.Text;

namespace SwmSdk.Internal;

internal static class ArtifactVerifier
{
    public static void VerifyUpdate(
        UpdateCheckResponse update,
        string appId,
        string expectedArch,
        string rootTrustKeyId,
        string rootTrustPublicKey)
    {
        if (!update.UpdateAvailable || update.OpenInBrowser ||
            string.Equals(update.DeliveryMethod, "external_link", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(update.ReleaseId) ||
            string.IsNullOrWhiteSpace(update.Version) ||
            string.IsNullOrWhiteSpace(update.DownloadUrl) ||
            string.IsNullOrWhiteSpace(update.ArtifactFileName) ||
            string.IsNullOrWhiteSpace(update.ManifestKeyId) ||
            string.IsNullOrWhiteSpace(update.ManifestPublicKey) ||
            string.IsNullOrWhiteSpace(update.RootTrustKeyId) ||
            string.IsNullOrWhiteSpace(update.RootTrustSignature) ||
            string.IsNullOrWhiteSpace(update.Signature) ||
            string.IsNullOrWhiteSpace(update.ChecksumSha256) ||
            update.ChecksumSha256.Length != 64 ||
            update.Size <= 0 ||
            !string.Equals(update.ArtifactPlatform, "windows", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(update.ArtifactArch, expectedArch, StringComparison.OrdinalIgnoreCase))
        {
            throw new SwmIntegrityException(
                0,
                "artifact_manifest_incomplete",
                "signed artifact manifest is incomplete or has the wrong identity",
                IntegrityFailureAction.ShutdownClient);
        }

        if (update.RootTrustKeyId != rootTrustKeyId)
        {
            throw new SwmIntegrityException(
                0,
                "artifact_root_trust_mismatch",
                "artifact root trust key does not match the SDK configuration",
                IntegrityFailureAction.ShutdownClient);
        }
        var rootCanonical = string.Join(
            "\n",
            "root_trust_manifest_v1",
            "app_id:" + appId,
            "signer_key_id:" + rootTrustKeyId,
            "key_id:" + update.ManifestKeyId,
            "public_key:" + update.ManifestPublicKey);
        if (!CryptoUtil.VerifyEd25519(
                rootTrustPublicKey,
                Encoding.UTF8.GetBytes(rootCanonical),
                update.RootTrustSignature!))
        {
            throw new SwmIntegrityException(
                0,
                "artifact_root_trust_invalid",
                "artifact online key root trust signature is invalid",
                IntegrityFailureAction.ShutdownClient);
        }

        var canonical = string.Join(
            "\n",
            "artifact_manifest_v1",
            "release_id:" + update.ReleaseId,
            "release_version:" + update.Version,
            "version_code:" + (update.VersionCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty),
            "platform:" + update.ArtifactPlatform!.Trim().ToLowerInvariant(),
            "arch:" + update.ArtifactArch!.Trim().ToLowerInvariant(),
            "size:" + update.Size.ToString(CultureInfo.InvariantCulture),
            "sha256:" + update.ChecksumSha256!.Trim().ToLowerInvariant(),
            "key_id:" + update.ManifestKeyId);
        if (!CryptoUtil.VerifyEd25519(
                update.ManifestPublicKey!,
                Encoding.UTF8.GetBytes(canonical),
                update.Signature!))
        {
            throw new SwmIntegrityException(
                0,
                "artifact_manifest_signature_invalid",
                "artifact manifest signature is invalid",
                IntegrityFailureAction.ShutdownClient);
        }
    }

    public static void VerifyDownload(UpdateCheckResponse update, string actualSha256)
    {
        if (string.IsNullOrWhiteSpace(update.ChecksumSha256) ||
            string.IsNullOrWhiteSpace(update.Signature) ||
            string.IsNullOrWhiteSpace(update.ManifestPublicKey) ||
            string.IsNullOrWhiteSpace(update.ManifestKeyId) ||
            string.IsNullOrWhiteSpace(update.ReleaseId) ||
            string.IsNullOrWhiteSpace(update.Version) ||
            string.IsNullOrWhiteSpace(update.ArtifactPlatform) ||
            string.IsNullOrWhiteSpace(update.ArtifactArch))
        {
            throw new SwmIntegrityException(
                0,
                "artifact_manifest_incomplete",
                "artifact verification material is missing",
                IntegrityFailureAction.ShutdownClient);
        }
        if (!string.Equals(actualSha256, update.ChecksumSha256, StringComparison.OrdinalIgnoreCase))
        {
            throw new SwmIntegrityException(
                0,
                "artifact_checksum_mismatch",
                "downloaded artifact SHA-256 does not match the signed manifest",
                IntegrityFailureAction.ShutdownClient);
        }
        var canonical = string.Join(
            "\n",
            "artifact_manifest_v1",
            "release_id:" + update.ReleaseId,
            "release_version:" + update.Version,
            "version_code:" + (update.VersionCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty),
            "platform:" + update.ArtifactPlatform!.Trim().ToLowerInvariant(),
            "arch:" + update.ArtifactArch!.Trim().ToLowerInvariant(),
            "size:" + update.Size.ToString(CultureInfo.InvariantCulture),
            "sha256:" + update.ChecksumSha256!.Trim().ToLowerInvariant(),
            "key_id:" + update.ManifestKeyId);
        if (!CryptoUtil.VerifyEd25519(
                update.ManifestPublicKey!,
                Encoding.UTF8.GetBytes(canonical),
                update.Signature!))
        {
            throw new SwmIntegrityException(
                0,
                "artifact_manifest_signature_invalid",
                "artifact manifest signature is invalid",
                IntegrityFailureAction.ShutdownClient);
        }
    }
}
