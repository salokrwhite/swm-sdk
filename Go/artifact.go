package swm

import (
	"strconv"
	"strings"
)

func verifyUpdateArtifact(update UpdateInfo, options Options) error {
	if !update.UpdateAvailable || update.OpenInBrowser ||
		strings.EqualFold(update.DeliveryMethod, "external_link") {
		return nil
	}
	if update.ReleaseID == "" || update.Version == "" || update.DownloadURL == "" ||
		update.ArtifactFileName == "" || update.ManifestKeyID == "" ||
		update.ManifestPublicKey == "" || update.RootTrustKeyID == "" ||
		update.RootTrustSignature == "" || update.Signature == "" ||
		update.ChecksumSHA256 == "" || len(update.ChecksumSHA256) != 64 ||
		update.Size <= 0 ||
		!strings.EqualFold(update.ArtifactPlatform, "windows") ||
		!strings.EqualFold(update.ArtifactArch, options.Arch) {
		return newError(KindIntegrity, "artifact", "artifact_manifest_incomplete", "signed artifact manifest is incomplete or has the wrong identity")
	}
	if update.RootTrustKeyID != options.RootTrustKeyID {
		return newError(KindIntegrity, "artifact", "artifact_root_trust_mismatch", "artifact root trust key does not match configuration")
	}
	rootCanonical := strings.Join([]string{
		"root_trust_manifest_v1",
		"app_id:" + options.AppID,
		"signer_key_id:" + options.RootTrustKeyID,
		"key_id:" + update.ManifestKeyID,
		"public_key:" + update.ManifestPublicKey,
	}, "\n")
	valid, err := verifyEd25519(options.RootTrustPublicKey, []byte(rootCanonical), update.RootTrustSignature)
	if err != nil || !valid {
		return newError(KindIntegrity, "artifact", "artifact_root_trust_invalid", "artifact online key root trust signature is invalid")
	}
	return verifyArtifactManifest(update)
}

func verifyDownloadArtifact(update UpdateInfo, actualSHA256 string) error {
	if update.ChecksumSHA256 == "" || update.Signature == "" ||
		update.ManifestPublicKey == "" || update.ManifestKeyID == "" ||
		update.ReleaseID == "" || update.Version == "" ||
		update.ArtifactPlatform == "" || update.ArtifactArch == "" {
		return newError(KindIntegrity, "download", "artifact_manifest_incomplete", "artifact verification material is missing")
	}
	if !strings.EqualFold(actualSHA256, update.ChecksumSHA256) {
		return newError(KindIntegrity, "download", "artifact_checksum_mismatch", "downloaded artifact SHA-256 does not match the signed manifest")
	}
	return verifyArtifactManifest(update)
}

func verifyArtifactManifest(update UpdateInfo) error {
	canonical := strings.Join([]string{
		"artifact_manifest_v1",
		"release_id:" + update.ReleaseID,
		"release_version:" + update.Version,
		"version_code:" + versionCodeString(update.VersionCode),
		"platform:" + strings.ToLower(strings.TrimSpace(update.ArtifactPlatform)),
		"arch:" + strings.ToLower(strings.TrimSpace(update.ArtifactArch)),
		"size:" + strconv.FormatInt(update.Size, 10),
		"sha256:" + strings.ToLower(strings.TrimSpace(update.ChecksumSHA256)),
		"key_id:" + update.ManifestKeyID,
	}, "\n")
	valid, err := verifyEd25519(update.ManifestPublicKey, []byte(canonical), update.Signature)
	if err != nil || !valid {
		return newError(KindIntegrity, "artifact", "artifact_manifest_signature_invalid", "artifact manifest signature is invalid")
	}
	return nil
}
