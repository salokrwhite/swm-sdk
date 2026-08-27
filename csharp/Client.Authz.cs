using System.Globalization;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace SwmSdk;

public partial class Client
{
    public const string ApiErrorCodeAuthzInvalid = "authz_invalid";
    public const string ApiErrorCodeAuthzDenied = "authz_denied";

    private const int MaxAuthzLifetimeSeconds = 15 * 60;

    public Dictionary<string, string> OnlinePublicKeys { get; } = new(StringComparer.Ordinal);

    public int AuthzClockSkewSeconds { get; set; } = 120;

    private async Task VerifyResponseAuthzAsync(
        HttpResponseMessage response,
        string requestNonce,
        CancellationToken cancellationToken)
    {
		var raw = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
		var carrier = JsonSerializer.Deserialize(raw, SwmJsonContext.Default.AuthzV3Carrier)
			?? throw InvalidAuthz("authorization response missing");
		var data = Encoding.UTF8.GetBytes(carrier.Data.GetRawText());
		VerifyAuthzV3OrThrow(carrier.Authz, requestNonce, data);
    }

	private void VerifyAuthzV3OrThrow(AuthzV3Envelope? envelope, string requestNonce, byte[] rawData)
	{
		if (envelope == null || !string.Equals(envelope.Version, "authz_v3", StringComparison.Ordinal))
		{
			throw InvalidAuthz("Authz v3 native verdict envelope missing");
		}
		var native = NativeSecurityContext ?? throw InvalidAuthz("MySwm native security context missing");
		try
		{
			native.VerifyAuthzV3(envelope, requestNonce, rawData);
		}
		catch (MySwmException ex)
		{
			throw InvalidAuthz("MySwm rejected the server verdict: " + ex.Message);
		}
		if (!string.IsNullOrWhiteSpace(envelope.Session))
		{
			SessionToken = envelope.Session!;
			SessionExpiresAt = envelope.ExpiresAt;
		}
	}

	private void VerifyArtifactManifestOrThrow(UpdateCheckResponse update)
	{
		var keyId = update.ManifestKeyId?.Trim() ?? string.Empty;
		var responsePublicKey = update.ManifestPublicKey?.Trim() ?? string.Empty;
		if (!string.IsNullOrWhiteSpace(responsePublicKey))
		{
			// update-check 的整个 data 已由当前 Release 的固定信任 Key 签名，
			// 因此可用它安全承载目标 Release 的轮换公钥。
			OnlinePublicKeys[keyId] = responsePublicKey;
		}
		if (string.IsNullOrWhiteSpace(update.ReleaseId) || string.IsNullOrWhiteSpace(update.Version) ||
			string.IsNullOrWhiteSpace(update.ChecksumSha256) || string.IsNullOrWhiteSpace(update.Signature) ||
			string.IsNullOrWhiteSpace(update.ArtifactPlatform) || string.IsNullOrWhiteSpace(update.ArtifactArch) ||
			!OnlinePublicKeys.TryGetValue(keyId, out var publicKey))
		{
			throw InvalidAuthz("signed artifact manifest incomplete or key unknown");
		}
		var canonical = string.Join("\n", new[]
		{
			"artifact_manifest_v1",
			"release_id:" + update.ReleaseId,
			"release_version:" + update.Version,
			"version_code:" + (update.VersionCode?.ToString(CultureInfo.InvariantCulture) ?? string.Empty),
			"platform:" + update.ArtifactPlatform!.Trim().ToLowerInvariant(),
			"arch:" + update.ArtifactArch!.Trim().ToLowerInvariant(),
			"size:" + update.Size.ToString(CultureInfo.InvariantCulture),
			"sha256:" + update.ChecksumSha256!.Trim().ToLowerInvariant(),
			"key_id:" + keyId
		});
		var verifier = new Ed25519Signer();
		verifier.Init(false, new Ed25519PublicKeyParameters(DecodeAuthzKeyMaterial(publicKey), 0));
		var message = Encoding.UTF8.GetBytes(canonical);
		verifier.BlockUpdate(message, 0, message.Length);
		if (!verifier.VerifySignature(DecodeAuthzKeyMaterial(update.Signature!)))
		{
			throw InvalidAuthz("artifact manifest signature invalid");
		}
	}

    private static byte[] DecodeAuthzKeyMaterial(string value)
    {
        var input = value.Trim();
        if (input.Length == 0)
        {
            throw new FormatException("empty key material");
        }

        if (input.Length % 2 == 0 && input.All(Uri.IsHexDigit))
        {
            var bytes = new byte[input.Length / 2];
            for (var index = 0; index < bytes.Length; index++)
            {
                bytes[index] = Convert.ToByte(input.Substring(index * 2, 2), 16);
            }
            return bytes;
        }

        return Convert.FromBase64String(input);
    }

    private static SwmUnauthorizedException InvalidAuthz(string message)
    {
        return new SwmUnauthorizedException(401, ApiErrorCodeAuthzInvalid, message);
    }
}
