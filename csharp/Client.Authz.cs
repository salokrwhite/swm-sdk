using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace SwmSdk;

public partial class Client
{
    public const string ApiErrorCodeAuthzInvalid = "authz_invalid";
    public const string ApiErrorCodeAuthzDenied = "authz_denied";

    /// <summary>
    /// Embedded Ed25519 public keys keyed by key_id (hex or base64). The matching
    /// private key lives only on the server, so a fake/offline server cannot
    /// produce a verdict that passes verification here.
    /// </summary>
    public Dictionary<string, string> AuthzPublicKeys { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// When true, every client call that can carry a signed verdict (update-check,
    /// heartbeat, events, feedback, stream) MUST be accompanied by a valid signed
    /// "allow" bound to this request's nonce and this device, or it throws (fail
    /// closed). Leave false for SDK consumers that don't use device authorization.
    /// </summary>
    public bool RequireAuthz { get; set; }

    /// <summary>Tolerated clock skew (seconds) when checking the verdict expiry.</summary>
    public int AuthzClockSkewSeconds { get; set; } = 120;

    // Must match backend internal/auth/authz.go authzCanonical byte-for-byte.
    private static string BuildAuthzCanonical(string appId, AuthzEnvelope env)
    {
        return string.Join("\n", new[]
        {
            "authz_v1",
            "app_id:" + appId,
            "device_id:" + (env.DeviceId ?? string.Empty),
            "nonce:" + (env.Nonce ?? string.Empty),
            "decision:" + (env.Decision ?? string.Empty),
            "reason:" + (env.Reason ?? string.Empty),
            "issued_at:" + env.IssuedAt.ToString(CultureInfo.InvariantCulture),
            "expires_at:" + env.ExpiresAt.ToString(CultureInfo.InvariantCulture),
            "key_id:" + (env.KeyId ?? string.Empty),
        });
    }

    /// <summary>
    /// Verifies a server authorization verdict. Throws on any failure so the
    /// caller fails closed. No-op when RequireAuthz is false. Order matters: the
    /// signature is verified before the decision is honored, so a forged "deny"
    /// cannot be used to probe behavior — anything unsigned fails.
    /// </summary>
    private void VerifyAuthzOrThrow(AuthzEnvelope? env, string requestNonce)
    {
        if (!RequireAuthz)
        {
            return;
        }
        if (env == null)
        {
            throw new SwmUnauthorizedException(401, ApiErrorCodeAuthzInvalid, "authorization missing");
        }

        // 1. Bind to the challenge we actually sent (defeats replay / captured responses).
        if (string.IsNullOrEmpty(requestNonce) || !string.Equals(env.Nonce, requestNonce, StringComparison.Ordinal))
        {
            throw new SwmUnauthorizedException(401, ApiErrorCodeAuthzInvalid, "authorization nonce mismatch");
        }

        // 2. Bind to this device (defeats reuse of one machine's verdict on another).
        if (!string.Equals(env.DeviceId ?? string.Empty, DeviceId ?? string.Empty, StringComparison.Ordinal))
        {
            throw new SwmUnauthorizedException(401, ApiErrorCodeAuthzInvalid, "authorization device mismatch");
        }

        // 3. Expiry with small skew tolerance.
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (env.ExpiresAt <= 0 || now > env.ExpiresAt + AuthzClockSkewSeconds)
        {
            throw new SwmUnauthorizedException(401, ApiErrorCodeAuthzInvalid, "authorization expired");
        }

        // 4. Signature must verify with the embedded public key for this key_id.
        var keyId = env.KeyId ?? string.Empty;
        if (!AuthzPublicKeys.TryGetValue(keyId, out var pubKeyEncoded) || string.IsNullOrWhiteSpace(pubKeyEncoded))
        {
            throw new SwmUnauthorizedException(401, ApiErrorCodeAuthzInvalid, $"authorization key unknown: {keyId}");
        }
        if (string.IsNullOrWhiteSpace(env.Signature))
        {
            throw new SwmUnauthorizedException(401, ApiErrorCodeAuthzInvalid, "authorization signature missing");
        }

        byte[] pubBytes = DecodeKeyMaterial(pubKeyEncoded!);
        if (pubBytes.Length != 32)
        {
            throw new SwmUnauthorizedException(401, ApiErrorCodeAuthzInvalid, "authorization public key invalid");
        }
        byte[] sigBytes = DecodeKeyMaterial(env.Signature!);

        var msg = Encoding.UTF8.GetBytes(BuildAuthzCanonical(AppId, env));
        bool ok;
        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(pubBytes, 0));
            verifier.BlockUpdate(msg, 0, msg.Length);
            ok = verifier.VerifySignature(sigBytes);
        }
        catch (Exception ex)
        {
            throw new SwmUnauthorizedException(401, ApiErrorCodeAuthzInvalid, $"authorization verify error: {ex.Message}");
        }
        if (!ok)
        {
            throw new SwmUnauthorizedException(401, ApiErrorCodeAuthzInvalid, "authorization signature invalid");
        }

        // 5. Only now honor the (authenticated) decision.
        if (!string.Equals(env.Decision, "allow", StringComparison.Ordinal))
        {
            var reason = string.IsNullOrWhiteSpace(env.Reason) ? "access denied" : env.Reason!;
            throw new SwmUnauthorizedException(403, ApiErrorCodeAuthzDenied, $"authorization denied: {reason}");
        }
    }

    // VerifyResponseAuthzAsync extracts the signed verdict from a response body and
    // enforces it (no-op when RequireAuthz is false). For endpoints whose body is
    // otherwise ignored (heartbeat / events / feedback).
    private async Task VerifyResponseAuthzAsync(HttpResponseMessage res, string requestNonce, CancellationToken cancellationToken)
    {
        if (!RequireAuthz)
        {
            return;
        }
        var carrier = await JsonDefaults.DeserializeAsync(res.Content, SwmJsonContext.Default.AuthzCarrier, cancellationToken).ConfigureAwait(false);
        VerifyAuthzOrThrow(carrier.Authz, requestNonce);
    }

    // Decode hex (preferred when the string is all-hex and even length) or base64.
    private static byte[] DecodeKeyMaterial(string value)
    {
        var v = value.Trim();
        if (v.Length == 0)
        {
            throw new SwmApiException(0, null, "empty key material");
        }
        if (v.Length % 2 == 0 && IsAllHex(v))
        {
            var bytes = new byte[v.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(v.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
        return Convert.FromBase64String(v);
    }

    private static bool IsAllHex(string s)
    {
        foreach (var ch in s)
        {
            var isHex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
            if (!isHex)
            {
                return false;
            }
        }
        return true;
    }
}
