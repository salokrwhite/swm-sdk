#nullable enable
using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace SwmSdk;

public partial class Client
{
    private const string BodyEncryptionHeader = "X-SWM-Body-Enc";
    private const string BodyEncryptionVersion = "x25519-aes-gcm-v1";
    private const string BodyEncryptionLabel = "swm-body-x25519-aes-gcm-v1";
    private const int X25519KeySize = 32;

    private HttpContent CreateRequestContent(HttpRequestMessage request, HttpContent original, byte[] bodyBytes)
    {
        var encrypted = EncryptBody(request, bodyBytes);
        var content = new ByteArrayContent(encrypted);
        CopyContentHeaders(original, content);
        request.Headers.TryAddWithoutValidation(BodyEncryptionHeader, BodyEncryptionVersion);
        return content;
    }

    private static void CopyContentHeaders(HttpContent source, HttpContent target)
    {
        foreach (var header in source.Headers)
        {
            target.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
    }

    private byte[] EncryptBody(HttpRequestMessage request, byte[] bodyBytes)
    {
        if (request.RequestUri == null)
        {
            throw new SwmApiException(0, null, "request uri required for body encryption");
        }

        var profile = RequireBodyEncryptionProfile();
        var ed25519PublicKey = DecodeAuthzKeyMaterial(profile.PublicKey);
        if (ed25519PublicKey.Length != X25519KeySize)
        {
            throw InvalidAuthz("authorization public key must be a 32-byte Ed25519 key");
        }

        var serverX25519PublicKey = ConvertEd25519PublicKeyToX25519(ed25519PublicKey);
        var ephemeralPrivateKey = new X25519PrivateKeyParameters(new SecureRandom());
        var ephemeralPublicKey = ephemeralPrivateKey.GeneratePublicKey();
        var ephemeralPublicBytes = new byte[X25519KeySize];
        var sharedSecret = new byte[X25519KeySize];
        ephemeralPublicKey.Encode(ephemeralPublicBytes, 0);

        try
        {
            ephemeralPrivateKey.GenerateSecret(
                new X25519PublicKeyParameters(serverX25519PublicKey, 0),
                sharedSecret,
                0);
            var key = DeriveRequestBodyKey(
                sharedSecret,
                ephemeralPublicBytes,
                profile,
                HexLower(ed25519PublicKey));
            try
            {
                var nonce = new byte[12];
                FillRandomBytes(nonce);
                var aad = BuildBodyEncryptionAad(request, profile);
                var cipherText = EncryptAesGcm(key, nonce, bodyBytes, aad);
                var sealedBody = new byte[ephemeralPublicBytes.Length + nonce.Length + cipherText.Length];
                Buffer.BlockCopy(ephemeralPublicBytes, 0, sealedBody, 0, ephemeralPublicBytes.Length);
                Buffer.BlockCopy(nonce, 0, sealedBody, ephemeralPublicBytes.Length, nonce.Length);
                Buffer.BlockCopy(cipherText, 0, sealedBody, ephemeralPublicBytes.Length + nonce.Length, cipherText.Length);
                return sealedBody;
            }
            finally
            {
                ClearBytes(key);
            }
        }
        catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException)
        {
            throw InvalidAuthz("request body key agreement failed: " + ex.Message);
        }
        finally
        {
            ClearBytes(sharedSecret);
            ClearBytes(serverX25519PublicKey);
        }
    }

    private ReleaseSecurityProfile RequireBodyEncryptionProfile()
    {
        var profile = RequireV3SecurityProfile();
        if (string.IsNullOrWhiteSpace(AppId) ||
            string.IsNullOrWhiteSpace(profile.ReleaseId) ||
            string.IsNullOrWhiteSpace(profile.KeyId) ||
            string.IsNullOrWhiteSpace(profile.PublicKey))
        {
            throw InvalidAuthz("request body encryption profile is incomplete");
        }
        return profile;
    }

    private static void FillRandomBytes(byte[] buffer)
    {
#if NETSTANDARD2_0
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(buffer);
#else
        RandomNumberGenerator.Fill(buffer);
#endif
    }

    private static void ClearBytes(byte[] buffer)
    {
#if NETSTANDARD2_0
        Array.Clear(buffer, 0, buffer.Length);
#else
        CryptographicOperations.ZeroMemory(buffer);
#endif
    }

    private byte[] DeriveRequestBodyKey(
        byte[] sharedSecret,
        byte[] ephemeralPublicKey,
        ReleaseSecurityProfile profile,
        string canonicalPublicKey)
    {
        var context = string.Join("\n", new[]
        {
            BodyEncryptionLabel,
            "app_id:" + AppId.Trim(),
            "release_id:" + profile.ReleaseId.Trim(),
            "key_id:" + profile.KeyId.Trim(),
            "public_key:" + canonicalPublicKey
        });
        byte[] salt;
        using (var sha256 = SHA256.Create())
        {
            salt = sha256.ComputeHash(Encoding.UTF8.GetBytes(context));
        }

        var info = Encoding.UTF8.GetBytes(
            context + "\nephemeral_public:" + Base64UrlEncode(ephemeralPublicKey));
        return HkdfSha256(sharedSecret, salt, info);
    }

    private static byte[] HkdfSha256(byte[] inputKeyMaterial, byte[] salt, byte[] info)
    {
        byte[] pseudoRandomKey;
        using (var extract = new HMACSHA256(salt))
        {
            pseudoRandomKey = extract.ComputeHash(inputKeyMaterial);
        }

        try
        {
            var expandInput = new byte[info.Length + 1];
            Buffer.BlockCopy(info, 0, expandInput, 0, info.Length);
            expandInput[expandInput.Length - 1] = 1;
            using var expand = new HMACSHA256(pseudoRandomKey);
            return expand.ComputeHash(expandInput);
        }
        finally
        {
            ClearBytes(pseudoRandomKey);
        }
    }

    private static string Base64UrlEncode(byte[] value)
    {
        return Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static byte[] ConvertEd25519PublicKeyToX25519(byte[] encoded)
    {
        var yBytes = new byte[X25519KeySize + 1];
        Buffer.BlockCopy(encoded, 0, yBytes, 0, X25519KeySize);
        yBytes[X25519KeySize - 1] &= 0x7f;

        var prime = (BigInteger.One << 255) - 19;
        var y = new BigInteger(yBytes);
        if (y.Sign < 0 || y >= prime)
        {
            throw InvalidAuthz("authorization Ed25519 public key is not canonical");
        }

        var denominator = (BigInteger.One - y) % prime;
        if (denominator.Sign < 0)
        {
            denominator += prime;
        }
        if (denominator.IsZero)
        {
            throw InvalidAuthz("authorization Ed25519 public key cannot be converted to X25519");
        }

        var u = ((BigInteger.One + y) * BigInteger.ModPow(denominator, prime - 2, prime)) % prime;
        var encodedU = u.ToByteArray();
        if (encodedU.Length > X25519KeySize)
        {
            throw InvalidAuthz("authorization X25519 public key is invalid");
        }

        var result = new byte[X25519KeySize];
        Buffer.BlockCopy(encodedU, 0, result, 0, encodedU.Length);
        return result;
    }

    private byte[] BuildBodyEncryptionAad(HttpRequestMessage request, ReleaseSecurityProfile profile)
    {
        var uri = request.RequestUri ?? throw new SwmApiException(0, null, "request uri required for body encryption");
        var timestamp = GetRequiredHeader(request.Headers, SignHeaderTimestamp);
        var nonce = GetRequiredHeader(request.Headers, SignHeaderNonce);
        var releaseId = GetOptionalHeader(request.Headers, ClientReleaseIdHeader);
        var version = GetOptionalHeader(request.Headers, ClientVersionHeader);
        var versionCode = GetOptionalHeader(request.Headers, ClientVersionCodeHeader);
        var capability = GetOptionalHeader(request.Headers, AuthzCapabilityHeader);

        var aad = string.Join("\n", new[]
        {
            BodyEncryptionLabel,
            request.Method.Method.ToUpperInvariant(),
            uri.AbsolutePath,
            BuildCanonicalQuery(uri),
            string.Empty,
            timestamp,
            nonce,
            AppId,
            "client_release_id:" + releaseId,
            "client_version:" + version,
            "client_version_code:" + versionCode,
            "authz_capability:" + capability,
            "body_enc:" + BodyEncryptionVersion,
            "key_id:" + profile.KeyId.Trim()
        });
        return Encoding.UTF8.GetBytes(aad);
    }

    private static string GetRequiredHeader(HttpRequestHeaders headers, string name)
    {
        var value = GetOptionalHeader(headers, name);
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new SwmApiException(0, null, $"missing request header: {name}");
        }
        return value;
    }

    private static string GetOptionalHeader(HttpRequestHeaders headers, string name)
    {
        if (headers.TryGetValues(name, out var values))
        {
            foreach (var value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value.Trim();
                }
            }
        }
        return string.Empty;
    }

    private static byte[] EncryptAesGcm(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(key), 128, nonce, aad);
        cipher.Init(true, parameters);
        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        var written = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        written += cipher.DoFinal(output, written);
        if (written == output.Length)
        {
            return output;
        }
        var trimmed = new byte[written];
        Buffer.BlockCopy(output, 0, trimmed, 0, written);
        return trimmed;
    }
}
