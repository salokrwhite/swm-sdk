using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace SwmSdk.Internal;

internal static class CryptoUtil
{
    private const int X25519KeySize = 32;
    private const string BodyEncryptionLabel = "swm-body-x25519-aes-gcm-v1";

    public static byte[] Sha256(ReadOnlySpan<byte> value)
    {
        return SHA256.HashData(value);
    }

    public static string Sha256Hex(ReadOnlySpan<byte> value)
    {
        return Convert.ToHexString(Sha256(value)).ToLowerInvariant();
    }

    public static string Sha256Base64Url(string value)
    {
        return Base64UrlEncode(Sha256(Encoding.UTF8.GetBytes(value)));
    }

    public static string HmacSha256Hex(string key, string value)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    public static byte[] RandomBytes(int size)
    {
        var value = new byte[size];
        RandomNumberGenerator.Fill(value);
        return value;
    }

    public static string Base64UrlEncode(ReadOnlySpan<byte> value)
    {
        return Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public static byte[] Base64UrlDecode(string value)
    {
        var normalized = value.Trim().Replace('-', '+').Replace('_', '/');
        normalized = normalized.PadRight(normalized.Length + ((4 - normalized.Length % 4) % 4), '=');
        return Convert.FromBase64String(normalized);
    }

    public static byte[] DecodeKeyMaterial(string value)
    {
        var input = value.Trim();
        if (input.Length == 0)
        {
            throw new FormatException("empty key material");
        }
        if (input.Length % 2 == 0 && input.All(Uri.IsHexDigit))
        {
            return Convert.FromHexString(input);
        }
        try
        {
            return Convert.FromBase64String(input);
        }
        catch (FormatException)
        {
            return Base64UrlDecode(input);
        }
    }

    public static bool VerifyEd25519(string publicKey, ReadOnlySpan<byte> message, string signature)
    {
        var keyBytes = DecodeKeyMaterial(publicKey);
        var signatureBytes = DecodeKeyMaterial(signature);
        if (keyBytes.Length != 32 || signatureBytes.Length != 64)
        {
            throw new SwmCryptographicException("Ed25519 key or signature has an invalid length");
        }
        var verifier = new Ed25519Signer();
        verifier.Init(false, new Ed25519PublicKeyParameters(keyBytes, 0));
        verifier.BlockUpdate(message);
        return verifier.VerifySignature(signatureBytes);
    }

    public static byte[] EncryptRequestBody(
        string method,
        string path,
        string canonicalQuery,
        long timestamp,
        string nonce,
        string appId,
        string releaseId,
        string releaseVersion,
        string? releaseVersionCode,
        string onlineKeyId,
        string onlinePublicKey,
        ReadOnlySpan<byte> plaintext)
    {
        var ed25519PublicKey = DecodeKeyMaterial(onlinePublicKey);
        if (ed25519PublicKey.Length != X25519KeySize)
        {
            throw new SwmCryptographicException("online authorization key must be a 32-byte Ed25519 key");
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
            var requestKey = DeriveRequestBodyKey(
                sharedSecret,
                ephemeralPublicBytes,
                appId,
                releaseId,
                onlineKeyId,
                ed25519PublicKey);
            try
            {
                var aesNonce = RandomBytes(12);
                var aad = BuildBodyEncryptionAad(
                    method,
                    path,
                    canonicalQuery,
                    timestamp,
                    nonce,
                    appId,
                    releaseId,
                    releaseVersion,
                    releaseVersionCode,
                    onlineKeyId);
                var cipherText = EncryptAesGcm(requestKey, aesNonce, plaintext, aad);
                var sealedBody = new byte[ephemeralPublicBytes.Length + aesNonce.Length + cipherText.Length];
                Buffer.BlockCopy(ephemeralPublicBytes, 0, sealedBody, 0, ephemeralPublicBytes.Length);
                Buffer.BlockCopy(aesNonce, 0, sealedBody, ephemeralPublicBytes.Length, aesNonce.Length);
                Buffer.BlockCopy(cipherText, 0, sealedBody, ephemeralPublicBytes.Length + aesNonce.Length, cipherText.Length);
                return sealedBody;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(requestKey);
            }
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
        {
            throw new SwmCryptographicException("request body key agreement failed", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            CryptographicOperations.ZeroMemory(serverX25519PublicKey);
        }
    }

    private static byte[] DeriveRequestBodyKey(
        ReadOnlySpan<byte> sharedSecret,
        ReadOnlySpan<byte> ephemeralPublicKey,
        string appId,
        string releaseId,
        string onlineKeyId,
        ReadOnlySpan<byte> ed25519PublicKey)
    {
        var context = string.Join(
            "\n",
            BodyEncryptionLabel,
            "app_id:" + appId,
            "release_id:" + releaseId,
            "key_id:" + onlineKeyId,
            "public_key:" + Convert.ToHexString(ed25519PublicKey).ToLowerInvariant());
        var salt = Sha256(Encoding.UTF8.GetBytes(context));
        var info = Encoding.UTF8.GetBytes(
            context + "\nephemeral_public:" + Base64UrlEncode(ephemeralPublicKey));
        return HkdfSha256(sharedSecret, salt, info);
    }

    private static byte[] HkdfSha256(
        ReadOnlySpan<byte> inputKeyMaterial,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info)
    {
        var pseudoRandomKey = HMACSHA256.HashData(salt, inputKeyMaterial);
        try
        {
            var expandInput = new byte[info.Length + 1];
            info.CopyTo(expandInput);
            expandInput[^1] = 1;
            return HMACSHA256.HashData(pseudoRandomKey, expandInput);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pseudoRandomKey);
        }
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
            throw new SwmCryptographicException("authorization Ed25519 public key is not canonical");
        }

        var denominator = (BigInteger.One - y) % prime;
        if (denominator.Sign < 0)
        {
            denominator += prime;
        }
        if (denominator.IsZero)
        {
            throw new SwmCryptographicException("authorization Ed25519 public key cannot be converted to X25519");
        }

        var u = ((BigInteger.One + y) * BigInteger.ModPow(denominator, prime - 2, prime)) % prime;
        var encodedU = u.ToByteArray();
        if (encodedU.Length > X25519KeySize)
        {
            throw new SwmCryptographicException("authorization X25519 public key is invalid");
        }
        var result = new byte[X25519KeySize];
        Buffer.BlockCopy(encodedU, 0, result, 0, encodedU.Length);
        return result;
    }

    private static byte[] BuildBodyEncryptionAad(
        string method,
        string path,
        string canonicalQuery,
        long timestamp,
        string nonce,
        string appId,
        string releaseId,
        string releaseVersion,
        string? releaseVersionCode,
        string onlineKeyId)
    {
        var aad = string.Join(
            "\n",
            BodyEncryptionLabel,
            method.ToUpperInvariant(),
            path,
            canonicalQuery,
            string.Empty,
            timestamp.ToString(System.Globalization.CultureInfo.InvariantCulture),
            nonce,
            appId,
            "client_release_id:" + releaseId,
            "client_version:" + releaseVersion,
            "client_version_code:" + (releaseVersionCode ?? string.Empty),
            "authz_capability:v3",
            "body_enc:x25519-aes-gcm-v1",
            "key_id:" + onlineKeyId);
        return Encoding.UTF8.GetBytes(aad);
    }

    private static byte[] EncryptAesGcm(
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> aad)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(key), 128, nonce, aad.ToArray());
        cipher.Init(true, parameters);
        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        var written = cipher.ProcessBytes(plaintext.ToArray(), 0, plaintext.Length, output, 0);
        written += cipher.DoFinal(output, written);
        if (written == output.Length)
        {
            return output;
        }
        return output.AsSpan(0, written).ToArray();
    }
}
