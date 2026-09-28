package com.swm.sdk.internal;

import com.swm.sdk.SwmException;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public final class CryptoUtil {
    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger CURVE_PRIME = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    private CryptoUtil() {}

    public static byte[] randomBytes(int size) {
        var value = new byte[size];
        RANDOM.nextBytes(value);
        return value;
    }

    public static String hex(byte[] value) {
        var result = new char[value.length * 2];
        for (int index = 0; index < value.length; index++) {
            result[index * 2] = HEX[(value[index] >>> 4) & 0x0f];
            result[index * 2 + 1] = HEX[value[index] & 0x0f];
        }
        return new String(result);
    }

    public static byte[] unhex(String value) {
        if ((value.length() & 1) != 0) {
            throw new SwmException.Configuration("invalid hexadecimal value");
        }
        var result = new byte[value.length() / 2];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
        }
        return result;
    }

    public static String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    public static byte[] decodeKeyMaterial(String value) {
        var cleaned = value == null ? "" : value.trim();
        if (cleaned.isEmpty()) {
            throw new SwmException.Configuration("empty key material");
        }
        if ((cleaned.length() & 1) == 0 && cleaned.matches("[0-9a-fA-F]+")) {
            return unhex(cleaned);
        }
        try {
            return Base64.getUrlDecoder().decode(cleaned);
        } catch (IllegalArgumentException exception) {
            throw new SwmException.Configuration("invalid key material");
        }
    }

    public static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (GeneralSecurityException exception) {
            throw new SwmException.Cryptographic("SHA-256 is unavailable", exception);
        }
    }

    public static String sha256Hex(byte[] value) {
        return hex(sha256(value));
    }

    public static byte[] hmacSha256(byte[] key, byte[] value) {
        var mac = new HMac(new SHA256Digest());
        mac.init(new KeyParameter(key));
        mac.update(value, 0, value.length);
        var output = new byte[mac.getMacSize()];
        mac.doFinal(output, 0);
        return output;
    }

    public static boolean verifyEd25519(String publicKey, byte[] message, String signature) {
        var key = decodeKeyMaterial(publicKey);
        var signatureBytes = decodeKeyMaterial(signature);
        if (key.length != 32 || signatureBytes.length != 64) {
            throw new SwmException.Cryptographic("invalid Ed25519 key or signature length", null);
        }
        var verifier = new Ed25519Signer();
        verifier.init(false, new Ed25519PublicKeyParameters(key, 0));
        verifier.update(message, 0, message.length);
        return verifier.verifySignature(signatureBytes);
    }

    public static byte[] ed25519PublicToX25519(byte[] publicKey) {
        if (publicKey.length != 32) {
            throw new SwmException.Cryptographic("invalid Ed25519 public key length", null);
        }
        var yBytes = Arrays.copyOf(publicKey, 32);
        yBytes[31] &= 0x7f;
        var y = new BigInteger(1, reverse(yBytes));
        if (y.compareTo(CURVE_PRIME) >= 0) {
            throw new SwmException.Cryptographic("non-canonical Ed25519 public key", null);
        }
        var denominator = BigInteger.ONE.subtract(y).mod(CURVE_PRIME);
        if (denominator.signum() == 0) {
            throw new SwmException.Cryptographic("Ed25519 public key cannot be converted", null);
        }
        var u = BigInteger.ONE.add(y).multiply(denominator.modPow(
            CURVE_PRIME.subtract(BigInteger.TWO), CURVE_PRIME)).mod(CURVE_PRIME);
        var encoded = u.toByteArray();
        var little = new byte[32];
        for (int index = 0; index < Math.min(encoded.length, 32); index++) {
            little[index] = encoded[encoded.length - 1 - index];
        }
        return little;
    }

    public static byte[] x25519SharedSecret(byte[] privateKey, byte[] publicKey) {
        var agreement = new X25519Agreement();
        agreement.init(new X25519PrivateKeyParameters(privateKey, 0));
        var output = new byte[32];
        agreement.calculateAgreement(new X25519PublicKeyParameters(publicKey, 0), output, 0);
        return output;
    }

    public static byte[] x25519PublicKey(byte[] privateKey) {
        return new X25519PrivateKeyParameters(privateKey, 0).generatePublicKey().getEncoded();
    }

    public static byte[] encryptAesGcm(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad) {
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException exception) {
            throw new SwmException.Cryptographic("AES-GCM encryption failed", exception);
        }
    }

    public static byte[] decryptAesGcm(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad) {
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException exception) {
            throw new SwmException.Cryptographic("AES-GCM decryption failed", exception);
        }
    }

    public static byte[] encryptRequestBody(
        String method,
        String path,
        String canonicalQuery,
        long timestamp,
        String nonce,
        String appId,
        String releaseId,
        String version,
        String versionCode,
        String onlineKeyId,
        String onlinePublicKey,
        byte[] plaintext
    ) {
        var serverX = ed25519PublicToX25519(decodeKeyMaterial(onlinePublicKey));
        var ephemeralPrivate = randomBytes(32);
        var ephemeralPublic = x25519PublicKey(ephemeralPrivate);
        var shared = x25519SharedSecret(ephemeralPrivate, serverX);
        var context = "swm-body-x25519-aes-gcm-v1\napp_id:" + appId
            + "\nrelease_id:" + releaseId + "\nkey_id:" + onlineKeyId
            + "\npublic_key:" + hex(decodeKeyMaterial(onlinePublicKey));
        var salt = sha256(context.getBytes(StandardCharsets.UTF_8));
        var prk = hmacSha256(salt, shared);
        var info = (context + "\nephemeral_public:" + base64Url(ephemeralPublic))
            .getBytes(StandardCharsets.UTF_8);
        var expand = Arrays.copyOf(info, info.length + 1);
        expand[expand.length - 1] = 1;
        var requestKey = hmacSha256(prk, expand);
        var aesNonce = randomBytes(12);
        var aad = bodyAad(method, path, canonicalQuery, timestamp, nonce, appId,
            releaseId, version, versionCode, onlineKeyId);
        var encrypted = encryptAesGcm(requestKey, aesNonce, plaintext,
            aad.getBytes(StandardCharsets.UTF_8));
        var result = new byte[ephemeralPublic.length + aesNonce.length + encrypted.length];
        System.arraycopy(ephemeralPublic, 0, result, 0, ephemeralPublic.length);
        System.arraycopy(aesNonce, 0, result, ephemeralPublic.length, aesNonce.length);
        System.arraycopy(encrypted, 0, result, ephemeralPublic.length + aesNonce.length,
            encrypted.length);
        return result;
    }

    private static String bodyAad(
        String method,
        String path,
        String query,
        long timestamp,
        String nonce,
        String appId,
        String releaseId,
        String version,
        String versionCode,
        String onlineKeyId
    ) {
        return "swm-body-x25519-aes-gcm-v1\n" + method + "\n" + path + "\n" + query
            + "\n\n" + timestamp + "\n" + nonce + "\n" + appId
            + "\nclient_release_id:" + releaseId
            + "\nclient_version:" + version
            + "\nclient_version_code:" + (versionCode == null ? "" : versionCode)
            + "\nauthz_capability:v3\nbody_enc:x25519-aes-gcm-v1\nkey_id:" + onlineKeyId;
    }

    private static byte[] reverse(byte[] value) {
        var result = new byte[value.length];
        for (int index = 0; index < value.length; index++) {
            result[index] = value[value.length - index - 1];
        }
        return result;
    }
}
