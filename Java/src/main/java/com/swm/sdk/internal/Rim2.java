package com.swm.sdk.internal;

import com.swm.sdk.SwmException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class Rim2 {
    private static final byte[] MAGIC = "OPLUSRIM".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] MANIFEST_DOMAIN =
        "OPLUS_RELEASE_MANIFEST_V2\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] KEY_DOMAIN =
        "OPLUS_RELEASE_KEY_V2\0".getBytes(StandardCharsets.US_ASCII);

    private Rim2() {}

    public static Manifest parseAndVerify(
        byte[] raw,
        String expectedAppId,
        String expectedReleaseId,
        String expectedVersion,
        Integer expectedVersionCode,
        String expectedArch,
        String expectedRootKeyId,
        String rootTrustPublicKey
    ) {
        if (raw.length == 0 || raw.length > 64 * 1024 || !startsWith(raw, MAGIC)) {
            throw new SwmException.Integrity(0, "host_manifest_invalid",
                "RIM2 manifest header is invalid", "");
        }
        var reader = new Reader(raw);
        reader.readBytes(MAGIC.length);
        if (reader.u16() != 2) {
            throw new SwmException.Integrity(0, "host_manifest_invalid",
                "RIM2 manifest version is invalid", "");
        }
        var bodySize = reader.u32();
        if (bodySize <= 0 || bodySize > reader.remaining()) {
            throw new SwmException.Integrity(0, "host_manifest_invalid",
                "RIM2 manifest body size is invalid", "");
        }
        var bodyStart = reader.offset();
        var body = java.util.Arrays.copyOfRange(raw, bodyStart, bodyStart + (int) bodySize);
        var bodyReader = new Reader(body);
        var app = bodyReader.bytes(16);
        var release = bodyReader.bytes(16);
        var versionCode = bodyReader.u64();
        var platform = bodyReader.u8();
        var architecture = bodyReader.u8();
        var version = bodyReader.string16();
        var count = bodyReader.u16();
        if (platform != 1 || count == 0 || count > 255 || version.isEmpty()) {
            throw new SwmException.Integrity(0, "host_manifest_invalid",
                "RIM2 identity fields are invalid", "");
        }
        var files = new ArrayList<FileEntry>();
        Set<String> paths = new HashSet<>();
        for (int index = 0; index < count; index++) {
            var path = bodyReader.string16();
            var size = bodyReader.u64();
            var hash = bodyReader.bytes(32);
            if (!safePath(path) || size == 0 || allZero(hash)
                || !paths.add(path.toLowerCase(Locale.ROOT))) {
                throw new SwmException.Integrity(0, "host_manifest_invalid",
                    "RIM2 contains an invalid file entry", "");
            }
            files.add(new FileEntry(path, size, hash));
        }
        if (bodyReader.remaining() != 0) {
            throw new SwmException.Integrity(0, "host_manifest_invalid",
                "RIM2 body has trailing bytes", "");
        }
        var trailer = new Reader(raw, bodyStart + (int) bodySize);
        var rootKeyId = trailer.string8();
        var signerKeyId = trailer.string8();
        var signerPublic = trailer.bytes(32);
        var rootSignature = trailer.bytes(64);
        var manifestSignature = trailer.bytes(64);
        if (trailer.remaining() != 0 || !guidText(app).equals(expectedAppId)
            || !guidText(release).equals(expectedReleaseId) || !version.equals(expectedVersion)
            || (expectedVersionCode != null && versionCode != expectedVersionCode.longValue())
            || !archText(architecture).equalsIgnoreCase(expectedArch)
            || !rootKeyId.equals(expectedRootKeyId)) {
            throw new SwmException.Integrity(0, "host_release_mismatch",
                "RIM2 identity does not match this release", "");
        }
        var keyMessage = concat(KEY_DOMAIN, app, string8(rootKeyId), string8(signerKeyId),
            signerPublic);
        if (!CryptoUtil.verifyEd25519(rootTrustPublicKey, keyMessage,
            CryptoUtil.base64Url(rootSignature))) {
            throw new SwmException.Integrity(0, "host_root_signature_invalid",
                "RIM2 root certificate signature is invalid", "");
        }
        var manifestMessage = concat(MANIFEST_DOMAIN, body);
        if (!CryptoUtil.verifyEd25519(CryptoUtil.base64Url(signerPublic), manifestMessage,
            CryptoUtil.base64Url(manifestSignature))) {
            throw new SwmException.Integrity(0, "host_manifest_signature_invalid",
                "RIM2 manifest signature is invalid", "");
        }
        return new Manifest(raw, CryptoUtil.sha256Hex(raw), expectedAppId, expectedReleaseId,
            versionCode, version, archText(architecture), rootKeyId, signerKeyId, files);
    }

    private static boolean safePath(String value) {
        if (value == null || value.isEmpty() || value.length() > 255
            || value.startsWith("/") || value.endsWith("/") || value.contains("\\")
            || value.contains(":") || value.contains("\0")) {
            return false;
        }
        for (var part : value.split("/", -1)) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) {
                return false;
            }
            for (int index = 0; index < part.length(); index++) {
                var character = part.charAt(index);
                if (character < 0x20 || character == 0x7f) {
                    return false;
                }
            }
        }
        return true;
    }

    private static String guidText(byte[] value) {
        var hex = CryptoUtil.hex(value);
        return hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-"
            + hex.substring(12, 16) + "-" + hex.substring(16, 20) + "-" + hex.substring(20);
    }

    private static String archText(int value) {
        return value == 1 ? "x86" : value == 2 ? "x64" : "";
    }

    private static byte[] string8(String value) {
        var bytes = value.getBytes(StandardCharsets.UTF_8);
        var result = new byte[bytes.length + 1];
        result[0] = (byte) bytes.length;
        System.arraycopy(bytes, 0, result, 1, bytes.length);
        return result;
    }

    private static byte[] concat(byte[]... values) {
        int size = 0;
        for (var value : values) {
            size += value.length;
        }
        var result = new byte[size];
        int offset = 0;
        for (var value : values) {
            System.arraycopy(value, 0, result, offset, value.length);
            offset += value.length;
        }
        return result;
    }

    private static boolean startsWith(byte[] value, byte[] prefix) {
        if (value.length < prefix.length) {
            return false;
        }
        for (int index = 0; index < prefix.length; index++) {
            if (value[index] != prefix[index]) {
                return false;
            }
        }
        return true;
    }

    private static boolean allZero(byte[] value) {
        for (var item : value) {
            if (item != 0) {
                return false;
            }
        }
        return true;
    }

    public record FileEntry(String path, long size, byte[] sha256) {}

    public record Manifest(
        byte[] raw,
        String manifestSha256,
        String appId,
        String releaseId,
        long versionCode,
        String version,
        String arch,
        String rootKeyId,
        String signerKeyId,
        List<FileEntry> files
    ) {}

    private static final class Reader {
        private final byte[] data;
        private int offset;

        Reader(byte[] data) { this(data, 0); }
        Reader(byte[] data, int offset) { this.data = data; this.offset = offset; }

        int offset() { return offset; }
        int remaining() { return data.length - offset; }

        int u8() {
            require(1);
            return data[offset++] & 0xff;
        }

        int u16() {
            require(2);
            var value = ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
            offset += 2;
            return value;
        }

        long u32() {
            require(4);
            long value = 0;
            for (int index = 0; index < 4; index++) {
                value = (value << 8) | (data[offset++] & 0xffL);
            }
            return value;
        }

        long u64() {
            require(8);
            long value = 0;
            for (int index = 0; index < 8; index++) {
                value = (value << 8) | (data[offset++] & 0xffL);
            }
            return value;
        }

        byte[] bytes(int size) {
            require(size);
            var value = java.util.Arrays.copyOfRange(data, offset, offset + size);
            offset += size;
            return value;
        }

        void readBytes(int size) {
            require(size);
            offset += size;
        }

        String string8() {
            return string(u8());
        }

        String string16() {
            return string(u16());
        }

        private String string(int size) {
            var value = bytes(size);
            return new String(value, StandardCharsets.UTF_8);
        }

        private void require(int size) {
            if (offset + size > data.length) {
                throw new SwmException.Integrity(0, "host_manifest_invalid",
                    "RIM2 manifest is truncated", "");
            }
        }
    }
}
