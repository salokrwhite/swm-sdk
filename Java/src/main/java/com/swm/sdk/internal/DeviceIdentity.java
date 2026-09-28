package com.swm.sdk.internal;

import com.swm.sdk.SwmException;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.WString;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class DeviceIdentity implements AutoCloseable {
    private static final int WAIT_OBJECT_0 = 0;
    private static final int WAIT_ABANDONED = 0x80;
    private static final int BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345;
    private static final int BCRYPT_ECCKEY_BLOB_SIZE = 8;

    private final StateStore store;
    private final String appId;
    private final String installId;
    private final String keyName;
    private final String keyId;
    private final String keyThumbprint;
    private final String publicKeySec1;
    private final String deviceId;
    private Pointer provider;
    private Pointer key;

    private DeviceIdentity(StateStore store, String appId, String installId, String keyName,
                           String keyId, String keyThumbprint, String publicKeySec1,
                           String deviceId, Pointer provider, Pointer key) {
        this.store = store;
        this.appId = appId;
        this.installId = installId;
        this.keyName = keyName;
        this.keyId = keyId;
        this.keyThumbprint = keyThumbprint;
        this.publicKeySec1 = publicKeySec1;
        this.deviceId = deviceId;
        this.provider = provider;
        this.key = key;
    }

    public static DeviceIdentity loadOrCreate(String appId, StateStore store) {
        var lockName = new WString("Local\\SwmSdkIdentity-" + CryptoUtil.hex(
            CryptoUtil.sha256(appId.getBytes(StandardCharsets.UTF_8))).substring(0, 16));
        var mutex = NativeWindows.kernel32.CreateMutexW(Pointer.NULL, false, lockName);
        if (mutex == null || Pointer.nativeValue(mutex) == 0) {
            throw new SwmException.Identity("cannot create identity mutex", null);
        }
        try {
            var wait = NativeWindows.kernel32.WaitForSingleObject(mutex, 30_000);
            if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
                throw new SwmException.Identity("identity mutex timeout", null);
            }
            try {
                var metadata = readMetadata(store);
                if (metadata != null) {
                    try {
                        return open(appId, store, metadata.installId, metadata.keyName);
                    } catch (RuntimeException ignored) {
                        store.erase("identity.bin");
                    }
                }
                return create(appId, store, false);
            } finally {
                NativeWindows.kernel32.ReleaseMutex(mutex);
            }
        } finally {
            NativeWindows.kernel32.CloseHandle(mutex);
        }
    }

    public static DeviceIdentity createPending(String appId, StateStore store) {
        return create(appId, store, true);
    }

    private static DeviceIdentity create(String appId, StateStore store, boolean rejectExisting) {
        var installId = CryptoUtil.hex(CryptoUtil.randomBytes(16));
        var keyName = buildKeyName(appId, installId);
        var providerRef = new PointerByReference();
        NativeWindows.checkNtStatus(NativeWindows.nCrypt.NCryptOpenStorageProvider(
            providerRef, new WString(NativeWindows.MS_KEY_STORAGE_PROVIDER), 0),
            "NCryptOpenStorageProvider");
        var provider = providerRef.getValue();
        try {
            var keyRef = new PointerByReference();
            if (rejectExisting && NativeWindows.nCrypt.NCryptOpenKey(provider, keyRef,
                    new WString(keyName), 0, NativeWindows.NCRYPT_SILENT_FLAG) >= 0) {
                NativeWindows.nCrypt.NCryptFreeObject(keyRef.getValue());
                return create(appId, store, true);
            }
            NativeWindows.checkNtStatus(NativeWindows.nCrypt.NCryptCreatePersistedKey(
                    provider, keyRef, new WString(NativeWindows.ECDSA_P256),
                    new WString(keyName), 0, NativeWindows.NCRYPT_SILENT_FLAG),
                "NCryptCreatePersistedKey");
            var key = keyRef.getValue();
            try {
                var usage = new IntByReference(NativeWindows.NCRYPT_ALLOW_SIGNING_FLAG);
                NativeWindows.checkNtStatus(NativeWindows.nCrypt.NCryptSetProperty(key,
                    new WString(NativeWindows.KEY_USAGE_PROPERTY), usage.getPointer(),
                    Integer.BYTES, 0), "NCryptSetProperty(key usage)");
                var exportPolicy = new IntByReference(0);
                NativeWindows.checkNtStatus(NativeWindows.nCrypt.NCryptSetProperty(key,
                    new WString(NativeWindows.EXPORT_POLICY_PROPERTY), exportPolicy.getPointer(),
                    Integer.BYTES, 0), "NCryptSetProperty(export policy)");
                NativeWindows.checkNtStatus(NativeWindows.nCrypt.NCryptFinalizeKey(
                    key, NativeWindows.NCRYPT_SILENT_FLAG), "NCryptFinalizeKey");
                var identity = fromKey(appId, store, installId, keyName, provider, key);
                provider = null;
                key = null;
                if (!rejectExisting) {
                    identity.writeMetadata();
                }
                return identity;
            } finally {
                if (key != null) {
                    NativeWindows.nCrypt.NCryptFreeObject(key);
                }
            }
        } finally {
            if (provider != null) {
                NativeWindows.nCrypt.NCryptFreeObject(provider);
            }
        }
    }

    private static DeviceIdentity open(String appId, StateStore store, String installId, String keyName) {
        var providerRef = new PointerByReference();
        NativeWindows.checkNtStatus(NativeWindows.nCrypt.NCryptOpenStorageProvider(
            providerRef, new WString(NativeWindows.MS_KEY_STORAGE_PROVIDER), 0),
            "NCryptOpenStorageProvider");
        var provider = providerRef.getValue();
        var keyRef = new PointerByReference();
        try {
            NativeWindows.checkNtStatus(NativeWindows.nCrypt.NCryptOpenKey(provider, keyRef,
                new WString(keyName), 0, NativeWindows.NCRYPT_SILENT_FLAG), "NCryptOpenKey");
            return fromKey(appId, store, installId, keyName, provider, keyRef.getValue());
        } catch (RuntimeException exception) {
            NativeWindows.nCrypt.NCryptFreeObject(provider);
            throw exception;
        }
    }

    private static DeviceIdentity fromKey(String appId, StateStore store, String installId,
                                          String keyName, Pointer provider, Pointer key) {
        var output = new Memory(72);
        var result = new IntByReference();
        NativeWindows.checkNtStatus(NativeWindows.nCrypt.NCryptExportKey(key, Pointer.NULL,
            new WString(NativeWindows.ECC_PUBLIC_BLOB), Pointer.NULL, output, 72, result, 0),
            "NCryptExportKey");
        var blob = output.getByteArray(0, result.getValue());
        if (blob.length != 72 || readInt(blob, 0) != BCRYPT_ECDSA_PUBLIC_P256_MAGIC
            || readInt(blob, 4) != 32) {
            throw new SwmException.Identity("device key is not P-256", null);
        }
        var sec1 = new byte[65];
        sec1[0] = 4;
        System.arraycopy(blob, BCRYPT_ECCKEY_BLOB_SIZE, sec1, 1, 64);
        var thumbprint = CryptoUtil.base64Url(CryptoUtil.sha256(sec1));
        var keyId = "swm-device-" + thumbprint.substring(0, 22);
        var deviceMaterial = ("device_credential_v2\napp_id:" + appId
            + "\ninstall_id:" + installId + "\nkey_thumbprint:" + thumbprint)
            .getBytes(StandardCharsets.UTF_8);
        var deviceId = CryptoUtil.sha256Hex(deviceMaterial);
        return new DeviceIdentity(store, appId, installId, keyName, keyId, thumbprint,
            CryptoUtil.base64Url(sec1), deviceId, provider, key);
    }

    public byte[] signSha256(byte[] digest) {
        if (digest.length != 32 || key == null) {
            throw new SwmException.Identity("device signing key is unavailable", null);
        }
        var input = new Memory(32);
        input.write(0, digest, 0, digest.length);
        var output = new Memory(64);
        var result = new IntByReference();
        NativeWindows.checkNtStatus(NativeWindows.nCrypt.NCryptSignHash(key, Pointer.NULL,
            input, 32, output, 64, result, NativeWindows.NCRYPT_SILENT_FLAG),
            "NCryptSignHash");
        if (result.getValue() != 64) {
            throw new SwmException.Identity("device signature length is invalid", null);
        }
        return output.getByteArray(0, 64);
    }

    public void commitPending() {
        writeMetadata();
    }

    public void deletePending() {
        if (key != null) {
            NativeWindows.nCrypt.NCryptDeleteKey(key, 0);
            key = null;
        }
        close();
    }

    private void writeMetadata() {
        var plaintext = ("v2\n" + installId + "\n" + keyName + "\n")
            .getBytes(StandardCharsets.UTF_8);
        store.writeProtected("identity.bin", plaintext);
    }

    private static Metadata readMetadata(StateStore store) {
        var value = store.readProtected("identity.bin");
        if (value.isEmpty()) {
            return null;
        }
        var text = new String(value.get(), StandardCharsets.UTF_8);
        var lines = text.split("\n", -1);
        if (lines.length < 3 || !"v2".equals(lines[0]) || lines[1].length() != 32
            || lines[2].isBlank()) {
            return null;
        }
        return new Metadata(lines[1], lines[2]);
    }

    private static String buildKeyName(String appId, String installId) {
        var hash = CryptoUtil.hex(CryptoUtil.sha256(appId.getBytes(StandardCharsets.UTF_8)));
        return "SwmSdk." + hash.substring(0, 12) + "." + installId;
    }

    private static int readInt(byte[] value, int offset) {
        return (value[offset] & 0xff) | ((value[offset + 1] & 0xff) << 8)
            | ((value[offset + 2] & 0xff) << 16) | ((value[offset + 3] & 0xff) << 24);
    }

    @Override
    public void close() {
        if (key != null) {
            NativeWindows.nCrypt.NCryptFreeObject(key);
            key = null;
        }
        if (provider != null) {
            NativeWindows.nCrypt.NCryptFreeObject(provider);
            provider = null;
        }
    }

    public String installId() { return installId; }
    public String keyName() { return keyName; }
    public String keyId() { return keyId; }
    public String keyThumbprint() { return keyThumbprint; }
    public String publicKeySec1() { return publicKeySec1; }
    public String deviceId() { return deviceId; }

    private record Metadata(String installId, String keyName) {}
}
