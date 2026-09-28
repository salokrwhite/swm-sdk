package com.swm.sdk.internal;

import com.swm.sdk.SwmException;
import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

final class NativeWindows {
    static final int CRYPTPROTECT_UI_FORBIDDEN = 0x1;
    static final int NCRYPT_SILENT_FLAG = 0x40;
    static final int NCRYPT_ALLOW_SIGNING_FLAG = 0x2;
    static final String MS_KEY_STORAGE_PROVIDER = "Microsoft Software Key Storage Provider";
    static final String ECDSA_P256 = "ECDSA_P256";
    static final String ECC_PUBLIC_BLOB = "ECCPUBLICBLOB";
    static final String KEY_USAGE_PROPERTY = "Key Usage";
    static final String EXPORT_POLICY_PROPERTY = "Export Policy";

    static final Crypt32 crypt32 = Native.load("crypt32", Crypt32.class);
    static final Shell32 shell32 = Native.load("shell32", Shell32.class);
    static final Kernel32Ex kernel32 = Native.load("kernel32", Kernel32Ex.class);
    static final NCrypt nCrypt = Native.load("ncrypt", NCrypt.class);

    private NativeWindows() {}

    static PathInfo localAppData() {
        var buffer = new char[260];
        var result = shell32.SHGetFolderPathW(Pointer.NULL, 0x001c | 0x8000,
            Pointer.NULL, 0, buffer);
        if (result != 0) {
            throw new SwmException.Identity("cannot resolve LocalAppData", null);
        }
        var length = 0;
        while (length < buffer.length && buffer[length] != 0) {
            length++;
        }
        return new PathInfo(new String(Arrays.copyOf(buffer, length)));
    }

    static byte[] protect(byte[] plaintext, byte[] entropy) {
        try {
            var inputMemory = MemoryUtil.copy(plaintext);
            var entropyMemory = MemoryUtil.copy(entropy);
            var input = new DataBlob(inputMemory, plaintext.length);
            var entropyBlob = new DataBlob(entropyMemory, entropy.length);
            var output = new DataBlob();
            if (!crypt32.CryptProtectData(input, new WString("SwmSdk"), entropyBlob,
                    Pointer.NULL, Pointer.NULL, CRYPTPROTECT_UI_FORBIDDEN, output)) {
                throw new SwmException.Identity("DPAPI protection failed", null);
            }
            var result = output.pbData.getByteArray(0, output.cbData);
            kernel32.LocalFree(output.pbData);
            return result;
        } catch (RuntimeException exception) {
            if (exception instanceof SwmException) {
                throw exception;
            }
            throw new SwmException.Identity("DPAPI protection failed", exception);
        }
    }

    static byte[] unprotect(byte[] ciphertext, byte[] entropy) {
        try {
            var inputMemory = MemoryUtil.copy(ciphertext);
            var entropyMemory = MemoryUtil.copy(entropy);
            var input = new DataBlob(inputMemory, ciphertext.length);
            var entropyBlob = new DataBlob(entropyMemory, entropy.length);
            var output = new DataBlob();
            if (!crypt32.CryptUnprotectData(input, null, entropyBlob,
                    Pointer.NULL, Pointer.NULL, CRYPTPROTECT_UI_FORBIDDEN, output)) {
                throw new SwmException.Identity("DPAPI unprotect failed", null);
            }
            var result = output.pbData.getByteArray(0, output.cbData);
            kernel32.LocalFree(output.pbData);
            return result;
        } catch (RuntimeException exception) {
            if (exception instanceof SwmException) {
                throw exception;
            }
            throw new SwmException.Identity("DPAPI unprotect failed", exception);
        }
    }

    static long checkNtStatus(int status, String operation) {
        if (status < 0) {
            throw new SwmException.Identity(operation + " failed: 0x"
                + Integer.toUnsignedString(status, 16), null);
        }
        return Integer.toUnsignedLong(status);
    }

    static final class PathInfo {
        final String value;
        PathInfo(String value) { this.value = value; }
    }

    static final class MemoryUtil {
        static Memory copy(byte[] bytes) {
            if (bytes == null || bytes.length == 0) {
                return new Memory(1);
            }
            var memory = new Memory(bytes.length);
            memory.write(0, bytes, 0, bytes.length);
            return memory;
        }
        private MemoryUtil() {}
    }

    @Structure.FieldOrder({"cbData", "pbData"})
    public static class DataBlob extends Structure {
        public int cbData;
        public Pointer pbData;

        public DataBlob() {}
        public DataBlob(Pointer data, int length) {
            this.pbData = data;
            this.cbData = length;
        }
    }

    public interface Crypt32 extends Library {
        boolean CryptProtectData(
            DataBlob dataIn,
            WString description,
            DataBlob optionalEntropy,
            Pointer reserved,
            Pointer prompt,
            int flags,
            DataBlob dataOut);

        boolean CryptUnprotectData(
            DataBlob dataIn,
            Pointer description,
            DataBlob optionalEntropy,
            Pointer reserved,
            Pointer prompt,
            int flags,
            DataBlob dataOut);
    }

    public interface Shell32 extends Library {
        int SHGetFolderPathW(Pointer hwnd, int csidl, Pointer token, int flags, char[] path);
    }

    public interface Kernel32Ex extends Library {
        Pointer LocalFree(Pointer value);
        Pointer CreateMutexW(Pointer attributes, boolean initialOwner, WString name);
        int WaitForSingleObject(Pointer handle, int milliseconds);
        boolean ReleaseMutex(Pointer handle);
        boolean CloseHandle(Pointer handle);
        Pointer CreateFileW(WString fileName, int desiredAccess, int shareMode,
            Pointer security, int creation, int flags, Pointer template);
        boolean DeviceIoControl(Pointer device, int controlCode, Structure input,
            int inputSize, Pointer output, int outputSize, IntByReference returned,
            Pointer overlapped);
        int GetSystemFirmwareTable(int provider, int tableId, Pointer buffer, int size);
        int GetLastError();
    }

    public interface NCrypt extends Library {
        int NCryptOpenStorageProvider(PointerByReference provider, WString name, int flags);
        int NCryptOpenKey(Pointer provider, PointerByReference key, WString name,
            int legacySpec, int flags);
        int NCryptCreatePersistedKey(Pointer provider, PointerByReference key, WString algorithm,
            WString keyName, int legacySpec, int flags);
        int NCryptSetProperty(Pointer object, WString property, Pointer input, int inputSize,
            int flags);
        int NCryptFinalizeKey(Pointer key, int flags);
        int NCryptExportKey(Pointer key, Pointer exportKey, WString blobType, Pointer parameter,
            Pointer output, int outputSize, IntByReference result, int flags);
        int NCryptSignHash(Pointer key, Pointer padding, Pointer hash, int hashSize,
            Pointer signature, int signatureSize, IntByReference result, int flags);
        int NCryptDeleteKey(Pointer key, int flags);
        int NCryptFreeObject(Pointer object);
    }
}
