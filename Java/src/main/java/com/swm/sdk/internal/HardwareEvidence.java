package com.swm.sdk.internal;

import com.swm.sdk.SwmException;
import com.swm.sdk.SwmModels;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinReg;
import com.sun.jna.ptr.IntByReference;

import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

public final class HardwareEvidence {
    private static final int IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
    private static final int STORAGE_DEVICE_PROPERTY = 0;
    private static final int PROPERTY_STANDARD_QUERY = 0;
    private static final int RAW_SMBIOS_PROVIDER = 0x52534D42;
    private static final int MAX_FIRMWARE_TABLE = 1024 * 1024;

    private HardwareEvidence() {}

    public static SwmModels.HardwareEvidence collect(String appId) {
        var cpu = readCpu();
        var smbios = readSmbios();
        var disk = readDiskSerial();
        var mac = readPhysicalMac();
        var machineGuid = readRegistry(
            "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid");
        return build(appId, new Fingerprint(cpu, smbios.motherboard, smbios.bios,
            disk, mac), machineGuid);
    }

    static SwmModels.HardwareEvidence build(String appId, Fingerprint fingerprint,
                                            String machineGuid) {
        var canonical = new StringBuilder("device_hardware_evidence_v2\napp_id:")
            .append(appId).append('\n');
        long mask = 0;
        mask |= append(canonical, 0x01, "cpu", fingerprint.cpu);
        mask |= append(canonical, 0x02, "motherboard", fingerprint.motherboard);
        mask |= append(canonical, 0x04, "smbios", fingerprint.bios);
        mask |= append(canonical, 0x08, "disk", fingerprint.disk);
        mask |= append(canonical, 0x10, "mac", fingerprint.mac);
        mask |= append(canonical, 0x20, "machine_guid", machineGuid);
        if (mask == 0) {
            throw new SwmException.Identity("device hardware evidence collection failed", null);
        }
        return new SwmModels.HardwareEvidence(2, mask,
            CryptoUtil.sha256Hex(canonical.toString().getBytes(StandardCharsets.UTF_8)));
    }

    private static long append(StringBuilder canonical, long bit, String name, String raw) {
        if (raw == null) {
            return 0;
        }
        var normalized = new StringBuilder();
        for (int index = 0; index < raw.length(); index++) {
            var character = raw.charAt(index);
            if (character > 0x20 && character != 0x7f) {
                normalized.append(Character.toLowerCase(character));
            }
        }
        if (normalized.length() == 0) {
            return 0;
        }
        canonical.append(name).append(':').append(normalized).append('\n');
        return bit;
    }

    private static String readCpu() {
        var vendor = readRegistry(
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            "VendorIdentifier");
        var name = readRegistry(
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            "ProcessorNameString");
        if (vendor.isBlank() && name.isBlank()) {
            return "";
        }
        return vendor.trim() + "_" + name.trim();
    }

    private static String readRegistry(String root, String name) {
        try {
            return Advapi32Util.registryGetStringValue(WinReg.HKEY_LOCAL_MACHINE, root, name);
        } catch (RuntimeException ignored) {
            return "";
        }
    }

    private static Smbios readSmbios() {
        var required = NativeWindows.kernel32.GetSystemFirmwareTable(
            RAW_SMBIOS_PROVIDER, 0, Pointer.NULL, 0);
        if (required <= 8 || required > MAX_FIRMWARE_TABLE) {
            return new Smbios("", "");
        }
        var memory = new Memory(required);
        var written = NativeWindows.kernel32.GetSystemFirmwareTable(
            RAW_SMBIOS_PROVIDER, 0, memory, required);
        if (written <= 8 || written > required) {
            return new Smbios("", "");
        }
        var tableLength = readInt(memory, 4);
        var data = memory.getByteArray(8, Math.min(tableLength, written - 8));
        var result = new Smbios("", "");
        var offset = 0;
        while (offset + 4 <= data.length) {
            var type = data[offset] & 0xff;
            var length = data[offset + 1] & 0xff;
            if (length < 4 || offset + length > data.length) {
                break;
            }
            var stringsEnd = findStringsEnd(data, offset + length);
            if (stringsEnd < 0) {
                break;
            }
            var stringIndex = length > 7 ? data[offset + 7] & 0xff : 0;
            var value = readSmbiosString(data, offset + length, stringsEnd, stringIndex);
            if (type == 1 && result.bios.isEmpty() && usable(value)) {
                result = new Smbios(value, result.motherboard);
            } else if (type == 2 && result.motherboard.isEmpty() && usable(value)) {
                result = new Smbios(result.bios, value);
            } else if (type == 127) {
                break;
            }
            offset = stringsEnd;
        }
        return result;
    }

    private static int findStringsEnd(byte[] data, int start) {
        for (int index = start; index + 1 < data.length; index++) {
            if (data[index] == 0 && data[index + 1] == 0) {
                return index + 2;
            }
        }
        return -1;
    }

    private static String readSmbiosString(byte[] data, int start, int end, int index) {
        if (index <= 0) {
            return "";
        }
        var cursor = start;
        for (int current = 1; current < index; current++) {
            while (cursor < end && data[cursor] != 0) {
                cursor++;
            }
            if (cursor >= end) {
                return "";
            }
            cursor++;
        }
        var stringEnd = cursor;
        while (stringEnd < end && data[stringEnd] != 0) {
            stringEnd++;
        }
        return new String(data, cursor, stringEnd - cursor, StandardCharsets.UTF_8);
    }

    private static String readDiskSerial() {
        for (int index = 0; index < 8; index++) {
            var path = new WString("\\\\.\\PhysicalDrive" + index);
            var handle = NativeWindows.kernel32.CreateFileW(path, 0, 3,
                Pointer.NULL, 3, 0, Pointer.NULL);
            if (handle == null || Pointer.nativeValue(handle) == -1L) {
                continue;
            }
            try {
                var query = new StoragePropertyQuery();
                query.propertyId = STORAGE_DEVICE_PROPERTY;
                query.queryType = PROPERTY_STANDARD_QUERY;
                var output = new Memory(4096);
                var returned = new IntByReference();
                if (!NativeWindows.kernel32.DeviceIoControl(handle,
                    IOCTL_STORAGE_QUERY_PROPERTY, query, query.size(), output, 4096,
                    returned, Pointer.NULL) || returned.getValue() < 36) {
                    continue;
                }
                var busType = output.getInt(28);
                if (busType == 7 || busType == 8 || busType == 12 || busType == 13) {
                    continue;
                }
                var serialOffset = output.getInt(24);
                if (serialOffset <= 0 || serialOffset >= returned.getValue()) {
                    continue;
                }
                var value = output.getString(serialOffset, "US-ASCII");
                value = value.trim();
                if (usable(value)) {
                    return value;
                }
            } finally {
                NativeWindows.kernel32.CloseHandle(handle);
            }
        }
        return "";
    }

    private static String readPhysicalMac() {
        var values = new ArrayList<byte[]>();
        try {
            var interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                var network = interfaces.nextElement();
                var description = (network.getDisplayName() + " " + network.getName())
                    .toLowerCase(Locale.ROOT);
                if (network.isLoopback() || network.isVirtual() || description.contains("virtual")
                    || description.contains("vmware") || description.contains("vethernet")
                    || description.contains("hyper-v") || description.contains("virtualbox")
                    || description.contains("tap-") || description.contains("loopback")
                    || description.contains("pseudo") || description.contains("bluetooth")
                    || description.contains("vpn") || description.contains("docker")) {
                    continue;
                }
                var address = network.getHardwareAddress();
                if (address != null && address.length == 6) {
                    values.add(address);
                }
            }
        } catch (Exception ignored) {
            return "";
        }
        values.sort(HardwareEvidence::compareBytes);
        if (values.isEmpty()) {
            return "";
        }
        var address = values.get(0);
        var result = new StringBuilder();
        for (int index = 0; index < address.length; index++) {
            if (index > 0) {
                result.append(':');
            }
            result.append(String.format("%02x", address[index] & 0xff));
        }
        return result.toString();
    }

    private static int compareBytes(byte[] left, byte[] right) {
        for (int index = 0; index < Math.min(left.length, right.length); index++) {
            var value = Integer.compare(left[index] & 0xff, right[index] & 0xff);
            if (value != 0) {
                return value;
            }
        }
        return Integer.compare(left.length, right.length);
    }

    private static boolean usable(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        var lower = value.trim().toLowerCase(Locale.ROOT);
        if (lower.chars().allMatch(character -> character == '0' || character == ' ')) {
            return false;
        }
        return !List.of("none", "n/a", "na", "null", "0", "default string",
            "to be filled by o.e.m.", "to be filled by oem", "system serial number",
            "base board serial number", "chassis serial number", "not specified",
            "not available", "unknown", "0000000000", "invalid", "filled by oem")
            .contains(lower);
    }

    private static int readInt(Pointer pointer, int offset) {
        return pointer.getInt(offset);
    }

    private static int readInt(byte[] value, int offset) {
        return (value[offset] & 0xff) | ((value[offset + 1] & 0xff) << 8)
            | ((value[offset + 2] & 0xff) << 16) | ((value[offset + 3] & 0xff) << 24);
    }

    public record Fingerprint(String cpu, String motherboard, String bios, String disk, String mac) {}
    private record Smbios(String bios, String motherboard) {}

    @Structure.FieldOrder({"propertyId", "queryType", "additionalParameters"})
    public static class StoragePropertyQuery extends Structure {
        public int propertyId;
        public int queryType;
        public byte[] additionalParameters = new byte[4];
    }
}
