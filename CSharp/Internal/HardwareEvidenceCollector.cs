using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;
using System.Text;
using Microsoft.Win32;

namespace SwmSdk.Internal;

internal sealed record HardwareFingerprint(
    string Cpu,
    string Motherboard,
    string Bios,
    string Disk,
    string Mac);

internal static class HardwareEvidenceCollector
{
    private const uint RawSmbiosProvider = 0x52534D42;
    private const int MaximumFirmwareTableBytes = 1024 * 1024;
    private const uint IoctlStorageQueryProperty = 0x002D1400;
    private const int StorageDeviceProperty = 0;
    private const int PropertyStandardQuery = 0;

    private static readonly string[] Placeholders =
    [
        "none", "n/a", "na", "null", "0", "default string",
        "to be filled by o.e.m.", "to be filled by oem", "system serial number",
        "base board serial number", "chassis serial number", "not specified",
        "not available", "unknown", "0000000000", "invalid", "filled by oem"
    ];

    public static HardwareEvidence Collect(string appId)
    {
        return BuildEvidence(appId, CollectFingerprint(), ReadMachineGuid());
    }

    internal static HardwareEvidence BuildEvidence(
        string appId,
        HardwareFingerprint fingerprint,
        string machineGuid)
    {
        var values = new (uint Bit, string Name, string Value)[]
        {
            (0x01, "cpu", fingerprint.Cpu),
            (0x02, "motherboard", fingerprint.Motherboard),
            (0x04, "smbios", fingerprint.Bios),
            (0x08, "disk", fingerprint.Disk),
            (0x10, "mac", fingerprint.Mac),
            (0x20, "machine_guid", machineGuid)
        };
        var canonical = new StringBuilder("device_hardware_evidence_v2\napp_id:")
            .Append(appId)
            .Append('\n');
        uint mask = 0;
        foreach (var field in values)
        {
            var normalized = NormalizeEvidenceValue(field.Value);
            if (normalized.Length == 0)
            {
                continue;
            }
            mask |= field.Bit;
            canonical.Append(field.Name).Append(':').Append(normalized).Append('\n');
        }
        if (mask == 0)
        {
            throw new SwmIdentityException("device hardware evidence collection failed");
        }
        return new HardwareEvidence
        {
            Version = 2,
            ComponentMask = mask,
            AggregateHash = CryptoUtil.Sha256Hex(Encoding.UTF8.GetBytes(canonical.ToString()))
        };
    }

    private static HardwareFingerprint CollectFingerprint()
    {
        var fingerprint = new HardwareFingerprint(
            ReadCpu(),
            string.Empty,
            string.Empty,
            ReadDiskSerial(),
            ReadPhysicalMac());
        return ReadSmbios(fingerprint);
    }

    private static string ReadCpu()
    {
        if (!X86Base.IsSupported)
        {
            return string.Empty;
        }
        var leaf0 = X86Base.CpuId(0, 0);
        var vendor = Encoding.ASCII.GetString(
        [
            (byte)leaf0.Ebx,
            (byte)(leaf0.Ebx >> 8),
            (byte)(leaf0.Ebx >> 16),
            (byte)(leaf0.Ebx >> 24),
            (byte)leaf0.Edx,
            (byte)(leaf0.Edx >> 8),
            (byte)(leaf0.Edx >> 16),
            (byte)(leaf0.Edx >> 24),
            (byte)leaf0.Ecx,
            (byte)(leaf0.Ecx >> 8),
            (byte)(leaf0.Ecx >> 16),
            (byte)(leaf0.Ecx >> 24)
        ]);
        var maximum = (uint)X86Base.CpuId(unchecked((int)0x80000000), 0).Eax;
        if (maximum < 0x80000004)
        {
            return TrimAscii(vendor) + "_";
        }
        var brand = new byte[48];
        for (var index = 0; index < 3; index++)
        {
            var leaf = X86Base.CpuId(unchecked((int)(0x80000002 + index)), 0);
            BitConverter.GetBytes(leaf.Eax).CopyTo(brand, index * 16);
            BitConverter.GetBytes(leaf.Ebx).CopyTo(brand, index * 16 + 4);
            BitConverter.GetBytes(leaf.Ecx).CopyTo(brand, index * 16 + 8);
            BitConverter.GetBytes(leaf.Edx).CopyTo(brand, index * 16 + 12);
        }
        var terminator = Array.IndexOf(brand, (byte)0);
        if (terminator >= 0)
        {
            Array.Resize(ref brand, terminator);
        }
        return TrimAscii(vendor) + "_" + TrimAscii(Encoding.ASCII.GetString(brand));
    }

    private static HardwareFingerprint ReadSmbios(HardwareFingerprint fingerprint)
    {
        try
        {
            var required = GetSystemFirmwareTable(RawSmbiosProvider, 0, null, 0);
            if (required == 0 || required > MaximumFirmwareTableBytes)
            {
                return fingerprint;
            }
            var buffer = new byte[required];
            var written = GetSystemFirmwareTable(RawSmbiosProvider, 0, buffer, required);
            if (written <= 8 || written > required)
            {
                return fingerprint;
            }
            var tableLength = BitConverter.ToUInt32(buffer, 4);
            var available = written - 8;
            var length = (int)Math.Min(tableLength, available);
            return ParseSmbiosTable(buffer.AsSpan(8, length), fingerprint);
        }
        catch
        {
            return fingerprint;
        }
    }

    private static HardwareFingerprint ParseSmbiosTable(
        ReadOnlySpan<byte> data,
        HardwareFingerprint fingerprint)
    {
        var offset = 0;
        while (offset + 4 <= data.Length)
        {
            var type = data[offset];
            var length = data[offset + 1];
            if (length < 4 || offset + length > data.Length)
            {
                return fingerprint;
            }
            var strings = data[(offset + length)..];
            var next = FindSmbiosEnd(strings);
            if (next < 0)
            {
                return fingerprint;
            }
            var stringIndex = length > 7 ? data[offset + 7] : (byte)0;
            var value = ReadSmbiosString(strings[..next], stringIndex);
            if (type == 1)
            {
                fingerprint = fingerprint with
                {
                    Bios = FirstUsable(fingerprint.Bios, value)
                };
            }
            else if (type == 2)
            {
                fingerprint = fingerprint with
                {
                    Motherboard = FirstUsable(fingerprint.Motherboard, value)
                };
            }
            else if (type == 127)
            {
                break;
            }
            var consumed = strings.Length - next;
            if (consumed <= 0)
            {
                return fingerprint;
            }
            offset += length + consumed;
        }
        return fingerprint;
    }

    private static int FindSmbiosEnd(ReadOnlySpan<byte> strings)
    {
        for (var index = 0; index + 1 < strings.Length; index++)
        {
            if (strings[index] == 0 && strings[index + 1] == 0)
            {
                return index + 2;
            }
        }
        return -1;
    }

    private static string ReadSmbiosString(ReadOnlySpan<byte> strings, byte index)
    {
        if (index == 0)
        {
            return string.Empty;
        }
        var offset = 0;
        for (var current = 1; current < index; current++)
        {
            var end = strings[offset..].IndexOf((byte)0);
            if (end < 0)
            {
                return string.Empty;
            }
            offset += end + 1;
            if (offset >= strings.Length)
            {
                return string.Empty;
            }
        }
        var stringEnd = strings[offset..].IndexOf((byte)0);
        if (stringEnd <= 0)
        {
            return string.Empty;
        }
        return Encoding.UTF8.GetString(strings.Slice(offset, stringEnd));
    }

    private static string ReadDiskSerial()
    {
        for (uint index = 0; index < 8; index++)
        {
            var path = $@"\\.\PhysicalDrive{index}";
            var handle = CreateFileW(path, 0, FileShare.ReadWrite, IntPtr.Zero,
                FileMode.Open, 0, IntPtr.Zero);
            if (handle == new IntPtr(-1))
            {
                continue;
            }
            try
            {
                var query = new byte[12];
                BitConverter.GetBytes(StorageDeviceProperty).CopyTo(query, 0);
                BitConverter.GetBytes(PropertyStandardQuery).CopyTo(query, 4);
                var buffer = new byte[4096];
                if (!DeviceIoControl(handle, IoctlStorageQueryProperty, query, query.Length,
                        buffer, buffer.Length, out var returned, IntPtr.Zero) ||
                    returned < 36)
                {
                    continue;
                }
                var busType = BitConverter.ToUInt32(buffer, 28);
                if (busType is 7 or 8 or 12 or 13)
                {
                    continue;
                }
                var serialOffset = BitConverter.ToInt32(buffer, 24);
                if (serialOffset <= 0 || serialOffset >= returned)
                {
                    continue;
                }
                var end = Array.IndexOf(buffer, (byte)0, serialOffset, returned - serialOffset);
                if (end < 0)
                {
                    end = returned;
                }
                var value = FirstUsable(
                    string.Empty,
                    Encoding.ASCII.GetString(buffer, serialOffset, end - serialOffset));
                if (value.Length > 0)
                {
                    return value;
                }
            }
            finally
            {
                CloseHandle(handle);
            }
        }
        return string.Empty;
    }

    private static string ReadPhysicalMac()
    {
        var addresses = new List<byte[]>();
        foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (adapter.OperationalStatus != OperationalStatus.Up ||
                adapter.NetworkInterfaceType is not (NetworkInterfaceType.Ethernet or NetworkInterfaceType.Wireless80211))
            {
                continue;
            }
            var description = adapter.Description.ToLowerInvariant();
            if (description.Contains("virtual") || description.Contains("vmware") ||
                description.Contains("vethernet") || description.Contains("hyper-v") ||
                description.Contains("virtualbox") || description.Contains("tap-") ||
                description.Contains("tap adapter") || description.Contains("loopback") ||
                description.Contains("pseudo") || description.Contains("bluetooth") ||
                description.Contains("wan miniport") || description.Contains("vpn") ||
                description.Contains("docker") || description.Contains("npcap"))
            {
                continue;
            }
            var bytes = adapter.GetPhysicalAddress().GetAddressBytes();
            if (bytes.Length != 6 || bytes.All(value => value == 0) || (bytes[0] & 0x02) != 0)
            {
                continue;
            }
            addresses.Add(bytes);
        }
        addresses.Sort(CompareBytes);
        return addresses.Count == 0
            ? string.Empty
            : string.Join(":", addresses[0].Select(value => value.ToString("x2")));
    }

    private static string ReadMachineGuid()
    {
        try
        {
            using var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            return key?.GetValue("MachineGuid")?.ToString() ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string FirstUsable(string existing, string candidate)
    {
        if (!string.IsNullOrWhiteSpace(existing))
        {
            return existing;
        }
        var value = TrimAscii(candidate);
        if (value.Length > 128)
        {
            value = value[..128];
        }
        return IsPlaceholder(value) ? string.Empty : value;
    }

    private static string TrimAscii(string value)
    {
        var begin = 0;
        while (begin < value.Length && (value[begin] <= 0x20 || value[begin] == 0x7f))
        {
            begin++;
        }
        var end = value.Length;
        while (end > begin && (value[end - 1] <= 0x20 || value[end - 1] == 0x7f))
        {
            end--;
        }
        return value[begin..end];
    }

    private static bool IsPlaceholder(string value)
    {
        if (value.Length == 0)
        {
            return true;
        }
        var lowered = value.ToLowerInvariant();
        if (lowered.All(character => character is '0' or ' ' or '\t'))
        {
            return true;
        }
        return Placeholders.Contains(lowered, StringComparer.Ordinal);
    }

    private static string NormalizeEvidenceValue(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var character in value)
        {
            if (character <= 0x20 || character == 0x7f)
            {
                continue;
            }
            builder.Append(char.ToLowerInvariant(character));
        }
        return builder.ToString();
    }

    private static int CompareBytes(byte[] left, byte[] right)
    {
        for (var index = 0; index < Math.Min(left.Length, right.Length); index++)
        {
            var comparison = left[index].CompareTo(right[index]);
            if (comparison != 0)
            {
                return comparison;
            }
        }
        return left.Length.CompareTo(right.Length);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetSystemFirmwareTable(
        uint firmwareTableProviderSignature,
        uint firmwareTableId,
        byte[]? firmwareTableBuffer,
        uint bufferSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(
        string fileName,
        uint desiredAccess,
        FileShare shareMode,
        IntPtr securityAttributes,
        FileMode creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        IntPtr device,
        uint ioControlCode,
        byte[] inputBuffer,
        int inputSize,
        byte[] outputBuffer,
        int outputSize,
        out int bytesReturned,
        IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
