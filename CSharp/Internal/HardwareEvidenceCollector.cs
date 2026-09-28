using System.Management;
using System.Net.NetworkInformation;
using System.Text;
using Microsoft.Win32;

namespace SwmSdk.Internal;

internal static class HardwareEvidenceCollector
{
    private static readonly string[] Placeholders =
    [
        "none", "n/a", "na", "null", "0", "default string",
        "to be filled by o.e.m.", "to be filled by oem", "system serial number",
        "base board serial number", "chassis serial number", "not specified",
        "not available", "unknown", "0000000000", "invalid", "filled by oem"
    ];

    public static HardwareEvidence Collect(string appId)
    {
        var fields = new List<(uint Bit, string Name, string Value)>();
        Add(fields, 0x01, "cpu", ReadCpu());
        Add(fields, 0x02, "motherboard", ReadWmi("Win32_BaseBoard", "SerialNumber"));
        Add(fields, 0x04, "smbios", ReadWmi("Win32_BIOS", "SerialNumber"));
        Add(fields, 0x08, "disk", ReadDiskSerial());
        Add(fields, 0x10, "mac", ReadPhysicalMac());
        Add(fields, 0x20, "machine_guid", ReadMachineGuid());

        if (fields.Count == 0)
        {
            throw new SwmIdentityException("device hardware evidence collection failed");
        }

        var canonical = new StringBuilder("device_hardware_evidence_v2\napp_id:")
            .Append(appId)
            .Append('\n');
        uint mask = 0;
        foreach (var field in fields)
        {
            mask |= field.Bit;
            canonical.Append(field.Name).Append(':').Append(field.Value).Append('\n');
        }

        return new HardwareEvidence
        {
            Version = 2,
            ComponentMask = mask,
            AggregateHash = CryptoUtil.Sha256Hex(Encoding.UTF8.GetBytes(canonical.ToString()))
        };
    }

    private static void Add(List<(uint Bit, string Name, string Value)> fields, uint bit, string name, string value)
    {
        var normalized = Normalize(value);
        if (normalized.Length > 0)
        {
            fields.Add((bit, name, normalized));
        }
    }

    private static string ReadCpu()
    {
        var manufacturer = ReadWmi("Win32_Processor", "Manufacturer");
        var name = ReadWmi("Win32_Processor", "Name");
        if (manufacturer.Length == 0 && name.Length == 0)
        {
            return string.Empty;
        }
        return manufacturer + "_" + name;
    }

    private static string ReadDiskSerial()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT SerialNumber, InterfaceType FROM Win32_DiskDrive");
            foreach (ManagementObject row in searcher.Get())
            {
                var interfaceType = row["InterfaceType"]?.ToString() ?? string.Empty;
                if (interfaceType.Contains("USB", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                var value = Normalize(row["SerialNumber"]?.ToString());
                if (value.Length > 0)
                {
                    return value;
                }
            }
        }
        catch
        {
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
            var description = (adapter.Description + " " + adapter.Name).ToLowerInvariant();
            if (description.Contains("virtual") || description.Contains("vmware") ||
                description.Contains("vethernet") || description.Contains("hyper-v") ||
                description.Contains("virtualbox") || description.Contains("loopback") ||
                description.Contains("vpn") || description.Contains("docker") ||
                description.Contains("tap") || description.Contains("pseudo"))
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
        if (addresses.Count == 0)
        {
            return string.Empty;
        }
        addresses.Sort(CompareBytes);
        return string.Join(":", addresses[0].Select(value => value.ToString("x2")));
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

    private static string ReadWmi(string className, string property)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT {property} FROM {className}");
            foreach (ManagementObject row in searcher.Get())
            {
                var value = Normalize(row[property]?.ToString());
                if (value.Length > 0)
                {
                    return value;
                }
            }
        }
        catch
        {
        }
        return string.Empty;
    }

    private static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }
        var builder = new StringBuilder(value.Length);
        foreach (var character in value)
        {
            if (character <= 0x20 || character == 0x7f)
            {
                continue;
            }
            builder.Append(char.ToLowerInvariant(character));
        }
        var normalized = builder.ToString();
        if (normalized.Length > 128)
        {
            normalized = normalized[..128];
        }
        if (normalized.All(character => character == '0') ||
            Placeholders.Contains(normalized, StringComparer.Ordinal))
        {
            return string.Empty;
        }
        return normalized;
    }
}
