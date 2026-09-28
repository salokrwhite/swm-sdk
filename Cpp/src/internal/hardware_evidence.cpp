#include "internal/hardware_evidence.hpp"
#include "internal/crypto.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winioctl.h>
#include <intrin.h>
#include <shlobj.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <vector>

namespace swm::internal {
namespace {

constexpr std::uint32_t raw_smbios_provider = 'RSMB';
constexpr std::size_t max_firmware_table_bytes = 1024U * 1024U;

bool is_placeholder(const std::string& value) {
    static constexpr std::string_view placeholders[] = {
        "none", "n/a", "na", "null", "0", "default string",
        "to be filled by o.e.m.", "to be filled by oem", "system serial number",
        "base board serial number", "chassis serial number", "not specified",
        "not available", "unknown", "0000000000", "invalid", "filled by oem"
    };
    if (value.empty()) {
        return true;
    }
    const auto lowered = lower_ascii(value);
    if (lowered.find_first_not_of("0 \t") == std::string::npos) {
        return true;
    }
    return std::find(std::begin(placeholders), std::end(placeholders), lowered) !=
        std::end(placeholders);
}

void assign_if_usable(std::string& target, std::string value) {
    if (!target.empty()) {
        return;
    }
    value = trim_ascii(std::move(value));
    if (value.size() > 128) {
        value.resize(128);
    }
    if (!is_placeholder(value)) {
        target = std::move(value);
    }
}

struct SmbiosHeader {
    std::uint8_t type;
    std::uint8_t length;
    std::uint16_t handle;
};

std::string read_smbios_string(const std::uint8_t* strings, const std::uint8_t* limit,
    const std::uint8_t index) {
    if (index == 0 || strings == nullptr || strings >= limit) {
        return {};
    }
    auto cursor = strings;
    for (std::uint8_t current = 1; current < index; ++current) {
        while (cursor < limit && *cursor != 0) {
            ++cursor;
        }
        if (cursor >= limit) {
            return {};
        }
        ++cursor;
        if (cursor < limit && *cursor == 0) {
            return {};
        }
    }
    auto end = cursor;
    while (end < limit && *end != 0) {
        ++end;
    }
    if (end == cursor) {
        return {};
    }
    return std::string(reinterpret_cast<const char*>(cursor),
        static_cast<std::size_t>(end - cursor));
}

void parse_smbios(const std::uint8_t* data, const std::size_t size,
    HardwareFingerprint& fingerprint) {
    auto cursor = data;
    const auto limit = data + size;
    while (cursor + sizeof(SmbiosHeader) <= limit) {
        SmbiosHeader header{};
        std::memcpy(&header, cursor, sizeof(header));
        if (header.length < sizeof(SmbiosHeader)) {
            return;
        }
        const auto formatted = cursor;
        const auto strings = cursor + header.length;
        if (strings > limit) {
            return;
        }
        auto scan = strings;
        while (scan + 1 < limit && !(scan[0] == 0 && scan[1] == 0)) {
            ++scan;
        }
        const auto next = scan + 1 < limit ? scan + 2 : limit;
        const auto formatted_byte = [&](const std::size_t offset) -> std::uint8_t {
            return offset < header.length ? formatted[offset] : 0;
        };
        if (header.type == 1) {
            assign_if_usable(fingerprint.bios,
                read_smbios_string(strings, next, formatted_byte(0x07)));
        } else if (header.type == 2) {
            assign_if_usable(fingerprint.motherboard,
                read_smbios_string(strings, next, formatted_byte(0x07)));
        } else if (header.type == 127) {
            return;
        }
        if (next <= cursor) {
            return;
        }
        cursor = next;
    }
}

void collect_smbios(HardwareFingerprint& fingerprint) {
    const UINT required = GetSystemFirmwareTable(raw_smbios_provider, 0, nullptr, 0);
    if (required == 0 || required > max_firmware_table_bytes) {
        return;
    }
    std::vector<std::uint8_t> buffer(required);
    const UINT written = GetSystemFirmwareTable(raw_smbios_provider, 0, buffer.data(), required);
    if (written <= 8 || written > required) {
        return;
    }
    std::uint32_t table_length = 0;
    std::memcpy(&table_length, buffer.data() + 4, sizeof(table_length));
    const auto available = static_cast<std::size_t>(written) - 8;
    const auto length = std::min<std::size_t>(table_length, available);
    if (length > 0) {
        parse_smbios(buffer.data() + 8, length, fingerprint);
    }
}

void collect_cpu(HardwareFingerprint& fingerprint) {
    std::array<int, 4> registers{};
    __cpuid(registers.data(), 0);
    std::string vendor(12, '\0');
    std::memcpy(vendor.data(), &registers[1], 4);
    std::memcpy(vendor.data() + 4, &registers[3], 4);
    std::memcpy(vendor.data() + 8, &registers[2], 4);

    std::string brand;
    __cpuid(registers.data(), 0x80000000);
    if (static_cast<unsigned>(registers[0]) >= 0x80000004U) {
        brand.resize(48);
        for (unsigned leaf = 0; leaf < 3; ++leaf) {
            __cpuidex(registers.data(), static_cast<int>(0x80000002U + leaf), 0);
            std::memcpy(brand.data() + leaf * 16, registers.data(), 16);
        }
        brand.resize(std::strlen(brand.c_str()));
    }
    assign_if_usable(fingerprint.cpu, trim_ascii(vendor) + "_" + trim_ascii(brand));
}

std::string query_physical_drive_serial(const unsigned index) {
    wchar_t path[32]{};
    if (swprintf_s(path, L"\\\\.\\PhysicalDrive%u", index) < 0) {
        return {};
    }
    const HANDLE device = CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
        OPEN_EXISTING, 0, nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        return {};
    }
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    std::vector<std::uint8_t> buffer(4096);
    DWORD returned = 0;
    std::string serial;
    if (DeviceIoControl(device, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
            buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr) &&
        returned >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        STORAGE_DEVICE_DESCRIPTOR descriptor{};
        std::memcpy(&descriptor, buffer.data(), sizeof(descriptor));
        const bool removable = descriptor.BusType == BusTypeUsb ||
            descriptor.BusType == BusType1394 || descriptor.BusType == BusTypeSd ||
            descriptor.BusType == BusTypeMmc;
        const DWORD offset = descriptor.SerialNumberOffset;
        if (!removable && offset != 0 && offset < returned) {
            const auto* text = reinterpret_cast<const char*>(buffer.data()) + offset;
            serial.assign(text, strnlen(text, static_cast<std::size_t>(returned) - offset));
        }
    }
    CloseHandle(device);
    return serial;
}

void collect_disk(HardwareFingerprint& fingerprint) {
    for (unsigned index = 0; index < 8 && fingerprint.disk.empty(); ++index) {
        assign_if_usable(fingerprint.disk, query_physical_drive_serial(index));
    }
}

bool virtual_adapter(const std::wstring& description) {
    static constexpr std::wstring_view markers[] = {
        L"virtual", L"vmware", L"vethernet", L"hyper-v", L"virtualbox",
        L"tap-", L"tap adapter", L"loopback", L"pseudo", L"bluetooth",
        L"wan miniport", L"vpn", L"docker", L"npcap"
    };
    auto lowered = description;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::towlower);
    return std::any_of(std::begin(markers), std::end(markers), [&](const auto marker) {
        return lowered.find(marker) != std::wstring::npos;
    });
}

void collect_mac(HardwareFingerprint& fingerprint) {
    constexpr ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
        GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME;
    ULONG size = 16U * 1024U;
    std::vector<std::uint8_t> buffer;
    ULONG result = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 4 && result == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buffer.assign(size, 0);
        result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
    }
    if (result != NO_ERROR) {
        return;
    }
    std::array<std::uint8_t, 6> best{};
    bool found = false;
    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
         adapter != nullptr; adapter = adapter->Next) {
        if (adapter->PhysicalAddressLength != 6 ||
            (adapter->IfType != IF_TYPE_ETHERNET_CSMACD && adapter->IfType != IF_TYPE_IEEE80211) ||
            adapter->OperStatus != IfOperStatusUp ||
            (adapter->Description != nullptr && virtual_adapter(adapter->Description))) {
            continue;
        }
        std::array<std::uint8_t, 6> mac{};
        std::memcpy(mac.data(), adapter->PhysicalAddress, mac.size());
        if (std::all_of(mac.begin(), mac.end(), [](const auto value) { return value == 0; }) ||
            (mac[0] & 0x02) != 0) {
            continue;
        }
        if (!found || mac < best) {
            best = mac;
            found = true;
        }
    }
    if (!found) {
        return;
    }
    char text[18]{};
    if (sprintf_s(text, "%02x:%02x:%02x:%02x:%02x:%02x",
            best[0], best[1], best[2], best[3], best[4], best[5]) > 0) {
        assign_if_usable(fingerprint.mac, text);
    }
}

std::string read_registry_string(const HKEY root, const wchar_t* subkey,
    const wchar_t* value_name) {
    HKEY key{};
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        return {};
    }
    std::wstring wide(256, L'\0');
    DWORD size = static_cast<DWORD>(wide.size() * sizeof(wchar_t));
    DWORD type = 0;
    const auto status = RegQueryValueExW(key, value_name, nullptr, &type,
        reinterpret_cast<LPBYTE>(wide.data()), &size);
    RegCloseKey(key);
    if (status != ERROR_SUCCESS || type != REG_SZ || size == 0) {
        return {};
    }
    wide.resize(size / sizeof(wchar_t));
    wide.resize(wcsnlen(wide.c_str(), wide.size()));
    return wide_to_utf8(wide);
}

} // namespace

HardwareFingerprint collect_hardware_fingerprint() {
    HardwareFingerprint fingerprint;
    collect_cpu(fingerprint);
    collect_smbios(fingerprint);
    collect_disk(fingerprint);
    collect_mac(fingerprint);
    return fingerprint;
}

std::string read_machine_guid() {
    return read_registry_string(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
}

HardwareEvidence collect_hardware_evidence(const std::string_view app_id) {
    return build_hardware_evidence(app_id, collect_hardware_fingerprint(), read_machine_guid());
}

HardwareEvidence build_hardware_evidence(const std::string_view app_id,
    const HardwareFingerprint& fingerprint, const std::string_view machine_guid) {
    std::string canonical = "device_hardware_evidence_v2\napp_id:" + std::string(app_id) + "\n";
    HardwareEvidence evidence;
    const auto append = [&](const std::uint32_t bit, const char* name, const std::string& raw) {
        std::string value;
        value.reserve(raw.size());
        for (const auto character : raw) {
            const auto byte = static_cast<unsigned char>(character);
            if (byte <= 0x20 || byte == 0x7f) {
                continue;
            }
            value.push_back(static_cast<char>(std::tolower(byte)));
        }
        if (value.empty()) {
            return;
        }
        evidence.component_mask |= bit;
        canonical += name;
        canonical.push_back(':');
        canonical += value;
        canonical.push_back('\n');
    };
    append(0x01U, "cpu", fingerprint.cpu);
    append(0x02U, "motherboard", fingerprint.motherboard);
    append(0x04U, "smbios", fingerprint.bios);
    append(0x08U, "disk", fingerprint.disk);
    append(0x10U, "mac", fingerprint.mac);
    append(0x20U, "machine_guid", std::string(machine_guid));
    if (evidence.component_mask == 0) {
        throw Error(ErrorKind::Identity, 0, {}, "device hardware evidence collection failed");
    }
    evidence.aggregate_hash = sha256_hex(std::span(
        reinterpret_cast<const std::uint8_t*>(canonical.data()), canonical.size()));
    evidence.version = 2;
    return evidence;
}

} // namespace swm::internal
