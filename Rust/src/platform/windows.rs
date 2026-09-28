use crate::crypto::sha256_hex;
use crate::error::{Error, ErrorKind, Result};
use crate::models::HardwareEvidence;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::slice;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, CRYPT_INTEGER_BLOB, CryptProtectData, CryptUnprotectData,
    NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_USAGE_PROPERTY,
    NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey,
    NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty, NCryptSignHash,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::SystemInformation::GetSystemFirmwareTable;
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};

const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;
const STORAGE_DEVICE_PROPERTY: u32 = 0;
const PROPERTY_STANDARD_QUERY: u32 = 0;
const RAW_SMBIOS_PROVIDER: u32 = 0x52534D42;
const MAXIMUM_FIRMWARE_TABLE_BYTES: usize = 1024 * 1024;

pub(crate) fn protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    if plaintext.is_empty() {
        return Err(Error::new(
            ErrorKind::Cryptographic,
            "DPAPI plaintext is empty",
        ));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let optional_entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            null(),
            if entropy.is_empty() {
                null()
            } else {
                &optional_entropy
            },
            null_mut(),
            null(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(Error::new(
            ErrorKind::Cryptographic,
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let result = unsafe { slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        let _ = LocalFree(output.pbData as *mut c_void);
    }
    Ok(result)
}

pub(crate) fn unprotect(ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.is_empty() {
        return Err(Error::new(
            ErrorKind::Cryptographic,
            "DPAPI ciphertext is empty",
        ));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let optional_entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            if entropy.is_empty() {
                null()
            } else {
                &optional_entropy
            },
            null_mut(),
            null(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(Error::new(
            ErrorKind::Cryptographic,
            std::io::Error::last_os_error().to_string(),
        ));
    }
    let result = unsafe { slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        let _ = LocalFree(output.pbData as *mut c_void);
    }
    Ok(result)
}

pub(crate) fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    let source = wide_os(source);
    let destination = wide_os(destination);
    let ok = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(Error::new(
            ErrorKind::Identity,
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

pub(crate) struct IdentityKey {
    handle: usize,
    name: String,
    lock: Mutex<()>,
}

impl IdentityKey {
    pub(crate) fn create(name: &str) -> Result<Self> {
        let provider = open_provider()?;
        let algorithm = wide("ECDSA_P256");
        let key_name = wide(name);
        let mut key = 0usize;
        let status = unsafe {
            NCryptCreatePersistedKey(
                provider,
                &mut key,
                algorithm.as_ptr(),
                key_name.as_ptr(),
                0,
                0,
            )
        };
        if status != 0 {
            unsafe {
                let _ = NCryptFreeObject(provider);
            }
            return Err(nt_error(status, "NCryptCreatePersistedKey"));
        }
        let result = (|| {
            set_property(key, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_SIGNING_FLAG)?;
            set_property(key, NCRYPT_EXPORT_POLICY_PROPERTY, 0)?;
            let status = unsafe { NCryptFinalizeKey(key, 0) };
            if status != 0 {
                return Err(nt_error(status, "NCryptFinalizeKey"));
            }
            Ok(())
        })();
        unsafe {
            let _ = NCryptFreeObject(provider);
        }
        if let Err(error) = result {
            unsafe {
                let _ = NCryptDeleteKey(key, 0);
            }
            return Err(error);
        }
        Ok(Self {
            handle: key,
            name: name.to_string(),
            lock: Mutex::new(()),
        })
    }

    pub(crate) fn open(name: &str) -> Result<Self> {
        let provider = open_provider()?;
        let key_name = wide(name);
        let mut key = 0usize;
        let status = unsafe { NCryptOpenKey(provider, &mut key, key_name.as_ptr(), 0, 0) };
        unsafe {
            let _ = NCryptFreeObject(provider);
        }
        if status != 0 {
            return Err(nt_error(status, "NCryptOpenKey"));
        }
        Ok(Self {
            handle: key,
            name: name.to_string(),
            lock: Mutex::new(()),
        })
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn public_key_sec1(&self) -> Result<Vec<u8>> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Error::new(ErrorKind::Identity, "key lock poisoned"))?;
        let mut size = 0u32;
        let status = unsafe {
            NCryptExportKey(
                self.handle,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                null_mut(),
                null_mut(),
                0,
                &mut size,
                0,
            )
        };
        if status != 0 || size < 8 {
            return Err(nt_error(status, "NCryptExportKey"));
        }
        let mut blob = vec![0u8; size as usize];
        let status = unsafe {
            NCryptExportKey(
                self.handle,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                null_mut(),
                blob.as_mut_ptr(),
                size,
                &mut size,
                0,
            )
        };
        if status != 0 {
            return Err(nt_error(status, "NCryptExportKey"));
        }
        blob.truncate(size as usize);
        if blob.len() < 72 {
            return Err(Error::new(
                ErrorKind::Identity,
                "CNG public key blob is truncated",
            ));
        }
        let mut sec1 = vec![0u8; 65];
        sec1[0] = 4;
        sec1[1..33].copy_from_slice(&blob[8..40]);
        sec1[33..].copy_from_slice(&blob[40..72]);
        Ok(sec1)
    }

    pub(crate) fn sign_digest(&self, digest: &[u8]) -> Result<[u8; 64]> {
        if digest.len() != 32 {
            return Err(Error::new(
                ErrorKind::Cryptographic,
                "CNG digest must be 32 bytes",
            ));
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Error::new(ErrorKind::Identity, "key lock poisoned"))?;
        let mut size = 0u32;
        let status = unsafe {
            NCryptSignHash(
                self.handle,
                null_mut(),
                digest.as_ptr(),
                digest.len() as u32,
                null_mut(),
                0,
                &mut size,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 || size != 64 {
            return Err(nt_error(status, "NCryptSignHash"));
        }
        let mut signature = [0u8; 64];
        let status = unsafe {
            NCryptSignHash(
                self.handle,
                null_mut(),
                digest.as_ptr(),
                digest.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut size,
                NCRYPT_SILENT_FLAG,
            )
        };
        if status != 0 || size != 64 {
            return Err(nt_error(status, "NCryptSignHash"));
        }
        Ok(signature)
    }

    pub(crate) fn delete(&self) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Error::new(ErrorKind::Identity, "key lock poisoned"))?;
        let status = unsafe { NCryptDeleteKey(self.handle, 0) };
        if status != 0 {
            return Err(nt_error(status, "NCryptDeleteKey"));
        }
        Ok(())
    }

    pub(crate) fn close(&self) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| Error::new(ErrorKind::Identity, "key lock poisoned"))?;
        let status = unsafe { NCryptFreeObject(self.handle) };
        if status != 0 {
            return Err(nt_error(status, "NCryptFreeObject"));
        }
        Ok(())
    }
}

fn open_provider() -> Result<usize> {
    let provider_name = wide("Microsoft Software Key Storage Provider");
    let mut provider = 0usize;
    let status = unsafe { NCryptOpenStorageProvider(&mut provider, provider_name.as_ptr(), 0) };
    if status != 0 {
        return Err(nt_error(status, "NCryptOpenStorageProvider"));
    }
    Ok(provider)
}

fn set_property(handle: usize, property: windows_sys::core::PCWSTR, value: u32) -> Result<()> {
    let status = unsafe {
        NCryptSetProperty(
            handle,
            property,
            &value as *const u32 as *const u8,
            std::mem::size_of::<u32>() as u32,
            0,
        )
    };
    if status != 0 {
        return Err(nt_error(status, "NCryptSetProperty"));
    }
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_os(value: &Path) -> Vec<u16> {
    value
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn nt_error(status: i32, operation: &str) -> Error {
    Error::new(
        ErrorKind::Identity,
        format!("{operation} failed with NTSTATUS {status:#010x}"),
    )
}

pub(crate) fn collect_hardware_evidence(app_id: &str) -> Result<HardwareEvidence> {
    let (cpu, motherboard, bios) = cpu_and_smbios();
    let disk = read_disk_serial();
    let mac = read_physical_mac();
    let machine_guid = read_machine_guid();
    build_hardware_evidence(
        app_id,
        &cpu,
        &motherboard,
        &bios,
        &disk,
        &mac,
        &machine_guid,
    )
}

fn build_hardware_evidence(
    app_id: &str,
    cpu: &str,
    motherboard: &str,
    bios: &str,
    disk: &str,
    mac: &str,
    machine_guid: &str,
) -> Result<HardwareEvidence> {
    let fields = [
        (0x01, "cpu", cpu),
        (0x02, "motherboard", motherboard),
        (0x04, "smbios", bios),
        (0x08, "disk", disk),
        (0x10, "mac", mac),
        (0x20, "machine_guid", machine_guid),
    ];
    let mut canonical = format!("device_hardware_evidence_v2\napp_id:{app_id}\n");
    let mut mask = 0u32;
    for (bit, name, value) in fields {
        let normalized = normalize_evidence(value);
        if normalized.is_empty() {
            continue;
        }
        mask |= bit;
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(&normalized);
        canonical.push('\n');
    }
    if mask == 0 {
        return Err(Error::new(
            ErrorKind::Identity,
            "device hardware evidence collection failed",
        ));
    }
    Ok(HardwareEvidence {
        version: 2,
        component_mask: mask,
        aggregate_hash: sha256_hex(canonical.as_bytes()),
    })
}

fn cpu_and_smbios() -> (String, String, String) {
    #[cfg(target_arch = "x86_64")]
    let cpu = cpu_id();
    #[cfg(target_arch = "x86")]
    let cpu = cpu_id_x86();
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    let cpu = String::new();
    let (motherboard, bios) = read_smbios();
    (cpu, motherboard, bios)
}

#[cfg(target_arch = "x86_64")]
fn cpu_id() -> String {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    let leaf = __cpuid(0);
    let vendor = bytes_to_trimmed(&[
        leaf.ebx as u8,
        (leaf.ebx >> 8) as u8,
        (leaf.ebx >> 16) as u8,
        (leaf.ebx >> 24) as u8,
        leaf.edx as u8,
        (leaf.edx >> 8) as u8,
        (leaf.edx >> 16) as u8,
        (leaf.edx >> 24) as u8,
        leaf.ecx as u8,
        (leaf.ecx >> 8) as u8,
        (leaf.ecx >> 16) as u8,
        (leaf.ecx >> 24) as u8,
    ]);
    let maximum = __cpuid(0x8000_0000).eax;
    if maximum < 0x8000_0004 {
        return format!("{vendor}_");
    }
    let mut brand = Vec::with_capacity(48);
    for index in 0..3 {
        let value = __cpuid_count(0x8000_0002 + index, 0);
        for part in [value.eax, value.ebx, value.ecx, value.edx] {
            brand.extend_from_slice(&part.to_le_bytes());
        }
    }
    format!("{vendor}_{}", bytes_to_trimmed(&brand))
}

#[cfg(target_arch = "x86")]
fn cpu_id_x86() -> String {
    use core::arch::x86::__cpuid;
    let leaf = __cpuid(0);
    let vendor = bytes_to_trimmed(&[
        leaf.ebx as u8,
        (leaf.ebx >> 8) as u8,
        (leaf.ebx >> 16) as u8,
        (leaf.ebx >> 24) as u8,
        leaf.edx as u8,
        (leaf.edx >> 8) as u8,
        (leaf.edx >> 16) as u8,
        (leaf.edx >> 24) as u8,
        leaf.ecx as u8,
        (leaf.ecx >> 8) as u8,
        (leaf.ecx >> 16) as u8,
        (leaf.ecx >> 24) as u8,
    ]);
    let maximum = __cpuid(0x8000_0000).eax;
    if maximum < 0x8000_0004 {
        return format!("{vendor}_");
    }
    let mut brand = Vec::with_capacity(48);
    for index in 0..3 {
        let value = __cpuid(0x8000_0002 + index);
        for part in [value.eax, value.ebx, value.ecx, value.edx] {
            brand.extend_from_slice(&part.to_le_bytes());
        }
    }
    format!("{vendor}_{}", bytes_to_trimmed(&brand))
}

fn bytes_to_trimmed(value: &[u8]) -> String {
    let end = value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len());
    trim_ascii(&String::from_utf8_lossy(&value[..end]))
}

fn read_smbios() -> (String, String) {
    let size = unsafe { GetSystemFirmwareTable(RAW_SMBIOS_PROVIDER, 0, null_mut(), 0) };
    if size == 0 || size as usize > MAXIMUM_FIRMWARE_TABLE_BYTES {
        return (String::new(), String::new());
    }
    let mut buffer = vec![0u8; size as usize];
    let written =
        unsafe { GetSystemFirmwareTable(RAW_SMBIOS_PROVIDER, 0, buffer.as_mut_ptr(), size) };
    if written <= 8 || written > size {
        return (String::new(), String::new());
    }
    let table_length = u32::from_le_bytes(buffer[4..8].try_into().unwrap()) as usize;
    let available = written as usize - 8;
    let length = table_length.min(available);
    parse_smbios(&buffer[8..8 + length])
}

fn parse_smbios(data: &[u8]) -> (String, String) {
    let mut motherboard = String::new();
    let mut bios = String::new();
    let mut offset = 0usize;
    while offset + 4 <= data.len() {
        let record_type = data[offset];
        let length = data[offset + 1] as usize;
        if length < 4 || offset + length > data.len() {
            break;
        }
        let strings_area = &data[offset + length..];
        let Some(next) = strings_area.windows(2).position(|window| window == [0, 0]) else {
            break;
        };
        let next = next + 2;
        let string_index = if length > 7 { data[offset + 7] } else { 0 };
        let value = read_smbios_string(&strings_area[..next], string_index);
        match record_type {
            1 if bios.is_empty() => bios = first_usable(&value),
            2 if motherboard.is_empty() => motherboard = first_usable(&value),
            127 => break,
            _ => {}
        }
        let consumed = strings_area.len() - next;
        if consumed == 0 {
            break;
        }
        offset += length + consumed;
    }
    (motherboard, bios)
}

fn read_smbios_string(value: &[u8], index: u8) -> String {
    if index == 0 {
        return String::new();
    }
    let mut offset = 0usize;
    for _ in 1..index {
        let Some(end) = value[offset..].iter().position(|byte| *byte == 0) else {
            return String::new();
        };
        offset += end + 1;
        if offset >= value.len() {
            return String::new();
        }
    }
    let Some(end) = value[offset..].iter().position(|byte| *byte == 0) else {
        return String::new();
    };
    String::from_utf8_lossy(&value[offset..offset + end]).to_string()
}

fn read_disk_serial() -> String {
    for index in 0..8 {
        let path = wide(&format!(r"\\.\PhysicalDrive{index}"));
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            continue;
        }
        let mut input = [0u8; 12];
        input[0..4].copy_from_slice(&STORAGE_DEVICE_PROPERTY.to_le_bytes());
        input[4..8].copy_from_slice(&PROPERTY_STANDARD_QUERY.to_le_bytes());
        let mut output = vec![0u8; 4096];
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                input.as_ptr() as *const c_void,
                input.len() as u32,
                output.as_mut_ptr() as *mut c_void,
                output.len() as u32,
                &mut returned,
                null_mut(),
            )
        };
        unsafe {
            let _ = CloseHandle(handle);
        }
        if ok == 0 || returned < 36 {
            continue;
        }
        let bus_type = u32::from_le_bytes(output[28..32].try_into().unwrap());
        if matches!(bus_type, 7 | 8 | 12 | 13) {
            continue;
        }
        let serial_offset = i32::from_le_bytes(output[24..28].try_into().unwrap());
        if serial_offset <= 0 || serial_offset as u32 >= returned {
            continue;
        }
        let start = serial_offset as usize;
        let end = output[start..returned as usize]
            .iter()
            .position(|byte| *byte == 0)
            .map(|value| start + value)
            .unwrap_or(returned as usize);
        let value = first_usable(&String::from_utf8_lossy(&output[start..end]));
        if !value.is_empty() {
            return value;
        }
    }
    String::new()
}

fn read_physical_mac() -> String {
    let mut size = 15 * 1024u32;
    for _ in 0..3 {
        let mut buffer = vec![0u8; size as usize];
        let first = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let result = unsafe {
            GetAdaptersAddresses(
                0,
                GAA_FLAG_SKIP_UNICAST
                    | GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST
                    | GAA_FLAG_SKIP_DNS_SERVER,
                null_mut(),
                first,
                &mut size,
            )
        };
        if result == 111 {
            continue;
        }
        if result != 0 {
            return String::new();
        }
        let mut addresses = Vec::new();
        let mut current = first;
        while !current.is_null() {
            let adapter = unsafe { &*current };
            if adapter.OperStatus == IfOperStatusUp
                && matches!(adapter.IfType, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211)
            {
                let description = unsafe {
                    if adapter.Description.is_null() {
                        String::new()
                    } else {
                        let mut length = 0usize;
                        while *adapter.Description.add(length) != 0 {
                            length += 1;
                        }
                        String::from_utf16_lossy(slice::from_raw_parts(adapter.Description, length))
                    }
                };
                if !contains_virtual_adapter(&description.to_lowercase())
                    && adapter.PhysicalAddressLength == 6
                {
                    let address = adapter.PhysicalAddress[..6].to_vec();
                    if address != [0u8; 6] && address[0] & 0x02 == 0 {
                        addresses.push(address);
                    }
                }
            }
            current = adapter.Next;
        }
        addresses.sort();
        let Some(address) = addresses.first() else {
            return String::new();
        };
        return address
            .iter()
            .map(|value| format!("{value:02x}"))
            .collect::<Vec<_>>()
            .join(":");
    }
    String::new()
}

fn contains_virtual_adapter(description: &str) -> bool {
    [
        "virtual",
        "vmware",
        "vethernet",
        "hyper-v",
        "virtualbox",
        "tap-",
        "tap adapter",
        "loopback",
        "pseudo",
        "bluetooth",
        "wan miniport",
        "vpn",
        "docker",
        "npcap",
    ]
    .iter()
    .any(|marker| description.contains(marker))
}

fn read_machine_guid() -> String {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            r"SOFTWARE\Microsoft\Cryptography",
            KEY_READ | KEY_WOW64_64KEY,
        )
        .ok()
        .and_then(|key| key.get_value::<String, _>("MachineGuid").ok())
        .unwrap_or_default()
}

fn normalize_evidence(value: &str) -> String {
    value
        .chars()
        .filter(|character| *character > '\u{20}' && *character != '\u{7f}')
        .flat_map(char::to_lowercase)
        .collect()
}

fn first_usable(value: &str) -> String {
    let value = trim_ascii(value);
    if value.is_empty()
        || value
            .chars()
            .all(|character| matches!(character, '0' | ' ' | '\t'))
        || matches!(
            value.to_ascii_lowercase().as_str(),
            "none"
                | "n/a"
                | "na"
                | "null"
                | "0"
                | "default string"
                | "to be filled by o.e.m."
                | "to be filled by oem"
                | "system serial number"
                | "base board serial number"
                | "chassis serial number"
                | "not specified"
                | "not available"
                | "unknown"
                | "0000000000"
                | "invalid"
                | "filled by oem"
        )
    {
        return String::new();
    }
    value.chars().take(128).collect()
}

fn trim_ascii(value: &str) -> String {
    value
        .trim_matches(|character: char| character <= '\u{20}' || character == '\u{7f}')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_round_trip() {
        let plaintext = b"identity state";
        let entropy = b"SwmSdkStateV2\ntest";
        let ciphertext = protect(plaintext, entropy).unwrap();
        let decoded = unprotect(&ciphertext, entropy).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn cng_key_round_trip() {
        let name = format!("SwmSdk.RustTest.{}", uuid::Uuid::new_v4());
        let key = IdentityKey::create(&name).unwrap();
        let public_key = key.public_key_sec1().unwrap();
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 4);
        let digest = sha256_hex(b"rust cng test");
        let signature = key.sign_digest(&hex::decode(digest).unwrap()).unwrap();
        assert_eq!(signature.len(), 64);
        key.delete().unwrap();
    }
}
