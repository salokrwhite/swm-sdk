from __future__ import annotations

import ctypes
import platform as host_platform
import struct
import winreg
from ctypes import wintypes

import cpuinfo  # type: ignore[import-untyped]

from ..crypto import sha256_hex
from ..errors import IdentityError
from ..models import HardwareEvidence


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


_crypt32 = ctypes.WinDLL("crypt32.dll")
_kernel32 = ctypes.WinDLL("kernel32.dll")
_crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(_DataBlob),
    wintypes.LPCWSTR,
    ctypes.POINTER(_DataBlob),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(_DataBlob),
]
_crypt32.CryptProtectData.restype = wintypes.BOOL
_crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(_DataBlob),
    ctypes.POINTER(wintypes.LPWSTR),
    ctypes.POINTER(_DataBlob),
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(_DataBlob),
]
_crypt32.CryptUnprotectData.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
_kernel32.LocalFree.restype = wintypes.HLOCAL


def supported() -> bool:
    return (
        host_platform.machine().lower() in {"amd64", "x86_64", "x86", "i386"}
        and struct.calcsize("P") in {4, 8}
    )


def protect(plaintext: bytes, entropy: bytes) -> bytes:
    input_buffer = (ctypes.c_ubyte * len(plaintext)).from_buffer_copy(plaintext)
    entropy_buffer = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy) if entropy else None
    input_blob = _DataBlob(len(plaintext), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    entropy_blob = (
        _DataBlob(len(entropy), ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        if entropy_buffer is not None
        else None
    )
    output_blob = _DataBlob()
    if not _crypt32.CryptProtectData(
        ctypes.byref(input_blob),
        None,
        ctypes.byref(entropy_blob) if entropy_blob is not None else None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        _kernel32.LocalFree(ctypes.cast(output_blob.pbData, wintypes.HLOCAL))


def unprotect(ciphertext: bytes, entropy: bytes) -> bytes:
    input_buffer = (ctypes.c_ubyte * len(ciphertext)).from_buffer_copy(ciphertext)
    entropy_buffer = (ctypes.c_ubyte * len(entropy)).from_buffer_copy(entropy) if entropy else None
    input_blob = _DataBlob(len(ciphertext), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_ubyte)))
    entropy_blob = (
        _DataBlob(len(entropy), ctypes.cast(entropy_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        if entropy_buffer is not None
        else None
    )
    output_blob = _DataBlob()
    if not _crypt32.CryptUnprotectData(
        ctypes.byref(input_blob),
        None,
        ctypes.byref(entropy_blob) if entropy_blob is not None else None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        _kernel32.LocalFree(ctypes.cast(output_blob.pbData, wintypes.HLOCAL))


_ncrypt = ctypes.WinDLL("ncrypt.dll")
_ncrypt.NCryptOpenStorageProvider.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),
    wintypes.LPCWSTR,
    wintypes.DWORD,
]
_ncrypt.NCryptOpenStorageProvider.restype = ctypes.c_long
_ncrypt.NCryptCreatePersistedKey.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
]
_ncrypt.NCryptCreatePersistedKey.restype = ctypes.c_long
_ncrypt.NCryptOpenKey.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
]
_ncrypt.NCryptOpenKey.restype = ctypes.c_long
_ncrypt.NCryptSetProperty.argtypes = [
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
]
_ncrypt.NCryptSetProperty.restype = ctypes.c_long
_ncrypt.NCryptFinalizeKey.argtypes = [ctypes.c_void_p, wintypes.DWORD]
_ncrypt.NCryptFinalizeKey.restype = ctypes.c_long
_ncrypt.NCryptExportKey.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.DWORD,
]
_ncrypt.NCryptExportKey.restype = ctypes.c_long
_ncrypt.NCryptSignHash.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.DWORD,
]
_ncrypt.NCryptSignHash.restype = ctypes.c_long
_ncrypt.NCryptDeleteKey.argtypes = [ctypes.c_void_p, wintypes.DWORD]
_ncrypt.NCryptDeleteKey.restype = ctypes.c_long
_ncrypt.NCryptFreeObject.argtypes = [ctypes.c_void_p]
_ncrypt.NCryptFreeObject.restype = ctypes.c_long

_NCRYPT_ALLOW_SIGNING_FLAG = 0x00000002
_NCRYPT_SILENT_FLAG = 0x00000040
_BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB"
_NCRYPT_KEY_USAGE_PROPERTY = "Key Usage"
_NCRYPT_EXPORT_POLICY_PROPERTY = "Export Policy"


class IdentityKey:
    def __init__(self, name: str, handle: int) -> None:
        self.name = name
        self._handle = ctypes.c_void_p(handle)

    @classmethod
    def create(cls, name: str) -> IdentityKey:
        provider = _open_provider()
        handle = ctypes.c_void_p()
        try:
            _check_ncrypt(
                _ncrypt.NCryptCreatePersistedKey(
                    provider,
                    ctypes.byref(handle),
                    "ECDSA_P256",
                    name,
                    0,
                    0,
                ),
                "NCryptCreatePersistedKey",
            )
            _set_property(handle, _NCRYPT_KEY_USAGE_PROPERTY, _NCRYPT_ALLOW_SIGNING_FLAG)
            _set_property(handle, _NCRYPT_EXPORT_POLICY_PROPERTY, 0)
            _check_ncrypt(_ncrypt.NCryptFinalizeKey(handle, 0), "NCryptFinalizeKey")
            return cls(name, handle.value or 0)
        except Exception:
            if handle:
                _ncrypt.NCryptDeleteKey(handle, 0)
            raise
        finally:
            _ncrypt.NCryptFreeObject(provider)

    @classmethod
    def open(cls, name: str) -> IdentityKey:
        provider = _open_provider()
        handle = ctypes.c_void_p()
        try:
            _check_ncrypt(
                _ncrypt.NCryptOpenKey(provider, ctypes.byref(handle), name, 0, 0),
                "NCryptOpenKey",
            )
            return cls(name, handle.value or 0)
        finally:
            _ncrypt.NCryptFreeObject(provider)

    def public_key_sec1(self) -> bytes:
        size = wintypes.DWORD()
        _check_ncrypt(
            _ncrypt.NCryptExportKey(
                self._handle,
                None,
                _BCRYPT_ECCPUBLIC_BLOB,
                None,
                None,
                0,
                ctypes.byref(size),
                0,
            ),
            "NCryptExportKey",
        )
        if size.value < 72:
            raise IdentityError("CNG public key blob is truncated")
        blob = (ctypes.c_ubyte * size.value)()
        _check_ncrypt(
            _ncrypt.NCryptExportKey(
                self._handle,
                None,
                _BCRYPT_ECCPUBLIC_BLOB,
                None,
                blob,
                size.value,
                ctypes.byref(size),
                0,
            ),
            "NCryptExportKey",
        )
        raw = bytes(blob[: size.value])
        return b"\x04" + raw[8:40] + raw[40:72]

    def sign_digest(self, digest: bytes) -> bytes:
        if len(digest) != 32:
            raise IdentityError("CNG digest must be 32 bytes")
        size = wintypes.DWORD()
        digest_buffer = (ctypes.c_ubyte * len(digest)).from_buffer_copy(digest)
        _check_ncrypt(
            _ncrypt.NCryptSignHash(
                self._handle,
                None,
                digest_buffer,
                len(digest),
                None,
                0,
                ctypes.byref(size),
                _NCRYPT_SILENT_FLAG,
            ),
            "NCryptSignHash",
        )
        if size.value != 64:
            raise IdentityError("CNG returned an invalid P-256 signature size")
        signature = (ctypes.c_ubyte * size.value)()
        _check_ncrypt(
            _ncrypt.NCryptSignHash(
                self._handle,
                None,
                digest_buffer,
                len(digest),
                signature,
                size.value,
                ctypes.byref(size),
                _NCRYPT_SILENT_FLAG,
            ),
            "NCryptSignHash",
        )
        return bytes(signature[: size.value])

    def delete(self) -> None:
        if self._handle:
            _check_ncrypt(_ncrypt.NCryptDeleteKey(self._handle, 0), "NCryptDeleteKey")
            self._handle = ctypes.c_void_p()

    def close(self) -> None:
        if self._handle:
            _ncrypt.NCryptFreeObject(self._handle)
            self._handle = ctypes.c_void_p()


def _open_provider() -> ctypes.c_void_p:
    provider = ctypes.c_void_p()
    _check_ncrypt(
        _ncrypt.NCryptOpenStorageProvider(
            ctypes.byref(provider),
            "Microsoft Software Key Storage Provider",
            0,
        ),
        "NCryptOpenStorageProvider",
    )
    return provider


def _set_property(handle: ctypes.c_void_p, name: str, value: int) -> None:
    data = wintypes.DWORD(value)
    _check_ncrypt(
        _ncrypt.NCryptSetProperty(handle, name, ctypes.byref(data), ctypes.sizeof(data), 0),
        "NCryptSetProperty",
    )


def _check_ncrypt(status: int, operation: str) -> None:
    if status != 0:
        raise IdentityError(f"{operation} failed with NTSTATUS {status:#010x}")


def collect_hardware_evidence(app_id: str) -> HardwareEvidence:
    cpu = _read_cpu()
    motherboard, bios = _read_smbios()
    disk = _read_disk_serial()
    mac = _read_mac()
    machine_guid = _read_machine_guid()
    fields = [
        (0x01, "cpu", cpu),
        (0x02, "motherboard", motherboard),
        (0x04, "smbios", bios),
        (0x08, "disk", disk),
        (0x10, "mac", mac),
        (0x20, "machine_guid", machine_guid),
    ]
    canonical = f"device_hardware_evidence_v2\napp_id:{app_id}\n"
    mask = 0
    for bit, name, value in fields:
        normalized = _normalize_evidence(value)
        if not normalized:
            continue
        mask |= bit
        canonical += f"{name}:{normalized}\n"
    if mask == 0:
        raise IdentityError("device hardware evidence collection failed")
    return HardwareEvidence(version=2, component_mask=mask, aggregate_hash=sha256_hex(canonical.encode("utf-8")))


def _read_cpu() -> str:
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            vendor = str(winreg.QueryValueEx(key, "VendorIdentifier")[0])
            brand = str(winreg.QueryValueEx(key, "ProcessorNameString")[0])
            if vendor or brand:
                return f"{vendor}_{brand}"
    except OSError:
        pass
    try:
        info = cpuinfo.get_cpu_info()
        vendor = str(info.get("vendor_id_raw") or info.get("vendor_id") or "")
        brand = str(info.get("brand_raw") or "")
        if vendor or brand:
            return f"{vendor}_{brand}"
    except Exception:
        pass
    return ""


_kernel32.GetSystemFirmwareTable.argtypes = [
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
]
_kernel32.GetSystemFirmwareTable.restype = wintypes.DWORD


def _read_smbios() -> tuple[str, str]:
    required = _kernel32.GetSystemFirmwareTable(0x52534D42, 0, None, 0)
    if not required or required > 1024 * 1024:
        return "", ""
    buffer = (ctypes.c_ubyte * required)()
    written = _kernel32.GetSystemFirmwareTable(0x52534D42, 0, buffer, required)
    if written <= 8 or written > required:
        return "", ""
    raw = bytes(buffer[:written])
    table_length = int.from_bytes(raw[4:8], "little")
    available = written - 8
    length = min(table_length, available)
    return _parse_smbios(raw[8 : 8 + length])


def _parse_smbios(data: bytes) -> tuple[str, str]:
    motherboard = ""
    bios = ""
    offset = 0
    while offset + 4 <= len(data):
        record_type = data[offset]
        length = data[offset + 1]
        if length < 4 or offset + length > len(data):
            break
        strings = data[offset + length :]
        end = strings.find(b"\x00\x00")
        if end < 0:
            break
        end += 2
        index = data[offset + 7] if length > 7 else 0
        value = _smbios_string(strings[:end], index)
        if record_type == 1 and not bios:
            bios = _first_usable(value)
        elif record_type == 2 and not motherboard:
            motherboard = _first_usable(value)
        elif record_type == 127:
            break
        consumed = len(strings) - end
        if consumed <= 0:
            break
        offset += length + consumed
    return motherboard, bios


def _smbios_string(data: bytes, index: int) -> str:
    if index == 0:
        return ""
    offset = 0
    for _ in range(1, index):
        end = data.find(b"\x00", offset)
        if end < 0:
            return ""
        offset = end + 1
    end = data.find(b"\x00", offset)
    return data[offset:end].decode("utf-8", errors="replace") if end > offset else ""


_kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
]
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.DeviceIoControl.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]
_kernel32.DeviceIoControl.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _AdapterUnion(ctypes.Union):
    _fields_ = [("Length", wintypes.ULONG), ("IfIndex", wintypes.DWORD)]


class _IpAdapterAddresses(ctypes.Structure):
    pass


_IpAdapterAddresses._fields_ = [
        ("Anonymous1", _AdapterUnion),
        ("Next", ctypes.POINTER(_IpAdapterAddresses)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.c_void_p),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", wintypes.LPWSTR),
        ("Description", wintypes.LPWSTR),
        ("FriendlyName", wintypes.LPWSTR),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", wintypes.DWORD),
        ("Flags", wintypes.DWORD),
        ("Mtu", wintypes.DWORD),
        ("IfType", wintypes.DWORD),
        ("OperStatus", ctypes.c_int),
]


_iphlpapi = ctypes.WinDLL("iphlpapi.dll")
_iphlpapi.GetAdaptersAddresses.argtypes = [
    wintypes.ULONG,
    wintypes.ULONG,
    ctypes.c_void_p,
    ctypes.POINTER(_IpAdapterAddresses),
    ctypes.POINTER(wintypes.ULONG),
]
_iphlpapi.GetAdaptersAddresses.restype = wintypes.ULONG


def _read_disk_serial() -> str:
    for index in range(8):
        handle = _kernel32.CreateFileW(
            rf"\\.\PhysicalDrive{index}",
            0,
            0x00000001 | 0x00000002,
            None,
            3,
            0,
            None,
        )
        if not handle or handle == _INVALID_HANDLE_VALUE:
            continue
        try:
            query = (ctypes.c_ubyte * 12)()
            output = (ctypes.c_ubyte * 4096)()
            returned = wintypes.DWORD()
            if not _kernel32.DeviceIoControl(
                handle,
                0x002D1400,
                query,
                12,
                output,
                4096,
                ctypes.byref(returned),
                None,
            ):
                continue
            raw = bytes(output[: returned.value])
            if len(raw) < 36:
                continue
            bus_type = int.from_bytes(raw[28:32], "little")
            if bus_type in {7, 8, 12, 13}:
                continue
            serial_offset = int.from_bytes(raw[24:28], "little", signed=True)
            if serial_offset <= 0 or serial_offset >= len(raw):
                continue
            end = raw.find(b"\x00", serial_offset)
            if end < 0:
                end = len(raw)
            value = _first_usable(raw[serial_offset:end].decode("ascii", errors="ignore"))
            if value:
                return value
        finally:
            _kernel32.CloseHandle(handle)
    return ""


def _read_mac() -> str:
    flags = 0x1 | 0x2 | 0x4 | 0x8
    size = wintypes.ULONG(15 * 1024)
    for _ in range(3):
        buffer = (ctypes.c_ubyte * size.value)()
        first = ctypes.cast(buffer, ctypes.POINTER(_IpAdapterAddresses))
        result = _iphlpapi.GetAdaptersAddresses(0, flags, None, first, ctypes.byref(size))
        if result == 111:
            continue
        if result != 0:
            break
        addresses: list[bytes] = []
        current = first
        while current:
            adapter = current.contents
            if adapter.OperStatus == 1 and adapter.IfType in {6, 71}:
                description = (adapter.Description or "").lower()
                if not any(
                    marker in description
                    for marker in (
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
                    )
                ) and adapter.PhysicalAddressLength == 6:
                    value = bytes(adapter.PhysicalAddress[:6])
                    if value != b"\x00" * 6 and value[0] & 0x02 == 0:
                        addresses.append(value)
            current = adapter.Next
        if addresses:
            addresses.sort()
            return ":".join(f"{item:02x}" for item in addresses[0])
        break
    return ""


def _read_machine_guid() -> str:
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            return str(winreg.QueryValueEx(key, "MachineGuid")[0])
    except OSError:
        return ""


def _normalize_evidence(value: str) -> str:
    return "".join(character.lower() for character in value if ord(character) > 0x20 and ord(character) != 0x7F)


def _first_usable(value: str) -> str:
    value = value.strip()
    placeholders = {
        "",
        "none",
        "n/a",
        "na",
        "null",
        "0",
        "default string",
        "to be filled by o.e.m.",
        "to be filled by oem",
        "system serial number",
        "base board serial number",
        "chassis serial number",
        "not specified",
        "not available",
        "unknown",
        "0000000000",
        "invalid",
        "filled by oem",
    }
    if value.lower() in placeholders or all(character in "0 \t" for character in value):
        return ""
    return value[:128]
