from __future__ import annotations

from dataclasses import dataclass

from .crypto import base64url_encode, sha256_hex, verify_ed25519
from .errors import ErrorKind, SwmError

MAGIC = b"OPLUSRIM"
MANIFEST_DOMAIN = b"OPLUS_RELEASE_MANIFEST_V2\x00"
KEY_DOMAIN = b"OPLUS_RELEASE_KEY_V2\x00"


@dataclass
class Rim2File:
    path: str
    size: int
    sha256: bytes


@dataclass
class Rim2Manifest:
    manifest_sha256: str
    version: str
    arch: str
    root_key_id: str
    signer_key_id: str
    files: list[Rim2File]


def parse_and_verify(
    raw: bytes,
    expected_app_id: str,
    expected_release_id: str,
    expected_version: str,
    expected_version_code: int | None,
    expected_arch: str,
    expected_root_key_id: str,
    root_trust_public_key: str,
) -> Rim2Manifest:
    if not raw or len(raw) > 64 * 1024:
        raise _error("host_manifest_invalid", "RIM2 manifest size is invalid")
    if not raw.startswith(MAGIC):
        raise _error("host_manifest_invalid", "RIM2 manifest magic is invalid")
    offset = len(MAGIC)
    protocol_version, offset = _read_u16(raw, offset)
    body_size, offset = _read_u32(raw, offset)
    if protocol_version != 2 or body_size == 0 or offset + body_size > len(raw):
        raise _error("host_manifest_invalid", "RIM2 manifest header is invalid")
    body = raw[offset : offset + body_size]
    offset += body_size
    body_offset = 0
    if len(body) < 32:
        raise _error("host_manifest_invalid", "RIM2 manifest body is truncated")
    app_bytes = body[body_offset : body_offset + 16]
    body_offset += 16
    release_bytes = body[body_offset : body_offset + 16]
    body_offset += 16
    version_code, body_offset = _read_u64(body, body_offset)
    platform = body[body_offset]
    architecture = body[body_offset + 1]
    body_offset += 2
    version, body_offset = _read_string16(body, body_offset)
    if not version or len(version.encode("utf-8")) > 100:
        raise _error("host_manifest_invalid", "RIM2 release version is invalid")
    file_count, body_offset = _read_u16(body, body_offset)
    if file_count == 0 or file_count > 255:
        raise _error("host_manifest_invalid", "RIM2 manifest file count is invalid")
    files: list[Rim2File] = []
    seen: set[str] = set()
    for _ in range(file_count):
        path, body_offset = _read_string16(body, body_offset)
        size, body_offset = _read_u64(body, body_offset)
        if body_offset + 32 > len(body):
            raise _error("host_manifest_invalid", "RIM2 manifest file hash is truncated")
        file_hash = body[body_offset : body_offset + 32]
        body_offset += 32
        if not _safe_path(path) or size == 0 or not any(file_hash) or path.lower() in seen:
            raise _error("host_manifest_invalid", "RIM2 manifest contains an unsafe or duplicate file")
        seen.add(path.lower())
        files.append(Rim2File(path, size, file_hash))
    if body_offset != len(body):
        raise _error("host_manifest_invalid", "RIM2 manifest body contains trailing bytes")
    trailer = offset
    root_key_id, trailer = _read_string8(raw, trailer)
    signer_key_id, trailer = _read_string8(raw, trailer)
    if (
        not root_key_id
        or len(root_key_id.encode("utf-8")) > 64
        or not signer_key_id
        or len(signer_key_id.encode("utf-8")) > 64
        or trailer + 160 > len(raw)
    ):
        raise _error("host_manifest_invalid", "RIM2 signing key id or trailer is invalid")
    signer_public = raw[trailer : trailer + 32]
    trailer += 32
    root_signature = raw[trailer : trailer + 64]
    trailer += 64
    manifest_signature = raw[trailer : trailer + 64]
    trailer += 64
    if trailer != len(raw):
        raise _error("host_manifest_invalid", "RIM2 manifest trailer is invalid")
    expected_app = _uuid_bytes(expected_app_id)
    expected_release = _uuid_bytes(expected_release_id)
    version_code_matches = expected_version_code is None or version_code == expected_version_code
    if (
        app_bytes != expected_app
        or release_bytes != expected_release
        or platform != 1
        or architecture != _arch_byte(expected_arch)
        or version != expected_version
        or not version_code_matches
        or root_key_id != expected_root_key_id
    ):
        raise _error("host_release_mismatch", "RIM2 manifest identity does not match this release")
    key_message = KEY_DOMAIN + app_bytes + _append_string8(root_key_id) + _append_string8(signer_key_id) + signer_public
    if not verify_ed25519(root_trust_public_key, key_message, base64url_encode(root_signature)):
        raise _error("host_root_signature_invalid", "RIM2 root certificate signature is invalid")
    if not verify_ed25519(
        base64url_encode(signer_public),
        MANIFEST_DOMAIN + body,
        base64url_encode(manifest_signature),
    ):
        raise _error("host_manifest_signature_invalid", "RIM2 manifest signature is invalid")
    return Rim2Manifest(
        manifest_sha256=sha256_hex(raw),
        version=version,
        arch=_normalize_arch(architecture),
        root_key_id=root_key_id,
        signer_key_id=signer_key_id,
        files=files,
    )


def _error(code: str, message: str) -> SwmError:
    return SwmError(ErrorKind.INTEGRITY, message, code=code)


def _read_u16(value: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(value):
        raise _error("host_manifest_invalid", "RIM2 manifest is truncated")
    return int.from_bytes(value[offset : offset + 2], "big"), offset + 2


def _read_u32(value: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(value):
        raise _error("host_manifest_invalid", "RIM2 manifest is truncated")
    return int.from_bytes(value[offset : offset + 4], "big"), offset + 4


def _read_u64(value: bytes, offset: int) -> tuple[int, int]:
    if offset + 8 > len(value):
        raise _error("host_manifest_invalid", "RIM2 manifest is truncated")
    return int.from_bytes(value[offset : offset + 8], "big"), offset + 8


def _read_string8(value: bytes, offset: int) -> tuple[str, int]:
    if offset + 1 > len(value):
        raise _error("host_manifest_invalid", "RIM2 manifest is truncated")
    length = value[offset]
    return _read_utf8(value, offset + 1, length)


def _read_string16(value: bytes, offset: int) -> tuple[str, int]:
    length, offset = _read_u16(value, offset)
    return _read_utf8(value, offset, length)


def _read_utf8(value: bytes, offset: int, length: int) -> tuple[str, int]:
    if offset + length > len(value):
        raise _error("host_manifest_invalid", "RIM2 manifest is truncated")
    try:
        return value[offset : offset + length].decode("utf-8"), offset + length
    except UnicodeDecodeError as error:
        raise _error("host_manifest_invalid", "RIM2 manifest contains invalid UTF-8") from error


def _append_string8(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return bytes([len(encoded)]) + encoded


def _safe_path(value: str) -> bool:
    return (
        0 < len(value.encode("utf-8")) <= 255
        and "\\" not in value
        and not value.startswith("/")
        and not value.endswith("/")
        and ":" not in value
        and "\x00" not in value
        and all(part not in {"", ".", ".."} for part in value.split("/"))
        and all(ord(character) >= 0x20 and ord(character) != 0x7F for character in value)
    )


def _arch_byte(value: str) -> int:
    return {"x86": 1, "386": 1, "i386": 1, "win-x86": 1, "x64": 2, "amd64": 2, "win-x64": 2}.get(
        value.lower(), 0
    )


def _normalize_arch(value: int) -> str:
    return {1: "x86", 2: "x64"}.get(value, "")


def _uuid_bytes(value: str) -> bytes:
    raw = bytes.fromhex(value.replace("-", ""))
    return bytes(
        [
            raw[3],
            raw[2],
            raw[1],
            raw[0],
            raw[5],
            raw[4],
            raw[7],
            raw[6],
            raw[8],
            raw[9],
            raw[10],
            raw[11],
            raw[12],
            raw[13],
            raw[14],
            raw[15],
        ]
    )
