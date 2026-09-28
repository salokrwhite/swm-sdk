from __future__ import annotations

import re
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

import requests

from .crypto import decode_key_material
from .errors import ConfigurationError, CryptographicError
from .models import IntegrityEvidence

ProgressCallback = Callable[[int, int], None]


def process_arch() -> str:
    return "x86" if struct.calcsize("P") == 4 else "x64"


class IntegrityEvidenceProvider(Protocol):
    def get_evidence(
        self,
        app_id: str,
        release_id: str,
        version: str,
        version_code: int | None,
        arch: str,
        package_root: Path,
        manifest_path: str,
    ) -> IntegrityEvidence:
        ...


@dataclass
class HostIntegrityOptions:
    enabled: bool = False
    package_root: Path | None = None
    manifest_path: str = "release-integrity.v2"
    evidence_provider: IntegrityEvidenceProvider | None = None


@dataclass
class CheckUpdateOptions:
    user_id: str | None = None
    attributes: dict[str, Any] | None = None


@dataclass
class HeartbeatOptions:
    app_version: str | None = None
    user_id: str | None = None
    attributes: dict[str, Any] | None = None


@dataclass
class ClientOptions:
    base_url: str
    app_id: str
    release_id: str
    version: str
    root_trust_key_id: str
    root_trust_public_key: str
    web_base_url: str | None = None
    version_code: int | None = None
    channel: str = "stable"
    platform: str = "windows"
    arch: str = field(default_factory=process_arch)
    device_id: str | None = None
    storage_directory: Path | None = None
    allow_insecure_http: bool = False
    session: requests.Session | None = None
    host_integrity: HostIntegrityOptions = field(default_factory=HostIntegrityOptions)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.strip().rstrip("/")
        if self.web_base_url:
            self.web_base_url = self.web_base_url.strip().rstrip("/")
        self.app_id = self.app_id.strip()
        self.release_id = self.release_id.strip()
        self.version = self.version.strip()
        self.root_trust_key_id = self.root_trust_key_id.strip()
        self.root_trust_public_key = self.root_trust_public_key.strip()
        self.channel = self.channel.strip() or "stable"
        self.platform = self.platform.strip().lower() or "windows"
        self.arch = normalize_arch(self.arch)
        self.host_integrity.manifest_path = (
            self.host_integrity.manifest_path.strip().replace("\\", "/")
            or "release-integrity.v2"
        )


def normalize_arch(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"386", "i386", "x86", "win-x86"}:
        return "x86"
    if lowered in {"amd64", "x86_64", "x64", "win-x64"}:
        return "x64"
    return lowered


def validate_options(options: ClientOptions) -> None:
    required = (
        options.base_url,
        options.app_id,
        options.release_id,
        options.version,
        options.root_trust_key_id,
        options.root_trust_public_key,
    )
    if any(not value or not value.strip() for value in required):
        raise ConfigurationError("base URL, app ID, release ID, version, and root trust material are required")
    if not _is_uuid(options.app_id) or not _is_uuid(options.release_id):
        raise ConfigurationError("app_id and release_id must be UUID values")
    _validate_service_url(options.base_url, options.allow_insecure_http, "base_url")
    if options.web_base_url:
        _validate_service_url(options.web_base_url, options.allow_insecure_http, "web_base_url")
    try:
        root_key = decode_key_material(options.root_trust_public_key)
    except CryptographicError as error:
        raise ConfigurationError("root_trust_public_key must be a 32-byte Ed25519 public key", cause=error) from error
    if len(root_key) != 32:
        raise ConfigurationError("root_trust_public_key must be a 32-byte Ed25519 public key")
    if options.version_code is not None and not 0 <= options.version_code <= 0x7FFFFFFF:
        raise ConfigurationError("version_code must be between 0 and 2147483647")
    if options.platform != "windows":
        raise ConfigurationError("platform must be windows")
    if options.arch not in {"x86", "x64"}:
        raise ConfigurationError("arch must be x86 or x64")
    options.host_integrity.manifest_path = _normalize_relative_path(
        options.host_integrity.manifest_path,
        "host integrity manifest path",
    )


def _validate_service_url(raw: str, allow_insecure: bool, name: str) -> None:
    parsed = urlsplit(raw)
    if (
        parsed.scheme not in ({"https"} if not allow_insecure else {"https", "http"})
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ConfigurationError(f"{name} must be an absolute HTTPS URL")


def _normalize_relative_path(raw: str, name: str) -> str:
    normalized = raw.strip().replace("\\", "/")
    if (
        not normalized
        or normalized.startswith("/")
        or ":" in normalized
        or "\x00" in normalized
        or any(part in {"", ".", ".."} for part in normalized.split("/"))
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized)
    ):
        raise ConfigurationError(f"{name} must be package-relative")
    return normalized


def _is_uuid(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value))
