from __future__ import annotations

import dataclasses
import datetime as dt
import typing
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CloudState(str, Enum):
    UNAVAILABLE = "unavailable"
    AUTHORIZING = "authorizing"
    AVAILABLE = "available"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INTEGRITY_FAILURE = "integrity_failure"
    TIME_SYNC_FAILURE = "time_sync_failure"
    OFFLINE_LOCKED = "offline_locked"


@dataclass
class MaintenanceInfo:
    enabled: bool = False
    start_at: str | None = None
    message: str | None = None
    active: bool = False


@dataclass
class UpdateInfo:
    update_available: bool = False
    mandatory: bool = False
    heartbeat_interval_seconds: int = 0
    open_in_browser: bool = False
    delivery_method: str | None = None
    release_id: str | None = None
    version: str | None = None
    version_code: int | None = None
    notes: str | None = None
    download_url: str | None = None
    checksum_sha256: str | None = None
    signature: str | None = None
    manifest_key_id: str | None = None
    manifest_public_key: str | None = None
    root_trust_key_id: str | None = None
    root_trust_signature: str | None = None
    artifact_file_name: str | None = None
    artifact_platform: str | None = None
    artifact_arch: str | None = None
    authz_protocol: str | None = None
    host_integrity_required: bool = False
    size: int = 0
    rollback_allowed: bool = False
    maintenance: MaintenanceInfo | None = None


@dataclass
class HeartbeatResult:
    ok: bool = False
    server_time: str | None = None
    maintenance: MaintenanceInfo | None = None


@dataclass
class Event:
    event_name: str
    event_time: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))
    device_id: str | None = None
    channel_code: str | None = None
    properties: dict[str, Any] | None = None
    attributes: dict[str, Any] | None = None


@dataclass
class FeedbackRequest:
    content: str
    rating: int | None = None
    contact: str | None = None
    app_version: str | None = None
    attachment_paths: list[str] = field(default_factory=list)
    metadata: dict[str, Any] | None = None


@dataclass
class FeedbackResult:
    ok: bool = False
    id: str = ""


@dataclass
class EnrollmentTicket:
    ticket: str = ""
    expires_at: int = 0
    audience: str = ""


@dataclass
class DeviceKeyRotationResult:
    registration_id: str = ""
    install_id: str = ""
    key_id: str = ""
    device_id: str = ""


@dataclass
class OperationAuthorizationRequest:
    operation: str
    plan: bytes
    step_count: int
    consumer_module: str
    total_bytes: int = 0
    consumer_challenge: bytes | None = None
    host_executable_path: str | None = None
    consumer_module_path: str | None = None


@dataclass
class OperationGrant:
    schema: str = ""
    app_id: str = ""
    release_id: str = ""
    device_id: str = ""
    device_key_id: str = ""
    key_thumbprint: str = ""
    device_public_key: str = ""
    authz_public_key: str = ""
    authz_key_id: str = ""
    authz_root_trust_key_id: str = ""
    authz_root_trust_signature: str = ""
    session: str = ""
    grant_id: str = ""
    operation: str = ""
    plan_sha256: str = ""
    step_count: int = 0
    total_bytes: int = 0
    issued_at: int = 0
    expires_at: int = 0
    consumer_challenge: str = ""
    integrity_manifest_sha256: str | None = None
    host_exe_sha256: str | None = None
    consumer_module: str = ""
    consumer_module_sha256: str | None = None


@dataclass
class OperationConsumptionReceipt:
    schema: str = ""
    grant_id: str = ""
    operation: str = ""
    plan_sha256: str = ""
    step_count: int = 0
    total_bytes: int = 0
    consumer_challenge: str = ""
    consumed_at: int = 0
    expires_at: int = 0
    integrity_manifest_sha256: str | None = None
    host_exe_sha256: str | None = None
    consumer_module: str = ""
    consumer_module_sha256: str | None = None


@dataclass
class UpdateEvent:
    id: str = ""
    event_type: str = ""
    org_id: str = ""
    app_id: str = ""
    device_id: str = ""
    channel_code: str = ""
    platform: str = ""
    arch: str = ""
    release_id: str = ""
    published_at: str | None = None
    reason: str = ""
    message: str = ""
    maintenance_start_at: str | None = None


@dataclass
class UpdateStreamOptions:
    current_version: str | None = None
    version_code: int | None = None
    reconnect: bool = True
    reconnect_backoff: float = 1.5
    reconnect_max_backoff: float = 20.0
    jitter: bool = True


@dataclass
class DebugRequestTicket:
    request_id: str
    watch_token: str
    expires_at: int
    credentials: DebugCredentials = field(repr=False)
    session_id: str = field(repr=False)


@dataclass
class DebugCredentials:
    client_id: str = ""
    client_secret: str = ""
    expires_at: int = 0


@dataclass
class DebugDecisionEvent:
    state: str
    reason: str | None = None
    authorization_expires_at: int = 0


@dataclass
class IntegrityEvidence:
    integrity_state: str | None = None
    integrity_failure_code: str | None = None
    integrity_evidence_version: int | None = None
    integrity_manifest_sha256: str | None = None
    integrity_files: dict[str, str] | None = None


@dataclass
class HardwareEvidence:
    version: int = 2
    component_mask: int = 0
    aggregate_hash: str = ""


def model_from_dict(cls: type[Any], value: Any) -> Any:
    """Convert protocol dictionaries into nested dataclasses."""

    if value is None:
        return None
    if not dataclasses.is_dataclass(cls):
        return value
    if not isinstance(value, dict):
        return value
    hints = typing.get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for field_info in dataclasses.fields(cls):
        if field_info.name not in value:
            continue
        raw = value[field_info.name]
        field_type = hints.get(field_info.name, Any)
        kwargs[field_info.name] = _convert_value(field_type, raw)
    return cls(**kwargs)


def _convert_value(field_type: Any, value: Any) -> Any:
    origin = typing.get_origin(field_type)
    args = typing.get_args(field_type)
    if origin is typing.Union or str(origin) == "types.UnionType":
        for arg in args:
            if arg is type(None):
                continue
            try:
                return _convert_value(arg, value)
            except Exception:
                continue
        return value
    if origin in (list, list) and args:
        return [_convert_value(args[0], item) for item in value]
    if origin in (dict, dict) and len(args) == 2:
        return {key: _convert_value(args[1], item) for key, item in value.items()}
    if isinstance(field_type, type) and dataclasses.is_dataclass(field_type):
        return model_from_dict(field_type, value)
    if field_type is dt.datetime and isinstance(value, str):
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


def model_to_dict(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {
            field_info.name: model_to_dict(getattr(value, field_info.name))
            for field_info in dataclasses.fields(value)
            if not field_info.name.startswith("_")
        }
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, bytes):
        return value
    if isinstance(value, dict):
        return {key: model_to_dict(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [model_to_dict(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    return value
