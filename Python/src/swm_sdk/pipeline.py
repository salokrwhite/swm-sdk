from __future__ import annotations

import json
import threading
import time as time_module
from dataclasses import dataclass
from email.utils import parsedate_to_datetime

import requests

from .errors import ErrorKind, SwmError


@dataclass
class ProtocolKey:
    key_id: str
    public_key: str
    issued_at: int
    refresh_after: int


@dataclass
class ProtocolRequest:
    operation: str
    method: str
    path: str
    body: bytes = b""
    query: list[tuple[str, str]] | None = None
    encrypt_body: bool = False
    require_session: bool = False
    require_trusted_time: bool = False
    require_online_key: bool = False
    content_type: str | None = None


@dataclass
class ProtocolResponse:
    status_code: int
    body: bytes
    nonce: str
    headers: requests.structures.CaseInsensitiveDict[str]


@dataclass(frozen=True)
class RequestPolicy:
    timeout: float
    retries: int
    backoff: float
    backoff_max: float
    deadline: float


REQUEST_POLICIES: dict[str, RequestPolicy] = {
    "trusted_time": RequestPolicy(10, 2, 1, 4, 40),
    "online_key": RequestPolicy(10, 2, 1, 4, 40),
    "update_check": RequestPolicy(15, 2, 1.5, 6, 60),
    "heartbeat": RequestPolicy(8, 2, 1, 4, 30),
    "operation_authorization": RequestPolicy(10, 2, 1, 4, 36),
    "operation_consume": RequestPolicy(10, 1, 1, 2, 24),
    "events": RequestPolicy(8, 1, 1, 2, 20),
    "feedback": RequestPolicy(10, 1, 1, 2, 24),
    "enrollment": RequestPolicy(10, 1, 1, 2, 24),
    "rotation": RequestPolicy(10, 1, 1, 2, 24),
    "download": RequestPolicy(30, 2, 2, 8, 0),
    "firmware": RequestPolicy(8, 1, 0.5, 1, 20),
    "debug": RequestPolicy(8, 1, 0.5, 1, 20),
}


class TrustedClock:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._initialized = False
        self._anchor_server_ms = 0
        self._anchor_monotonic = time_module.monotonic()

    def is_initialized(self) -> bool:
        with self._lock:
            return self._initialized

    def now_ms(self) -> int:
        with self._lock:
            if not self._initialized:
                return 0
            elapsed = int((time_module.monotonic() - self._anchor_monotonic) * 1000)
            return self._anchor_server_ms + elapsed

    def now_seconds(self) -> int:
        value = self.now_ms()
        return 0 if value <= 0 else value // 1000

    def set_authoritative(self, server_ms: int, started: float, received: float) -> None:
        if not 1_577_836_800_000 <= server_ms <= 4_102_444_800_000:
            raise SwmError(ErrorKind.CLOCK, "signed server time is outside the accepted range")
        round_trip_ms = int(max(0.0, received - started) * 1000)
        if round_trip_ms > 5000:
            raise SwmError(ErrorKind.CLOCK, "signed server time round trip is too slow")
        with self._lock:
            self._anchor_server_ms = server_ms + round_trip_ms // 2
            self._anchor_monotonic = received
            self._initialized = True


def policy_for(operation: str) -> RequestPolicy:
    return REQUEST_POLICIES.get(operation, RequestPolicy(8, 1, 0.5, 1, 20))


def is_transient_status(status: int) -> bool:
    return status in {408, 429, 500, 502, 503, 504}


def backoff(policy: RequestPolicy, attempt: int) -> float:
    if policy.backoff <= 0:
        return 0.0
    return min(policy.backoff * (1 << min(attempt, 16)), max(policy.backoff_max, policy.backoff))


def retry_after(headers: requests.structures.CaseInsensitiveDict[str]) -> float | None:
    value = headers.get("Retry-After")
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            date = parsedate_to_datetime(value)
            return max(0.0, date.timestamp() - time_module.time())
        except Exception:
            return None


def extract_raw_field(raw: bytes, field_name: str) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SwmError(
            ErrorKind.PROTOCOL,
            "Authz v3 carrier is not valid UTF-8",
            cause=error,
        ) from error
    decoder = json.JSONDecoder()
    index = 0
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text) or text[index] != "{":
        raise SwmError(ErrorKind.PROTOCOL, "Authz v3 carrier must be a JSON object")
    index += 1
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            raise SwmError(ErrorKind.PROTOCOL, "Authz v3 carrier is truncated")
        if text[index] == "}":
            break
        try:
            key, index = decoder.raw_decode(text, index)
        except Exception as error:
            raise SwmError(ErrorKind.PROTOCOL, "Authz v3 carrier key is invalid", cause=error) from error
        if not isinstance(key, str):
            raise SwmError(ErrorKind.PROTOCOL, "Authz v3 carrier key is invalid")
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text) or text[index] != ":":
            raise SwmError(ErrorKind.PROTOCOL, "Authz v3 carrier field separator is invalid")
        index += 1
        while index < len(text) and text[index].isspace():
            index += 1
        value_start = index
        try:
            _, index = decoder.raw_decode(text, value_start)
        except Exception as error:
            raise SwmError(ErrorKind.PROTOCOL, "Authz v3 carrier field is invalid", cause=error) from error
        if key == field_name:
            return text[value_start:index].encode("utf-8")
        while index < len(text) and text[index].isspace():
            index += 1
        if index < len(text) and text[index] == ",":
            index += 1
            continue
        if index < len(text) and text[index] == "}":
            break
        raise SwmError(ErrorKind.PROTOCOL, "Authz v3 carrier is invalid")
    raise SwmError(ErrorKind.PROTOCOL, f"Authz v3 carrier is missing {field_name}")
