from __future__ import annotations

from enum import Enum
from typing import Any


class ErrorKind(str, Enum):
    CONFIGURATION = "configuration"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    NETWORK = "network"
    TIMEOUT = "timeout"
    PROTOCOL = "protocol"
    IDENTITY = "identity"
    CRYPTOGRAPHIC = "cryptographic"
    CLOCK = "clock"
    SESSION = "session"
    UNAUTHORIZED = "unauthorized"
    VALIDATION = "validation"
    RATE_LIMIT = "rate_limit"
    API = "api"
    DEVICE_BLOCKED = "device_blocked"
    UNSUPPORTED_VERSION = "unsupported_version"
    UPDATE_REGION_BLOCKED = "update_region_blocked"
    FEEDBACK_DISABLED = "feedback_disabled"
    INTEGRITY = "integrity"
    OPERATION_AUTHORIZATION = "operation_authorization"
    OFFLINE_BUDGET = "offline_budget"


class IntegrityFailureAction(str, Enum):
    DENY_OPERATIONS = "deny_operations"
    SHUTDOWN_CLIENT = "shutdown_client"


class SwmError(Exception):
    """Common SDK exception with stable service metadata."""

    def __init__(
        self,
        kind: ErrorKind,
        message: str,
        *,
        status_code: int | None = None,
        code: str | None = None,
        response_body: str | None = None,
        retry_after: float | None = None,
        failure_action: IntegrityFailureAction | None = None,
        minimum_supported_version: str | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.status_code = status_code
        self.code = code
        self.response_body = response_body
        self.retry_after = retry_after
        self.failure_action = failure_action
        self.minimum_supported_version = minimum_supported_version
        self.cause = cause

    def __str__(self) -> str:
        parts = [self.kind.value]
        if self.status_code is not None:
            parts.append(f"HTTP {self.status_code}")
        if self.code:
            parts.append(self.code)
        parts.append(self.message)
        return ": ".join(parts)


class UnsupportedPlatformError(SwmError):
    def __init__(self, message: str = "SWM SDK requires Windows x86 or x64") -> None:
        super().__init__(ErrorKind.UNSUPPORTED_PLATFORM, message)


class ConfigurationError(SwmError):
    def __init__(self, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(ErrorKind.CONFIGURATION, message, cause=cause)


class IdentityError(SwmError):
    def __init__(self, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(ErrorKind.IDENTITY, message, cause=cause)


class CryptographicError(SwmError):
    def __init__(self, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(ErrorKind.CRYPTOGRAPHIC, message, cause=cause)


def service_error(
    *,
    status_code: int,
    body: bytes,
    retry_after: float | None = None,
) -> SwmError:
    text = body.decode("utf-8", errors="replace")
    code = ""
    message = text[:1024] if text else f"HTTP {status_code}"
    minimum_supported_version = None
    failure_action = None
    try:
        import json

        payload: Any = json.loads(text)
        error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(error, dict):
            code = str(error.get("code") or "")
            message = str(error.get("message") or message)
            minimum_supported_version = error.get("minimum_supported_version")
            action = error.get("failure_action")
            if action == "deny_operations":
                failure_action = IntegrityFailureAction.DENY_OPERATIONS
            elif action == "shutdown_client":
                failure_action = IntegrityFailureAction.SHUTDOWN_CLIENT
        elif isinstance(error, str):
            message = error
            if error and all(character.islower() or character.isdigit() or character == "_" for character in error):
                code = error
        elif isinstance(payload, dict):
            code = str(payload.get("code") or "")
            message = str(payload.get("message") or message)
    except Exception:
        pass

    if code == "device_blocked":
        kind = ErrorKind.DEVICE_BLOCKED
    elif code == "client_version_unsupported":
        kind = ErrorKind.UNSUPPORTED_VERSION
    elif code == "update_region_blocked":
        kind = ErrorKind.UPDATE_REGION_BLOCKED
    elif code == "feedback_disabled":
        kind = ErrorKind.FEEDBACK_DISABLED
    elif code.startswith("release_integrity_"):
        kind = ErrorKind.INTEGRITY
        if failure_action is None:
            failure_action = IntegrityFailureAction.SHUTDOWN_CLIENT
    elif code.startswith(("operation_auth_", "operation_grant_")):
        kind = ErrorKind.OPERATION_AUTHORIZATION
    elif status_code == 429:
        kind = ErrorKind.RATE_LIMIT
    elif status_code == 401:
        kind = ErrorKind.SESSION
    elif status_code == 403:
        kind = ErrorKind.UNAUTHORIZED
    elif 400 <= status_code < 500:
        kind = ErrorKind.VALIDATION
    else:
        kind = ErrorKind.API
    return SwmError(
        kind,
        message,
        status_code=status_code,
        code=code or None,
        response_body=text,
        retry_after=retry_after,
        failure_action=failure_action,
        minimum_supported_version=minimum_supported_version,
    )
