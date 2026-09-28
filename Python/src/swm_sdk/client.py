from __future__ import annotations

import json
import threading
import time
from typing import Any, TypeVar
from urllib.parse import urlencode, urlsplit, urlunsplit

import requests

from .crypto import (
    base64url_encode,
    encrypt_request_body,
    random_uuid,
    sha256,
    sha256_hex,
    verify_ed25519,
)
from .download import DownloadMixin
from .errors import ErrorKind, SwmError, UnsupportedPlatformError, service_error
from .host_integrity import HostIntegrityManager
from .identity import DeviceIdentity
from .models import CloudState, HardwareEvidence, model_from_dict
from .operations import OperationsMixin
from .optional import OptionalMixin
from .options import ClientOptions, validate_options
from .pipeline import (
    ProtocolKey,
    ProtocolRequest,
    ProtocolResponse,
    TrustedClock,
    backoff,
    extract_raw_field,
    is_transient_status,
    policy_for,
    retry_after,
)
from .platform import collect_hardware_evidence, supported
from .state import OFFLINE_FILE, StateStore
from .stream import StreamMixin

T = TypeVar("T")


class OfflineBudget:
    def __init__(self, store: StateStore, install_id: str, key_thumbprint: str) -> None:
        self.store = store
        self.install_id = install_id
        self.key_thumbprint = key_thumbprint
        self._lock = threading.RLock()
        self._loaded = False
        self._has_record = False
        self._latched = False
        self._had_verified = False
        self._last_verified_ms = 0
        self._last_persisted_ms = 0

    def is_locked(self, clock: TrustedClock) -> bool:
        with self._lock:
            self._ensure_loaded()
            if self._latched:
                return True
            now = clock.now_ms()
            return (
                not self._has_record
                or now <= 0
                or now < self._last_verified_ms
                or now - self._last_verified_ms > 24 * 60 * 60 * 1000
            )

    def note_verified(self, trusted_ms: int) -> None:
        if trusted_ms <= 0:
            return
        with self._lock:
            self._ensure_loaded()
            if (
                self._had_verified
                and self._has_record
                and trusted_ms >= self._last_verified_ms
                and trusted_ms - self._last_verified_ms > 24 * 60 * 60 * 1000
            ):
                self._latched = True
            self._had_verified = True
            self._has_record = True
            self._last_verified_ms = max(self._last_verified_ms, trusted_ms)
            if (
                self._last_persisted_ms == 0
                or trusted_ms - self._last_persisted_ms >= 5 * 60 * 1000
            ):
                self.store.write_protected(
                    OFFLINE_FILE,
                    (
                        "SwmSdkOfflineBudgetV1\n"
                        f"{self.install_id}\n{self.key_thumbprint}\n{self._last_verified_ms}\n"
                    ).encode(),
                )
                self._last_persisted_ms = self._last_verified_ms

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        plaintext = self.store.read_protected(OFFLINE_FILE)
        if plaintext is None:
            return
        try:
            parts = plaintext.decode("utf-8").split("\n")
            if (
                len(parts) < 4
                or parts[0] != "SwmSdkOfflineBudgetV1"
                or parts[1] != self.install_id
                or parts[2] != self.key_thumbprint
            ):
                return
            value = int(parts[3])
            if value <= 0:
                return
            self._has_record = True
            self._last_verified_ms = value
            self._last_persisted_ms = value
        except Exception:
            return


class Client(OperationsMixin, DownloadMixin, StreamMixin, OptionalMixin):
    """Synchronous Windows desktop client for Software Web Manager."""

    _identity: DeviceIdentity | None
    _offline: OfflineBudget | None
    _current_key: ProtocolKey | None

    def __init__(self, options: ClientOptions) -> None:
        if not supported():
            raise UnsupportedPlatformError()
        validate_options(options)
        self.options = options
        self._base_url = options.base_url
        self._web_url = options.web_base_url or options.base_url
        self._http = options.session or requests.Session()
        self._owns_http = options.session is None
        self._http.max_redirects = 0
        self._store = StateStore(options.app_id, options.storage_directory)
        self._host = HostIntegrityManager(options, self._store)
        self._clock = TrustedClock()
        self._identity: DeviceIdentity | None = None
        self._hardware: HardwareEvidence | None = None
        self._offline: OfflineBudget | None = None
        self._session_token = ""
        self._session_expires_at = 0
        self._current_key: ProtocolKey | None = None
        self._previous_keys: list[ProtocolKey] = []
        self._host_policy_required = bool(self._host.read_cached_policy() or False)
        self._last_failure_action = "shutdown_client"
        self._closed = False
        self._lock = threading.RLock()
        self._key_lock = threading.RLock()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._identity is not None:
                self._identity.close()
            if self._owns_http:
                self._http.close()

    def device_id(self) -> str:
        if self.options.device_id and self.options.device_id.strip():
            return self.options.device_id.strip()
        return self._ensure_identity().device_id

    def install_id(self) -> str:
        return self._ensure_identity().install_id

    def device_key_id(self) -> str:
        return self._ensure_identity().key_id

    def key_thumbprint(self) -> str:
        return self._ensure_identity().key_thumbprint

    def session_token(self) -> str | None:
        with self._lock:
            return self._session_token or None

    def session_expires_at(self) -> int:
        with self._lock:
            return self._session_expires_at

    def cloud_state(self) -> CloudState:
        if not self._clock.is_initialized():
            return CloudState.UNAVAILABLE
        with self._lock:
            if not self._session_token or self._session_expires_at <= self._clock.now_seconds():
                return CloudState.EXPIRED if self._session_expires_at > 0 else CloudState.UNAVAILABLE
            return CloudState.AVAILABLE

    def refresh_online_keys(self) -> None:
        self._ensure_not_closed()
        self._refresh_online_keys(force=True)

    def _ensure_identity(self) -> DeviceIdentity:
        with self._lock:
            if self._closed:
                raise SwmError(ErrorKind.IDENTITY, "client is closed")
            if self._identity is None:
                self._identity = DeviceIdentity.load_or_create(self.options.app_id, self._store)
            return self._identity

    def _hardware_evidence(self) -> HardwareEvidence:
        with self._lock:
            if self._hardware is None:
                self._hardware = collect_hardware_evidence(self.options.app_id)
            return self._hardware

    def _offline_budget(self) -> OfflineBudget:
        identity = self._ensure_identity()
        with self._lock:
            if self._offline is None:
                self._offline = OfflineBudget(self._store, identity.install_id, identity.key_thumbprint)
            return self._offline

    def _is_offline_locked(self) -> bool:
        return self._offline_budget().is_locked(self._clock)

    def _note_verified_interaction(self) -> None:
        self._offline_budget().note_verified(self._clock.now_ms())

    def _ensure_session(self) -> str:
        with self._lock:
            if not self._session_token or self._session_expires_at <= self._clock.now_seconds():
                self._session_token = ""
                self._session_expires_at = 0
                raise SwmError(ErrorKind.SESSION, "authorization session is missing or expired")
            return self._session_token

    def _clear_session(self) -> None:
        with self._lock:
            self._session_token = ""
            self._session_expires_at = 0

    def _install_session(self, token: str, expires_at: int) -> None:
        with self._lock:
            self._session_token = token
            self._session_expires_at = expires_at

    def _ensure_not_closed(self) -> None:
        if self._closed:
            raise SwmError(ErrorKind.CONFIGURATION, "client is closed")

    def _create_device_auth(self, identity: DeviceIdentity, challenge: str | None = None) -> dict[str, Any]:
        hardware = self._hardware_evidence()
        return {
            "install_id": identity.install_id,
            "key_id": identity.key_id,
            "key_thumbprint": identity.key_thumbprint,
            "public_key_sec1": base64url_encode(identity.public_key_sec1),
            "credential_version": "device_credential_v2",
            "challenge": challenge,
            "hardware_evidence": {
                "version": hardware.version,
                "component_mask": hardware.component_mask,
                "aggregate_hash": hardware.aggregate_hash,
            },
        }

    def _make_url(self, path: str, query: list[tuple[str, str]] | None = None) -> str:
        parts = urlsplit(self._base_url)
        return urlunsplit((parts.scheme, parts.netloc, path, urlencode(query or []), ""))

    def _make_web_url(self, path: str) -> str:
        parts = urlsplit(self._web_url)
        return urlunsplit((parts.scheme, parts.netloc, path, "", ""))

    def _send(self, request: ProtocolRequest) -> ProtocolResponse:
        self._ensure_not_closed()
        if request.require_trusted_time and not self._clock.is_initialized():
            self._refresh_trusted_time()
        if request.require_online_key:
            self._refresh_online_keys(force=False)
        if request.require_session:
            self._ensure_session()
        policy = policy_for(request.operation)
        started = time.monotonic()
        last_error: SwmError | None = None
        for attempt in range(policy.retries + 1):
            if policy.deadline > 0 and time.monotonic() - started + policy.timeout > policy.deadline:
                break
            try:
                response = self._send_attempt(request, policy.timeout)
                if is_transient_status(response.status_code) and attempt < policy.retries:
                    delay = retry_after(response.headers)
                    if delay is None:
                        delay = backoff(policy, attempt)
                    if policy.deadline > 0 and (
                        time.monotonic() - started + delay + policy.timeout > policy.deadline
                    ):
                        return response
                    time.sleep(delay)
                    continue
                return response
            except SwmError as error:
                last_error = error
                if error.kind not in {ErrorKind.NETWORK, ErrorKind.TIMEOUT} or attempt >= policy.retries:
                    break
                delay = backoff(policy, attempt)
                if policy.deadline > 0 and (
                    time.monotonic() - started + delay + policy.timeout > policy.deadline
                ):
                    break
                time.sleep(delay)
        raise last_error or SwmError(ErrorKind.TIMEOUT, "request deadline exceeded")

    def _send_attempt(self, request: ProtocolRequest, timeout: float) -> ProtocolResponse:
        url = self._make_url(request.path, request.query)
        timestamp = str(self._clock.now_seconds() if request.require_trusted_time else int(time.time()))
        nonce = random_uuid()
        body = request.body
        session = ""
        headers: dict[str, str] = {
            "X-App-Id": self.options.app_id,
            "X-Timestamp": timestamp,
            "X-Nonce": nonce,
            "X-Authz-Capability": "v3",
            "X-Client-Release-Id": self.options.release_id,
            "X-Client-Version": self.options.version,
            "X-Client-Version-Code": str(self.options.version_code or ""),
        }
        if request.require_session:
            session = self._ensure_session()
            headers["X-SWM-Session"] = session
        if request.require_online_key:
            key = self._get_current_key()
            headers["X-SWM-DPoP"] = self._create_dpop(request.method, url, session, body)
            if request.encrypt_body:
                body = encrypt_request_body(
                    request.method,
                    urlsplit(url).path,
                    _canonical_query(url),
                    int(timestamp),
                    nonce,
                    self.options.app_id,
                    self.options.release_id,
                    self.options.version,
                    self.options.version_code,
                    key.key_id,
                    key.public_key,
                    body,
                )
                headers["X-SWM-Body-Enc"] = "x25519-aes-gcm-v1"
                headers["X-SWM-Online-Key-Id"] = key.key_id
        if request.content_type:
            headers["Content-Type"] = request.content_type
        elif body:
            headers["Content-Type"] = "application/json; charset=utf-8"
        try:
            response = self._http.request(
                request.method,
                url,
                headers=headers,
                data=body,
                timeout=timeout,
                allow_redirects=False,
            )
        except requests.Timeout as error:
            raise SwmError(ErrorKind.TIMEOUT, "request timed out", cause=error) from error
        except requests.RequestException as error:
            raise SwmError(ErrorKind.NETWORK, "network request failed", cause=error) from error
        try:
            content = _read_response_body(response, 16 * 1024 * 1024, "response")
        except requests.RequestException as error:
            raise SwmError(ErrorKind.NETWORK, "response read failed", cause=error) from error
        return ProtocolResponse(response.status_code, content, nonce, response.headers)

    def _send_and_verify(self, request: ProtocolRequest, model: type[T] | None = None) -> T | Any:
        response = self._send(request)
        self._throw_if_error(response)
        data = self._verify_authz(response)
        value = _decode_json(data, "Authz v3 response data")
        return model_from_dict(model, value) if model is not None else value

    def _verify_authz(self, response: ProtocolResponse) -> bytes:
        data = extract_raw_field(response.body, "data")
        if not data or data == b"null":
            raise SwmError(ErrorKind.PROTOCOL, "Authz v3 carrier data is empty")
        payload = _decode_json_object(response.body, "Authz v3 carrier")
        envelope = payload.get("authz")
        if not isinstance(envelope, dict):
            raise SwmError(ErrorKind.PROTOCOL, "Authz v3 carrier is missing authz")
        now = self._clock.now_seconds()
        issued_at = _required_int(envelope, "issued_at", "Authz v3")
        expires_at = _required_int(envelope, "expires_at", "Authz v3")
        if (
            envelope.get("version") != "authz_v3"
            or envelope.get("decision") != "allow"
            or envelope.get("release_id") != self.options.release_id
            or envelope.get("device_id") != self.device_id()
            or envelope.get("nonce") != response.nonce
            or not envelope.get("key_id")
            or issued_at <= 0
            or expires_at <= issued_at
            or expires_at - issued_at > 900
            or issued_at > now + 120
            or expires_at < now - 120
        ):
            raise SwmError(ErrorKind.UNAUTHORIZED, "Authz v3 response identity or lifetime is invalid")
        key = self._find_key(str(envelope.get("key_id")))
        if key is None:
            raise SwmError(ErrorKind.UNAUTHORIZED, "Authz v3 response key is unknown")
        if str(envelope.get("data_sha256", "")).lower() != sha256_hex(data):
            raise SwmError(ErrorKind.INTEGRITY, "Authz v3 response data hash is invalid")
        canonical = "\n".join(
            [
                "authz_v3",
                f"app_id:{self.options.app_id}",
                f"release_id:{envelope.get('release_id', '')}",
                f"device_id:{envelope.get('device_id', '')}",
                f"nonce:{envelope.get('nonce', '')}",
                f"decision:{envelope.get('decision', '')}",
                f"reason:{envelope.get('reason') or ''}",
                f"data_sha256:{envelope.get('data_sha256', '')}",
                f"session:{envelope.get('session') or ''}",
                f"issued_at:{issued_at}",
                f"expires_at:{expires_at}",
                f"key_id:{envelope.get('key_id', '')}",
            ]
        )
        if not verify_ed25519(key.public_key, canonical.encode("utf-8"), str(envelope.get("signature", ""))):
            raise SwmError(ErrorKind.INTEGRITY, "Authz v3 response signature is invalid")
        session = envelope.get("session")
        if session:
            self._install_session(str(session), expires_at)
        self._note_verified_interaction()
        return data

    def _throw_if_error(self, response: ProtocolResponse) -> None:
        if 200 <= response.status_code < 300:
            return
        error = service_error(
            status_code=response.status_code,
            body=response.body,
            retry_after=retry_after(response.headers),
        )
        if error.kind == ErrorKind.INTEGRITY and error.failure_action is not None:
            self._last_failure_action = error.failure_action.value
        raise error

    def _create_dpop(self, method: str, url: str, session: str, body: bytes) -> str:
        identity = self._ensure_identity()
        now = self._clock.now_seconds()
        if now <= 0:
            raise SwmError(ErrorKind.CLOCK, "trusted time is unavailable")
        header = {"alg": "ES256", "kid": identity.key_id, "typ": "swm-dpop+jwt"}
        payload = {
            "app_id": self.options.app_id,
            "ath": base64url_encode(sha256(session.encode("utf-8"))),
            "body_sha256": sha256_hex(body),
            "channel": self.options.channel,
            "device_id": self.device_id(),
            "exp": now + 60,
            "htm": method.upper(),
            "htu": url,
            "iat": now,
            "install_id": identity.install_id,
            "jti": random_uuid(),
            "pcid": self.device_id(),
            "release_id": self.options.release_id,
        }
        signing_input = (
            base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
            + "."
            + base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        )
        signature = identity.sign_digest(sha256(signing_input.encode("utf-8")))
        return signing_input + "." + base64url_encode(signature)

    def _refresh_trusted_time(self) -> None:
        started = time.monotonic()
        response = self._send(
            ProtocolRequest("trusted_time", "GET", "/api/client/time")
        )
        received = time.monotonic()
        self._throw_if_error(response)
        manifest = _decode_json_object(response.body, "signed server time")
        server_time_ms = _required_int(manifest, "server_time_ms", "signed server time")
        expires_at_ms = _required_int(manifest, "expires_at_ms", "signed server time")
        if (
            manifest.get("manifest_version") != "server_time_v1"
            or manifest.get("app_id") != self.options.app_id
            or manifest.get("release_id") != self.options.release_id
            or manifest.get("nonce") != response.nonce
            or manifest.get("root_trust_key_id") != self.options.root_trust_key_id
            or not manifest.get("signature")
            or server_time_ms <= 0
            or expires_at_ms <= server_time_ms
            or expires_at_ms - server_time_ms > 60_000
        ):
            raise SwmError(ErrorKind.CLOCK, "signed server time identity or lifetime is invalid")
        canonical = "\n".join(
            [
                "server_time_v1",
                f"app_id:{manifest['app_id']}",
                f"release_id:{manifest['release_id']}",
                f"nonce:{manifest['nonce']}",
                f"server_time_ms:{server_time_ms}",
                f"expires_at_ms:{expires_at_ms}",
                f"root_trust_key_id:{manifest['root_trust_key_id']}",
            ]
        )
        if not verify_ed25519(
            self.options.root_trust_public_key,
            canonical.encode("utf-8"),
            manifest["signature"],
        ):
            raise SwmError(ErrorKind.CLOCK, "signed server time signature is invalid")
        self._clock.set_authoritative(server_time_ms, started, received)
        self._note_verified_interaction()

    def _refresh_online_keys(self, force: bool) -> None:
        if not force and self._has_fresh_key():
            return
        with self._key_lock:
            if not force and self._has_fresh_key():
                return
            if not self._clock.is_initialized():
                self._refresh_trusted_time()
            try:
                response = self._send(
                    ProtocolRequest(
                        "online_key",
                        "GET",
                        "/api/client/key-manifest",
                        require_trusted_time=True,
                    )
                )
            except SwmError:
                if self._can_use_current_key():
                    return
                raise
            try:
                self._throw_if_error(response)
            except SwmError:
                if is_transient_status(response.status_code) and self._can_use_current_key():
                    return
                raise
            manifest = _decode_json_object(response.body, "online key manifest")
            issued_at = _required_int(manifest, "issued_at", "online key manifest")
            refresh_after = _required_int(manifest, "refresh_after", "online key manifest")
            if (
                manifest.get("manifest_version") != "online_key_manifest_v1"
                or manifest.get("purpose") != "online_body"
                or manifest.get("app_id") != self.options.app_id
                or manifest.get("release_id") != self.options.release_id
                or manifest.get("root_trust_key_id") != self.options.root_trust_key_id
                or not manifest.get("key_id")
                or not manifest.get("public_key")
                or not manifest.get("root_trust_signature")
                or issued_at <= 0
                or refresh_after <= issued_at
                or refresh_after - issued_at > 30 * 24 * 60 * 60
            ):
                raise SwmError(ErrorKind.INTEGRITY, "online key manifest identity or lifetime is invalid")
            now = self._clock.now_seconds()
            if issued_at > now + 120 or refresh_after < now - 120:
                raise SwmError(ErrorKind.INTEGRITY, "online key manifest is outside its accepted lifetime")
            canonical = "\n".join(
                [
                    manifest["manifest_version"],
                    f"purpose:{manifest['purpose']}",
                    f"app_id:{manifest['app_id']}",
                    f"release_id:{manifest['release_id']}",
                    f"key_id:{manifest['key_id']}",
                    f"public_key:{manifest['public_key']}",
                    f"root_trust_key_id:{manifest['root_trust_key_id']}",
                    f"issued_at:{issued_at}",
                    f"refresh_after:{refresh_after}",
                ]
            )
            if not verify_ed25519(
                self.options.root_trust_public_key,
                canonical.encode("utf-8"),
                manifest["root_trust_signature"],
            ):
                raise SwmError(ErrorKind.INTEGRITY, "online key manifest root signature is invalid")
            self._install_key(
                ProtocolKey(
                    key_id=str(manifest["key_id"]),
                    public_key=str(manifest["public_key"]),
                    issued_at=issued_at,
                    refresh_after=refresh_after,
                )
            )

    def _has_fresh_key(self) -> bool:
        with self._lock:
            return (
                self._current_key is not None
                and self._clock.is_initialized()
                and self._clock.now_seconds() < self._current_key.refresh_after - 300
            )

    def _can_use_current_key(self) -> bool:
        with self._lock:
            return (
                self._current_key is not None
                and self._clock.is_initialized()
                and self._clock.now_seconds() < self._current_key.refresh_after
            )

    def _get_current_key(self) -> ProtocolKey:
        with self._lock:
            if self._current_key is None:
                raise SwmError(ErrorKind.SESSION, "online authorization key is unavailable")
            if self._clock.is_initialized() and self._clock.now_seconds() >= self._current_key.refresh_after:
                raise SwmError(ErrorKind.SESSION, "online authorization key has expired")
            return self._current_key

    def _find_key(self, key_id: str) -> ProtocolKey | None:
        with self._lock:
            if self._current_key and self._current_key.key_id == key_id:
                return self._current_key
            for key in reversed(self._previous_keys):
                if key.key_id == key_id:
                    return key
            return None

    def _install_key(self, next_key: ProtocolKey) -> None:
        with self._lock:
            if self._current_key and self._current_key.key_id == next_key.key_id:
                if self._current_key.public_key != next_key.public_key:
                    raise SwmError(ErrorKind.INTEGRITY, "online key id was rebound to different key material")
                self._current_key = next_key
                return
            for key in self._previous_keys:
                if key.key_id == next_key.key_id and key.public_key != next_key.public_key:
                    raise SwmError(
                        ErrorKind.INTEGRITY,
                        "online key id was rebound to different key material",
                    )
            if self._current_key is not None:
                self._previous_keys.append(self._current_key)
                self._previous_keys = self._previous_keys[-4:]
            self._previous_keys = [
                key for key in self._previous_keys if key.key_id != next_key.key_id
            ]
            self._current_key = next_key

    def _set_host_policy_required(self, required: bool) -> None:
        self._host_policy_required = required
        self._host.store_policy(required)

    def _host_required(self) -> bool:
        return self._host_policy_required

    def _last_failure(self) -> str:
        return self._last_failure_action


def _canonical_query(url: str) -> str:
    from .crypto import canonical_query

    return canonical_query(url)


def _decode_json(raw: bytes, context: str) -> Any:
    try:
        return json.loads(raw)
    except Exception as error:
        raise SwmError(ErrorKind.PROTOCOL, f"{context} is not valid JSON", cause=error) from error


def _decode_json_object(raw: bytes, context: str) -> dict[str, Any]:
    value = _decode_json(raw, context)
    if not isinstance(value, dict):
        raise SwmError(ErrorKind.PROTOCOL, f"{context} must be a JSON object")
    return value


def _required_int(value: dict[str, Any], field: str, context: str) -> int:
    raw = value.get(field)
    if raw is None:
        raise SwmError(ErrorKind.PROTOCOL, f"{context} field {field} is invalid")
    try:
        parsed = int(raw)
    except (TypeError, ValueError, OverflowError) as error:
        raise SwmError(ErrorKind.PROTOCOL, f"{context} field {field} is invalid", cause=error) from error
    return parsed


def _read_response_body(response: requests.Response, maximum: int, context: str) -> bytes:
    if response.raw is None or response._content_consumed:
        content = response.content
        if len(content) > maximum:
            raise SwmError(ErrorKind.PROTOCOL, f"{context} body exceeds the accepted limit")
        return content
    body = bytearray()
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        body.extend(chunk)
        if len(body) > maximum:
            raise SwmError(ErrorKind.PROTOCOL, f"{context} body exceeds the accepted limit")
    return bytes(body)
