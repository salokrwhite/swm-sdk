import base64
import binascii
import hashlib
import hmac
import json
import os
import random
import threading
import time
import uuid
from dataclasses import dataclass, fields
from typing import Any, Callable, Dict, Optional
from urllib.parse import quote

import requests


class FeedbackDisabledError(Exception):
    pass


API_ERROR_CODE_AUTHZ_INVALID = "authz_invalid"
API_ERROR_CODE_AUTHZ_DENIED = "authz_denied"


class AuthzError(Exception):
    """Raised when a required authorization verdict is missing or invalid (fail closed)."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def _is_feedback_disabled(resp) -> bool:
    try:
        payload = resp.json()
    except Exception:
        return False
    if not isinstance(payload, dict):
        return False
    err = payload.get("error")
    if isinstance(err, dict):
        return str(err.get("code", "")).strip().lower() == "feedback_disabled"
    if isinstance(err, str):
        return err.strip().lower() == "feedback_disabled"
    return False


CONTROL_EVENT_SHUTDOWN = "device_shutdown"
CONTROL_EVENT_MAINTENANCE_SCHEDULED = "maintenance_scheduled"
CONTROL_EVENT_MAINTENANCE_CANCELLED = "maintenance_cancelled"


@dataclass
class Maintenance:
    enabled: bool = False
    start_at: Optional[str] = None
    message: Optional[str] = None
    active: bool = False


@dataclass
class AuthzEnvelope:
    decision: Optional[str] = None
    nonce: Optional[str] = None
    device_id: Optional[str] = None
    issued_at: int = 0
    expires_at: int = 0
    key_id: Optional[str] = None
    reason: Optional[str] = None
    signature: Optional[str] = None


@dataclass
class UpdateCheckResponse:
    update_available: bool
    mandatory: bool
    heartbeat_interval_seconds: Optional[int] = None
    open_in_browser: Optional[bool] = None
    delivery_method: Optional[str] = None
    release_id: Optional[str] = None
    version: Optional[str] = None
    notes: Optional[str] = None
    download_url: Optional[str] = None
    checksum_sha256: Optional[str] = None
    signature: Optional[str] = None
    size: Optional[int] = None
    rollback_allowed: Optional[bool] = None
    release_notes_url: Optional[str] = None
    maintenance: Optional[Maintenance] = None
    authz: Optional[AuthzEnvelope] = None


@dataclass
class UpdatePushEvent:
    event_type: str
    org_id: str
    app_id: str
    channel_code: str
    platform: str
    arch: str
    release_id: str
    published_at: str
    reason: str
    id: Optional[str] = None
    message: Optional[str] = None
    maintenance_start_at: Optional[str] = None


def _filter_known(cls, data: Dict[str, Any]) -> Dict[str, Any]:
    known = {f.name for f in fields(cls)}
    return {k: v for k, v in data.items() if k in known}


@dataclass
class UpdateStreamOptions:
    channel_code: Optional[str] = None
    platform: Optional[str] = None
    arch: Optional[str] = None
    device_id: Optional[str] = None
    current_version: Optional[str] = None
    version_code: Optional[int] = None
    reconnect: bool = True
    reconnect_backoff_ms: int = 1500
    reconnect_max_backoff_ms: int = 20000
    jitter: bool = True
    on_error: Optional[Callable[[Exception], None]] = None


class UpdateWatchHandle:
    def __init__(self, stop_event: threading.Event, thread: threading.Thread):
        self._stop_event = stop_event
        self._thread = thread

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)


class Client:
    def __init__(
        self,
        base_url: str,
        app_id: str,
        app_secret: str,
        timeout: int = 30,
        retries: int = 2,
        backoff: float = 0.5,
        public_key: Optional[str] = None,
        verify_signature: bool = False,
        require_authz: bool = False,
        authz_clock_skew_seconds: int = 120,
    ):
        self.base_url = base_url.rstrip("/")
        self.app_id = app_id
        self.app_secret = app_secret
        self.channel = ""
        self.platform = ""
        self.arch = ""
        self.device_id = ""
        self.attributes: Dict[str, Any] = {}
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.public_key = public_key
        self.verify_signature = verify_signature
        # When true, every call that can carry a signed verdict fails closed unless
        # the response has a valid Ed25519 "allow" bound to this request + device.
        self.require_authz = require_authz
        # key_id -> Ed25519 public key (hex or base64).
        self.authz_public_keys: Dict[str, str] = {}
        self.authz_clock_skew_seconds = authz_clock_skew_seconds

    # --- request signing (HMAC) -------------------------------------------------

    @staticmethod
    def _canonical_query(pairs) -> str:
        items = sorted(((str(k), str(v)) for k, v in pairs), key=lambda kv: (kv[0], kv[1]))
        return "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in items)

    @staticmethod
    def _sha256_hex(body: bytes) -> str:
        return hashlib.sha256(body or b"").hexdigest()

    def _hmac_hex(self, canonical: str) -> str:
        return hmac.new(self.app_secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def _sign_headers(self, method: str, pathname: str, canonical_q: str, body: bytes):
        ts = str(int(time.time()))
        nonce = str(uuid.uuid4())
        canonical = "\n".join([
            method.upper(),
            pathname,
            canonical_q,
            self._sha256_hex(body),
            ts,
            nonce,
            self.app_id,
        ])
        headers = {
            "X-App-Id": self.app_id,
            "X-Timestamp": ts,
            "X-Nonce": nonce,
            "X-Signature": self._hmac_hex(canonical),
            "X-Sign-Version": "v1",
        }
        return headers, nonce

    # --- authz verification -----------------------------------------------------

    @staticmethod
    def _decode_key_material(value: str) -> bytes:
        v = (value or "").strip()
        if not v:
            raise AuthzError(API_ERROR_CODE_AUTHZ_INVALID, "empty key material")
        if len(v) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in v):
            return binascii.unhexlify(v)
        return base64.b64decode(v)

    @staticmethod
    def _authz_canonical(app_id: str, env: AuthzEnvelope) -> str:
        return "\n".join([
            "authz_v1",
            "app_id:" + app_id,
            "device_id:" + (env.device_id or ""),
            "nonce:" + (env.nonce or ""),
            "decision:" + (env.decision or ""),
            "reason:" + (env.reason or ""),
            "issued_at:" + str(env.issued_at or 0),
            "expires_at:" + str(env.expires_at or 0),
            "key_id:" + (env.key_id or ""),
        ])

    def _verify_authz(self, env: Optional[AuthzEnvelope], request_nonce: str) -> None:
        if not self.require_authz:
            return
        if env is None:
            raise AuthzError(API_ERROR_CODE_AUTHZ_INVALID, "authorization missing")
        if not request_nonce or env.nonce != request_nonce:
            raise AuthzError(API_ERROR_CODE_AUTHZ_INVALID, "authorization nonce mismatch")
        if (env.device_id or "") != (self.device_id or ""):
            raise AuthzError(API_ERROR_CODE_AUTHZ_INVALID, "authorization device mismatch")
        skew = self.authz_clock_skew_seconds if self.authz_clock_skew_seconds > 0 else 120
        now = int(time.time())
        if (env.expires_at or 0) <= 0 or now > (env.expires_at or 0) + skew:
            raise AuthzError(API_ERROR_CODE_AUTHZ_INVALID, "authorization expired")
        key_id = env.key_id or ""
        pub_encoded = self.authz_public_keys.get(key_id)
        if not pub_encoded or not pub_encoded.strip():
            raise AuthzError(API_ERROR_CODE_AUTHZ_INVALID, f"authorization key unknown: {key_id}")
        if not env.signature or not env.signature.strip():
            raise AuthzError(API_ERROR_CODE_AUTHZ_INVALID, "authorization signature missing")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("cryptography is required for authz verification") from exc
        pub_bytes = self._decode_key_material(pub_encoded)
        if len(pub_bytes) != 32:
            raise AuthzError(API_ERROR_CODE_AUTHZ_INVALID, "authorization public key invalid")
        sig_bytes = self._decode_key_material(env.signature)
        msg = self._authz_canonical(self.app_id, env).encode("utf-8")
        try:
            Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, msg)
        except AuthzError:
            raise
        except Exception:  # noqa: BLE001
            raise AuthzError(API_ERROR_CODE_AUTHZ_INVALID, "authorization signature invalid")
        if env.decision != "allow":
            reason = env.reason if (env.reason and env.reason.strip()) else "access denied"
            raise AuthzError(API_ERROR_CODE_AUTHZ_DENIED, f"authorization denied: {reason}")

    def _verify_response_authz(self, resp, request_nonce: str) -> None:
        if not self.require_authz:
            return
        env = None
        try:
            payload = resp.json()
            if isinstance(payload, dict) and isinstance(payload.get("authz"), dict):
                env = AuthzEnvelope(**_filter_known(AuthzEnvelope, payload["authz"]))
        except Exception:  # noqa: BLE001
            env = None
        self._verify_authz(env, request_nonce)

    def _request(self, method: str, path: str, payload: Dict[str, Any]):
        # Serialize once and sign the exact bytes we send (the server hashes the raw body).
        body = json.dumps(payload).encode("utf-8")
        last_err = None
        for attempt in range(self.retries + 1):
            try:
                headers, nonce = self._sign_headers(method, path, "", body)
                headers["Content-Type"] = "application/json"
                resp = requests.request(
                    method,
                    f"{self.base_url}{path}",
                    data=body,
                    headers=headers,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                return resp, nonce
            except Exception as err:  # noqa: BLE001
                last_err = err
                if attempt >= self.retries:
                    raise
                time.sleep(self.backoff * (2 ** attempt))
        raise last_err  # type: ignore[misc]

    def start_update_stream(self, options: UpdateStreamOptions, on_event: Callable[[UpdatePushEvent], None]) -> UpdateWatchHandle:
        channel_code = (options.channel_code or self.channel or "").strip()
        platform = (options.platform or self.platform or "").strip()
        arch = (options.arch or self.arch or "").strip()
        device_id = (options.device_id or self.device_id or "").strip()
        if not channel_code or not platform or not arch or not device_id:
            raise ValueError("channel_code/platform/arch/device_id required")

        stop_event = threading.Event()

        def loop() -> None:
            backoff = max(300, int(options.reconnect_backoff_ms or 1500))
            max_backoff = max(backoff, int(options.reconnect_max_backoff_ms or 20000))
            while not stop_event.is_set():
                try:
                    pairs = [
                        ("device_id", device_id),
                        ("channel_code", channel_code),
                        ("platform", platform),
                        ("arch", arch),
                    ]
                    if options.current_version:
                        pairs.append(("current_version", options.current_version))
                    if options.version_code is not None:
                        pairs.append(("version_code", str(options.version_code)))
                    canonical_q = self._canonical_query(pairs)
                    headers, nonce = self._sign_headers("GET", "/api/client/updates/stream", canonical_q, b"")
                    with requests.get(
                        f"{self.base_url}/api/client/updates/stream?{canonical_q}",
                        headers=headers,
                        timeout=self.timeout,
                        stream=True,
                    ) as resp:
                        if resp.status_code in (401, 403):
                            raise RuntimeError(f"stream unauthorized: {resp.status_code}")
                        resp.raise_for_status()
                        backoff = max(300, int(options.reconnect_backoff_ms or 1500))
                        # When require_authz, ignore pushed events until a valid authz
                        # event proves the stream comes from the real server.
                        authz_ok = not self.require_authz
                        event_type = ""
                        data_lines: list[str] = []
                        for raw in resp.iter_lines(decode_unicode=True):
                            if stop_event.is_set():
                                return
                            if raw is None:
                                continue
                            line = raw.strip()
                            if not line:
                                if data_lines:
                                    data = "\n".join(data_lines)
                                    if event_type == "authz":
                                        if self.require_authz:
                                            try:
                                                env = AuthzEnvelope(**_filter_known(AuthzEnvelope, json.loads(data)))
                                            except AuthzError:
                                                raise
                                            except Exception:  # noqa: BLE001
                                                raise AuthzError(API_ERROR_CODE_AUTHZ_INVALID, "authorization malformed")
                                            self._verify_authz(env, nonce)
                                            authz_ok = True
                                    elif event_type != "connected" and authz_ok:
                                        payload = json.loads(data)
                                        on_event(UpdatePushEvent(**_filter_known(UpdatePushEvent, payload)))
                                event_type = ""
                                data_lines = []
                                continue
                            if line.startswith(":"):
                                continue
                            if line.startswith("event:"):
                                event_type = line[6:].strip()
                            elif line.startswith("data:"):
                                data_lines.append(line[5:].strip())
                except Exception as err:  # noqa: BLE001
                    if options.on_error:
                        options.on_error(err)
                    # A failed/denied verdict means the server is fake or the device
                    # is revoked — stop, don't reconnect.
                    if isinstance(err, AuthzError):
                        return
                    if not options.reconnect:
                        return
                    wait_ms = backoff
                    if options.jitter:
                        wait_ms += random.randint(0, max(1, wait_ms // 2))
                    time.sleep(wait_ms / 1000.0)
                    backoff = min(max_backoff, backoff * 2)

        t = threading.Thread(target=loop, daemon=True)
        t.start()
        return UpdateWatchHandle(stop_event, t)

    def watch_updates(self, options: UpdateStreamOptions, on_update_available: Callable[[UpdateCheckResponse], None]) -> UpdateWatchHandle:
        def handle_event(_: UpdatePushEvent) -> None:
            try:
                resp = self.check_update(options.current_version or "", options.version_code)
                if resp.update_available:
                    on_update_available(resp)
            except Exception as err:  # noqa: BLE001
                if options.on_error:
                    options.on_error(err)

        return self.start_update_stream(options, handle_event)

    def check_update(self, current_version: str, version_code: Optional[int] = None) -> UpdateCheckResponse:
        payload = {
            "channel_code": self.channel,
            "current_version": current_version,
            "version_code": version_code,
            "platform": self.platform,
            "arch": self.arch,
            "device_id": self.device_id,
            "attributes": self.attributes,
        }
        resp, nonce = self._request("POST", "/api/client/update-check", payload)
        data = resp.json()
        maintenance_raw = data.get("maintenance") if isinstance(data, dict) else None
        authz_raw = data.get("authz") if isinstance(data, dict) else None
        result = UpdateCheckResponse(**_filter_known(UpdateCheckResponse, data))
        if isinstance(maintenance_raw, dict):
            result.maintenance = Maintenance(**_filter_known(Maintenance, maintenance_raw))
        result.authz = AuthzEnvelope(**_filter_known(AuthzEnvelope, authz_raw)) if isinstance(authz_raw, dict) else None
        # Fail closed: when require_authz, the response must carry a valid signed "allow".
        self._verify_authz(result.authz, nonce)
        if self.verify_signature and result.signature and result.checksum_sha256:
            self._verify_signature(result.checksum_sha256, result.signature)
        return result

    def report_event(self, event_name: str, properties: Optional[Dict[str, Any]] = None) -> None:
        payload = {
            "device_id": self.device_id,
            "event_name": event_name,
            "event_time": None,
            "channel_code": self.channel,
            "properties": properties or {},
            "attributes": self.attributes,
        }
        resp, nonce = self._request("POST", "/api/client/events", payload)
        self._verify_response_authz(resp, nonce)

    def report_heartbeat(self, app_version: Optional[str] = None, user_id: Optional[str] = None) -> None:
        if not self.device_id:
            raise ValueError("device_id required")
        payload: Dict[str, Any] = {
            "device_id": self.device_id,
        }
        if self.channel:
            payload["channel_code"] = self.channel
        if app_version:
            payload["app_version"] = app_version
        if self.platform:
            payload["platform"] = self.platform
        if self.arch:
            payload["arch"] = self.arch
        if user_id:
            payload["user_id"] = user_id
        if self.attributes:
            payload["attributes"] = self.attributes
        resp, nonce = self._request("POST", "/api/client/heartbeat", payload)
        self._verify_response_authz(resp, nonce)

    def report_events(self, events: list[Dict[str, Any]]) -> None:
        payload = {
            "events": events,
        }
        resp, nonce = self._request("POST", "/api/client/events", payload)
        self._verify_response_authz(resp, nonce)

    def report_feedback(
        self,
        content: str,
        rating: Optional[int] = None,
        contact: Optional[str] = None,
        attachments: Optional[list[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not content or not content.strip():
            raise ValueError("content required")
        data = {
            "device_id": self.device_id,
            "channel_code": self.channel,
            "content": content,
        }
        if rating is not None:
            data["rating"] = str(rating)
        if contact:
            data["contact"] = contact
        merged = dict(metadata or {})
        if self.attributes and "attributes" not in merged:
            merged["attributes"] = self.attributes
        if merged:
            data["metadata"] = json.dumps(merged)
            if "app_version" in merged:
                data["app_version"] = str(merged["app_version"])

        files: list[tuple[str, Any]] = []
        for file_path in attachments or []:
            if not file_path:
                continue
            files.append(("attachments", open(file_path, "rb")))
        try:
            # Build the request to materialize the exact multipart body, then sign it
            # (the server's request signature covers the raw body bytes).
            session = requests.Session()
            prepared = session.prepare_request(
                requests.Request("POST", f"{self.base_url}/api/client/feedback", data=data, files=files)
            )
            body = prepared.body if prepared.body is not None else b""
            if isinstance(body, str):
                body = body.encode("utf-8")
            headers, nonce = self._sign_headers("POST", "/api/client/feedback", "", body)
            prepared.headers.update(headers)
            resp = session.send(prepared, timeout=self.timeout)
            if resp.status_code >= 400 and _is_feedback_disabled(resp):
                raise FeedbackDisabledError("feedback disabled")
            resp.raise_for_status()
            self._verify_response_authz(resp, nonce)
        finally:
            for _, fh in files:
                try:
                    fh.close()
                except Exception:
                    pass

    def download(
        self,
        url: str,
        dest_path: str,
        checksum_sha256: Optional[str] = None,
        signature: Optional[str] = None,
        chunk_size: int = 1024 * 32,
    ) -> None:
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        sha256 = hashlib.sha256()

        with requests.get(url, stream=True, timeout=self.timeout) as r:
            r.raise_for_status()
            with open(dest_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if not chunk:
                        continue
                    f.write(chunk)
                    sha256.update(chunk)

        if checksum_sha256:
            got = sha256.hexdigest()
            if got.lower() != checksum_sha256.lower():
                raise ValueError(f"checksum mismatch: {got} != {checksum_sha256}")
        if self.verify_signature and signature and checksum_sha256:
            self._verify_signature(checksum_sha256, signature)

    def _verify_signature(self, checksum_hex: str, signature: str) -> None:
        if not self.public_key:
            return
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError("cryptography is required for signature verification") from exc
        pub_bytes = self._decode_base64_or_hex(self.public_key)
        sig_bytes = self._decode_base64_or_hex(signature)
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub.verify(sig_bytes, checksum_hex.encode("utf-8"))

    @staticmethod
    def _decode_base64_or_hex(value: str) -> bytes:
        value = value.strip()
        try:
            return base64.b64decode(value)
        except Exception:
            return binascii.unhexlify(value)
