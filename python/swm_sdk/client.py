import base64
import binascii
import hashlib
import json
import os
import random
import threading
import time
from dataclasses import dataclass, fields
from typing import Any, Callable, Dict, Optional

import requests


class FeedbackDisabledError(Exception):
    pass


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
        app_key: str,
        timeout: int = 30,
        retries: int = 2,
        backoff: float = 0.5,
        public_key: Optional[str] = None,
        verify_signature: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.app_key = app_key
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

    def _request(self, method: str, path: str, payload: Dict[str, Any]):
        last_err = None
        for attempt in range(self.retries + 1):
            try:
                resp = requests.request(
                    method,
                    f"{self.base_url}{path}",
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                return resp
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
                    params: Dict[str, Any] = {
                        "app_key": self.app_key,
                        "channel_code": channel_code,
                        "platform": platform,
                        "arch": arch,
                        "device_id": device_id,
                    }
                    if options.current_version:
                        params["current_version"] = options.current_version
                    if options.version_code is not None:
                        params["version_code"] = options.version_code
                    with requests.get(
                        f"{self.base_url}/api/client/updates/stream",
                        params=params,
                        timeout=self.timeout,
                        stream=True,
                    ) as resp:
                        if resp.status_code in (401, 403):
                            raise RuntimeError(f"stream unauthorized: {resp.status_code}")
                        resp.raise_for_status()
                        backoff = max(300, int(options.reconnect_backoff_ms or 1500))
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
                                    if event_type != "connected":
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
            "app_key": self.app_key,
            "channel_code": self.channel,
            "current_version": current_version,
            "version_code": version_code,
            "platform": self.platform,
            "arch": self.arch,
            "device_id": self.device_id,
            "attributes": self.attributes,
        }
        resp = self._request("POST", "/api/client/update-check", payload)
        data = resp.json()
        maintenance_raw = data.get("maintenance") if isinstance(data, dict) else None
        result = UpdateCheckResponse(**_filter_known(UpdateCheckResponse, data))
        if isinstance(maintenance_raw, dict):
            result.maintenance = Maintenance(**_filter_known(Maintenance, maintenance_raw))
        if self.verify_signature and result.signature and result.checksum_sha256:
            self._verify_signature(result.checksum_sha256, result.signature)
        return result

    def report_event(self, event_name: str, properties: Optional[Dict[str, Any]] = None) -> None:
        payload = {
            "app_key": self.app_key,
            "device_id": self.device_id,
            "event_name": event_name,
            "event_time": None,
            "channel_code": self.channel,
            "properties": properties or {},
            "attributes": self.attributes,
        }
        self._request("POST", "/api/client/events", payload)

    def report_heartbeat(self, app_version: Optional[str] = None, user_id: Optional[str] = None) -> None:
        if not self.device_id:
            raise ValueError("device_id required")
        payload: Dict[str, Any] = {
            "app_key": self.app_key,
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
        self._request("POST", "/api/client/heartbeat", payload)

    def report_events(self, events: list[Dict[str, Any]]) -> None:
        payload = {
            "app_key": self.app_key,
            "events": events,
        }
        self._request("POST", "/api/client/events", payload)

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
            "app_key": self.app_key,
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
            resp = requests.post(
                f"{self.base_url}/api/client/feedback",
                data=data,
                files=files,
                timeout=self.timeout,
            )
            if resp.status_code >= 400 and _is_feedback_disabled(resp):
                raise FeedbackDisabledError("feedback disabled")
            resp.raise_for_status()
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
