from __future__ import annotations

import json
import random
import time
from collections.abc import Iterator
from typing import Any

import requests
from requests.structures import CaseInsensitiveDict

from .crypto import random_uuid
from .errors import ErrorKind, SwmError
from .models import (
    DebugDecisionEvent,
    DebugRequestTicket,
    UpdateEvent,
    UpdateStreamOptions,
    model_from_dict,
)
from .pipeline import ProtocolResponse


class StreamMixin:
    def watch_updates(self, options: UpdateStreamOptions | None = None) -> Iterator[UpdateEvent]:
        options = options or UpdateStreamOptions()
        attempt = 0
        while not self._closed:  # type: ignore[attr-defined]
            try:
                yield from self._read_update_stream_once(options)
                return
            except GeneratorExit:
                return
            except SwmError as error:
                if not options.reconnect or error.kind in {
                    ErrorKind.DEVICE_BLOCKED,
                    ErrorKind.UNSUPPORTED_VERSION,
                    ErrorKind.UPDATE_REGION_BLOCKED,
                    ErrorKind.UNAUTHORIZED,
                    ErrorKind.INTEGRITY,
                }:
                    raise
                delay = min(
                    options.reconnect_backoff * (2 ** min(attempt, 4)),
                    options.reconnect_max_backoff,
                )
                if options.jitter:
                    delay += random.random() * delay / 2
                attempt += 1
                time.sleep(delay)
            except (OSError, ValueError) as error:
                if not options.reconnect:
                    raise SwmError(ErrorKind.NETWORK, str(error), cause=error) from error
                time.sleep(min(options.reconnect_backoff * (2 ** min(attempt, 4)), options.reconnect_max_backoff))
                attempt += 1

    def _read_update_stream_once(self, options: UpdateStreamOptions) -> Iterator[UpdateEvent]:
        if not self._clock.is_initialized():  # type: ignore[attr-defined]
            self._refresh_trusted_time()  # type: ignore[attr-defined]
        session = self._ensure_session()  # type: ignore[attr-defined]
        query = [
            ("device_id", self.device_id()),  # type: ignore[attr-defined]
            ("channel_code", self.options.channel),  # type: ignore[attr-defined]
            ("platform", self.options.platform),  # type: ignore[attr-defined]
            ("arch", self.options.arch),  # type: ignore[attr-defined]
            ("current_version", options.current_version or self.options.version),  # type: ignore[attr-defined]
        ]
        version_code = options.version_code if options.version_code is not None else self.options.version_code  # type: ignore[attr-defined]
        if version_code is not None:
            query.append(("version_code", str(version_code)))
        url = self._make_url("/api/client/updates/stream", query)  # type: ignore[attr-defined]
        nonce = random_uuid()
        headers = {
            "Accept": "text/event-stream",
            "X-App-Id": self.options.app_id,  # type: ignore[attr-defined]
            "X-Timestamp": str(self._clock.now_seconds()),  # type: ignore[attr-defined]
            "X-Nonce": nonce,
            "X-Authz-Capability": "v3",
            "X-Client-Release-Id": self.options.release_id,  # type: ignore[attr-defined]
            "X-Client-Version": self.options.version,  # type: ignore[attr-defined]
            "X-Client-Version-Code": str(self.options.version_code or ""),  # type: ignore[attr-defined]
            "X-SWM-Session": session,
            "X-SWM-DPoP": self._create_dpop("GET", url, session, b""),  # type: ignore[attr-defined]
        }
        try:
            response = self._http.get(  # type: ignore[attr-defined]
                url,
                headers=headers,
                stream=True,
                allow_redirects=False,
            )
        except requests.Timeout as error:
            raise SwmError(ErrorKind.TIMEOUT, "update stream request timed out", cause=error) from error
        except requests.RequestException as error:
            raise SwmError(ErrorKind.NETWORK, "update stream request failed", cause=error) from error
        try:
            if response.status_code < 200 or response.status_code >= 300:
                raise SwmError(
                    ErrorKind.API,
                    f"update stream failed with HTTP {response.status_code}",
                    status_code=response.status_code,
                    response_body=response.text[:1024],
                )
            event_name = ""
            event_id = ""
            data_lines: list[str] = []
            authz_verified = False
            for raw_line in response.iter_lines(decode_unicode=False):
                line = raw_line.decode("utf-8", errors="replace")
                if line.startswith(":"):
                    continue
                if not line:
                    if data_lines:
                        event, verified = self._parse_update_sse(
                            event_name,
                            event_id,
                            data_lines,
                            nonce,
                            authz_verified,
                        )
                        if verified:
                            authz_verified = True
                        if event is not None:
                            yield event
                    event_name = ""
                    event_id = ""
                    data_lines = []
                    continue
                if line.startswith("event:"):
                    event_name = line[6:].strip()
                elif line.startswith("id:"):
                    event_id = line[3:].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[5:].strip())
        except requests.RequestException as error:
            raise SwmError(ErrorKind.NETWORK, "update stream interrupted", cause=error) from error
        finally:
            response.close()
        raise SwmError(ErrorKind.NETWORK, "update stream closed by server")

    def _parse_update_sse(
        self,
        event_name: str,
        event_id: str,
        data_lines: list[str],
        nonce: str,
        authz_verified: bool,
    ) -> tuple[UpdateEvent | None, bool]:
        if event_name.lower() == "connected":
            return None, False
        if event_name.lower() in {"authz_expired", "authz-expired"}:
            self._clear_session()  # type: ignore[attr-defined]
            raise SwmError(ErrorKind.SESSION, "update stream authorization expired")
        data = "\n".join(data_lines).encode("utf-8")
        if event_name.lower() == "authz":
            self._verify_authz(  # type: ignore[attr-defined]
                ProtocolResponse(200, data, nonce, CaseInsensitiveDict())
            )
            return None, True
        if not authz_verified:
            return None, False
        verified = self._verify_authz(  # type: ignore[attr-defined]
            ProtocolResponse(200, data, nonce, CaseInsensitiveDict())
        )
        event = model_from_dict(UpdateEvent, _decode_json(verified, "update stream event"))
        if not event.id:
            event.id = event_id
        if not event.event_type:
            event.event_type = event_name
        return event, True

    def watch_debug_request(self, ticket: DebugRequestTicket) -> Iterator[DebugDecisionEvent]:
        if (
            not ticket.request_id
            or not ticket.watch_token
            or not ticket.credentials.client_id
            or not ticket.session_id
        ):
            raise SwmError(ErrorKind.VALIDATION, "debug ticket is incomplete")
        response, nonce = self._open_debug_stream(ticket)  # type: ignore[attr-defined]
        try:
            if response.status_code < 200 or response.status_code >= 300:
                raise SwmError(
                    ErrorKind.API,
                    f"debug stream failed with HTTP {response.status_code}",
                    status_code=response.status_code,
                    response_body=response.text[:1024],
                )
            expected_hash = __import__("hashlib").sha256(ticket.session_id.encode("utf-8")).hexdigest()
            event_name = ""
            data_lines: list[str] = []
            for raw_line in response.iter_lines(decode_unicode=False):
                line = raw_line.decode("utf-8", errors="replace")
                if not line:
                    if data_lines and event_name in {"debug-request-state", "debug_request_state"}:
                        data = "\n".join(data_lines).encode("utf-8")
                        verified = self._verify_authz(  # type: ignore[attr-defined]
                            ProtocolResponse(200, data, nonce, CaseInsensitiveDict())
                        )
                        payload = _decode_json_object(verified, "debug decision payload")
                        expires_at = _required_int(payload, "expires_at", "debug decision payload")
                        if (
                            payload.get("version") != "debug_decision_v1"
                            or payload.get("request_id") != ticket.request_id
                            or str(payload.get("session_id_hash", "")).lower() != expected_hash
                            or payload.get("status") not in {"pending", "approved", "rejected", "cancelled"}
                            or expires_at <= 0
                        ):
                            raise SwmError(ErrorKind.PROTOCOL, "debug decision payload is invalid")
                        decision = DebugDecisionEvent(
                            state=str(payload["status"]),
                            reason=payload.get("reason")
                            if isinstance(payload.get("reason"), str)
                            else None,
                            authorization_expires_at=expires_at
                            if payload["status"] == "approved"
                            else 0,
                        )
                        yield decision
                        if decision.state in {"approved", "rejected", "cancelled"}:
                            return
                    event_name = ""
                    data_lines = []
                    continue
                if line.startswith("event:"):
                    event_name = line[6:].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[5:].strip())
        except requests.RequestException as error:
            raise SwmError(ErrorKind.NETWORK, "debug stream interrupted", cause=error) from error
        finally:
            response.close()


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
        return int(raw)
    except (TypeError, ValueError, OverflowError) as error:
        raise SwmError(ErrorKind.PROTOCOL, f"{context} field {field} is invalid", cause=error) from error
