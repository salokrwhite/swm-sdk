from __future__ import annotations

import datetime as dt
import json
import os
import re
from typing import Any

from .crypto import base64url_encode, random_bytes, sha256_hex, verify_ed25519
from .errors import ErrorKind, SwmError
from .models import (
    DeviceKeyRotationResult,
    EnrollmentTicket,
    Event,
    FeedbackRequest,
    FeedbackResult,
    HeartbeatResult,
    OperationAuthorizationRequest,
    OperationConsumptionReceipt,
    OperationGrant,
    UpdateInfo,
    model_from_dict,
    model_to_dict,
)
from .options import CheckUpdateOptions, HeartbeatOptions
from .pipeline import ProtocolRequest


class OperationsMixin:
    _identity: Any
    _offline: Any

    def check_update(self, options: CheckUpdateOptions | None = None) -> UpdateInfo:
        self._ensure_not_closed()  # type: ignore[attr-defined]
        options = options or CheckUpdateOptions()
        evidence = self._host.get_evidence()  # type: ignore[attr-defined]
        challenge: str | None = None
        for attempt in range(2):
            identity = self._ensure_identity()  # type: ignore[attr-defined]
            payload = {
                "channel_code": self.options.channel,  # type: ignore[attr-defined]
                "current_version": self.options.version,  # type: ignore[attr-defined]
                "version_code": self.options.version_code,  # type: ignore[attr-defined]
                "platform": self.options.platform,  # type: ignore[attr-defined]
                "arch": self.options.arch,  # type: ignore[attr-defined]
                "device_id": self.device_id(),  # type: ignore[attr-defined]
                "user_id": options.user_id,
                "attributes": options.attributes,
                "device_auth": self._create_device_auth(identity, challenge),  # type: ignore[attr-defined]
                "integrity_state": evidence.integrity_state,
                "integrity_failure_code": evidence.integrity_failure_code,
                "integrity_evidence_version": evidence.integrity_evidence_version,
                "integrity_manifest_sha256": evidence.integrity_manifest_sha256,
                "integrity_files": evidence.integrity_files,
            }
            response = self._send(  # type: ignore[attr-defined]
                ProtocolRequest(
                    "update_check",
                    "POST",
                    "/api/client/update-check",
                    json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                    encrypt_body=True,
                    require_trusted_time=True,
                    require_online_key=True,
                )
            )
            if response.status_code == 428 and attempt == 0:
                challenge_data = _decode_json_object(response.body, "device registration challenge")
                if (
                    not challenge_data.get("challenge")
                    or _required_int(challenge_data, "expires_at", "device registration challenge")
                    <= self._clock.now_seconds()  # type: ignore[attr-defined]
                ):
                    raise SwmError(ErrorKind.PROTOCOL, "device registration challenge is missing or expired")
                challenge = str(challenge_data["challenge"])
                continue
            self._throw_if_error(response)  # type: ignore[attr-defined]
            data = self._verify_authz(response)  # type: ignore[attr-defined]
            update = model_from_dict(UpdateInfo, _decode_json(data, "update response"))
            self._set_host_policy_required(update.host_integrity_required)  # type: ignore[attr-defined]
            verify_update_artifact(update, self.options)  # type: ignore[attr-defined]
            return update
        raise SwmError(ErrorKind.PROTOCOL, "device registration challenge retry was exhausted")

    def report_heartbeat(self, options: HeartbeatOptions | None = None) -> HeartbeatResult:
        self._ensure_not_closed()  # type: ignore[attr-defined]
        options = options or HeartbeatOptions()
        evidence = self._host.get_evidence()  # type: ignore[attr-defined]
        if self._host_required() and evidence.integrity_state != "verified":  # type: ignore[attr-defined]
            raise SwmError(
                ErrorKind.INTEGRITY,
                evidence.integrity_failure_code or "host_manifest_missing",
                code=evidence.integrity_failure_code,
            )
        payload = {
            "device_id": self.device_id(),  # type: ignore[attr-defined]
            "channel_code": self.options.channel,  # type: ignore[attr-defined]
            "app_version": options.app_version or self.options.version,  # type: ignore[attr-defined]
            "platform": self.options.platform,  # type: ignore[attr-defined]
            "arch": self.options.arch,  # type: ignore[attr-defined]
            "user_id": options.user_id,
            "attributes": options.attributes,
            "integrity_evidence_version": evidence.integrity_evidence_version,
            "integrity_manifest_sha256": evidence.integrity_manifest_sha256,
            "integrity_files": evidence.integrity_files,
        }
        return self._send_and_verify(  # type: ignore[attr-defined]
            ProtocolRequest(
                "heartbeat",
                "POST",
                "/api/client/heartbeat",
                json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                encrypt_body=True,
                require_session=True,
                require_trusted_time=True,
                require_online_key=True,
            ),
            HeartbeatResult,
        )

    def report_event(self, event_name: str, properties: dict[str, Any] | None = None) -> None:
        self.report_events(
            [
                Event(
                    event_name=event_name,
                    event_time=dt.datetime.now(dt.timezone.utc),
                    device_id=self.device_id(),  # type: ignore[attr-defined]
                    channel_code=self.options.channel,  # type: ignore[attr-defined]
                    properties=properties,
                )
            ]
        )

    def report_events(self, events: list[Event]) -> None:
        self._ensure_not_closed()  # type: ignore[attr-defined]
        if not events:
            return
        normalized: list[dict[str, Any]] = []
        for event in events:
            if not event.event_name.strip():
                raise SwmError(ErrorKind.VALIDATION, "event_name is required")
            event.device_id = event.device_id or self.device_id()  # type: ignore[attr-defined]
            event.channel_code = event.channel_code or self.options.channel  # type: ignore[attr-defined]
            normalized.append(model_to_dict(event))
        body = normalized[0] if len(normalized) == 1 else {"events": normalized}
        self._send_and_verify(  # type: ignore[attr-defined]
            ProtocolRequest(
                "events",
                "POST",
                "/api/client/events",
                json.dumps(body, separators=(",", ":")).encode("utf-8"),
                encrypt_body=True,
                require_session=True,
                require_trusted_time=True,
                require_online_key=True,
            )
        )

    def submit_feedback(self, request: FeedbackRequest) -> FeedbackResult:
        self._ensure_not_closed()  # type: ignore[attr-defined]
        if not request.content.strip():
            raise SwmError(
                ErrorKind.VALIDATION,
                "feedback content is required",
                code="feedback_content_required",
            )
        if request.rating is not None and not 1 <= request.rating <= 5:
            raise SwmError(
                ErrorKind.VALIDATION,
                "feedback rating must be between 1 and 5",
                code="feedback_rating_invalid",
            )
        body, content_type = build_feedback_payload(self, request)
        return self._send_and_verify(  # type: ignore[attr-defined]
            ProtocolRequest(
                "feedback",
                "POST",
                "/api/client/feedback",
                body,
                encrypt_body=True,
                require_session=True,
                require_trusted_time=True,
                require_online_key=True,
                content_type=content_type,
            ),
            FeedbackResult,
        )

    def request_enrollment_ticket(self, audience: str) -> EnrollmentTicket:
        self._ensure_not_closed()  # type: ignore[attr-defined]
        audience = audience.strip().lower()
        if not audience:
            raise SwmError(ErrorKind.VALIDATION, "enrollment audience is required")
        return self._send_and_verify(  # type: ignore[attr-defined]
            ProtocolRequest(
                "enrollment",
                "POST",
                "/api/client/enrollment-ticket",
                json.dumps({"audience": audience}, separators=(",", ":")).encode("utf-8"),
                encrypt_body=True,
                require_session=True,
                require_trusted_time=True,
                require_online_key=True,
            ),
            EnrollmentTicket,
        )

    def rotate_device_key(self) -> DeviceKeyRotationResult:
        from .identity import DeviceIdentity

        self._ensure_not_closed()  # type: ignore[attr-defined]
        if not self._clock.is_initialized():  # type: ignore[attr-defined]
            self._refresh_trusted_time()  # type: ignore[attr-defined]
        self._refresh_online_keys(False)  # type: ignore[attr-defined]
        self._ensure_session()  # type: ignore[attr-defined]
        pending = DeviceIdentity.create_pending(self.options.app_id, self._store)  # type: ignore[attr-defined]
        challenge: str | None = None
        proof_digest: str | None = None
        try:
            for attempt in range(2):
                device_auth = self._create_device_auth(pending, challenge)  # type: ignore[attr-defined]
                proof = None
                if challenge and proof_digest:
                    proof = base64url_encode(pending.sign_digest(bytes.fromhex(proof_digest)))
                response = self._send(  # type: ignore[attr-defined]
                    ProtocolRequest(
                        "rotation",
                        "POST",
                        "/api/client/device-key/rotate",
                        json.dumps(
                            {"new_device_auth": device_auth, "new_key_proof": proof},
                            separators=(",", ":"),
                        ).encode("utf-8"),
                        encrypt_body=True,
                        require_session=True,
                        require_trusted_time=True,
                        require_online_key=True,
                    )
                )
                if response.status_code == 428 and attempt == 0:
                    value = _decode_json_object(response.body, "device key rotation challenge")
                    if (
                        not value.get("challenge")
                        or not value.get("proof_digest")
                        or _required_int(value, "expires_at", "device key rotation challenge")
                        <= self._clock.now_seconds()  # type: ignore[attr-defined]
                    ):
                        raise SwmError(ErrorKind.PROTOCOL, "device key rotation challenge is invalid")
                    challenge = str(value["challenge"])
                    proof_digest = str(value["proof_digest"])
                    continue
                self._throw_if_error(response)  # type: ignore[attr-defined]
                value = _decode_json_object(response.body, "device key rotation response")
                if (
                    not value.get("rotated")
                    or not _is_uuid(str(value.get("registration_id", "")))
                    or value.get("install_id") != pending.install_id
                    or value.get("key_id") != pending.key_id
                ):
                    raise SwmError(ErrorKind.PROTOCOL, "device key rotation response is invalid")
                pending.commit_pending()
                with self._lock:  # type: ignore[attr-defined]
                    previous = self._identity  # type: ignore[attr-defined,has-type]
                    self._identity = pending  # type: ignore[attr-defined]
                    self._offline = None  # type: ignore[attr-defined]
                if previous is not None:
                    previous.close()
                self._clear_session()  # type: ignore[attr-defined]
                return DeviceKeyRotationResult(
                    registration_id=str(value["registration_id"]),
                    install_id=pending.install_id,
                    key_id=pending.key_id,
                    device_id=self.device_id(),  # type: ignore[attr-defined]
                )
        except Exception:
            pending.delete_pending()
            raise
        raise SwmError(ErrorKind.PROTOCOL, "device key rotation challenge retry was exhausted")

    def authorize_operation(self, request: OperationAuthorizationRequest) -> OperationGrant:
        self._ensure_not_closed()  # type: ignore[attr-defined]
        if self._is_offline_locked():  # type: ignore[attr-defined]
            raise SwmError(ErrorKind.OFFLINE_BUDGET, "offline budget exceeded")
        operation = request.operation.strip()
        consumer_module = request.consumer_module.strip()
        if (
            not operation
            or not request.plan
            or request.step_count <= 0
            or request.step_count > 100000
            or not consumer_module
        ):
            raise SwmError(ErrorKind.VALIDATION, "operation authorization request is invalid")
        has_host_path = bool(request.host_executable_path)
        has_module_path = bool(request.consumer_module_path)
        if has_host_path != has_module_path:
            raise SwmError(ErrorKind.VALIDATION, "host and consumer module paths must be provided together")
        host_bound = has_host_path or self._host_required()  # type: ignore[attr-defined]
        if host_bound and not has_host_path:
            raise SwmError(ErrorKind.VALIDATION, "host-bound operation requires both paths")
        challenge = request.consumer_challenge or random_bytes(32)
        if len(challenge) != 32:
            raise SwmError(ErrorKind.VALIDATION, "consumer challenge must contain exactly 32 bytes")
        manifest_sha = None
        host_hash = None
        module_hash = None
        if host_bound:
            evidence = self._host.get_required_evidence()  # type: ignore[attr-defined]
            manifest_sha = evidence.integrity_manifest_sha256
            host_hash, module_hash = self._host.resolve_operation_hashes(  # type: ignore[attr-defined]
                str(request.host_executable_path),
                str(request.consumer_module_path),
            )
        payload = {
            "schema": "operation_grant_v3_host" if host_bound else "operation_grant_v3_unbound",
            "operation": operation,
            "plan_sha256": sha256_hex(request.plan),
            "step_count": request.step_count,
            "total_bytes": request.total_bytes,
            "consumer_challenge": challenge.hex(),
            "integrity_manifest_sha256": manifest_sha,
            "host_exe_sha256": host_hash,
            "consumer_module": consumer_module,
            "consumer_module_sha256": module_hash,
        }
        return self._send_and_verify(  # type: ignore[attr-defined]
            ProtocolRequest(
                "operation_authorization",
                "POST",
                "/api/client/operation-authorizations",
                json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                encrypt_body=True,
                require_session=True,
                require_trusted_time=True,
                require_online_key=True,
            ),
            OperationGrant,
        )

    def consume_operation_authorization(self, grant: OperationGrant) -> OperationConsumptionReceipt:
        self._ensure_not_closed()  # type: ignore[attr-defined]
        if self._is_offline_locked():  # type: ignore[attr-defined]
            raise SwmError(ErrorKind.OFFLINE_BUDGET, "offline budget exceeded")
        if (
            grant.schema not in {"operation_grant_v3_host", "operation_grant_v3_unbound"}
            or not _is_uuid(grant.grant_id)
            or not grant.operation
            or len(grant.plan_sha256) != 64
            or not grant.consumer_module
            or not grant.consumer_challenge
            or grant.step_count == 0
            or grant.issued_at <= 0
            or grant.expires_at <= grant.issued_at
        ):
            raise SwmError(ErrorKind.VALIDATION, "operation grant is incomplete or invalid")
        payload = {
            "schema": "operation_grant_consume_v2",
            "grant_id": grant.grant_id,
            "operation": grant.operation,
            "plan_sha256": grant.plan_sha256,
            "step_count": grant.step_count,
            "total_bytes": grant.total_bytes,
            "consumer_challenge": grant.consumer_challenge,
            "issued_at": grant.issued_at,
            "expires_at": grant.expires_at,
            "integrity_manifest_sha256": grant.integrity_manifest_sha256,
            "host_exe_sha256": grant.host_exe_sha256,
            "consumer_module": grant.consumer_module,
            "consumer_module_sha256": grant.consumer_module_sha256,
        }
        return self._send_and_verify(  # type: ignore[attr-defined]
            ProtocolRequest(
                "operation_consume",
                "POST",
                "/api/client/operation-authorizations/consume",
                json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                encrypt_body=True,
                require_session=True,
                require_trusted_time=True,
                require_online_key=True,
            ),
            OperationConsumptionReceipt,
        )


def build_feedback_payload(client: Any, request: FeedbackRequest) -> tuple[bytes, str]:
    if len(request.attachment_paths) > 3:
        raise SwmError(
            ErrorKind.VALIDATION,
            "feedback supports at most 3 attachments",
            code="feedback_attachments_limit",
        )
    boundary = "----------------------------" + random_bytes(12).hex()
    body = bytearray()

    def field(name: str, value: str) -> None:
        body.extend(f"--{boundary}\r\n".encode("ascii"))
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("ascii"))
        body.extend(value.encode("utf-8"))
        body.extend(b"\r\n")

    field("device_id", client.device_id())
    field("channel_code", client.options.channel)
    field("content", request.content)
    if request.rating is not None:
        field("rating", str(request.rating))
    if request.contact:
        field("contact", request.contact)
    field("app_version", request.app_version or client.options.version)
    if request.metadata:
        try:
            metadata = json.dumps(request.metadata, separators=(",", ":"))
        except (TypeError, ValueError) as error:
            raise SwmError(
                ErrorKind.VALIDATION,
                "feedback metadata must be JSON-serializable",
                code="feedback_metadata_invalid",
                cause=error,
            ) from error
        field("metadata", metadata)
    for path_value in request.attachment_paths:
        if not str(path_value).strip():
            continue
        path = os.path.abspath(path_value)
        try:
            if not os.path.isfile(path):
                raise SwmError(
                    ErrorKind.VALIDATION,
                    "feedback attachment is not a file",
                    code="feedback_attachment_invalid",
                )
            size = os.path.getsize(path)
        except SwmError:
            raise
        except OSError as error:
            raise SwmError(
                ErrorKind.VALIDATION,
                "feedback attachment could not be read",
                code="feedback_attachment_invalid",
                cause=error,
            ) from error
        if size > 5 * 1024 * 1024:
            raise SwmError(
                ErrorKind.VALIDATION,
                "feedback attachment exceeds 5 MiB",
                code="feedback_attachment_too_large",
            )
        if len(body) + size + 1024 > 32 * 1024 * 1024:
            raise SwmError(
                ErrorKind.VALIDATION,
                "feedback payload exceeds 32 MiB",
                code="feedback_payload_too_large",
            )
        body.extend(f"--{boundary}\r\n".encode("ascii"))
        filename = _escape_multipart_value(os.path.basename(path))
        body.extend(
            f'Content-Disposition: form-data; name="attachments"; filename="{filename}"\r\n'.encode()
        )
        body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
        try:
            read_size = 0
            with open(path, "rb") as stream:
                while True:
                    chunk = stream.read(128 * 1024)
                    if not chunk:
                        break
                    read_size += len(chunk)
                    if read_size > 5 * 1024 * 1024:
                        raise SwmError(
                            ErrorKind.VALIDATION,
                            "feedback attachment exceeds 5 MiB",
                            code="feedback_attachment_too_large",
                        )
                    body.extend(chunk)
        except SwmError:
            raise
        except OSError as error:
            raise SwmError(
                ErrorKind.VALIDATION,
                "feedback attachment could not be read",
                code="feedback_attachment_invalid",
                cause=error,
            ) from error
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("ascii"))
    if len(body) > 32 * 1024 * 1024:
        raise SwmError(
            ErrorKind.VALIDATION,
            "feedback payload exceeds 32 MiB",
            code="feedback_payload_too_large",
        )
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def verify_update_artifact(update: UpdateInfo, options: Any) -> None:
    if (
        not update.update_available
        or update.open_in_browser
        or (update.delivery_method or "").lower() == "external_link"
    ):
        return
    required = [
        update.release_id,
        update.version,
        update.download_url,
        update.artifact_file_name,
        update.manifest_key_id,
        update.manifest_public_key,
        update.root_trust_key_id,
        update.root_trust_signature,
        update.signature,
        update.checksum_sha256,
    ]
    if (
        any(not value for value in required)
        or len(update.checksum_sha256 or "") != 64
        or update.size <= 0
        or (update.artifact_platform or "").lower() != "windows"
        or (update.artifact_arch or "").lower() != options.arch
    ):
        raise SwmError(ErrorKind.INTEGRITY, "artifact manifest is incomplete")
    if update.root_trust_key_id != options.root_trust_key_id:
        raise SwmError(ErrorKind.INTEGRITY, "artifact root trust key mismatch")
    root_canonical = "\n".join(
        [
            "root_trust_manifest_v1",
            f"app_id:{options.app_id}",
            f"signer_key_id:{options.root_trust_key_id}",
            f"key_id:{update.manifest_key_id}",
            f"public_key:{update.manifest_public_key}",
        ]
    )
    if not verify_ed25519(
        options.root_trust_public_key,
        root_canonical.encode("utf-8"),
        update.root_trust_signature or "",
    ):
        raise SwmError(ErrorKind.INTEGRITY, "artifact root trust signature is invalid")
    verify_artifact_manifest(update)


def verify_artifact_manifest(update: UpdateInfo) -> None:
    canonical = "\n".join(
        [
            "artifact_manifest_v1",
            f"release_id:{update.release_id or ''}",
            f"release_version:{update.version or ''}",
            f"version_code:{update.version_code if update.version_code is not None else ''}",
            f"platform:{(update.artifact_platform or '').lower()}",
            f"arch:{(update.artifact_arch or '').lower()}",
            f"size:{update.size}",
            f"sha256:{(update.checksum_sha256 or '').lower()}",
            f"key_id:{update.manifest_key_id or ''}",
        ]
    )
    if not verify_ed25519(
        update.manifest_public_key or "",
        canonical.encode("utf-8"),
        update.signature or "",
    ):
        raise SwmError(ErrorKind.INTEGRITY, "artifact manifest signature is invalid")


def _is_uuid(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            value,
        )
    )


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


def _escape_multipart_value(value: str) -> str:
    return value.replace('"', "%22").replace("\r", "").replace("\n", "")
