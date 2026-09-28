from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from threading import RLock

from .errors import ErrorKind, SwmError
from .models import IntegrityEvidence
from .options import ClientOptions
from .rim2 import Rim2Manifest, parse_and_verify
from .state import INTEGRITY_POLICY_FILE, StateStore


class HostIntegrityManager:
    def __init__(self, options: ClientOptions, store: StateStore) -> None:
        self.options = options
        self.store = store
        self._lock = RLock()
        self._manifest: Rim2Manifest | None = None
        self._root: Path | None = None

    def read_cached_policy(self) -> bool | None:
        plaintext = self.store.read_protected(INTEGRITY_POLICY_FILE)
        if plaintext is None:
            return None
        try:
            parts = plaintext.decode("utf-8").split("\n")
            if (
                len(parts) < 5
                or parts[0] != "SwmSdkIntegrityPolicyV1"
                or parts[2] != self.options.app_id
                or parts[3] != self.options.release_id
                or parts[4] != _version_code(self.options.version_code)
            ):
                return None
            return {"1": True, "0": False}.get(parts[1])
        except Exception:
            return None

    def store_policy(self, required: bool) -> None:
        if self.read_cached_policy() == required:
            return
        text = "\n".join(
            [
                "SwmSdkIntegrityPolicyV1",
                "1" if required else "0",
                self.options.app_id,
                self.options.release_id,
                _version_code(self.options.version_code),
                str(int(__import__("time").time() * 1000)),
            ]
        ) + "\n"
        self.store.write_protected(INTEGRITY_POLICY_FILE, text.encode("utf-8"))

    def get_evidence(self) -> IntegrityEvidence:
        provider = self.options.host_integrity.evidence_provider
        if provider is not None:
            return provider.get_evidence(
                self.options.app_id,
                self.options.release_id,
                self.options.version,
                self.options.version_code,
                self.options.arch,
                self.package_root(),
                self.options.host_integrity.manifest_path,
            )
        if not self.options.host_integrity.enabled:
            return IntegrityEvidence()
        try:
            manifest = self.load_manifest()
            root = self.package_root()
            files: dict[str, str] = {}
            for item in manifest.files:
                path = resolve_package_path(root, item.path)
                if not path.exists():
                    continue
                files[item.path.lower()] = _hash_file(path)
            return IntegrityEvidence(
                integrity_state="verified",
                integrity_evidence_version=2,
                integrity_manifest_sha256=manifest.manifest_sha256,
                integrity_files=files,
            )
        except SwmError as error:
            return IntegrityEvidence(
                integrity_state="failed",
                integrity_failure_code=error.code or "host_integrity_internal_error",
            )
        except Exception:
            return IntegrityEvidence(
                integrity_state="failed",
                integrity_failure_code="host_file_io_failed",
            )

    def get_required_evidence(self) -> IntegrityEvidence:
        evidence = self.get_evidence()
        if evidence.integrity_state == "failed":
            raise SwmError(
                ErrorKind.INTEGRITY,
                evidence.integrity_failure_code or "host_integrity_internal_error",
                code=evidence.integrity_failure_code,
            )
        return evidence

    def resolve_operation_hashes(self, host_path: str, module_path: str) -> tuple[str, str]:
        if not host_path or not module_path:
            raise SwmError(ErrorKind.VALIDATION, "host and consumer module paths are required")
        return _hash_file(Path(host_path)), _hash_file(Path(module_path))

    def load_manifest(self) -> Rim2Manifest:
        root = self.package_root()
        with self._lock:
            if self._manifest is not None and self._root == root:
                return self._manifest
            path = resolve_package_path(root, self.options.host_integrity.manifest_path)
            raw = path.read_bytes()
            manifest = parse_and_verify(
                raw,
                self.options.app_id,
                self.options.release_id,
                self.options.version,
                self.options.version_code,
                self.options.arch,
                self.options.root_trust_key_id,
                self.options.root_trust_public_key,
            )
            self._manifest = manifest
            self._root = root
            return manifest

    def package_root(self) -> Path:
        if self.options.host_integrity.package_root:
            return Path(self.options.host_integrity.package_root).resolve()
        return Path(sys.executable).resolve().parent


def resolve_package_path(root: Path, relative: str) -> Path:
    normalized = relative.replace("\\", "/")
    if (
        not normalized
        or normalized.startswith("/")
        or ":" in normalized
        or any(part in {"", ".", ".."} for part in normalized.split("/"))
    ):
        raise SwmError(ErrorKind.INTEGRITY, "integrity path is unsafe", code="host_unsafe_path")
    path = (root / normalized).resolve()
    if root.resolve() not in path.parents and path != root.resolve():
        raise SwmError(ErrorKind.INTEGRITY, "integrity path escapes package root", code="host_unsafe_path")
    return path


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _version_code(value: int | None) -> str:
    return "" if value is None else str(value)
