from __future__ import annotations

import os
from pathlib import Path

from .crypto import sha256, sha256_hex
from .errors import IdentityError
from .platform import protect, unprotect

IDENTITY_FILE = "identity.bin"
OFFLINE_FILE = "offline.bin"
INTEGRITY_POLICY_FILE = "integrity-policy.bin"


class StateStore:
    def __init__(self, app_id: str, override_directory: Path | None = None) -> None:
        self.app_id = app_id
        self.directory = Path(override_directory) if override_directory else _default_directory(app_id)
        self.directory.mkdir(parents=True, exist_ok=True)
        self._entropy = sha256(f"SwmSdkStateV2\n{app_id}".encode())

    def path(self, file_name: str) -> Path:
        return self.directory / file_name

    def read_protected(self, file_name: str) -> bytes | None:
        path = self.path(file_name)
        if not path.exists():
            return None
        try:
            ciphertext = path.read_bytes()
            if not ciphertext or len(ciphertext) > 1024 * 1024:
                return None
            return unprotect(ciphertext, self._entropy)
        except Exception:
            return None

    def write_protected(self, file_name: str, plaintext: bytes) -> None:
        path = self.path(file_name)
        temporary = path.with_suffix(path.suffix + ".tmp")
        try:
            temporary.write_bytes(protect(plaintext, self._entropy))
            os.replace(temporary, path)
        except Exception as error:
            try:
                temporary.unlink(missing_ok=True)
            except Exception:
                pass
            raise IdentityError(f"failed to write protected state {file_name}", cause=error) from error

    def delete(self, file_name: str) -> None:
        try:
            self.path(file_name).unlink(missing_ok=True)
        except OSError:
            pass


def _default_directory(app_id: str) -> Path:
    local = os.environ.get("LOCALAPPDATA")
    root = Path(local) if local else Path.home() / "AppData" / "Local"
    return root / "SwmSdk" / sha256_hex(app_id.encode("utf-8"))[:12]
