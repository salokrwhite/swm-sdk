from __future__ import annotations

import hashlib
import threading

from .crypto import base64url_encode, random_bytes, sha256
from .errors import IdentityError
from .platform import IdentityKey
from .state import IDENTITY_FILE, StateStore

_creation_locks: dict[str, threading.Lock] = {}
_creation_locks_guard = threading.Lock()


class DeviceIdentity:
    def __init__(
        self,
        store: StateStore,
        key: IdentityKey,
        install_id: str,
        device_id: str,
        key_id: str,
        key_thumbprint: str,
        public_key_sec1: bytes,
    ) -> None:
        self.store = store
        self.key = key
        self.install_id = install_id
        self.device_id = device_id
        self.key_id = key_id
        self.key_thumbprint = key_thumbprint
        self.public_key_sec1 = public_key_sec1
        self._lock = threading.RLock()

    @classmethod
    def load_or_create(cls, app_id: str, store: StateStore) -> DeviceIdentity:
        lock_key = f"{store.directory}\n{app_id}"
        with _creation_locks_guard:
            lock = _creation_locks.setdefault(lock_key, threading.Lock())
        with lock:
            metadata = _read_metadata(store)
            if metadata is not None:
                install_id, key_name = metadata
                try:
                    key = IdentityKey.open(key_name)
                    return _from_key(store, key, install_id)
                except Exception:
                    store.delete(IDENTITY_FILE)
            install_id = random_bytes(16).hex()
            key_name = build_key_name(app_id, install_id)
            key = IdentityKey.create(key_name)
            try:
                identity = _from_key(store, key, install_id)
                _write_metadata(store, install_id, key_name)
                return identity
            except Exception:
                key.delete()
                raise

    @classmethod
    def create_pending(cls, app_id: str, store: StateStore) -> DeviceIdentity:
        install_id = random_bytes(16).hex()
        key_name = build_key_name(app_id, install_id)
        key = IdentityKey.create(key_name)
        try:
            return _from_key(store, key, install_id)
        except Exception:
            key.delete()
            raise

    def sign_digest(self, digest: bytes) -> bytes:
        with self._lock:
            return self.key.sign_digest(digest)

    def commit_pending(self) -> None:
        _write_metadata(self.store, self.install_id, self.key.name)

    def delete_pending(self) -> None:
        with self._lock:
            self.key.delete()

    def close(self) -> None:
        with self._lock:
            self.key.close()


def _from_key(store: StateStore, key: IdentityKey, install_id: str) -> DeviceIdentity:
    public_key = key.public_key_sec1()
    if len(public_key) != 65 or public_key[0] != 4:
        raise IdentityError("CNG key did not return a P-256 SEC1 public key")
    thumbprint = base64url_encode(sha256(public_key))
    device_id = hashlib.sha256(
        (
            "device_credential_v2\n"
            f"app_id:{store.app_id}\n"
            f"install_id:{install_id}\n"
            f"key_thumbprint:{thumbprint}"
        ).encode()
    ).hexdigest()
    return DeviceIdentity(
        store=store,
        key=key,
        install_id=install_id,
        device_id=device_id,
        key_id="swm-device-" + thumbprint[:22],
        key_thumbprint=thumbprint,
        public_key_sec1=public_key,
    )


def build_key_name(app_id: str, install_id: str) -> str:
    app_hash = hashlib.sha256(app_id.encode("utf-8")).hexdigest()[:12]
    return f"SwmSdk.{app_hash}.{install_id}"


def _read_metadata(store: StateStore) -> tuple[str, str] | None:
    plaintext = store.read_protected(IDENTITY_FILE)
    if plaintext is None:
        return None
    try:
        parts = plaintext.decode("utf-8").split("\n")
        if len(parts) < 3 or parts[0] != "v2" or len(parts[1]) != 32 or not parts[2].strip():
            return None
        return parts[1], parts[2].strip()
    except Exception:
        return None


def _write_metadata(store: StateStore, install_id: str, key_name: str) -> None:
    store.write_protected(IDENTITY_FILE, f"v2\n{install_id}\n{key_name}\n".encode())
