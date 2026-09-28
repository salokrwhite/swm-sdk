from __future__ import annotations

from ..errors import UnsupportedPlatformError


def supported() -> bool:
    return False


def protect(_plaintext: bytes, _entropy: bytes) -> bytes:
    raise UnsupportedPlatformError()


def unprotect(_ciphertext: bytes, _entropy: bytes) -> bytes:
    raise UnsupportedPlatformError()


class IdentityKey:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise UnsupportedPlatformError()


def collect_hardware_evidence(_app_id: str) -> object:
    raise UnsupportedPlatformError()
