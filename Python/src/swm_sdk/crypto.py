from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import uuid
from urllib.parse import parse_qsl, quote, urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import CryptographicError

BODY_ENCRYPTION_LABEL = "swm-body-x25519-aes-gcm-v1"


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def random_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)


def random_uuid() -> str:
    return str(uuid.uuid4())


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def base64url_decode(value: str) -> bytes:
    normalized = value.strip().replace("-", "+").replace("_", "/")
    normalized += "=" * ((4 - len(normalized) % 4) % 4)
    try:
        return base64.b64decode(normalized, validate=True)
    except Exception as error:
        raise CryptographicError("invalid base64url value", cause=error) from error


def decode_key_material(value: str) -> bytes:
    value = value.strip()
    if not value:
        raise CryptographicError("key material is empty")
    if len(value) % 2 == 0:
        try:
            return bytes.fromhex(value)
        except ValueError:
            pass
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        return base64url_decode(value)


def verify_ed25519(public_key: str, message: bytes, signature: str) -> bool:
    key_bytes = decode_key_material(public_key)
    signature_bytes = decode_key_material(signature)
    if len(key_bytes) != 32 or len(signature_bytes) != 64:
        raise CryptographicError("Ed25519 key or signature has an invalid length")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature_bytes, message)
        return True
    except Exception:
        return False


def hmac_sha256_hex(secret: str, value: str) -> str:
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def canonical_query(url: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pairs.sort(key=lambda item: (item[0], item[1]))
    return "&".join(
        f"{quote(key, safe='-._~')}={quote(value, safe='-._~')}" for key, value in pairs
    )


def build_body_encryption_aad(
    method: str,
    path: str,
    query: str,
    timestamp: int,
    nonce: str,
    app_id: str,
    release_id: str,
    release_version: str,
    release_version_code: int | None,
    online_key_id: str,
) -> str:
    return "\n".join(
        [
            BODY_ENCRYPTION_LABEL,
            method.upper(),
            path,
            query,
            "",
            str(timestamp),
            nonce,
            app_id,
            f"client_release_id:{release_id}",
            f"client_version:{release_version}",
            f"client_version_code:{release_version_code if release_version_code is not None else ''}",
            "authz_capability:v3",
            "body_enc:x25519-aes-gcm-v1",
            f"key_id:{online_key_id}",
        ]
    )


def ed25519_public_key_to_x25519(encoded: bytes) -> bytes:
    if len(encoded) != 32:
        raise CryptographicError("authorization public key has invalid length")
    y_bytes = bytearray(encoded)
    y_bytes[31] &= 0x7F
    y = int.from_bytes(y_bytes, "little")
    prime = (1 << 255) - 19
    if y >= prime:
        raise CryptographicError("authorization Ed25519 public key is not canonical")
    denominator = (1 - y) % prime
    if denominator == 0:
        raise CryptographicError("authorization Ed25519 public key cannot be converted")
    u = ((1 + y) * pow(denominator, prime - 2, prime)) % prime
    return u.to_bytes(32, "little")


def encrypt_request_body(
    method: str,
    path: str,
    query: str,
    timestamp: int,
    nonce: str,
    app_id: str,
    release_id: str,
    release_version: str,
    release_version_code: int | None,
    online_key_id: str,
    online_public_key: str,
    plaintext: bytes,
) -> bytes:
    ed_key = decode_key_material(online_public_key)
    if len(ed_key) != 32:
        raise CryptographicError("online authorization key must be a 32-byte Ed25519 key")
    server_public = x25519.X25519PublicKey.from_public_bytes(ed25519_public_key_to_x25519(ed_key))
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes_raw()
    shared = ephemeral_private.exchange(server_public)
    context = "\n".join(
        [
            BODY_ENCRYPTION_LABEL,
            f"app_id:{app_id}",
            f"release_id:{release_id}",
            f"key_id:{online_key_id}",
            f"public_key:{ed_key.hex()}",
        ]
    )
    salt = sha256(context.encode("utf-8"))
    info = f"{context}\nephemeral_public:{base64url_encode(ephemeral_public)}"
    request_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info.encode("utf-8"),
    ).derive(shared)
    aes_nonce = os.urandom(12)
    aad = build_body_encryption_aad(
        method,
        path,
        query,
        timestamp,
        nonce,
        app_id,
        release_id,
        release_version,
        release_version_code,
        online_key_id,
    )
    ciphertext = AESGCM(request_key).encrypt(aes_nonce, plaintext, aad.encode("utf-8"))
    return ephemeral_public + aes_nonce + ciphertext
