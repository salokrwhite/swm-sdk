use crate::error::{Error, ErrorKind, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use url::Url;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

pub(crate) const BODY_ENCRYPTION_LABEL: &str = "swm-body-x25519-aes-gcm-v1";

pub(crate) fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

pub(crate) fn sha256_hex(value: &[u8]) -> String {
    hex::encode(sha256(value))
}

pub(crate) fn random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut value = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut value);
    Ok(value)
}

pub(crate) fn random_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub(crate) fn base64url_encode(value: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value)
}

pub(crate) fn base64url_decode(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|error| Error::new(ErrorKind::Cryptographic, error.to_string()).with_source(error))
}

pub(crate) fn decode_key_material(value: &str) -> Result<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::new(
            ErrorKind::Cryptographic,
            "key material is empty",
        ));
    }
    if value.len() % 2 == 0 {
        if let Ok(decoded) = hex::decode(value) {
            return Ok(decoded);
        }
    }
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) {
        return Ok(decoded);
    }
    base64url_decode(value)
}

pub(crate) fn verify_ed25519(public_key: &str, message: &[u8], signature: &str) -> Result<bool> {
    let public_key = decode_key_material(public_key)?;
    let signature = decode_key_material(signature)?;
    if public_key.len() != 32 || signature.len() != 64 {
        return Err(Error::new(
            ErrorKind::Cryptographic,
            "Ed25519 key or signature has an invalid length",
        ));
    }
    let key = VerifyingKey::from_bytes(
        public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Cryptographic, "invalid Ed25519 public key"))?,
    )
    .map_err(|error| Error::new(ErrorKind::Cryptographic, error.to_string()).with_source(error))?;
    let signature = Signature::from_slice(&signature).map_err(|error| {
        Error::new(ErrorKind::Cryptographic, error.to_string()).with_source(error)
    })?;
    Ok(key.verify(message, &signature).is_ok())
}

pub(crate) fn hmac_sha256_hex(secret: &str, value: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts keys of arbitrary size");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub(crate) fn canonical_query(url: &Url) -> String {
    let mut pairs = BTreeMap::<String, Vec<String>>::new();
    for (key, value) in url.query_pairs() {
        pairs
            .entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    let mut output = Vec::new();
    for (key, mut values) in pairs {
        values.sort();
        for value in values {
            output.push(format!(
                "{}={}",
                escape_canonical(&key),
                escape_canonical(&value)
            ));
        }
    }
    output.join("&")
}

fn escape_canonical(value: &str) -> String {
    let mut output = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'.' | b'_' | b'~') {
            output.push(*byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

pub(crate) fn build_body_encryption_aad(
    method: &str,
    path: &str,
    query: &str,
    timestamp: i64,
    nonce: &str,
    app_id: &str,
    release_id: &str,
    release_version: &str,
    release_version_code: Option<i32>,
    online_key_id: &str,
) -> String {
    [
        BODY_ENCRYPTION_LABEL.to_string(),
        method.to_ascii_uppercase(),
        path.to_string(),
        query.to_string(),
        String::new(),
        timestamp.to_string(),
        nonce.to_string(),
        app_id.to_string(),
        format!("client_release_id:{release_id}"),
        format!("client_version:{release_version}"),
        format!(
            "client_version_code:{}",
            release_version_code
                .map(|value| value.to_string())
                .unwrap_or_default()
        ),
        "authz_capability:v3".into(),
        "body_enc:x25519-aes-gcm-v1".into(),
        format!("key_id:{online_key_id}"),
    ]
    .join("\n")
}

pub(crate) fn encrypt_request_body(
    method: &str,
    path: &str,
    query: &str,
    timestamp: i64,
    nonce: &str,
    app_id: &str,
    release_id: &str,
    release_version: &str,
    release_version_code: Option<i32>,
    online_key_id: &str,
    online_public_key: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let ed25519_public_key = decode_key_material(online_public_key)?;
    if ed25519_public_key.len() != 32 {
        return Err(Error::new(
            ErrorKind::Cryptographic,
            "online authorization key must be a 32-byte Ed25519 key",
        ));
    }
    let server_public_key = ed25519_public_key_to_x25519(&ed25519_public_key)?;
    let server_public_key = PublicKey::from(server_public_key);
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(&server_public_key);

    let context = [
        BODY_ENCRYPTION_LABEL.to_string(),
        format!("app_id:{app_id}"),
        format!("release_id:{release_id}"),
        format!("key_id:{online_key_id}"),
        format!("public_key:{}", hex::encode(&ed25519_public_key)),
    ]
    .join("\n");
    let salt = sha256(context.as_bytes());
    let info = format!(
        "{context}\nephemeral_public:{}",
        base64url_encode(ephemeral_public.as_bytes())
    );
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());
    let mut request_key = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut request_key)
        .map_err(|_| Error::new(ErrorKind::Cryptographic, "HKDF expand failed"))?;

    let cipher = Aes256Gcm::new_from_slice(&request_key)
        .map_err(|error| Error::new(ErrorKind::Cryptographic, error.to_string()))?;
    request_key.zeroize();
    let mut aes_nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut aes_nonce);
    let aad = build_body_encryption_aad(
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
    );
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&aes_nonce),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::new(ErrorKind::Cryptographic, "AES-GCM encryption failed"))?;
    let mut sealed = Vec::with_capacity(32 + 12 + ciphertext.len());
    sealed.extend_from_slice(ephemeral_public.as_bytes());
    sealed.extend_from_slice(&aes_nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

fn ed25519_public_key_to_x25519(encoded: &[u8]) -> Result<[u8; 32]> {
    let compressed = CompressedEdwardsY(
        encoded
            .try_into()
            .map_err(|_| Error::new(ErrorKind::Cryptographic, "invalid Ed25519 key length"))?,
    );
    let point = compressed
        .decompress()
        .ok_or_else(|| Error::new(ErrorKind::Cryptographic, "Ed25519 key is not a valid point"))?;
    Ok(point.to_montgomery().to_bytes())
}

pub(crate) fn constant_time_eq(left: &str, right: &str) -> bool {
    use subtle::ConstantTimeEq;
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sha2::Sha512;

    #[test]
    fn converts_ed25519_to_x25519_and_encrypts_body() {
        let seed = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let converted = ed25519_public_key_to_x25519(&public_key).unwrap();
        let digest = Sha512::digest(seed);
        let mut private = [0u8; 32];
        private.copy_from_slice(&digest[..32]);
        private[0] &= 248;
        private[31] &= 127;
        private[31] |= 64;
        let x25519_private = x25519_dalek::StaticSecret::from(private);
        let x25519_public = PublicKey::from(&x25519_private);
        assert_eq!(converted, x25519_public.to_bytes());

        let plaintext = b"hello rust sdk";
        let sealed = encrypt_request_body(
            "POST",
            "/api/client/update-check",
            "",
            1_700_000_000,
            "nonce",
            "app",
            "release",
            "1.0.0",
            None,
            "key-1",
            &hex::encode(public_key),
            plaintext,
        )
        .unwrap();
        assert!(sealed.len() > 60);
    }
}
