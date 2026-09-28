use crate::crypto::{sha256_hex, verify_ed25519};
use crate::error::{Error, ErrorKind, Result};
use std::collections::HashSet;

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAGIC: &[u8] = b"OPLUSRIM";
const MANIFEST_DOMAIN: &[u8] = b"OPLUS_RELEASE_MANIFEST_V2\0";
const KEY_DOMAIN: &[u8] = b"OPLUS_RELEASE_KEY_V2\0";

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct Rim2File {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) sha256: [u8; 32],
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct Rim2Manifest {
    pub(crate) manifest_sha256: String,
    pub(crate) version: String,
    pub(crate) arch: String,
    pub(crate) root_key_id: String,
    pub(crate) signer_key_id: String,
    pub(crate) files: Vec<Rim2File>,
}

pub(crate) fn parse_and_verify(
    raw: &[u8],
    expected_app_id: &str,
    expected_release_id: &str,
    expected_version: &str,
    expected_version_code: Option<i32>,
    expected_arch: &str,
    expected_root_key_id: &str,
    root_trust_public_key: &str,
) -> Result<Rim2Manifest> {
    if raw.is_empty() || raw.len() > MAX_MANIFEST_BYTES {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest size is invalid",
        ));
    }
    if raw.len() < MAGIC.len() || &raw[..MAGIC.len()] != MAGIC {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest magic is invalid",
        ));
    }
    let mut offset = MAGIC.len();
    let protocol_version = read_u16(raw, &mut offset)?;
    let body_size = read_u32(raw, &mut offset)? as usize;
    if protocol_version != 2 || body_size == 0 || offset + body_size > raw.len() {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest header is invalid",
        ));
    }
    let body = &raw[offset..offset + body_size];
    offset += body_size;
    let mut body_offset = 0usize;
    if body.len() < 32 {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest body is truncated",
        ));
    }
    let app_bytes = body[body_offset..body_offset + 16].to_vec();
    body_offset += 16;
    let release_bytes = body[body_offset..body_offset + 16].to_vec();
    body_offset += 16;
    let version_code = read_u64(body, &mut body_offset)?;
    if body_offset + 2 > body.len() {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest body is truncated",
        ));
    }
    let platform = body[body_offset];
    let architecture = body[body_offset + 1];
    body_offset += 2;
    let version = read_string16(body, &mut body_offset)?;
    if version.is_empty() || version.len() > 100 {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 release version is invalid",
        ));
    }
    let file_count = read_u16(body, &mut body_offset)? as usize;
    if file_count == 0 || file_count > 255 {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest file count is invalid",
        ));
    }
    let mut files = Vec::with_capacity(file_count);
    let mut seen = HashSet::new();
    for _ in 0..file_count {
        let path = read_string16(body, &mut body_offset)?;
        let size = read_u64(body, &mut body_offset)?;
        if body_offset + 32 > body.len() {
            return Err(integrity_error(
                "host_manifest_invalid",
                "RIM2 manifest file hash is truncated",
            ));
        }
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&body[body_offset..body_offset + 32]);
        body_offset += 32;
        if !safe_path(&path) || size == 0 || sha256.iter().all(|value| *value == 0) {
            return Err(integrity_error(
                "host_manifest_invalid",
                "RIM2 manifest contains an unsafe file",
            ));
        }
        if !seen.insert(path.to_ascii_lowercase()) {
            return Err(integrity_error(
                "host_manifest_invalid",
                "RIM2 manifest contains a duplicate file path",
            ));
        }
        files.push(Rim2File { path, size, sha256 });
    }
    if body_offset != body.len() {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest body contains trailing bytes",
        ));
    }
    let mut trailer = offset;
    let root_key_id = read_string8(raw, &mut trailer)?;
    let signer_key_id = read_string8(raw, &mut trailer)?;
    if root_key_id.is_empty()
        || root_key_id.len() > 64
        || signer_key_id.is_empty()
        || signer_key_id.len() > 64
        || trailer + 160 > raw.len()
    {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 signing key id or trailer is invalid",
        ));
    }
    let signer_public_key = raw[trailer..trailer + 32].to_vec();
    trailer += 32;
    let root_signature = raw[trailer..trailer + 64].to_vec();
    trailer += 64;
    let manifest_signature = raw[trailer..trailer + 64].to_vec();
    trailer += 64;
    if trailer != raw.len() {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest trailer is invalid",
        ));
    }
    let expected_app_bytes = uuid_bytes(expected_app_id)?;
    let expected_release_bytes = uuid_bytes(expected_release_id)?;
    let version_code_matches = expected_version_code
        .map(|value| value >= 0 && version_code == value as u64)
        .unwrap_or(true);
    if app_bytes != expected_app_bytes
        || release_bytes != expected_release_bytes
        || platform != 1
        || architecture != arch_byte(expected_arch)
        || version != expected_version
        || !version_code_matches
        || root_key_id != expected_root_key_id
    {
        return Err(integrity_error(
            "host_release_mismatch",
            "RIM2 manifest identity does not match this release",
        ));
    }
    let mut key_message = Vec::with_capacity(KEY_DOMAIN.len() + 16 + 64 + 32);
    key_message.extend_from_slice(KEY_DOMAIN);
    key_message.extend_from_slice(&app_bytes);
    append_string8(&mut key_message, &root_key_id);
    append_string8(&mut key_message, &signer_key_id);
    key_message.extend_from_slice(&signer_public_key);
    if !verify_ed25519(
        root_trust_public_key,
        &key_message,
        &base64url_encode(&root_signature),
    )? {
        return Err(integrity_error(
            "host_root_signature_invalid",
            "RIM2 root certificate signature is invalid",
        ));
    }
    let mut manifest_message = MANIFEST_DOMAIN.to_vec();
    manifest_message.extend_from_slice(body);
    if !verify_ed25519(
        &base64url_encode(&signer_public_key),
        &manifest_message,
        &base64url_encode(&manifest_signature),
    )? {
        return Err(integrity_error(
            "host_manifest_signature_invalid",
            "RIM2 manifest signature is invalid",
        ));
    }
    Ok(Rim2Manifest {
        manifest_sha256: sha256_hex(raw),
        version,
        arch: normalize_arch(architecture),
        root_key_id,
        signer_key_id,
        files,
    })
}

fn integrity_error(code: &str, message: &str) -> Error {
    Error::new(ErrorKind::Integrity, message).with_code(code)
}

fn read_u16(value: &[u8], offset: &mut usize) -> Result<u16> {
    if *offset + 2 > value.len() {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest is truncated",
        ));
    }
    let result = u16::from_be_bytes(value[*offset..*offset + 2].try_into().unwrap());
    *offset += 2;
    Ok(result)
}

fn read_u32(value: &[u8], offset: &mut usize) -> Result<u32> {
    if *offset + 4 > value.len() {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest is truncated",
        ));
    }
    let result = u32::from_be_bytes(value[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    Ok(result)
}

fn read_u64(value: &[u8], offset: &mut usize) -> Result<u64> {
    if *offset + 8 > value.len() {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest is truncated",
        ));
    }
    let result = u64::from_be_bytes(value[*offset..*offset + 8].try_into().unwrap());
    *offset += 8;
    Ok(result)
}

fn read_string8(value: &[u8], offset: &mut usize) -> Result<String> {
    if *offset + 1 > value.len() {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest is truncated",
        ));
    }
    let length = value[*offset] as usize;
    *offset += 1;
    read_utf8(value, offset, length)
}

fn read_string16(value: &[u8], offset: &mut usize) -> Result<String> {
    let length = read_u16(value, offset)? as usize;
    read_utf8(value, offset, length)
}

fn read_utf8(value: &[u8], offset: &mut usize, length: usize) -> Result<String> {
    if *offset + length > value.len() {
        return Err(integrity_error(
            "host_manifest_invalid",
            "RIM2 manifest is truncated",
        ));
    }
    let result = std::str::from_utf8(&value[*offset..*offset + length])
        .map_err(|_| {
            integrity_error(
                "host_manifest_invalid",
                "RIM2 manifest contains invalid UTF-8",
            )
        })?
        .to_string();
    *offset += length;
    Ok(result)
}

fn append_string8(target: &mut Vec<u8>, value: &str) {
    target.push(value.len() as u8);
    target.extend_from_slice(value.as_bytes());
}

fn safe_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.contains('\\')
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains(':')
        && !value.contains('\0')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && value
            .chars()
            .all(|character| character >= '\u{20}' && character != '\u{7f}')
}

fn arch_byte(value: &str) -> u8 {
    match value.to_ascii_lowercase().as_str() {
        "x86" | "386" | "i386" | "win-x86" => 1,
        "x64" | "amd64" | "win-x64" => 2,
        _ => 0,
    }
}

fn normalize_arch(value: u8) -> String {
    match value {
        1 => "x86".into(),
        2 => "x64".into(),
        _ => String::new(),
    }
}

fn uuid_bytes(value: &str) -> Result<Vec<u8>> {
    let clean = value.replace('-', "");
    let raw = hex::decode(clean)
        .map_err(|_| integrity_error("host_manifest_invalid", "expected UUID is invalid"))?;
    if raw.len() != 16 {
        return Err(integrity_error(
            "host_manifest_invalid",
            "expected UUID is invalid",
        ));
    }
    Ok(vec![
        raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9], raw[10],
        raw[11], raw[12], raw[13], raw[14], raw[15],
    ])
}

fn base64url_encode(value: &[u8]) -> String {
    crate::crypto::base64url_encode(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn parses_and_rejects_tampered_manifest() {
        let app_id = "00000000-0000-0000-0000-000000000801";
        let release_id = "00000000-0000-0000-0000-000000000802";
        let (raw, root_public) = build_manifest(app_id, release_id);
        let manifest = parse_and_verify(
            &raw,
            app_id,
            release_id,
            "1.2.3",
            Some(10203),
            "x64",
            "root-1",
            &root_public,
        )
        .unwrap();
        assert_eq!(manifest.version, "1.2.3");
        assert_eq!(manifest.files[0].path, "app.exe");

        let mut tampered = raw;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(
            parse_and_verify(
                &tampered,
                app_id,
                release_id,
                "1.2.3",
                Some(10203),
                "x64",
                "root-1",
                &root_public,
            )
            .is_err()
        );
    }

    fn build_manifest(app_id: &str, release_id: &str) -> (Vec<u8>, String) {
        let root_key = SigningKey::from_bytes(&[0u8; 32]);
        let signer_key = SigningKey::from_bytes(&[1u8; 32]);
        let root_public = root_key.verifying_key().to_bytes();
        let signer_public = signer_key.verifying_key().to_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&uuid_bytes(app_id).unwrap());
        body.extend_from_slice(&uuid_bytes(release_id).unwrap());
        body.extend_from_slice(&10203u64.to_be_bytes());
        body.push(1);
        body.push(2);
        append_string16(&mut body, "1.2.3");
        body.extend_from_slice(&1u16.to_be_bytes());
        append_string16(&mut body, "app.exe");
        body.extend_from_slice(&1234u64.to_be_bytes());
        body.extend_from_slice(&[0x55u8; 32]);

        let mut key_message = KEY_DOMAIN.to_vec();
        key_message.extend_from_slice(&uuid_bytes(app_id).unwrap());
        append_string8(&mut key_message, "root-1");
        append_string8(&mut key_message, "signer-1");
        key_message.extend_from_slice(&signer_public);
        let root_signature = root_key.sign(&key_message).to_bytes();
        let mut manifest_message = MANIFEST_DOMAIN.to_vec();
        manifest_message.extend_from_slice(&body);
        let manifest_signature = signer_key.sign(&manifest_message).to_bytes();

        let mut raw = MAGIC.to_vec();
        raw.extend_from_slice(&2u16.to_be_bytes());
        raw.extend_from_slice(&(body.len() as u32).to_be_bytes());
        raw.extend_from_slice(&body);
        append_string8(&mut raw, "root-1");
        append_string8(&mut raw, "signer-1");
        raw.extend_from_slice(&signer_public);
        raw.extend_from_slice(&root_signature);
        raw.extend_from_slice(&manifest_signature);
        (raw, hex::encode(root_public))
    }

    fn append_string16(target: &mut Vec<u8>, value: &str) {
        target.extend_from_slice(&(value.len() as u16).to_be_bytes());
        target.extend_from_slice(value.as_bytes());
    }
}
