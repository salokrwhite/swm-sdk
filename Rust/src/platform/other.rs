use crate::error::{Error, ErrorKind, Result};
use crate::models::HardwareEvidence;
use std::path::Path;

pub(crate) fn protect(_plaintext: &[u8], _entropy: &[u8]) -> Result<Vec<u8>> {
    Err(Error::new(
        ErrorKind::UnsupportedPlatform,
        "Windows x86 or x64 is required",
    ))
}

pub(crate) fn unprotect(_ciphertext: &[u8], _entropy: &[u8]) -> Result<Vec<u8>> {
    Err(Error::new(
        ErrorKind::UnsupportedPlatform,
        "Windows x86 or x64 is required",
    ))
}

pub(crate) fn replace_file(_source: &Path, _destination: &Path) -> Result<()> {
    Err(Error::new(
        ErrorKind::UnsupportedPlatform,
        "Windows x86 or x64 is required",
    ))
}

pub(crate) fn collect_hardware_evidence(_app_id: &str) -> Result<HardwareEvidence> {
    Err(Error::new(
        ErrorKind::UnsupportedPlatform,
        "Windows x86 or x64 is required",
    ))
}

pub(crate) struct IdentityKey;

impl IdentityKey {
    pub(crate) fn create(_name: &str) -> Result<Self> {
        Err(Error::new(
            ErrorKind::UnsupportedPlatform,
            "Windows x86 or x64 is required",
        ))
    }

    pub(crate) fn open(_name: &str) -> Result<Self> {
        Err(Error::new(
            ErrorKind::UnsupportedPlatform,
            "Windows x86 or x64 is required",
        ))
    }

    pub(crate) fn name(&self) -> &str {
        ""
    }

    pub(crate) fn public_key_sec1(&self) -> Result<Vec<u8>> {
        Err(Error::new(
            ErrorKind::UnsupportedPlatform,
            "Windows x86 or x64 is required",
        ))
    }

    pub(crate) fn sign_digest(&self, _digest: &[u8]) -> Result<[u8; 64]> {
        Err(Error::new(
            ErrorKind::UnsupportedPlatform,
            "Windows x86 or x64 is required",
        ))
    }

    pub(crate) fn delete(&self) -> Result<()> {
        Err(Error::new(
            ErrorKind::UnsupportedPlatform,
            "Windows x86 or x64 is required",
        ))
    }

    pub(crate) fn close(&self) -> Result<()> {
        Ok(())
    }
}
