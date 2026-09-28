//! Async Windows desktop client SDK for Software Web Manager.
//!
//! The crate implements the SWM 2.0 client protocol, including CNG device
//! identity, DPAPI state, signed Authz v3 responses, encrypted request bodies,
//! RIM2 release integrity, secure downloads, SSE streams, and operation
//! authorization. Browser management APIs are intentionally outside this
//! crate.

#![allow(clippy::result_large_err, clippy::too_many_arguments)]

mod client;
mod crypto;
mod download;
mod error;
mod host_integrity;
mod identity;
mod models;
mod operations;
mod optional;
mod options;
mod pipeline;
mod platform;
mod rim2;
mod state;
mod stream;

pub use client::Client;
pub use error::{Error, ErrorKind, Result};
pub use models::*;
pub use optional::DebugStream;
pub use options::{
    CheckUpdateOptions, ClientOptions, ClientOptionsBuilder, HostIntegrityOptions,
    IntegrityEvidenceProvider, IntegrityEvidenceRequest, ProgressCallback,
};
pub use stream::UpdateStream;
