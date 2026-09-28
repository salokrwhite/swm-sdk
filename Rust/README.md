# SWM Rust SDK 2.0

`swm-sdk` is the async Windows desktop client SDK for Software Web Manager.
It implements the SWM 2.0 client protocol and intentionally does not expose
browser management APIs.

## Requirements

- Windows 10 or later
- Windows x86 or x64
- Rust 1.85 or later
- Tokio runtime

The SDK uses the Microsoft Software Key Storage Provider for a non-exportable
P-256 device key, DPAPI for local state, and native Win32 APIs for hardware
evidence. It does not provide a portable fallback identity.

## Basic Usage

```rust
use swm_sdk::{CheckUpdateOptions, Client, ClientOptions};

#[tokio::main]
async fn main() -> swm_sdk::Result<()> {
    let options = ClientOptions::builder()
        .base_url("https://swm-backend.anteasy.com")
        .app_id("00000000-0000-0000-0000-000000000001")
        .release_id("00000000-0000-0000-0000-000000000002")
        .version("1.0.0")
        .root_trust_key_id("root-1")
        .root_trust_public_key("<root-ed25519-public-key>")
        .channel("stable")
        .build()?;
    let client = Client::new(options)?;

    let update = client.check_update(CheckUpdateOptions::default()).await?;
    if update.update_available && !update.open_in_browser {
        client
            .download_update(update, "update.bin".into(), None)
            .await?;
    }
    Ok(())
}
```

All network operations are asynchronous. `Client` is cheaply cloneable and
safe to share across tasks.

## Client Operations

- Update checks, heartbeat, single and batch events
- Explicit online authorization key refresh
- Multipart feedback with up to three 5 MiB attachments
- Enrollment tickets and device key rotation
- RIM2 host integrity evidence and signed download verification
- Range-continuation downloads with SHA-256 verification
- Signed update SSE with reconnect, backoff, and cancellation
- Operation Authorization v3 issue and one-time consumption
- Firmware identity resolution
- Debug enrollment, request, cancellation, and decision streams

## Local Identity

The SDK uses the same v2 state directory and format as the C# and C++ SDKs:

```text
%LOCALAPPDATA%\SwmSdk\<sha256(app_id)[0..12]>\
  identity.bin
  offline.bin
  integrity-policy.bin
```

`identity.bin` contains the installation ID and the non-exportable CNG key
name. Metadata, offline budget, and cached integrity policy are protected with
current-user DPAPI.

## Host Integrity

Enable `HostIntegrityOptions.enabled` and set `package_root` for Releases that
use `host_integrity_required`. Applications can replace the built-in RIM2
scanner with `IntegrityEvidenceProvider`.

## Operation Authorization

Operation names are caller-defined strings. The SDK does not define product
specific flash, erase, unlock, or repair enums.

```rust
let grant = client
    .authorize_operation(swm_sdk::OperationAuthorizationRequest {
        operation: "vendor_update".into(),
        plan: plan_bytes,
        step_count: 12,
        total_bytes,
        consumer_module: "vendor-operation-module.dll".into(),
        consumer_challenge: Some(challenge),
        host_executable_path: None,
        consumer_module_path: None,
    })
    .await?;
let receipt = client.consume_operation_authorization(grant).await?;
```

## Update Streams

`watch_updates` returns a `Stream`. Dropping the stream cancels its background
task.

```rust
use futures_util::StreamExt;

let mut stream = client.watch_updates(Default::default());
while let Some(event) = stream.next().await {
    let event = event?;
    println!("{}", event.event_type);
}
```

## Build and Test

```powershell
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release --target x86_64-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```

Set `SWM_TEST_CROSS_LANGUAGE=1` when running `cargo test` to enable the
bidirectional C#/Rust DPAPI and CNG identity compatibility test.

Non-Windows targets compile through an unsupported-platform stub, but
`Client::new` returns `UnsupportedPlatform`.

## Third-Party Notices

See `THIRD_PARTY_NOTICES.md`.
