# SWM Python SDK 2.0

`swm-sdk` is the synchronous Windows desktop client SDK for Software Web
Manager. It implements the SWM 2.0 client protocol and does not expose browser
management APIs.

## Requirements

- Windows 10 or later
- Windows x86 or x64
- Python 3.10 or later
- `cryptography`, `requests`, and `py-cpuinfo`

The SDK uses Python `ctypes` to call Windows CNG and DPAPI. It does not use
`pywin32` or a software-only identity fallback.

## Basic Usage

```python
from swm_sdk import CheckUpdateOptions, Client, ClientOptions

options = ClientOptions(
    base_url="https://swm-backend.anteasy.com",
    app_id="00000000-0000-0000-0000-000000000001",
    release_id="00000000-0000-0000-0000-000000000002",
    version="1.0.0",
    root_trust_key_id="root-1",
    root_trust_public_key="<root-ed25519-public-key>",
    channel="stable",
)

with Client(options) as client:
    update = client.check_update(CheckUpdateOptions())
    if update.update_available and not update.open_in_browser:
        client.download_update(update, "update.bin")
```

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

`Client` is synchronous. Use one client per application process or synchronize
calls made from multiple threads.

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

```python
grant = client.authorize_operation(
    OperationAuthorizationRequest(
        operation="vendor_update",
        plan=plan_bytes,
        step_count=12,
        total_bytes=total_bytes,
        consumer_module="vendor-operation-module.dll",
        consumer_challenge=challenge,
    )
)
receipt = client.consume_operation_authorization(grant)
```

## Update Streams

`watch_updates` returns a synchronous generator. Closing the generator stops
the stream and its reconnect loop.

```python
for event in client.watch_updates():
    print(event.event_type)
```

## Build and Test

```powershell
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests
python -m mypy src
python -m build
```

Set `SWM_TEST_CROSS_LANGUAGE=1` on Windows to enable the C#/Python DPAPI and
CNG identity compatibility test.

Non-Windows targets import an unsupported-platform stub and raise
`UnsupportedPlatformError` when constructing a client.

## Third-Party Notices

See `THIRD_PARTY_NOTICES.md`.
