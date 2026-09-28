# SwmSdk C++ 2.0

`swm_sdk` is a standalone C++20 SDK for the software runtime protocol. It does
not load, link, package, or depend on `MySwm.dll`. Management and browser
backend APIs are intentionally outside this SDK.

Supported targets:

- Windows 10 or later
- MSVC 2019/2022 or newer
- x86 and x64
- CMake static library with the `swm::sdk` package target

## Build

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
cmake --install build --config Release --prefix install
```

For Ninja, use a Visual Studio developer command prompt:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The library statically links Monocypher. It uses WinHTTP, BCrypt/NCrypt, DPAPI,
iphlpapi, and Win32 system APIs. No runtime third-party DLL is produced.

## CMake Consumer

```cmake
find_package(swm_sdk CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE swm::sdk)
target_compile_features(my_app PRIVATE cxx_std_20)
```

## Basic Usage

```cpp
#include "swm/client.hpp"

#include <iostream>

int main() {
    swm::ClientOptions options;
    options.base_url = "https://example.com";
    options.app_id = "00000000-0000-0000-0000-000000000001";
    options.release_id = "00000000-0000-0000-0000-000000000002";
    options.version = "1.0.0";
    options.version_code = 100;
    options.root_trust_key_id = "root-1";
    options.root_trust_public_key = "<root-ed25519-public-key>";

    swm::Client client(options);
    const auto update = client.check_update();
    if (update.update_available) {
        client.download_update(update, "downloads/package.zip");
    }
}
```

Every normal operation has a synchronous method and an `AsyncTask<T>` variant:

```cpp
auto task = client.check_update_async();
task.on_error([](const std::exception_ptr& error) {
    try {
        std::rethrow_exception(error);
    } catch (const swm::Error& sdk_error) {
        std::cerr << sdk_error.service_code << ": " << sdk_error.what() << '\n';
    }
});
const auto update = task.wait();
```

## Local Identity

C++ and C# share the same v2 state format and directory:

```text
%LOCALAPPDATA%\SwmSdk\<sha256(app_id)[0..12]>\
  identity.bin
  offline.bin
  integrity-policy.bin
```

`identity.bin` contains the install ID and the non-exportable CNG P-256 key
name. The key is created in `Microsoft Software Key Storage Provider`, and the
metadata and local policy files are protected with DPAPI. Set
`ClientOptions::storage_directory` to override the directory.

The legacy `MySwm` storage is not read or migrated.

## Host Integrity

Enable host integrity with a package root and the signed RIM2 v2 manifest:

```cpp
options.host_integrity.enabled = true;
options.host_integrity.package_root = "C:/Program Files/MyApp";
options.host_integrity.manifest_path = "release-integrity.v2";
```

The SDK verifies the root certificate, signer key, manifest signature, release
identity, architecture, and path safety. It reports the actual SHA-256 for
present RIM2 files and omits missing files so the server can apply the signed
Release policy (`required`, `optional`, or `ignored`). A server `failure_action`
maps to `IntegrityFailureAction::DenyOperations` or
`IntegrityFailureAction::ShutdownClient`; invalid error bodies fail closed as
`ShutdownClient`.

An application can replace built-in scanning with
`HostIntegrityOptions::evidence_provider`.

## Operation Authorization

Operations are caller-defined strings. The SDK does not define flash, erase,
unlock, or other product-specific operation enums.

```cpp
swm::OperationAuthorizationRequest request;
request.operation = "vendor_update";
request.plan = plan_bytes;
request.step_count = 12;
request.total_bytes = total_bytes;
request.consumer_module = "vendor-operation-module.dll";
request.consumer_challenge = challenge_bytes; // exactly 32 bytes

const auto grant = client.authorize_operation(request);
// Execute only after the caller has accepted and bound the returned grant.
const auto receipt = client.consume_operation_authorization(grant);
```

Host-bound authorization additionally requires
`host_executable_path` and `consumer_module_path`.

## Feedback

Feedback supports at most three attachments, a maximum of 5 MiB per
attachment, and a maximum multipart body of 32 MiB. `FeedbackRequest::content`
is required, and `rating` must be between 1 and 5 when supplied.

## Security Behavior

- Trusted time is established from the signed `server_time_v1` response.
- DPoP and time-sensitive checks fail closed before trusted time is available.
- Online keys are verified from `online_key_manifest_v1` and refreshed before
  expiry. Up to four previous keys remain available for in-flight responses.
- POST bodies use X25519, HKDF-SHA256, and AES-256-GCM.
- Authz v3 carriers verify identity, nonce, raw data SHA-256, validity, online
  key ID, and Ed25519 signature.
- Downloads verify HTTPS, redirects, Range continuation, length, SHA-256, and
  the signed artifact manifest. Invalid `.part` files are deleted.
- SSE streams verify Authz v3, support cancellation, reconnect, backoff, and
  jitter.

## License

See `THIRD_PARTY_NOTICES.md`. Monocypher is distributed under CC0-1.0 or
BSD-2-Clause. nlohmann/json is distributed under the MIT license.
