# SWM Java SDK 2.0

Pure Java 17 Windows desktop SDK for Software Web Manager, targeting x86 and
x64 JVMs. It does not load, link, or package `MySwm.dll`, and it does not expose
browser management APIs.

## Build

```powershell
.\mvnw.cmd verify
```

The Maven artifact is `com.swm:swm-sdk-java:2.0.0`. Runtime dependencies are
BouncyCastle, Jackson, JNA, and jna-platform.

Third-party notices are in `THIRD_PARTY_NOTICES.md`.

## Basic Usage

```java
var options = SwmClientOptions.builder()
    .baseUrl("https://swm.example.com")
    .appId(appId)
    .releaseId(releaseId)
    .version("1.0.0")
    .versionCode(100)
    .rootTrustKeyId(rootKeyId)
    .rootTrustPublicKey(rootPublicKey)
    .build();

try (var client = new SwmClient(options)) {
    var update = client.checkUpdate();
    if (update.updateAvailable()) {
        client.downloadUpdate(update, java.nio.file.Path.of("update.bin"), null);
    }
}
```

The client exposes blocking methods and `CompletableFuture` methods. Update
streams use `UpdateStream` and can be closed or stopped independently.

## Identity And Windows APIs

Device identity is stored in the same v2 location as the C# and C++ SDKs:

```text
%LOCALAPPDATA%\SwmSdk\<sha256(app_id)[0..12]>\identity.bin
```

The path is resolved at runtime through Windows shell APIs. Java uses JNA to
call system DPAPI and CNG APIs for the non-exportable P-256 installation key.
No machine path, user name, or environment variable is compiled into the SDK.

The CPU hardware evidence component is read from the Windows registry
`VendorIdentifier` and `ProcessorNameString`; other components use Raw SMBIOS,
physical disk serials, physical MAC addresses, and MachineGuid. This may cause
an existing C#/C++ device to report one expected hardware-summary change.

## Security Behavior

- Signed server time and root-trusted online key manifests.
- DPoP proofs and X25519/HKDF-SHA256/AES-256-GCM request bodies.
- Authz v3 verification over the original response data bytes.
- RIM2 signature verification and policy-driven runtime evidence.
- Secure downloads with Range continuation and SHA-256 verification.
- Signed SSE streams with reconnect, backoff, jitter, and cancellation.

## Testing

Tests are kept under `tests/java` and are excluded from Git by `sdk/.gitignore`
in the same way as the C# and C++ test trees.
