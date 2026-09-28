# SwmSdk 2.0

`SwmSdk` is a pure managed C# client SDK for Software Web Manager.

This version targets `net10.0` and supports Windows x86 and x64. It does not
load, package, or require `MySwm.dll`, and it does not expose the browser
management API.

## Features

- CNG-backed, non-exportable P-256 device identity
- DPAPI-protected local state
- Hardware risk evidence for `device_credential_v2`
- Signed server time and root-trusted online key manifests
- DPoP request proofs and Authz v3 response verification
- X25519, HKDF-SHA256, and AES-256-GCM request body encryption
- Update checks, heartbeat, events, feedback, enrollment, and secure download
- Device key rotation
- RIM2 parsing, file scanning, and integrity evidence
- Signed SSE update streams
- Generic protected-operation authorization and consumption
- Optional firmware identity and Debug protocol extensions

## Basic Usage

```csharp
using SwmSdk;

await using var client = new SwmClient(new SwmClientOptions
{
    BaseUrl = "https://swm.example.com",
    AppId = appId,
    ReleaseId = releaseId,
    Version = "1.0.0",
    VersionCode = 100,
    RootTrustKeyId = rootTrustKeyId,
    RootTrustPublicKey = rootTrustPublicKey,
    Channel = "stable",
    Platform = "windows",
    Arch = Environment.Is64BitProcess ? "x64" : "x86"
});

var update = await client.CheckUpdateAsync();
if (update.UpdateAvailable && !update.OpenInBrowser)
{
    await client.DownloadUpdateAsync(update, "update.bin");
}
```

## Device Identity

The SDK creates a new installation identity under:

```text
%LOCALAPPDATA%\SwmSdk\<sha256(app_id)[0..12]>\
```

The identity is not compatible with old MySwm native storage. Upgrade
installations intentionally register as new devices.

## Host Integrity

Enable `SwmClientOptions.HostIntegrity` and set `PackageRoot` when the Release
uses `host_integrity_required`. By default the SDK reads
`release-integrity.v2` relative to the package root. Applications can replace
the built-in scanner with `IIntegrityEvidenceProvider`.

## Generic Operation Authorization

Operation names are provided by the calling application. The SDK does not
contain built-in flash, erase, unlock, or other product-specific operation
enums.

```csharp
var grant = await client.AuthorizeOperationAsync(new OperationAuthorizationRequest
{
    Operation = operationCode,
    Plan = planBytes,
    StepCount = stepCount,
    TotalBytes = totalBytes,
    ConsumerModule = consumerModule,
    ConsumerChallenge = challenge,
    HostExecutablePath = hostExecutablePath,
    ConsumerModulePath = consumerModulePath
});

var receipt = await client.ConsumeOperationAuthorizationAsync(grant);
```

## User Feedback

```csharp
var feedback = await client.SubmitFeedbackAsync(new FeedbackRequest
{
    Content = userComment,
    Rating = 5,
    Contact = "user@example.com",
    Metadata = new Dictionary<string, object?>
    {
        ["os_version"] = Environment.OSVersion.VersionString
    },
    AttachmentPaths = ["screen.png"]
});
```

The SDK supports up to three attachments, each no larger than 5 MiB, matching
the server-side feedback limits.

## Target Frameworks

- `net10.0`
- `win-x86`
- `win-x64`

## Build and Test

```powershell
dotnet build .\SwmSdk.csproj -c Release
dotnet test .\tests\SwmSdk.Tests\SwmSdk.Tests.csproj -c Release
dotnet pack .\SwmSdk.csproj -c Release
```
