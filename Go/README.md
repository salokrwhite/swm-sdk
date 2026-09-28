# SWM Go SDK 2.0

`github.com/salokrwhite/swm-sdk/Go/v2` is the Windows desktop client SDK for
Software Web Manager. It is a full protocol client and intentionally does not
expose the browser management API.

## Requirements

- Windows 10 or later
- Windows x86 or x64
- Go 1.26 or later
- `CGO_ENABLED=0`

The SDK uses the Microsoft Software Key Storage Provider for a non-exportable
P-256 device key, DPAPI for local state, Win32 APIs for hardware evidence, and
`golang.org/x/sys/windows` for Windows syscall bindings.

## Basic Usage

```go
package main

import (
	"context"
	"log"

	swm "github.com/salokrwhite/swm-sdk/Go/v2"
)

func main() {
	client, err := swm.NewClient(swm.Options{
		BaseURL:            "https://swm-backend.anteasy.com",
		AppID:              "<application-uuid>",
		ReleaseID:          "<release-uuid>",
		Version:            "1.0.0",
		RootTrustKeyID:     "<root-trust-key-id>",
		RootTrustPublicKey: "<root-trust-ed25519-public-key>",
		Channel:            "stable",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	update, err := client.CheckUpdate(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}
	if update.UpdateAvailable && !update.OpenInBrowser {
		err = client.DownloadUpdate(
			context.Background(),
			update,
			"downloads/update.bin",
			nil,
		)
		if err != nil {
			log.Fatal(err)
		}
	}
}
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

All network methods accept a `context.Context`. They are safe to call
concurrently on one `Client`.

## Local Identity

The SDK uses the same v2 state directory and format as the C# and C++ SDKs:

```text
%LOCALAPPDATA%\SwmSdk\<sha256(app_id)[0..12]>\
  identity.bin
  offline.bin
  integrity-policy.bin
```

`identity.bin` contains the installation ID and the non-exportable CNG key
name. The metadata, offline budget, and cached integrity policy are protected
with current-user DPAPI. Set `Options.StorageDirectory` to override the
directory for tests or portable deployments.

## Host Integrity

Enable the built-in scanner with `Options.HostIntegrity.Enabled` and provide
`PackageRoot` when the Release uses `host_integrity_required`. The default
manifest name is `release-integrity.v2`.

Applications can replace the built-in scanner by implementing
`IntegrityEvidenceProvider`. Evidence contains only package-relative paths and
SHA-256 values; missing optional files are omitted for the server to evaluate.

## Operation Authorization

Operation names are caller-defined strings. The SDK does not contain product
specific flash, erase, unlock, or repair enums.

```go
grant, err := client.AuthorizeOperation(ctx, swm.OperationAuthorizationRequest{
	Operation:         "vendor_update",
	Plan:              planBytes,
	StepCount:         12,
	TotalBytes:        totalBytes,
	ConsumerModule:    "vendor-operation-module.dll",
	ConsumerChallenge: challenge,
})
if err != nil {
	return err
}
receipt, err := client.ConsumeOperationAuthorization(ctx, grant)
```

Host-bound operation authorization also requires `HostExecutablePath` and
`ConsumerModulePath`.

## Update Streams

`WatchUpdates` returns an iterator. Cancel via the context or stop by returning
false from the range body.

```go
options := swm.DefaultUpdateStreamOptions()
options.CurrentVersion = "1.0.0"
for event, err := range client.WatchUpdates(ctx, options) {
	if err != nil {
		log.Println(err)
		break
	}
	log.Printf("update event: %s", event.EventType)
}
```

Transient reconnect failures are handled internally. Terminal authorization,
region, version, device, and integrity failures are yielded once.

## Security Behavior

- Signed `server_time_v1` establishes trusted time before authenticated calls.
- `online_key_manifest_v1` is root-signed; up to four previous keys remain
  available for in-flight signed responses.
- DPoP uses the CNG P-256 key and P1363 signatures.
- POST bodies use X25519, HKDF-SHA256, and AES-256-GCM.
- Authz v3 verifies the response carrier, identity, nonce, raw data SHA-256,
  validity window, key ID, and Ed25519 signature.
- Download URLs are restricted to the configured SWM origin and fixed artifact
  ticket route. Downloads verify the signed artifact manifest and SHA-256.
- Operation authorization fails closed when integrity, policy, session, or
  one-time consumption state is invalid.

## Build and Test

This directory is a standalone Go module. Disable the repository's parent
`go.work` when running commands from this nested module:

```powershell
$env:GOWORK = "off"
go test ./...
go vet ./...
$env:GOOS = "windows"; $env:GOARCH = "386"; $env:CGO_ENABLED = "0"
go build ./...
```

Non-Windows targets compile through an unsupported-platform stub, but
`NewClient` returns `ErrUnsupportedPlatform`.

## License

See `THIRD_PARTY_NOTICES.md`.
