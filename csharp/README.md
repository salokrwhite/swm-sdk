# SwmSdk (C#)

`SwmSdk` is the C# SDK for Software Web Manager.

## Target Frameworks

- `net10.0`
- `net8.0`
- `netstandard2.0`（可由 Windows 7 SP1 上的 .NET Framework 4.8 宿主使用）

## Core Features

- Update check / SSE update stream
- Device shutdown control event (`device_shutdown`)
- Device blocked contract (`error.code = device_blocked`)
- Heartbeat / events / feedback / download
- Full management APIs

## Quick Start

```csharp
using SwmSdk;

using var native = MySwmContext.Create("device-001");
var profile = new ReleaseSecurityProfile(
    "release_id", "1.0.0", 100, "v3", "server_key_id", "server_public_key");
var client = new Client("http://localhost:8080", "your_app_id",
    securityProfile: profile, nativeSecurityContext: native)
{
    Channel = "stable",
    Platform = "windows",
    Arch = "amd64",
    DeviceId = "device-001"
};

var update = await client.CheckUpdateAsync("1.0.0", 100);
```

## Authz v3 / MySwm.dll

安全 Release 必须使用与进程架构一致的 `MySwm.dll`。NuGet 包将原生文件放在
`runtimes/win-x86/native` 和 `runtimes/win-x64/native`；打包时若缺少任一架构会直接失败。

`MySwmContext` 不再公开通用 `CreateDpop(...)`。对外仅保留固定用途方法：
`CreateFirmwareIdentityProof`、`CreateDebugCreateProof`、`CreateDebugCancelProof`、
`CreateDebugStreamProof`；SDK 内部继续为 update-check / heartbeat / events / feedback /
enrollment / download / SSE 使用固定 proof 路径。

当前 `MySwm` ABI 为 `0x00010005`。

```csharp
using var native = MySwmContext.Create(pcid);
var profile = new ReleaseSecurityProfile(
    releaseId, version, versionCode, "v3", serverKeyId, serverEd25519PublicKey);
var client = new Client(baseUrl, appId, securityProfile: profile,
    nativeSecurityContext: native)
{
    Channel = "stable",
    Platform = "windows",
    Arch = Environment.Is64BitProcess ? "x64" : "x86",
    DeviceId = pcid
};
```

`MySwm.dll` 持有每安装 CNG P-256 私钥、DPAPI 元数据、短期 Session 和 DPoP
状态，并在 Native 内验证服务端 Ed25519 裁决。Session 到期只禁用云功能；明确的
撤销、封禁或验签失败应由宿主走安全关闭路径。

## Signature Verification

When `VerifySignature=true` and `PublicKey` is configured, the SDK verifies update signatures with Ed25519 by default.
If you need custom verification logic, set `SignatureVerifier` to override the default behavior.

## Analytics Event Convention

`CheckUpdateAsync` / `DownloadAsync` do not auto-report analytics events. You need to call `ReportEventAsync` manually.

Recommended event names used by the built-in analytics page:

- `check_update`
- `update_available`
- `download_started`
- `download_completed`
- `install_completed`
- `app_started`
- `update_failed`

For release-channel metrics, include `release_id` in `properties` (from `CheckUpdateAsync` response). Also ensure `client.Channel` matches an existing channel code (for example `stable`).

## Device Blocked Handling

```csharp
try
{
    await client.ReportHeartbeatAsync("1.0.0");
}
catch (SwmDeviceBlockedException)
{
    Environment.Exit(23);
}
```

## SSE Control Event

```csharp
var handle = client.StartUpdateStream(
    new UpdateStreamOptions
    {
        CurrentVersion = "1.0.0",
        VersionCode = 100,
        OnControlEvent = evt =>
        {
            if (evt.Type == Client.ControlEventShutdown)
            {
                Environment.Exit(23);
            }
        }
    },
    evt => { /* release events */ });
```

## Maintenance Mode

管理员开启维护模式后，`CheckUpdateAsync` / heartbeat 响应带 `Maintenance` 对象（`Enabled` / `StartAt` / `Message` / `Active`），SSE 流推送 `maintenance_scheduled`（含 `StartAt`、`Message`）与 `maintenance_cancelled` 控制事件。约定：`Active=true` 提示「系统维护中」并退出；否则按 `StartAt - now` 倒计时，到点退出。

```csharp
var update = await client.CheckUpdateAsync("1.0.0", 100);
if (update.Maintenance is { Enabled: true, Active: true } m)
{
    Console.WriteLine($"系统维护中: {m.Message}");
    Environment.Exit(0);
}

var handle = client.StartUpdateStream(
    new UpdateStreamOptions
    {
        CurrentVersion = "1.0.0",
        OnControlEvent = evt =>
        {
            if (evt.Type == Client.ControlEventMaintenanceScheduled)
            {
                // evt.StartAt / evt.Message：自行倒计时并到点退出
            }
            else if (evt.Type == Client.ControlEventMaintenanceCancelled)
            {
                // 取消退出计划
            }
        }
    },
    evt => { });
```

## Management APIs

```csharp
client.SetAuthToken("jwt_token");
var app = await client.GetAppAsync("app_id");
var channels = await client.ListChannelsAsync("app_id");
```

## NativeAOT

See [README.NativeAOT.md](README.NativeAOT.md).
