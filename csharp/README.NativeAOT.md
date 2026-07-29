# SwmSdk NativeAOT 指南

本 SDK 已按 NativeAOT 兼容方式实现：

- 使用 `System.Text.Json` 源生成上下文（`SwmJsonContext`）
- 不依赖运行时反射式 JSON 序列化
- 启用 AOT/Trim 分析器配置

## 在 NativeAOT 项目中使用

示例项目 `csproj`：

```xml
<PropertyGroup>
  <TargetFramework>net10.0</TargetFramework>
  <PublishAot>true</PublishAot>
  <InvariantGlobalization>true</InvariantGlobalization>
</PropertyGroup>
```

示例代码：

```csharp
using SwmSdk;

using var native = MySwmContext.Create("device-001");
var profile = new ReleaseSecurityProfile(
    "release_id", "1.0.0", 100, "v3", "server_key_id", "server_public_key");
var client = new Client("http://localhost:8080", "app_id",
    securityProfile: profile, nativeSecurityContext: native)
{
    Channel = "stable",
    Platform = "windows",
    Arch = "amd64",
    DeviceId = "device-001"
};

try
{
    await client.ReportHeartbeatAsync("1.0.0");
}
catch (SwmDeviceBlockedException)
{
    Environment.Exit(23);
}
```

## 签名验证说明

若启用 `VerifySignature=true` 且设置了 `PublicKey`，SDK 会自动执行 Ed25519 验签。  
如果你需要自定义验签实现（例如接入 HSM），可设置 `SignatureVerifier` 回调覆盖默认行为。

Authz v3 不使用该可替换回调作为信任根；服务端裁决由同架构 `MySwm.dll` 内的
固定 Ed25519 验证器校验。NativeAOT `win-x86` 只能加载 x86 DLL，`win-x64` 只能
加载 x64 DLL。

## SSE 下线控制事件

`device_shutdown` 会通过 `UpdateStreamOptions.OnControlEvent` 回调触发，建议在该回调中主动退出进程。
