# SwmSdk (C#)

`SwmSdk` is the C# SDK for Software Web Manager.

## Target Frameworks

- `net8.0`
- `netstandard2.0`

## Core Features

- Update check / SSE update stream
- Device shutdown control event (`device_shutdown`)
- Device blocked contract (`error.code = device_blocked`)
- Heartbeat / events / feedback / download
- Full management APIs aligned with Go SDK

## Quick Start

```csharp
using SwmSdk;

var client = new Client("http://localhost:8080", "your_app_id", "your_app_secret")
{
    Channel = "stable",
    Platform = "windows",
    Arch = "amd64",
    DeviceId = "device-001"
};

var update = await client.CheckUpdateAsync("1.0.0", 100);
```

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

## Management APIs

```csharp
client.SetAuthToken("jwt_token");
var app = await client.GetAppAsync("app_id");
var channels = await client.ListChannelsAsync("app_id");
```

## NativeAOT

See [README.NativeAOT.md](README.NativeAOT.md).
