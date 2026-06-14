# SwmSdk (Java)

`SwmSdk` is the Java SDK for Software Web Manager.

## Requirements

- Java 17+
- Maven 3.9+

## Features

- Update check / download / heartbeat / events / feedback
- SSE update stream with reconnect support
- Device shutdown control event (`device_shutdown`)
- Maintenance mode control events (`maintenance_scheduled` / `maintenance_cancelled`)
- Device blocked / region blocked error mapping
- Management APIs aligned with `sdk/go`

## Quick Start

```java
import com.swm.sdk.Client;

var client = new Client("http://localhost:8080", "your_app_id", "your_app_secret");
client.setChannel("stable");
client.setPlatform("windows");
client.setArch("amd64");
client.setDeviceId("device-001");

var update = client.checkUpdate("1.0.0", 100);
```

## Maintenance Mode

管理员开启维护模式后，`checkUpdate(...)` / heartbeat 响应带 `maintenance` 对象（`enabled` / `startAt` / `message` / `active`），SSE 流推送 `maintenance_scheduled`（含 `startAt`、`message`）与 `maintenance_cancelled` 控制事件。约定：`active=true` 提示「系统维护中」并退出；否则按 `startAt - now` 倒计时，到点退出。

```java
var update = client.checkUpdate("1.0.0", 100);
var m = update.getMaintenance();
if (m != null && m.isEnabled() && m.isActive()) {
    System.out.println("系统维护中: " + m.getMessage());
    System.exit(0);
}

var options = new UpdateStreamOptions()
    .setChannelCode("stable").setPlatform("windows").setArch("amd64").setDeviceId("device-001")
    .setOnControlEvent(evt -> {
        if (Client.CONTROL_EVENT_MAINTENANCE_SCHEDULED.equals(evt.getType())) {
            // evt.getStartAt() / evt.getMessage()：自行倒计时并到点退出
        } else if (Client.CONTROL_EVENT_MAINTENANCE_CANCELLED.equals(evt.getType())) {
            // 取消退出计划
        }
    });
client.startUpdateStream(options, evt -> {});
```

## Management API

```java
client.setAuthToken("jwt_token");
var app = client.getApp("app_id");
var channels = client.listChannels("app_id");
```
