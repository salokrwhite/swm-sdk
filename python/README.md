# SWM Python SDK

Usage example:

```python
from swm_sdk import Client

client = Client("http://localhost:8080", "YOUR_APP_KEY")
client.channel = "stable"
client.platform = "windows"
client.arch = "x64"
client.device_id = "device-1"
client.attributes = {"country": "CN", "os_version": "10.0"}

resp = client.check_update("1.0.0")
print(resp)

client.report_event("app_started", {"version": "1.0.0"})

client.report_events([
    {"event_name": "check_update", "device_id": "device-1", "properties": {"version": "1.0.0"}},
    {"event_name": "update_failed", "device_id": "device-1", "properties": {"reason": "network"}}
])
```

## 维护模式 (Maintenance Mode)

管理员在控制台开启维护模式后：

- `check_update()` / heartbeat 响应会带上 `maintenance` 对象：`enabled` / `start_at`(RFC3339) / `message` / `active`。
- SSE 更新流会推送控制事件 `maintenance_scheduled`（含 `maintenance_start_at`、`message`）与 `maintenance_cancelled`。

约定行为：`active=true` 表示维护已开始，应提示「系统维护中」并退出；否则按 `start_at - now` 倒计时弹窗，到点自动退出。

```python
from swm_sdk import (
    Client, CONTROL_EVENT_MAINTENANCE_SCHEDULED, CONTROL_EVENT_MAINTENANCE_CANCELLED,
)

resp = client.check_update("1.0.0")
if resp.maintenance and resp.maintenance.enabled:
    if resp.maintenance.active:
        print("系统维护中:", resp.maintenance.message)
        raise SystemExit(0)
    print("维护将在", resp.maintenance.start_at, "开始")

def on_event(evt):
    if evt.event_type == CONTROL_EVENT_MAINTENANCE_SCHEDULED:
        print("维护已排期:", evt.maintenance_start_at, evt.message)  # 自行倒计时并到点退出
    elif evt.event_type == CONTROL_EVENT_MAINTENANCE_CANCELLED:
        print("维护已取消")  # 取消退出计划

handle = client.start_update_stream(options, on_event)
```
