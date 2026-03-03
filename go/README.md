# swmsdk (Go)

此文件夹包含项目所使用的 Go SDK 源代码。

## 分析事件约定

`CheckUpdate` 和 `Download` 不会自动上报分析事件。
请在每个更新阶段手动调用 `ReportEvent`。

内置 SWM 分析页面推荐的事件名称如下：

- `check_update`
- `update_available`
- `download_started`
- `download_completed`
- `install_completed`
- `app_started`
- `update_failed`

示例代码：

```go
_ = client.ReportEvent(ctx, "check_update", map[string]interface{}{
    "version":          currentVersion,
    "update_available": resp.UpdateAvailable,
    "release_id":       resp.ReleaseID,
})
```

允许使用自定义事件名称，这些事件可以在事件概述列表中查看，
但摘要 KPI 卡片仅会聚合上述标准事件名称。