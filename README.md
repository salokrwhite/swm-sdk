# SWM SDK

自研的统一软件版本管理平台，支持版本发布、灰度/预览、回滚、强更/可选更新、渠道分发与数据分析。

## 说明

新系统仅发布 C# SDK。客户端协议固定为 Authz v3，并强制使用 Native 设备密钥、DPoP、X25519 + HKDF-SHA256 + AES-256-GCM 请求体加密和服务端签名响应。请求体加密复用每租户 Ed25519 授权密钥派生出的 X25519 密钥，不引入平台共享签名密钥。

## 链接

- 官网：https://swm.anteasy.com
- 注册使用：https://swm.anteasy.com/register
