# 文档导航

这组文档按使用任务组织。首次使用 Signet 时，先完成部署，再把应用接入 OIDC。

| 你的目标 | 阅读内容 |
| --- | --- |
| 在本地或服务器上运行 Signet | [部署指南](deployment.md) |
| 让 Web 应用使用 Signet 登录 | [OIDC 应用接入](oidc-integration.md) |
| 在公网安全运行、接入自建前端 | [安全指南](security.md) |
| 查找协议、接口和高级能力的精确行为 | [完整技术参考](technical-reference.md) |

## 建议路线

1. 用[项目首页](../README.md#快速开始)启动服务，并注册第一个管理员。
2. 在管理控制台的“运行配置”中填入实际公网地址和 OIDC Issuer。
3. 创建 OIDC 客户端，登记应用回调地址，然后按 discovery 文档完成应用配置。
4. 上线前完成 HTTPS、Cookie、CORS、验证码投递和数据备份检查。

## 按主题查找

- [部署与配置](deployment.md)：Docker、源码运行、环境变量、反向代理、数据库和上线检查。
- [OIDC 应用接入](oidc-integration.md)：discovery、客户端注册、授权码流程和高级协议能力。
- [安全运行](security.md)：公开地址、反向代理信任、Cookie、CORS、CSRF、密钥和备份。
- [账户与后台](technical-reference.md#注册与后台设置)：注册策略、身份源、组织、MFA、Passkey 和用户生命周期。
- [企业协议](technical-reference.md#oidc-示例)：OIDC 扩展、SCIM、Device Flow、IAP/ForwardAuth 和审计 Webhook。
- [开发与验证](technical-reference.md#自动化检查与浏览器-smoke)：开发环境、CI 和浏览器 smoke test。

`config/default.toml` 是全部配置项及其开发默认值的参考。不要把其中的示例密码、客户端 secret 或本地 Cookie 设置直接用于生产环境。
