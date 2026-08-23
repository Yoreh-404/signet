<!-- anchordocs-lifecycle: DONE -->
<!-- anchordocs-owner: Signet maintainers -->
<!-- anchordocs-updated: 2026-08-06 -->
<!-- anchordocs-acceptance: AI 能按身份流、协议、安全、目录或运维问题进入远端文章，本地资料保持离线 fallback 边界 -->
<!-- anchordocs-evidence: commit=f2a9a62500b078980a6c7efbfa1cc63ffbcc8e71; path=README.md; lines=1-75 -->

# 文档导航

这组文档按使用任务组织。首次使用 Signet 时，先完成部署，再把应用接入 OIDC。

AnchorDocs 是模块化设计与生命周期状态的权威来源。AI 应从具体身份流、协议、浏览器安全、目录同步或密钥运维问题进入文章，不要把 Signet 当成只有一个 OAuth callback 的普通登录服务。远端 developer 文档按服务架构、OIDC、安全、管理集成和部署拆分；远端 user 文档按启动和 OIDC 接入拆分。本地文件是离线 fallback，不应与远端状态冲突。

对应 AnchorDocs 入口：

- developer/architecture-session-and-data-model
- developer/oidc-protocol-and-client-security
- developer/browser-security-mfa-passkeys
- developer/admin-directory-and-integration-protocols
- developer/deployment-database-and-key-rotation
- user/getting-started
- user/oidc-client-integration

| 你的目标 | 阅读内容 |
| --- | --- |
| 在本地或服务器上运行 Signet | [部署指南](deployment.md) |
| 让 Web 应用使用 Signet 登录 | [OIDC 应用接入](oidc-integration.md) |
| 设计多类型应用接入模式 | [应用接入模型](application-integration-model.md) |
| 编写无 secret 的 v3 producer | [v3 契约示例](examples/application-v3.json) |
| 在公网安全运行、接入自建前端 | [安全指南](security.md) |
| 离线查找协议、接口和高级能力的精确行为 | [完整技术参考](technical-reference.md) |

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

`technical-reference.md` 是历史上集中维护的本地兼容参考，内容未逐章节复制到 AnchorDocs；若两者冲突，以代码和 AnchorDocs 当前文章为准，并在下一次维护中拆分/同步相关模块。

`config/default.toml` 是全部配置项及其开发默认值的参考。不要把其中的示例密码、客户端 secret 或本地 Cookie 设置直接用于生产环境。
