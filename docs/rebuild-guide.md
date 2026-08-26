# Signet 重建指南

Signet 是身份、组织、应用和协议的统一控制面，也是 OIDC Provider；它不是
只有一个 OAuth callback 的登录组件。一个“应用”是要被保护的网站接入包，
而不是需要逐个加入用户的成员组；协议、第三方登录、目录同步和授权模块
可以独立保存，但最终都受账户、企业、应用 active 状态和安全策略约束。

## 项目身份与硬边界

- Signet 账户是统一主体；组织成员关系、应用访问和角色是不同边界。
- 应用默认面向所有 active 且未归档账户，不能重新引入旧的 `assigned_accounts` 作为当前准入模型。
- OIDC/OAuth、SAML/CAS/JWT、SCIM、LDAP/AD、IAP/ForwardAuth 和 Device Flow 是协议适配面，不是互相独立的登录产品。
- 浏览器 Cookie 写请求有 CSRF、CORS、SameSite、反向代理信任和 session 边界；不能只验证 JWT 就结束。
- 签名密钥持久化并支持轮换/JWKS 退役；service account、client assertion、DPoP 和 token exchange 各有 audience/scope/replay 规则。
- 管理 API、登录协议和后台配置必须经过授权、审计和危险操作确认；不要把业务逻辑塞进 React 页面。

## 重建拓扑

```text
frontend (React/Vite)
  └─ frontend/src/lib/api.ts + features/*
                 │ JSON/HTML embedded
backend/src/server.rs ── routes/middleware/health
  ├─ access/authorization/session
  ├─ applications/admin/organizations/users
  ├─ oidc/oauth/dcr/device/token exchange/dpop
  ├─ directory_sync/scim/iap/webhooks
  ├─ db/* + Diesel migrations
  └─ config/default.toml + key/session stores
```

- `backend/src/server.rs` 负责路由组装、CORS、压缩、请求 ID、安全头和停机。
- `backend/src/` 领域模块分别处理 access、authorization、OIDC、目录、应用、账单和管理。
- `backend/src/db/` 是 Diesel adapter 与数据库边界；SQLite、PostgreSQL、MySQL/MariaDB 通过 feature 选择。
- `frontend/src/features/` 按后台领域拆分，`frontend/src/lib/api.ts` 统一错误/空响应/网络语义。
- `backend/build.rs` 将前端构建嵌入二进制；生产不需要独立 Vite 服务。

## 关键流程

1. 首次启动建立/导入签名密钥和数据库迁移，再完成第一个管理员注册。
2. 用户登录由本地密码/Passkey/MFA 或外部 OIDC/LDAP 身份源进入统一账户。
3. 应用工作区分别保存 protocols、login_adapters、directory_sync、authorization 配置。
4. 授权码、PKCE、client authentication、resource/audience、scope 和 redirect URI 经过协议校验后签发 token。
5. 浏览器请求经 session Cookie + CSRF；服务间调用经 audience、scope、issuer、expiry 和主体校验。
6. 管理变更写审计；SCIM/IAP/Webhook/密钥轮换走各自契约与失败策略。

## 需求路由

| 需求 | 先读 | 主要代码 |
| --- | --- | --- |
| 登录、账户、session | [技术参考](technical-reference.md) | `backend/src/access.rs`, `session` |
| OIDC/OAuth/PKCE/token | [OIDC 接入](oidc-integration.md) | `backend/src/oidc.rs`, `token_exchange.rs` |
| 应用模块和授权 | [应用接入模型](application-integration-model.md) | `applications.rs`, `authorization.rs`, `frontend/src/features/applications/` |
| 浏览器安全、MFA、Passkey | [安全指南](security.md) | `browser/security` 模块与 middleware |
| 组织、LDAP、SCIM、IAP | [技术参考](technical-reference.md) | `directory_sync.rs`, `scim.rs`, `iap.rs` |
| 数据库/迁移/密钥 | [部署指南](deployment.md) | `backend/src/db/`, `config/default.toml` |
| 前端页面和 API 状态 | 技术参考前端章节 | `frontend/src/features/`, `frontend/src/lib/api.ts` |
| Nix OCI 部署 | 根 README 与 workflow | `flake.nix`, `.github/workflows/deploy.yml` |

## 从零重写顺序

1. 固定账户、组织、应用、session、client、scope、role 和审计模型。
2. 实现 Diesel schema/迁移、配置和签名密钥生命周期。
3. 实现本地/外部身份认证、session、CSRF 和浏览器安全 middleware。
4. 实现 OIDC/OAuth 协议及 client authentication、resource、DPoP、device flow。
5. 实现应用模块、组织授权、目录同步、SCIM、IAP 和 Webhook。
6. 实现管理 API/React 控制台、browser smoke、Nix 构建和生产部署。

## 事实来源

- 配置与数据库：`config/default.toml`、`backend/src/db/`、`migrations/`。
- 协议：[`oidc-integration.md`](oidc-integration.md)、[`technical-reference.md`](technical-reference.md)。
- 安全：[`security.md`](security.md)；上线：[`deployment.md`](deployment.md)。
- 修改后运行前端检查、workspace tests、数据库 feature tests 和浏览器 smoke；功能列表不能代替协议测试。
