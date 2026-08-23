<!-- anchordocs-lifecycle: DONE -->
<!-- anchordocs-owner: Signet maintainers -->
<!-- anchordocs-updated: 2026-08-06 -->
<!-- anchordocs-acceptance: 本地离线技术参考保留完整协议细节，并明确 AnchorDocs 模块文档是状态权威来源 -->
<!-- anchordocs-evidence: commit=f2a9a62500b078980a6c7efbfa1cc63ffbcc8e71; path=backend/src/server.rs; lines=1-220 -->

# Signet 技术参考

> 本文是可离线检索的集中式兼容参考。模块边界、实现状态和未完成项以 AnchorDocs developer/user 文档为准；新增能力应优先写入对应模块文章，不要继续把互不相关的设计堆到本文。

AI 读取本地参考时，先根据任务选择远端行为合同：身份/Session 读
`architecture-session-and-data-model`，授权协议读
`oidc-protocol-and-client-security`，浏览器安全和 MFA 读
`browser-security-mfa-passkeys`，组织/目录/外部协议读
`admin-directory-and-integration-protocols`，部署和密钥读
`deployment-database-and-key-rotation`。本文用于核对具体协议细节，不是默认的设计入口，也不应被整理成阶段计划。

本文保留 Signet 的完整技术说明、协议示例和开发验证信息。若你是首次部署或接入应用，请先阅读 [文档导航](README.md) 和 [项目首页](../README.md)。

一个 Rust + Diesel + Axum 的 SSO/OIDC Provider starter，包含后端服务、嵌入式 React 管理前台、完整配置样例和 nix-shell 开发环境。

为兼容已有部署，默认 SQLite 文件名、会话 Cookie 名和既有协议扩展字段（例如 `X-GPT-SSO-*`、`gpt_sso_*`、`urn:gpt-sso:*`）继续使用历史标识；它们不代表当前产品名称。

## 网站应用模型

Signet 的“应用”对应一个需要接入的网站，不是需要把用户逐个加入的成员组。新建应用默认使用 `all_users` 访问模式：任何启用且未归档的 Signet 统一账户都可以进入网站，企业成员关系只用于企业默认权限和管理边界。

应用工作区把接入拆成四个可以独立保存的模块：

- `protocols`：OAuth 2.0 / OIDC 客户端连接，以及 SAML 2.0、CAS、JWT 的网站端点与令牌配置。
- `login_adapters`：应用允许使用的第三方 OIDC 登录适配器；外部身份最终绑定到同一个 Signet 账户。
- `directory_sync`：应用使用的 LDAP/AD 源和 SCIM 2.0 用户/组供应配置。
- `authorization`：继承企业默认角色后叠加应用专属角色和 Claim 的映射配置。

模块通过管理 API `/api/admin/applications/{id}/modules/{module_key}` 保存 JSON 配置。历史的 `assigned_accounts`、`organization_members` 和 `legacy_all_users` 字段仅为升级兼容而保留；当前登录准入统一由“应用 active + 企业 active + Signet 账户 active 且未归档”决定，不再建立或依赖应用成员关系。

## 功能

- OIDC Provider 端点：discovery、JWKS、authorize、token、userinfo、logout。
- 授权码模式：支持 `authorization_code`、PKCE `plain`/`S256`、refresh token rotation。
- OAuth/OIDC 扩展：支持 token introspection、token revocation、`client_credentials`、Token Exchange、Pushed Authorization Requests、JWT Secured Authorization Request、JWT Secured Authorization Response Mode、Device Authorization Grant、Rich Authorization Requests、`prompt=login`、`max_age`、`acr_values`、基础 `claims` 参数、Back-Channel Logout、Front-Channel Logout 和可配置 Dynamic Client Registration。
- Resource Indicators / RAR：授权码、Device Flow、refresh token 和 client credentials 可用 `resource` 指定 access token audience；支持 `authorization_details` 请求结构化授权细节。
- 客户端认证：支持 `client_secret_basic`、`client_secret_post`、`client_secret_jwt`、`none` 和 `private_key_jwt`；JWT 断言认证会校验 audience、过期时间和一次性 `jti`。
- 服务账号 / 机器身份：OIDC 客户端可启用 service account，使用 `client_credentials` 获取带机器主体和权限列表的 access token。
- DPoP：token endpoint 可用 DPoP proof 申请 proof-of-possession access token；`userinfo` 校验 `cnf.jkt`、`ath` 和 proof `jti` 重放。
- RS256 JWT：签名密钥持久化到数据库，首次启动从配置私钥导入或自动生成，支持后台轮换并在 JWKS 中保留已退役公钥。
- 管理 API：登录、退出、当前用户、用户 CRUD、CSV 原子批量开通、用户详情、登录审计、OIDC 客户端管理、授权码管理、注册策略管理、第三方 OIDC Provider / LDAP Provider 管理、配置摘要。
- 注册能力：首次启动注册第一个管理员；支持无条件注册、邮箱验证码、手机号验证码、注册授权码、第三方 OIDC 注册和 LDAP/AD 目录注册。
- 授权码：区分普通注册、账号恢复、仅能创建新受限账号的体验入驻码，以及受 OIDC 应用约束的管理员通用登录；可设置一次性、限时、永久或指定次数，并记录使用次数和兑换明细。
- 用户生命周期：正常账户可禁用；禁用账户可启用或归档；归档账户只读，可启用恢复或最终删除。
- 组织管理：支持后台创建组织、维护组织成员和成员角色，用户详情展示所属组织，OIDC 客户端可绑定所属组织作为多租户边界。
- MFA：当前账号可启用 TOTP 二次验证、生成一次性恢复码、轮换恢复码；Passkey 登录可直接满足 MFA；OIDC 客户端可要求 MFA step-up；后台可重置用户 MFA。
- Passkey / WebAuthn：当前账号可注册、查看和删除 Passkey；登录页可直接使用 Passkey 无密码登录，服务端在数据库保存 credential 和一次性 challenge 状态。
- 账号自助安全：当前用户可查看登录会话/设备信息、撤销其他会话，并管理已记住的 OIDC 授权应用。
- 自助密码重置：登录页可通过邮箱验证码重置密码，遵守后台密码策略，成功后清理旧 session、authorization code 和 refresh token。
- 安全策略：后台可配置密码复杂度、拒绝账号信息入密、登录失败统计窗口、临时锁定、失败后 CAPTCHA、可信网络 MFA、登录/注册 IP allow/block 和邮箱域名 allow/block。
- 认证流程基础：后端提供 trait 化 `AuthStage` / `AuthFlow` 组合器，登录入口统一串联风险规则和临时锁定检查，OIDC 登录、授权和 Device Flow 复用 stage 化 MFA 决策，后续可继续挂载 CAPTCHA、组织策略、设备风险或第三方身份源 stage。
- OIDC 授权同意：可关闭全局跳过 consent；用户按客户端和 scope 记住授权，后续同 scope 子集请求自动放行。
- OIDC Claim Mapper / Assurance：每个客户端可配置自定义 claim，支持用户字段、客户端字段、固定值和 scope 标记，分别输出到 ID token、access token 和 userinfo；授权请求可用 `acr_values` 或 `claims.id_token.acr/amr` 要求基础认证等级或 MFA step-up，ID token 会携带 `acr` / `amr`。
- 外部 OIDC 身份源模板：后台内置 Google、Microsoft Entra ID、Keycloak、authentik、ZITADEL、Logto 模板，并可通过 OIDC discovery 自动导入 issuer、authorization、token、userinfo 端点和常用 scopes；支持按企业邮箱域发现并跳转到匹配 Provider。
- LDAP/AD 目录身份源：后台可配置多个 LDAP Provider，支持服务账号搜索、StartTLS、目录密码登录、首次/按策略自动创建本地账号，并通过 `linked_identities` 绑定目录 subject。
- IAP / ForwardAuth：后台可配置受保护应用的外部 Host、路径前缀、组织和权限要求；反向代理调用 `/api/iap/forward-auth` 后，服务按当前 SSO Cookie 返回放行/拒绝决策并注入用户身份响应头。
- SCIM 2.0：提供 `/scim/v2/Users` 和 `/scim/v2/Groups` 供应 API，强制专用 audience 与 `scim.read`/`scim.write` scope，支持分页、基础过滤、创建、替换、PATCH；用户删除转禁用，组删除移除组和成员关系。
- 审计 Webhook：后台可配置审计事件投递 URL、HMAC 签名密钥、action 过滤、启用状态和超时，审计入库成功后异步 best-effort 投递。
- 多语言前台：支持 `zh-CN` / `en-US` 点击切换，并保存到浏览器本地。
- 登录入口品牌：后台可配置 Signet Logo URL；OIDC 客户端可配置标准 `logo_uri`，在 SSO 账号选择页显示目标应用标识。
- 管理前台：React/Vite 控制台，支持用户、用户详情、客户端、授权码、注册策略、身份源和运行配置查看；由 `backend/build.rs` 自动构建并嵌入后端二进制。
- Diesel 数据库层：通过配置选择 SQLite、PostgreSQL 或 MySQL/MariaDB。

## 数据库

配置在 [config/default.toml](../config/default.toml)：

```toml
[database]
kind = "sqlite" # sqlite | postgres | mysql
url = "data/gpt-sso.sqlite3"
pool_size = 10
run_migrations = true
```

Cargo feature：

- 默认：`sqlite`
- PostgreSQL：`--no-default-features --features postgres`
- MySQL/MariaDB：`--no-default-features --features mysql`
- 同时编译全部后端：`--all-features`

示例 URL：

```toml
# SQLite
kind = "sqlite"
url = "data/gpt-sso.sqlite3"

# PostgreSQL
kind = "postgres"
url = "postgres://sso:sso@127.0.0.1:5432/gpt_sso"

# MySQL/MariaDB
kind = "mysql"
url = "mysql://sso:sso@127.0.0.1:3306/gpt_sso"
```

## 架构与前端体验

- `backend/src/server.rs` 负责路由组装、CORS、压缩、请求 ID、安全响应头和优雅停机；业务模块只维护各自路由与处理逻辑。
- `backend/src/health.rs` 分离存活与就绪探针；就绪状态会检查数据库、运行配置和活动签名密钥。
- `frontend/src/lib/api.ts` 统一处理 JSON、空响应、网络故障和 API 错误；`frontend/src/components/` 提供可访问弹窗、表单、搜索、状态与错误边界。
- 管理端按当前页面懒加载数据，切换筛选不再重新请求全部管理资源；页面写入 URL hash，可刷新、后退和直接分享。
- 控制台支持当前页搜索、深浅色主题、危险操作确认、操作反馈，以及手机/平板抽屉导航。

## 浏览器 CSRF 与跨域安全

使用登录 Cookie 的浏览器写请求采用同步器令牌保护。自定义前端或 API 客户端应按以下流程调用：

1. 携带当前会话 Cookie 请求 `GET /api/csrf`，取得响应中的 `csrf_token`。
2. 对受保护的 `POST`、`PUT`、`PATCH`、`DELETE` 请求同时携带 Cookie，并发送 `X-CSRF-Token: <csrf_token>`。
3. 会话变化后重新获取令牌；令牌只属于签发它的当前会话，不应持久化或跨用户复用。

受保护范围包括 `/api/admin/*`、`/api/logout`、`/api/me/*`、`/api/mfa/*`，以及 Passkey 注册和删除接口。若这些请求带有 `Origin` 或 `Referer`，其 scheme、host 和 port 还必须与运行时 `public_base_url`、OIDC `issuer` 或 `[cors].allowed_origins` 中的一个精确一致；没有来源头的非浏览器调用仍必须提交有效 CSRF 令牌。

登录、注册、验证码、密码重置和 Passkey 登录等尚未建立会话的公共浏览器写接口不能预取会话令牌，因此必须带可信的 `Origin` 或 `Referer`，缺失或不匹配都会返回 `403 csrf_failed`。反向代理部署时应确保运行时公网地址正确；跨域管理前端还需把其完整 origin 显式加入 `[cors].allowed_origins`。

本地调试若暂时无法配置 HTTPS 或固定前端来源，可设置 `SSO_DISABLE_CSRF_ORIGIN_CHECK=true` 跳过来源校验。该选项只适用于回环地址测试；它不会关闭会话写请求的 CSRF token 校验，但会允许公共浏览器写接口不带可信来源头，因此生产环境必须保持关闭。

OAuth/OIDC 和机器调用端点不受这层浏览器 `X-CSRF-Token` 中间件影响，例如 `/oauth2/token`、`/oauth2/par`、`/oauth2/introspect`、`/oauth2/revoke`、`/oauth2/device_authorization`、动态客户端注册 `/connect/register`、`/scim/v2/*` 和 `/api/iap/forward-auth`。这些端点继续使用各协议规定的客户端认证、Bearer token、DPoP 或专用交互表单校验，协议客户端不应先调用 `/api/csrf`。

内置前端的 `api()` 客户端会为同源受保护写请求懒加载并缓存 CSRF 令牌，并合并并发获取请求。收到 `403 csrf_failed` 时会清除缓存、重新获取并安全重试一次；收到 `401`，或登录、注册、Passkey 登录完成及退出导致会话变化时，也会清除旧令牌。

跨站 Cookie 与 credentialed CORS 有以下启动时强制约束：

- `[security].cookie_same_site = "None"` 时必须同时设置 `cookie_secure = true`，即只通过 HTTPS 发送 Cookie。
- `[cors].allow_credentials = true` 时，`allowed_origins` 不能包含 `*`，必须逐项配置完整 origin。
- `X-CSRF-Token` 会被服务端自动加入 CORS 允许请求头；默认配置仍显式列出 `x-csrf-token`，便于审计。

从旧版本升级时，直接使用 `fetch`、移动端 WebView 或自建管理前端的调用方必须实现上述令牌流程；旧客户端否则会在 Cookie 写接口收到 `403 csrf_failed`。测试脚本直接调用公共认证接口时也要显式发送可信 `Origin`。现有 OAuth、SCIM、DCR 和 IAP 协议集成不需要增加 CSRF 请求头；如果旧配置使用 `SameSite=None` 配合非安全 Cookie，或 credentialed CORS 配合通配 origin，需先修正配置再启动。

## 开发环境

进入 nix-shell 安装 Diesel 需要的系统库：

```bash
nix-shell
```

[shell.nix](../shell.nix) 包含：

- `sqlite`
- `postgresql` / `libpq`
- `mariadb-connector-c` / mysqlclient
- `openssl`
- `pkg-config`
- `cargo` / `rustc`
- `nodejs_22`

## 运行

进入 nix-shell 后直接运行：

```bash
nix-shell --run "cargo run"
```

`cargo run` 会在编译后端前自动执行：

- 如果 `frontend/package-lock.json` 存在，执行 `npm ci --no-audit --fund=false`。
- 如果 lockfile 不存在，执行 `npm install --no-audit --fund=false`。
- 执行 `npm run build`。
- 把 `frontend/dist` 复制到 Cargo `OUT_DIR` 并生成 `include_bytes!` 嵌入表。

运行时后端从内存返回前端资源，不再读取 `frontend/dist`，也不需要启动 Vite。

如需只使用已有的 `frontend/dist`，可以设置：

```bash
SSO_SKIP_FRONTEND_BUILD=1 nix-shell --run "cargo run"
```

这个模式要求 `frontend/dist` 已存在。

### 内网穿透 / 反向代理

OIDC discovery 文档里的 `issuer`、`authorization_endpoint`、`token_endpoint`、`jwks_uri` 等地址必须是客户端能访问的公网地址，不能暴露 `localhost`。

推荐在后台 `运行配置` 页手动保存：

- 公网 Base URL，例如 `https://oidc.shanshen.de5.net`
- OIDC Issuer，通常与公网 Base URL 相同
- 是否信任代理/穿透请求头

后台设置会写入数据库，保存后立即影响 discovery、OIDC token 的 `iss`、管理前台概览和第三方 OIDC 回调地址。

也可以用环境变量提供首次启动默认值：

```bash
SSO_PUBLIC_BASE_URL=https://oidc.shanshen.de5.net nix-shell --run "cargo run"
```

如果没有单独设置 `SSO_ISSUER`，`SSO_PUBLIC_BASE_URL` 会同时作为 OIDC issuer。

如果确实在可信反向代理后运行，可以开启请求头推导：

```toml
[server]
trust_proxy_headers = true
```

开启后服务会从 `Forwarded`、`X-Forwarded-Proto`、`X-Forwarded-Host` 或 `Host` 推导外部 URL。登录审计、最近 IP、会话来源和可信网络 MFA 也会优先使用可信代理传入的来源 IP；未开启时使用实际 TCP 远端地址。内网穿透不一定会带这些请求头；这种情况下应保持关闭，并使用后台手动保存的公网地址。

首次启动：

- 默认不会自动创建管理员。
- 访问 `http://localhost:8080/` 会进入注册页。
- 第一个注册成功的用户会自动成为管理员。
- 首个用户管理员判定会在数据库事务里复查；并发注册时只有真正先写入的首个用户能获得管理员身份，其他按首个用户路径进入的请求会被要求重试。
- 如果确实需要启动时创建配置文件里的管理员，可把 `[bootstrap.admin].create_on_startup` 设置为 `true`。

上线前必须修改 [config/default.toml](../config/default.toml) 中的客户端 secret、cookie secure、issuer、RSA 私钥、验证码投递方式和第三方 OIDC Provider 配置。

## 注册与后台设置

注册策略在配置文件中作为初始值，启动后写入数据库并可在后台修改：

```toml
[registration]
allow_password_registration = true
require_email_verification = false
require_phone_verification = false
allow_external_oidc_registration = true
require_invitation = false
default_user_active = true
```

`require_invitation = true` 表示非首个用户注册时必须提供 `code_type = registration` 的授权码；账号恢复码和管理员通用码都不能替代注册授权码。

首个通过注册、第三方 OIDC 或目录登录创建的用户始终会成为管理员；旧版 `first_user_direct_admin` 字段仍被读取以兼容已有数据库和配置，但不会允许关闭这个不变量。

验证码默认使用 `dev_log`，仅写入本地服务日志，不会通过 HTTP 响应回显或自动填入页面。生产环境应改为公司内部邮件/短信网关、SMTP 或短信 Provider：

```toml
[verification.email]
enabled = true
delivery = "webhook" # dev_log | webhook | sms_provider | smtp
code_ttl_seconds = 600
max_attempts = 5
webhook_url = "https://notify.example.internal/sso/verification"
webhook_secret = "change-me"
webhook_timeout_seconds = 5
# 如果需要直接 SMTP 发邮箱验证码：
smtp_host = "smtp.example.com"
smtp_port = 587
smtp_username = "sso@example.com"
smtp_password = "change-me"
smtp_from = "Signet <sso@example.com>"
smtp_starttls = true
```

同一 `channel + target + purpose` 的验证码会按 `resend_interval_seconds` 做服务端重发限流；未到间隔时不会写入新验证码，也不会触发投递。验证码会先写入数据库再投递；如果投递失败，后端会按验证码 ID 清理这条未消费记录，避免用户没有收到验证码却被重发间隔卡住。

`delivery = "webhook"` 会向 `webhook_url` POST JSON：

```json
{
  "type": "verification.code",
  "channel": "email",
  "target": "user@example.com",
  "purpose": "registration",
  "code": "123456",
  "expires_at": 1730000000,
  "message": "registration verification code"
}
```

如果配置 `webhook_secret`，请求会带 `X-GPT-SSO-Signature: sha256=<base64url-hmac-sha256>`。`delivery = "sms_provider"` 会把同样的 JSON POST 到 `sms_provider` 字段指定的 HTTP URL，并在配置 `sms_api_key` 时带 `Authorization: Bearer <sms_api_key>`。`delivery = "smtp"` 可用于邮箱通道，要求配置 `smtp_host` 和 `smtp_from`；`smtp_username` / `smtp_password` 必须成对配置。默认使用 STARTTLS，内网明文 SMTP 中继可显式设置 `smtp_starttls = false`。

登录页的“重置密码”使用同一套邮箱验证码配置，验证码 purpose 为 `password_reset`。重置成功后后端会重新哈希密码并清理该用户既有登录态和 OAuth 授权中间态，避免旧会话继续有效。

第三方 OIDC Provider 可在配置文件初始化，也可在后台增删改查。启用后注册页会显示对应第三方按钮，回调地址形如：

```text
http://localhost:8080/api/register/oidc/<slug>/callback
```

后台的“允许第三方 OIDC 注册”和 Provider 级“允许注册”只控制是否可通过未知外部身份创建新用户；已绑定过的外部身份仍可通过启用的 Provider 登录。首次启动且没有任何用户时，Provider 级“允许注册”仍必须开启，才能通过第三方 OIDC 创建第一个管理员。

第三方 OIDC 创建新用户时，用户记录和 `linked_identities` 绑定会在同一个数据库事务里写入；如果外部邮箱已经属于现有账号，或同一个 Provider subject 已被并发绑定，会返回业务错误而不是留下未绑定账号。

后台 `身份源` 页提供常见 OIDC Provider 模板，用于快速填入 slug、显示名、issuer 和 scopes。内置模板包括 Google、Microsoft Entra ID、Keycloak、authentik、ZITADEL 和 Logto；带 `example` 占位的 issuer 需要先替换成真实租户、realm 或应用路径。

外部 OIDC Provider 还可以配置企业邮箱域名，例如 `example.com` 或 `team.example.com`。登录/注册页会根据用户输入的邮箱域显示匹配的公司 SSO 跳转按钮；父域规则会匹配子域，多个 Provider 同时匹配时使用最长、最具体的域名规则。该路由只负责发现和跳转，是否允许新建用户仍由全局“允许第三方 OIDC 注册”和 Provider 自身“允许注册”共同控制。

Provider 可选绑定所属组织。未知外部身份首次通过该 Provider 创建本地账号时，后端会先检查组织邮箱域 allowlist，再在同一个事务里把用户加入该组织，默认组织角色为 `member`；已绑定身份后续登录不会改写组织成员关系。删除组织会自动清空 Provider 绑定，避免后续新用户进入不存在的组织。

OIDC discovery 导入接口：

```text
GET  /api/admin/external-oidc-provider-templates
POST /api/admin/external-oidc-provider-discovery
```

`POST /api/admin/external-oidc-provider-discovery` 接收 JSON：

```json
{
  "issuer": "https://idp.example.com/realms/company"
}
```

后端会尝试兼容两种常见 discovery 地址：

- `https://idp.example.com/realms/company/.well-known/openid-configuration`
- `https://idp.example.com/.well-known/openid-configuration/realms/company`

成功后返回规范化的 `issuer`、`authorization_endpoint`、`token_endpoint`、`userinfo_endpoint` 和 `openid profile email` 子集 scopes。请求由后台 `providers.manage` 权限保护，响应只用于填表，不会自动保存 Provider；管理员仍需要填写 client ID/secret 并手动保存。

OIDC Provider 的 client secret 不会回传到前端。编辑现有 Provider 时密钥留空表示保留原值；只有勾选“清空已保存的客户端密钥”才会显式删除，填写新值则执行轮换。

LDAP/AD Provider 可在后台 `身份源` 页维护，接口为：

```text
GET    /api/admin/ldap-providers
POST   /api/admin/ldap-providers
PUT    /api/admin/ldap-providers/{id}
DELETE /api/admin/ldap-providers/{id}
```

LDAP 登录复用登录页邮箱/密码表单：本地密码认证失败或本地账号不存在时，后端会按启用的 LDAP Provider 依次尝试目录认证。每个 Provider 使用服务账号可选 bind，按 `base_dn` 和 `user_filter` 搜索用户 DN，再用用户输入的密码对该 DN 做 simple bind。`user_filter` 必须包含 `{login}`，后端会按 LDAP 规则转义用户输入，常见模板为：

```text
(&(|(mail={login})(uid={login})(sAMAccountName={login}))(objectClass=person))
```

目录账号会通过 `linked_identities.provider_slug = ldap:<slug>` 和目录 subject 绑定本地用户。已绑定身份可继续登录；未绑定身份只有在全局“允许第三方 OIDC 注册”和 Provider 级“允许注册”同时允许时才会自动创建本地用户，首次启动创建第一个管理员时也要求 Provider 允许注册。目录返回的邮箱如果已经属于现有本地账号，后端不会自动合并或抢占该账号。

LDAP Provider 返回给前端时只暴露 `has_bind_password`，不会回传 bind 密码；编辑时密码留空表示保留，勾选“清空 Bind 密码”才会删除已保存密码。启用目录登录后，登录事件会记录 `login_method = ldap` / `oidc_ldap`，并把 `external_provider` 记录为 `ldap:<slug>`，便于用户详情和审计查看来源。

授权码后台接口使用：

```text
GET    /api/admin/authorization-codes
POST   /api/admin/authorization-codes
PUT    /api/admin/authorization-codes/{id}
DELETE /api/admin/authorization-codes/{id}
```

旧版 `/api/admin/invitations` 路径仍作为兼容别名保留。

管理接口使用 `code_type = registration | login`；登录码再通过 `login_code_level = account_recovery | trial_enrollment | admin_universal` 区分权限。列表会返回使用次数、最近兑换记录和允许的客户端；体验入驻码还会返回固定的 `organization_id` 和 `organization_role`。完整授权码只在创建响应中显示一次，之后仅保留前缀。

| 类型 | 用途与约束 |
| --- | --- |
| `registration` | 仅用于正常注册。用户仍须提交邮箱、密码并满足密码策略及已启用的邮箱/手机验证；创建的是普通非归档账户。可预先绑定邮箱、用户名和显示名。 |
| `login / account_recovery` | 必须在创建时绑定一个已存在、启用且非归档账号的 `authorized_username`，绑定后不可更改；不存在、禁用或归档的账号会被拒绝。登录时提交的用户名必须精确匹配。成功后只为真实账号建立最长 15 分钟的受限恢复 Session，不创建或归档账号，也不是可改投其他账号的通用凭据。它可通过一次性 `account_flow` 加入当前多账号上下文。 |
| `login / trial_enrollment` | 面向社团内测、产品体验或受控入驻分发。创建或更新同时需要 `authorization_codes.manage` 与 `organizations.manage`；创建时必须固定至少一个已启用 OIDC 客户端、一个启用组织、组织角色（`owner` / `admin` / `member`）、到期时间和最大使用次数；这些范围创建后不可扩大或修改。兑换时必须提交一个此前未注册的用户名和邮箱，可选显示名；用户名或邮箱与已有账号冲突会整体拒绝，绝不借共享码登录、覆盖或占用已有账户。成功后创建非管理员、受限体验账号，并只可进入码允许的应用。 |
| `login / admin_universal` | 仅真正的超级管理员可创建。登录时可指定任意已存在、启用且非归档的用户名，但只对创建时写入 `allowed_client_ids` 的已启用 OIDC 客户端有效；应用范围创建后不可更改。它只能从服务端生成并校验的 OIDC interaction 中使用，不能在普通登录页自报 `client_id` 或脱离目标应用使用。 |

注册使用 `POST /api/register` 并提交 `authorization_code`；登录使用：

```http
POST /api/login/authorization-code
Content-Type: application/json

{
  "username": "alice",
  "authorization_code": "LOGIN-...",
  "email": "alice@example.com",
  "display_name": "Alice",
  "return_to": "/oauth2/authorize?interaction_request=...",
  "account_flow": "alf1...."
}
```

`email` 和 `display_name` 只由 `trial_enrollment` 使用：邮箱必填、显示名可选，其他登录码会忽略它们。`return_to` 仅接受本地、服务端可验证的继续地址；`account_flow` 仅在“添加其他账号”流程中提供。账号恢复成功返回 `mode = session` 的临时恢复登录响应，其 Session 最长 15 分钟；体验入驻成功也返回 `mode = session`，但会明确标记为受限体验登录。若存在合法 `return_to`，前端会继续原 OIDC 流程。管理员通用码返回 `mode = oidc_continuation` 和 `continue_to`。

管理员通用码不会创建主 Session，也不会加入浏览器多账号列表。后端仅签发绑定 interaction、OIDC client 和目标用户、约 3 分钟有效的独立一次性 grant，并使用 Path 限定为 `/oauth2/authorize` 的独立 HttpOnly Cookie；签发 authorization code 时即消费。该流程拒绝 `offline_access`、refresh token、需要 MFA 的授权请求和持久化 consent，不能用于后台、IAP 或 Device Flow。

通过登录授权码完成的 OIDC access token / ID token 会携带私有来源声明 `gpt_sso_login_code_level`。资源服务可以据此区分 `account_recovery`、`trial_enrollment` 与 `admin_universal` 登录来源；带有该声明的 access token 一律禁止用于 SCIM 和 Token Exchange，未来新增但本服务尚不认识的级别也按拒绝处理。

管理员通用码属于高风险凭据：其持有者可在允许应用范围内指定用户名完成授权。创建时应只选择必需应用，设置较短有效期和最小使用次数，并通过安全渠道分发；创建后如需调整账号范围或应用范围，应停用旧码并重新创建，不能直接扩大已有凭据权限。

授权码校验、用途/账号/客户端约束、`uses_count` 更新、用户创建、验证码消费和兑换记录均在数据库事务中完成；失败不会消耗码，并发兑换也不能突破使用次数。类型、登录级别、账户恢复码绑定账号、体验入驻码的组织/角色/应用范围及管理员通用码应用范围创建后不可变。

体验入驻账户是 code-only 的受限身份：不能使用密码重置、密码、Passkey、LDAP 或外部 IdP 登录来升级为普通 SSO Session，不能进入后台、Device Flow、IAP/ForwardAuth、SCIM 或 Token Exchange，也不能保存 consent。普通 OIDC 仅限创建时的客户端 allowlist，拒绝 `offline_access` 与 refresh token；停用、删除、到期或删除绑定组织时会撤销其 Session 和尚未兑换的 OAuth authorization code。已发出的自包含 JWT 仍受其短 access-token TTL 约束，资源服务应同时检查 `gpt_sso_login_code_level`。

账号恢复码不会创建临时或归档账户；它在绑定的真实账号上创建最长 15 分钟的受限恢复 Session。该 Session 的权限列表为空，不能修改资料、安全设置或授权同意，不能进入后台、确认 Device Flow 或访问 IAP/ForwardAuth；但可以继续交互式 OIDC Authorization Code → Token → UserInfo 流程。它不能请求 `offline_access`，不会获得 refresh token，签发的 access token 也不能用于 SCIM 或 Token Exchange。会话过期不会改变真实账号状态，后续长期使用应通过账号原有的正常认证方式登录。

## 浏览器多账号与 OIDC 账号选择

多账号使用两个相互独立的 HttpOnly Cookie：主 Session Cookie 只代表当前活动账号；`${cookie_name}_accounts` 只标识浏览器账号上下文。账号、Session 和两者的映射均保存在服务端数据库，浏览器不会得到其他账号的 bearer 或数据库 Session ID。两个 Cookie 继承配置的 Secure、SameSite 和 Domain 策略；切换账号时后端为已保存 Session 签发新的上下文绑定凭据。

账号选择页支持选择、添加、移除和退出全部：

```text
GET    /api/browser-accounts?return_to=...          # 账号列表和目标应用提示
GET    /api/browser-accounts/csrf                   # 多账号上下文 CSRF 令牌
POST   /api/browser-accounts/select                 # { account_ref, return_to } -> { continue_to }
POST   /api/browser-accounts/add/start              # { return_to } -> { login_url }
DELETE /api/browser-accounts/{account_ref}          # 移除账号并撤销对应 Session
POST   /api/browser-accounts/logout-all             # 撤销该上下文全部 Session
```

所有写操作都要求 `X-CSRF-Token`。`account_ref` 是上下文内的不透明引用。添加账号时，后端签发约 10 分钟有效、只能在同一浏览器上下文消费一次的 `account_flow`；密码、Passkey、LDAP、外部 OIDC、注册和账号恢复码登录都会透传它。成功后新 Session 加入账号列表而不删除其他账号。移除当前账号会同时清除主 Session Cookie；“退出全部”会删除上下文中的 Session、派生凭据和映射，并清除两个 Cookie。管理员通用码使用独立 OIDC grant，不进入此列表。

OIDC `prompt` 行为如下：

- 未提供 `prompt` 时优先复用当前活动账号；客户端启用“强制账号选择”时仍会显示选择页。
- `prompt=select_account` 强制显示账号选择页；可与 `login` 或 `consent` 组合。`login_hint` 只用于推荐和排序，不会替 RP 静默切换账号。
- `prompt=login` 要求所选账号重新认证，但不会删除浏览器上下文中的其他账号。`max_age` 过期采用相同的重新认证路径。
- `prompt=none` 不允许与其他 prompt 值组合，也绝不显示登录、选择、MFA 或 consent 页面；缺少登录返回 `login_required`，需要选账号返回 `account_selection_required`，需要 consent 返回 `consent_required`，需要 MFA step-up 返回 `interaction_required`。

选择操作只接受服务端生成的 interaction handle。后端会校验目标 client、所选 Session 和用户，把选择结果写入下一次一次性 interaction，再返回 `continue_to`；因此 RP 不能通过篡改 Cookie、`account_ref` 或裸 `client_id` 把授权切换到另一个账号。

## 用户归档与性能

用户管理页默认只查询未归档账户，归档账户需要通过筛选条件单独查看；选择“全部账户”时归档账户仍会排在末尾。后端接口对应为：

```text
GET /api/admin/users?status=live      # 默认：正常/禁用，排除归档
GET /api/admin/users?status=active    # 正常账户
GET /api/admin/users?status=disabled  # 禁用账户
GET /api/admin/users?status=archived  # 归档账户
GET /api/admin/users?status=all       # 全部，归档末尾
```

归档账户保留注册时间、最近登录、最近 IP、最近 OIDC 客户端、登录事件和绑定身份等审计信息，但禁止编辑资料、密码、MFA 和授权同意等账号写操作。恢复时先启用账户，启用会清除 `archived_at` 并回到正常账户列表。

账号恢复码只能绑定并登录已存在、启用且非归档的账号；用户名不存在、账号禁用或已归档时，创建与兑换都会被拒绝。兑换成功只建立最长 15 分钟的受限恢复 Session，刷新页面可在剩余有效期内保持登录，也可完成不含离线访问的 OIDC Authorization Code 流程，但不能用于 Device Flow、IAP、后台管理或任何账号自助修改接口。该流程不会创建新账号，也不会修改真实账号的 `active` / `archived` 状态。

性能策略：

- 热路径列表和统计优先走 `archived_at IS NULL`，避免归档账户随普通管理操作一起加载。
- 数据库为 `(archived_at, is_active, created_at)` 建索引，支撑状态筛选和默认排序。
- SCIM 用户列表默认只扫描未归档账户；`active eq true/false` 会分别落到正常/禁用账户范围，归档账户只通过直接详情查询保留审计可见性。
- 禁用和归档会清理 session、authorization code、refresh token、Device Flow 和 WebAuthn 挑战，减少后续鉴权检查的无效状态。
- OIDC 登录和管理登录拒绝禁用或归档账户；token、userinfo 和 introspection 只接受仍启用且非归档的真实账号。恢复 Session 签发的 token 带登录码来源声明且不会获得 refresh token。
- 权限系统会把禁用、归档、临时恢复 Session 或体验入驻 Session 视为无管理权限主体；即使恢复码绑定的真实账号是管理员，该临时 Session 的 `permissions` 仍为空。

## CSV 原子批量开通

企业批量设置账户应使用 CSV（小规模、人工审核场景）或 SCIM / LDAP（持续同步场景），而不是分发管理员通用码。管理端“用户”页提供文件上传和文本粘贴两种入口，默认先执行 dry-run，并显示逐行结果；取消 dry-run 后还必须明确确认才会提交。

接口为：

```text
POST /api/admin/users/import-csv?dry_run=true|false
Content-Type: text/csv
```

调用需要 `users.manage`；任意行填写 `organization_slug` 时还需要 `organizations.manage`。CSV 必须使用以下精确表头（UTF-8，标准 CSV 引号规则）：

```csv
email,username,display_name,organization_slug,organization_role,is_active
alex@example.com,alex,Alex Example,example-club,member,true
```

- `email`、`username` 必填且整批内、以及与已有账号均不可重复。
- `display_name`、`organization_slug`、`organization_role` 可留空；指定组织时角色必须是 `owner`、`admin` 或 `member`。
- `is_active` 必须为 `true` 或 `false`；不提供管理员列，所有导入账号均为本地非管理员。
- 导入邮箱会被标记为已验证。服务端写入不可得的初始密码，不返回或记录可用初始凭据；请在后续通过受控的设置密码、密码重置或入驻流程交付登录凭据。

成功和校验失败都会提供同一种逐行结构；当任一行无效时接口返回 `422`、`committed = false`，并保证整个批次零写入：

```json
{
  "dry_run": true,
  "atomic": true,
  "committed": false,
  "summary": { "total": 2, "created": 0, "would_create": 1, "invalid": 1 },
  "rows": [
    { "row": 2, "email": "alex@example.com", "username": "alex", "outcome": "would_create" },
    { "row": 3, "email": "bad@example.com", "username": "alex", "outcome": "invalid", "error": "username is duplicated" }
  ]
}
```

`outcome` 为 `created`、`would_create`、`invalid` 或 `not_committed`。dry-run 永远不写入；真实提交仅在所有行都通过时返回 `committed = true`，其余情况不会留下部分账户或部分组织成员关系。

## 组织管理

Signet 以“一个账号可属于多个企业”为基本模型。登录后的右上角企业选择器只保存管理台上下文；每个 API 仍会重新校验当前账号对目标企业的成员资格，不能依赖前端过滤实现隔离。

- 企业包含 `slug`、名称、描述、启用状态和可选邮箱域 allowlist；allowlist 为空表示不额外限制。成员角色为 `owner`、`admin`、`member`。普通用户可自助创建企业，并自动成为该企业 owner。
- 内置的 `Signet` 是系统企业，用于平台级资源和历史资源迁移。它不可自助创建、编辑或删除；其成员名单只能由拥有平台 `organizations.manage` 权限的管理员修改，企业内角色本身不会提升为平台管理员。
- 所有业务资源属于一个企业：应用、OIDC 连接、外部 OIDC/LDAP 身份源以及应用入驻码均不能跨企业引用。身份源首次自动建号时会将用户加入其所属企业，并执行该企业的邮箱域规则。
- **应用**是网站接入配置与授权策略的主体，OIDC client 只是应用的协议连接。一个连接只属于一个应用，同一应用可有多个连接；新建管理台 OIDC client 会同时得到一个默认的、关闭注册且允许所有 active Signet 统一账户登录的应用。
- 升级前已有的连接会保留必要的兼容数据，以免升级时意外中断服务；移除连接或删除应用时，连接会自动获得新的默认锁定应用，绝不会因为脱离原应用而回落到未定义的协议策略。
- 活跃且未归档的 Signet 统一账户都可以登录 active 网站应用，不需要加入应用。企业成员关系只影响企业默认权限、目录同步归属和管理边界；应用角色、应用权限和 Claims 再叠加网站专属授权，不能被解释为“应用成员资格”。
- 应用注册策略可选关闭、仅应用邀请码或企业目录/邀请流程；它只控制新 Signet 账户如何创建以及是否加入企业，不会把既有账户加入应用成员名单。邀请码会同时校验应用、企业和 OIDC 返回上下文，不能被转用于其他企业或应用。
- 应用可要求选账号。该策略会与 OIDC client 的 `require_account_selection` 合并，账户选择页只展示当前浏览器中 active 且未归档的 Signet 统一账户；最终授权、授权码换 token、refresh、userinfo 与设备授权都会再执行同一应用校验。
- 应用可要求“已验证邮箱唯一”和/或“已验证手机号唯一”。服务端以加密摘要保存每个应用内的当前身份租约，并由数据库唯一键处理并发冲突；邮箱或手机号改变只释放对应因子，账号停用或归档会释放其全部相关租约。应用成员名单的历史兼容数据不会成为登录拒绝规则。
- 删除企业前必须先转移或删除其应用，避免 OIDC 连接脱离策略边界。禁用或归档用户会保留企业关系用于审计，物理删除用户时才清理成员关系。
- 平台 RBAC 仍支持 `organizations.read` / `organizations.manage` 等全局权限；企业 owner/admin 则只可管理自己当前企业的应用、OIDC 连接、身份源和成员，不会获得其他企业可见性。

### 传统 SaaS 应用如何映射

以“差旅报销”这个传统企业 SaaS 为例：`Acme` 企业创建一个 `expense` 应用；它的 Web、iOS 和后台任务可以各有一个 OIDC 连接，但都归属同一个应用。因此三个入口共享同一份“谁能进入、是否可自助入驻、是否必须选账号、身份是否已被占用”的业务规则，而不必把规则复制到每一个回调地址或客户端配置中。

- 员工版可绑定企业 LDAP/AD 或 SCIM 作为人员主数据，并通过企业默认角色和应用角色授予报销权限；所有 active Signet 账户仍通过统一账户登录，目录同步只负责企业成员和权限生命周期。
- 供应商版可使用独立第三方身份源、邀请码和应用专属权限/Claims；同一企业中的普通员工不会因为登录 Signet 而获得供应商网站的业务权限，但也不需要维护一份应用成员名单。
- 如果用户常在同一浏览器登录个人与工作账号，可要求账号选择；即使某个 OIDC 连接没有单独要求，应用级规则仍会阻止静默选错账号。
- 若业务需要降低重复开户风险，可要求已验证邮箱和/或手机号在该应用内唯一。该约束仅是可审计的身份信号与成本提升，不能证明现实中的“同一个自然人”；需要更强保证时，应接入企业 IdP、SCIM 人员主数据或业务侧实名/KYC 校验。

这保留了传统应用常见的组合能力：同一企业可以同时拥有面向员工、供应商和测试人员的不同应用；同一用户也可以属于多个企业。每次 OIDC 授权、换取或刷新 token、调用 userinfo、设备授权及账号选择都会重新计算应用资格，因而策略变更会立即作用于已建立的协议会话，而不是只影响管理台列表。

## MFA 与客户端 Step-Up

用户可在账号页启用 TOTP MFA，并获得一次性恢复码。启用后，管理登录和 OIDC 登录都会要求输入 TOTP 或恢复码。

后台客户端页面可单独开启“强制 MFA”。开启后，该 OIDC 客户端的授权请求和 Device Flow 确认页都会检查当前 SSO session 是否由 MFA 完成；普通密码 session 会被带到 MFA 页面做 step-up。`prompt=none` 请求不会显示交互页面，而是按 OIDC 规范返回 `interaction_required`。如果用户尚未配置 TOTP，强制 MFA 客户端会拒绝授权并返回 `access_denied`。

后台安全策略还可以配置可信 IP/CIDR 列表，并开启“外部网络强制 MFA”。开启后，管理登录、OIDC 登录/授权和 Device Flow 确认都会根据请求来源判断是否必须 MFA；可信网络内仍按用户自身 MFA 和客户端强制 MFA 策略执行。未开启“信任代理/穿透请求头”时，来源 IP 使用实际 TCP 远端地址；开启后优先使用 `X-Forwarded-For`、`X-Real-IP` 或 `CF-Connecting-IP`，再回退到远端地址，因此只应在可信反向代理或内网穿透前置层后启用。

后台安全策略还支持登录/注册风险规则：

- `allowed_ip_cidrs`：非空时，管理登录、OIDC 登录、Passkey 登录、普通注册和授权码注册必须来自这些 IP/CIDR。
- `blocked_ip_cidrs`：命中时直接拒绝登录或注册；阻止规则优先于允许规则。
- `allowed_email_domains`：非空时，密码注册、第三方 OIDC 新建用户和登录 subject 必须属于这些邮箱域名；子域名也会匹配父域名规则，例如 `team.example.com` 会匹配 `example.com`。
- `blocked_email_domains`：命中时直接拒绝，优先于允许规则。

账号恢复码登录只应用 IP 风险规则；它绑定现有账号且不会创建或改写邮箱，因此兑换时不重新执行邮箱域 allowlist。注册授权码仍按普通注册执行邮箱域、密码和验证策略。管理员通用码还必须满足目标 interaction、OIDC client allowlist、无 MFA 和无离线访问等专用约束。

后台安全策略还可以开启登录 CAPTCHA。开启后，同一失败统计窗口内某个登录 subject 的失败次数达到阈值时，管理登录和 OIDC 密码登录会先要求完成一次性算术 challenge；challenge 保存在 `captcha_challenges` 表中，成功或失败尝试后都会被消费。默认关闭，默认阈值为 3 次失败、有效期 300 秒。

## Passkey / WebAuthn

Passkey 使用 `webauthn-rs` 完成协议校验。注册和认证 challenge 状态只保存在服务端数据库的 `webauthn_challenges` 表中，浏览器只接收一次性 `publicKey` options；长期凭据保存在 `passkeys` 表中。禁用、归档或物理删除用户会清理相关临时 challenge；物理删除用户也会删除该用户的 Passkey。

WebAuthn 的 Origin 和 RP ID 从当前生效的公网 Base URL 派生。生产或内网穿透部署时，应先在后台 `运行配置` 保存公网 Base URL，例如 `https://oidc.example.com`。RP ID 使用该 URL 的 host，已经注册的 Passkey 会绑定到这个域名，后续随意更换域名会导致旧 Passkey 无法验证。

Passkey 登录的 session `login_method` 为 `passkey`，可满足客户端强制 MFA 和外部网络强制 MFA 策略。

## IAP / ForwardAuth

IAP 用于保护不支持 OIDC 的内部应用。后台 `IAP 应用` 页可登记：

- `external_host`：应用对浏览器暴露的 Host，支持精确 Host、`*.example.com` 和 `*`。
- `path_prefix`：受保护路径前缀，按路径段边界匹配，`/docs` 不会误匹配 `/docs2`。
- 可选组织和组织角色要求。
- 可选后台权限要求，例如 `users.read`；空列表表示只要求已登录的有效 SSO 会话。

反向代理把受保护请求转到：

```text
GET /api/iap/forward-auth
```

也可以显式传 `target`：

```text
GET /api/iap/forward-auth?target=https%3A%2F%2Fdocs.example.com%2Fprivate
```

未传 `target` 时后端会从 `X-Original-URL`、`X-Forwarded-URL`、`X-Forwarded-Host`、`X-Forwarded-Proto`、`X-Forwarded-Uri` 或 `Host` 推导目标。允许访问时返回 `204 No Content`，并带：

```text
X-Auth-Request-User
X-Auth-Request-Email
X-Auth-Request-User-Id
X-Auth-Request-Name
X-GPT-SSO-IAP-Application
```

未登录时返回 `401`，并通过 `Location` / `X-Auth-Request-Redirect` 指向 `/api/iap/start?return_to=...`。用户完成 `/login` 后会进入 `/api/iap/finish`，后端再次校验目标 URL 已配置且当前用户满足组织/权限要求，再跳回原应用，避免开放重定向。

## 后台 RBAC 权限

后台不只依赖超级管理员标记，也支持把细粒度权限授予普通用户。`/api/me` 会返回当前用户有效权限，前端根据权限显示可访问的管理页；后端每个管理接口仍独立校验权限。

- `users.read` / `users.manage`：读取或管理用户；`security.manage` 和 `organizations.manage` 会附带用户只读能力，便于维护角色、组和组织成员。
- `clients.read` / `clients.manage`：读取或管理 OIDC 客户端；`clients.manage` 可读取最小化组织选项，便于绑定组织。
- `iap.read` / `iap.manage`：读取或管理 IAP / ForwardAuth 受保护应用，并可读取最小化组织选项以显示绑定关系。
- `settings.manage`：管理注册策略、运行公网地址、登录入口品牌 Logo、邮箱后缀和快捷跳转。
- `authorization_codes.manage`：管理授权码，并可读取非敏感 OIDC 客户端元数据以选择授权码的应用范围；创建或更新体验入驻码仍额外需要 `organizations.manage`。
- `providers.manage`：管理第三方 OIDC Provider 和 LDAP/AD Provider，并可读取最小化组织选项。
- `organizations.read` / `organizations.manage`：读取或管理组织。
- `security.manage`：管理角色、组、签名密钥、安全策略和审计 Webhook。
- `audit.read`：查看审计事件和审计 Webhook 投递状态。

## 签名密钥轮换

服务启动时会确保数据库里至少有一个 active 签名密钥。首次启动优先导入 `[security].rsa_private_key_pem`，未配置时自动生成 RSA 私钥并持久化，后续重启不会改变 `kid` 或私钥。

安全管理员可以通过后台 API 查看和轮换签名密钥：

```text
GET /api/admin/signing-keys
POST /api/admin/signing-keys
```

管理 API 只返回 `id`、`kid`、active/retired 状态和时间戳，不返回私钥。轮换时后端会在一个事务里退役旧 active key 并创建新 active key，然后立即刷新内存签名器；`/oauth2/jwks` 会继续发布 active 和 retired 公钥，使旧 token 在过期前仍可验证。

## 审计 Webhook

安全管理员可在后台 `安全` 页配置审计 Webhook：

- URL 必须是绝对 `http(s)` 地址，不能包含 fragment 或 userinfo。
- Action 过滤为空表示接收全部审计事件；也可以配置 `user.*`、`client.create` 等精确或前缀过滤。
- 如果配置签名密钥，投递请求会带 `X-GPT-SSO-Signature: sha256=<base64url-hmac-sha256>`。
- 审计事件先写入数据库，再后台异步 best-effort 投递；Webhook 故障不会导致登录、授权或管理操作失败。
- 后台会记录每个 Webhook 最近投递时间、HTTP 状态码和错误摘要，方便排查下游故障。

投递 payload 形如：

```json
{
  "type": "audit.event",
  "id": "event-id",
  "created_at": 1730000000,
  "event": {
    "action": "user.create",
    "target_kind": "user",
    "outcome": "success",
    "details": {}
  }
}
```

## OIDC 示例

Discovery：

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

授权地址示例：

```text
http://localhost:8080/oauth2/authorize?response_type=code&client_id=demo-web&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid%20profile%20email%20offline_access&state=demo
```

换 token：

```bash
curl -u demo-web:demo-secret-change-me \
  -d grant_type=authorization_code \
  -d code=AUTH_CODE \
  -d redirect_uri=http://localhost:3000/callback \
  http://localhost:8080/oauth2/token
```

Userinfo：

```bash
curl -H "Authorization: Bearer ACCESS_TOKEN" \
  http://localhost:8080/oauth2/userinfo
```

Resource Indicators：

```text
http://localhost:8080/oauth2/authorize?response_type=code&client_id=demo-web&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid%20profile&resource=https%3A%2F%2Fapi.example.com%2F
```

`resource` 必须是绝对 URI 且不能包含 fragment。授权码、Device Flow 和 refresh token 会记住 resource，签发的 access token 使用该值作为 `aud`；未提供时继续使用客户端 ID 作为 `aud`。refresh token 续签时不能把 resource 换成另一个 audience。

运行时受众策略：

- `/oauth2/userinfo` 是面向 OIDC client 的具体资源端点，只接受 `aud` 精确等于签发该 token 的当前 `client_id` 的 access token。面向 API 的 Resource Indicators token 不能拿来调用 UserInfo。
- `/oauth2/introspect` 是 issuer 级别的检查端点，可以检查带有 API resource audience 的 token；但调用方只能 introspect `claims.client_id` 等于自身的 token，不能依靠 `aud` 绕过客户端绑定。
- Token Exchange 允许 subject token 原本面向另一个 resource，但请求中的目标 `audience` 只能省略（默认当前 client）或精确等于认证 client，不能借此签发任意资源的 token。
- SCIM 普通用户 token 的 `aud` 必须是 `{public_base_url}/scim/v2`；Application 专用 SCIM token 的 `aud` 必须精确匹配该网站 directory_sync 模块配置的 `scim_audience`。应用和所属企业停用后两种 token 都立即失效。
- 没有具体 resource 上下文的内部兼容 bearer helper 只做签名、issuer、过期和 token-use 检查；新的资源端点必须先确定受众，再调用 audience-aware 验证 API。

Rich Authorization Requests：

客户端可在后台客户端页面或 Dynamic Client Registration 中配置允许的 `authorization_details_types`。空列表表示该客户端不能请求 RAR；请求里每个 `authorization_details` 对象都必须包含已允许的字符串 `type`。

授权请求、PAR 和 JAR signed request object 都支持 `authorization_details`：

```bash
curl -G http://localhost:8080/oauth2/authorize \
  --data-urlencode response_type=code \
  --data-urlencode client_id=demo-web \
  --data-urlencode redirect_uri=http://localhost:3000/callback \
  --data-urlencode scope="openid profile offline_access" \
  --data-urlencode 'authorization_details=[{"type":"resource_access","locations":["https://api.example/"],"actions":["read"]}]'
```

`client_credentials` 和 Device Authorization 请求也可直接提交 `authorization_details`。授权码、Device Flow 和 refresh token 会保留已授予的结构化授权细节；token endpoint 不能新增或更换授权细节。access token、token response 和 token introspection 会返回最终授予的 `authorization_details`。

RP-Initiated Logout：

```text
http://localhost:8080/oauth2/logout?id_token_hint=ID_TOKEN&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2F&state=done
```

`post_logout_redirect_uri` 必须精确匹配客户端登记的退出回调地址。只有签名、issuer、client、当前用户 subject 均有效的 `id_token_hint` 才能让 RP 的 GET 请求立即退出；token 带 `sid` 时还必须精确匹配当前浏览器会话。缺少/无效 hint、`sid` 不匹配或仅提供 `client_id` 时，服务会显示本地退出确认页，并要求当前会话的 CSRF 令牌通过 POST 确认，RP 不能用跨站 GET 静默结束用户会话。未登记的退出 URI 始终不会跳转。

Back-Channel Logout：

客户端可在后台客户端页面或 Dynamic Client Registration 中配置：

- `backchannel_logout_uri`: RP 接收 logout token 的绝对 `http(s)` 地址。
- `backchannel_logout_session_required`: 是否要求 Logout Token 包含 `sid`。

用户通过 `/oauth2/logout` 或管理前台 `/api/logout` 结束当前 OP 会话时，后端会查找该用户已授权过且配置了 `backchannel_logout_uri` 的活跃客户端，向每个客户端 POST：

```text
Content-Type: application/x-www-form-urlencoded

logout_token=SIGNED_LOGOUT_TOKEN
```

Logout Token 使用当前 RS256 签名密钥，包含 `iss`、`sub`、`aud`、`iat`、`exp`、`jti`、`events`，并在当前浏览器会话可用时包含 `sid`。授权码换取 ID Token 时也会写入同一个 `sid`，便于 RP 精确清理本地会话。客户端回调失败不会阻止本地登出；成功和失败都会写入审计。

Front-Channel Logout：

客户端可配置：

- `frontchannel_logout_uri`: RP 接收浏览器 iframe 登出通知的绝对 `http(s)` 地址，必须与某个已登记 `redirect_uri` 同 scheme、host 和 port，且不能包含 fragment。
- `frontchannel_logout_session_required`: 是否要求 iframe 通知 URL 携带 `iss` 和 `sid`。

通过 `/oauth2/logout` 登出时，如果存在 front-channel 客户端，后端会返回一个短暂的中转页，加载隐藏 iframe 后再跳转到 `post_logout_redirect_uri` 或首页。管理前台调用 `/api/logout` 时，后端返回 `frontchannel_logout_frames`，前端会自动插入隐藏 iframe 完成同样的浏览器端通知。

### Subject Type

客户端支持 `public` 和 `pairwise` 两种 subject type，默认是 `public`。`public` 会把内部用户 ID 作为 ID token / userinfo 的 `sub`；`pairwise` 会按 issuer、sector identifier 和用户 ID 派生稳定的不可读 `sub`，避免不同站点之间直接用同一个 subject 关联用户。后台客户端页面和 Dynamic Client Registration 都支持配置：

- `subject_type`: `public` 或 `pairwise`
- `sector_identifier_uri`: 可选；为空时使用首个 `redirect_uri` 的 host 作为 sector

### private_key_jwt

OIDC 客户端可把 `token_endpoint_auth_method` 设为 `private_key_jwt`，并在后台客户端页面或 Dynamic Client Registration 中配置：

- `jwks_uri`: 客户端公钥 JWKS 地址，必须是绝对 `http(s)` URL。
- `jwks`: 内联 JWKS JSON，优先于 `jwks_uri` 使用。

客户端调用 token、PAR、device authorization、introspection 或 revocation 端点时，在表单中提交：

```text
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=CLIENT_SIGNED_JWT
```

断言 JWT 需要用客户端私钥以 `RS256` 签名，`iss` 和 `sub` 必须等于 `client_id`，`aud` 必须匹配当前调用端点的公网 URL，`exp` 不能超过 10 分钟，并且必须包含非空 `jti`。后端会把 `(client_id, jti)` 写入数据库直到断言过期，重复使用同一个断言会被拒绝。

### client_secret_jwt

OIDC 客户端也可把 `token_endpoint_auth_method` 设为 `client_secret_jwt`。后台客户端页面保存的 `client_secret` 会作为 HMAC 共享密钥；Dynamic Client Registration 会像普通 confidential client 一样生成并只返回一次 `client_secret`。

调用 token、PAR、device authorization、introspection 或 revocation 端点时同样提交 `client_assertion_type` 和 `client_assertion`。断言 JWT 需要使用 `HS256`，`iss` / `sub` / `aud` / `exp` / `jti` 规则与 `private_key_jwt` 相同，并复用同一张 `client_assertion_jtis` 表做重放保护。

### 服务账号 / 机器身份

后台客户端页面可为 OIDC 客户端启用 service account，并维护该机器身份持有的后台权限列表。启用时客户端必须允许 `client_credentials` grant；权限值复用后台 RBAC 权限键，例如 `users.read`、`clients.manage`。

客户端用 `client_credentials` 换取 access token 后，token 会继续以客户端作为 audience，并额外带上机器身份 claim：

```json
{
  "sub": "service-account:reports-worker",
  "client_id": "reports-worker",
  "service_account": true,
  "permissions": ["users.read"]
}
```

未启用 service account 的客户端仍可按普通 OAuth `client_credentials` 签发客户端 token，但不会获得 `service_account` 和 `permissions` claim。该设计把“客户端能拿 token”和“客户端代表一个有权限的机器主体”分开，避免所有 M2M 客户端天然拥有后台权限。

### JAR / Request Object

授权端点支持 JWT Secured Authorization Request 的 `request` 参数。客户端需要先配置 `jwks` 或 `jwks_uri`，然后把授权请求参数放进由客户端私钥签名的 `RS256` JWT：

```text
iss=CLIENT_ID
aud=https://sso.example.com
exp=NOW+120
client_id=CLIENT_ID
response_type=code
redirect_uri=https://app.example/callback
scope=openid profile email
state=...
nonce=...
```

`aud` 可使用当前生效 issuer，也可使用授权端点 URL。`exp` 最多允许 10 分钟，`iss` 和 `client_id` 必须等于登记的客户端 ID。后端会用客户端登记的 JWKS 验签，再把签名对象转换成普通授权请求继续执行 redirect URI、scope、PKCE、consent 等既有校验。

直接授权跳转：

```text
https://sso.example.com/oauth2/authorize?client_id=CLIENT_ID&request=SIGNED_REQUEST_OBJECT
```

PAR 也可提交同一个 signed request object：

```bash
curl -d client_id=CLIENT_ID \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion=SIGNED_CLIENT_ASSERTION \
  -d request=SIGNED_REQUEST_OBJECT \
  https://sso.example.com/oauth2/par
```

### Authorization Response Modes

授权请求默认使用 `response_mode=query`，把 `code/state` 或 `error/error_description/state` 放在回调地址 query 中。也可以显式使用 `response_mode=fragment`，让后端把这些字段放进回调 URL fragment。

授权请求可带 `response_mode=form_post`。成功或失败的授权响应会返回一个 `no-store` HTML 页面，自动用 `POST` 把字段提交到客户端登记的 `redirect_uri`，避免把授权结果放进浏览器地址栏。

```text
response_type=code
client_id=demo-web
redirect_uri=https://app.example/callback
response_mode=form_post
```

### JARM / Signed Authorization Response

授权请求可带 `response_mode=query.jwt`、`response_mode=fragment.jwt` 或 `response_mode=form_post.jwt`。成功或失败的授权响应会把 `code/state` 或 `error/error_description/state` 放入一个由服务端 RS256 签名的 JWT；`query.jwt` 通过回调地址的 `response` query 参数返回，`fragment.jwt` 通过 URL fragment 字段 `response` 返回，`form_post.jwt` 通过自动提交的 POST 表单字段 `response` 返回：

```text
https://app.example/callback?response=SIGNED_AUTHORIZATION_RESPONSE_JWT
```

JWT 中包含 `iss`、`aud`、`exp`、`iat`。`aud` 是客户端 ID，`iss` 是当前生效 issuer。普通授权请求、JAR signed request object 和 PAR 都支持这些 signed response modes；未设置时仍使用兼容的 query 返回 `code` 和 `state`。

### DPoP

客户端可以在 token endpoint 请求中带 `DPoP` HTTP header。proof 是客户端私钥签名的 `dpop+jwt`，当前支持 `RS256`，header 内必须包含公钥 JWK；payload 至少包含：

```text
htm=POST
htu=https://sso.example.com/oauth2/token
iat=NOW
jti=RANDOM_UNIQUE_ID
```

校验通过后，签发的 access token 会带 `cnf.jkt`，token response 的 `token_type` 为 `DPoP`。如果同次请求也签发 refresh token，refresh token 会绑定到同一个 `jkt`；后续 refresh 时必须继续提交同一把钥匙签出的 DPoP proof。

访问 `userinfo` 时使用：

```text
Authorization: DPoP ACCESS_TOKEN
DPoP: RESOURCE_PROOF_JWT
```

资源 proof 的 `htu` 要匹配 userinfo 端点，`htm` 要匹配请求方法，并且必须包含 `ath=base64url(sha256(ACCESS_TOKEN))`。后端会按 `jkt+jti` 做重放保护。未绑定 `cnf` 的旧 access token 继续使用 `Authorization: Bearer ...`。

### Claim Mapper

后台客户端页面可为每个 OIDC 客户端添加 claim mapper。每条 mapper 包含 claim 名称、来源、来源值、值类型、输出目标和启用状态。来源支持：

- `user_field`：从用户字段读取，例如 `username`、`display_name`、`phone`、`is_admin`、`last_login_ip`。
- `client`：从客户端字段读取，例如 `client_id`、`client_name`。
- `static`：输出固定值，值类型支持 `string`、`bool`、`number`、`json`。
- `scope`：按请求 scope 输出布尔标记。

为避免破坏 OIDC 标准行为，`iss`、`sub`、`aud`、`exp`、`iat`、`email`、`name`、`preferred_username` 等结构性标准 claim 不允许被 mapper 覆盖。对于 OpenAI 等要求 `email_verified=true` 的客户端，推荐在客户端设置里开启“信任邮箱已验证”；这会按客户端把 ID token、access token 和 userinfo 的 `email_verified` 视为 `true`，适用于本系统已通过企业邮箱或线下流程信任该邮箱的场景。登录设置页中的公司邮箱后缀只用于登录和注册表单的快速选择，不会限制 OIDC 客户端可使用的账户。网站的登录准入由应用、企业和 Signet 账户生命周期决定；网站内的具体业务范围应使用企业角色、应用角色、应用权限和 Claims。OpenAI 当前可能不传 `login_hint`，如果同一浏览器里可能登录多个本系统账户，建议同时开启“强制账号选择”，避免静默复用错误账户。

### PAR

Pushed Authorization Requests 可以把授权请求参数先推送到后端，客户端随后只需要把返回的 `request_uri` 放到授权地址里：

```bash
curl -u demo-web:demo-secret-change-me \
  -d response_type=code \
  -d client_id=demo-web \
  -d redirect_uri=http://localhost:3000/callback \
  -d scope="openid profile email offline_access" \
  http://localhost:8080/oauth2/par
```

返回：

```json
{
  "request_uri": "urn:ietf:params:oauth:request_uri:...",
  "expires_in": 90
}
```

再跳转用户到：

```text
http://localhost:8080/oauth2/authorize?request_uri=REQUEST_URI
```

### Token Exchange

Token Exchange 支持内部受信客户端把本系统签发的用户 `access_token` 换成面向当前客户端的新 `access_token`。客户端需要允许 grant type：

```text
urn:ietf:params:oauth:grant-type:token-exchange
```

示例：

```bash
curl -u demo-web:demo-secret-change-me \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d requested_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d subject_token=ACCESS_TOKEN \
  -d scope="openid profile email" \
  http://localhost:8080/oauth2/token
```

当前实现只接受本服务签发的用户 access token，且请求 scope 必须同时不超过原 token 和目标客户端允许范围。带有 `gpt_sso_login_code_level` 来源声明的授权码登录 token 会 fail-closed 拒绝交换，包括未来新增但当前实现尚不认识的级别。

### 授权同意

`[oidc].skip_consent = true` 时，已登录用户访问 `/oauth2/authorize` 会直接签发 authorization code。设为 `false` 后，首次授权某个客户端或请求新增 scope 时会显示同意页；用户允许并勾选记住后，后端把 `user_id + client_id + authorization_profile_id + granted_scopes` 写入 `client_grants`，后续同一客户端和授权 Profile 请求已授权 scope 的子集会直接放行。用户拒绝时，后端会按 OAuth 规范带 `error=access_denied` 跳回客户端 `redirect_uri`。

授权请求支持 `prompt=consent` 强制重新显示同意页、`prompt=login` 强制重新认证、`prompt=select_account` 强制选择浏览器账号，以及 `prompt=none` 静默授权。无法静默完成时会按原因返回 `login_required`、`account_selection_required`、`consent_required` 或其他交互错误；`prompt=none` 不能与其他 prompt 值组合。

授权同意表单使用当前会话的同步 CSRF 令牌；令牌会在消费一次性 interaction `request_uri` 前验证，因此伪造或过期表单既不能完成授权，也不会使合法的一次性请求失效。`login_hint`、`prompt=login`、`prompt=select_account` 或客户端强制账号选择只会进入本地登录/选择流程，RP 的授权 GET 不会直接删除任一已保存会话。

授权请求也支持 `max_age`。当当前 SSO session 的认证时间超过 `max_age` 秒时，后端会要求用户重新登录；`max_age=0` 可用于要求新鲜认证。授权码换取 ID token 时，`auth_time` 使用完成登录的 session 创建时间，而不是 authorization code 的创建时间。

授权请求支持 `acr_values` 和基础 `claims` 参数。当前 discovery 暴露：

```text
acr_values_supported = [
  "urn:gpt-sso:acr:loa:1", # 普通密码/目录登录等级
  "urn:gpt-sso:acr:loa:2"  # Passkey、TOTP 或恢复码满足的 MFA 等级
]
claims_parameter_supported = true
```

如果请求只接受 `urn:gpt-sso:acr:loa:2`，或 `claims.id_token.acr/amr` 标记 essential 且要求 MFA 相关值，普通 session 会进入 MFA step-up；`prompt=none` 场景会返回 `interaction_required`。授权码会保存当次认证上下文，换取 ID token 时返回 `acr` 和 `amr`，例如 `["otp","mfa"]`、`["hwk","mfa"]` 或 `["pwd"]`。

登录后的账号页会列出当前用户记住的客户端授权，包含客户端、授权 scope、授权时间和更新时间。用户可在前台撤销授权，也可通过 `GET /api/me/consents` 查看、`DELETE /api/me/consents/{client_id}` 撤销；撤销后下一次相同客户端请求对应 scope 会重新进入同意流程。

账号页也会列出当前用户的活跃登录会话，包含当前会话标记、来源 IP、User-Agent、登录方式、创建时间和过期时间。用户可通过 `GET /api/me/sessions` 查看，通过 `DELETE /api/me/sessions/{session_id}` 撤销自己的其他会话；当前会话仍通过 `/api/logout` 退出。

主 Session Cookie、浏览器账号上下文 Cookie、数据库会话标识和对外 OIDC `sid` 使用相互隔离的派生值。由于旧版本曾复用同一 bearer，升级到本版本会有意拒绝旧格式 Cookie，现有用户需要重新登录一次，以关闭已暴露 `sid` 被重放为会话的迁移窗口。重新认证同一账号会轮换对应会话；切换账号只轮换当前浏览器凭据，其他已加入上下文的 Session 会保留到过期、被移除或执行“退出全部”。

## SCIM 2.0

SCIM 接口使用本服务签发的用户 Bearer access token 鉴权，并同时执行 OAuth 委派与数据库实时 RBAC：

- token 的 `aud` 必须精确等于 `{public_base_url}/scim/v2`；客户端申请 token 时使用同值的 `resource` 参数。
- 读取操作要求精确 scope `scim.read`，写操作要求 `scim.write`；两者互不隐含。
- 用户接口还要求管理员或 `users.read` / `users.manage` 权限；组接口还要求管理员或 `security.manage` 权限。
- client-credentials 与 `service-account:*` 主体当前会被拒绝，避免把机器客户端混淆为同 ID 用户；正式 M2M SCIM 需要单独配置服务账号主体。
- 带有 `gpt_sso_login_code_level` 来源声明的账号恢复码或管理员通用码 token 会被拒绝，即使 audience、scope 与数据库实时权限均满足要求。

例如公网地址为 `https://sso.example.com` 时，授权请求应包含：

```text
scope=openid scim.read scim.write
resource=https://sso.example.com/scim/v2
```

现有客户端升级时，需要先给指定客户端加入这两个 scope 并重新授权/签发 token；旧 refresh token 不能扩充 scope。公网地址改变后也必须重新签发。SCIM 组只同步组和成员，不直接分配角色，避免外部 IdP 意外改变系统授权策略。

服务元数据：

```bash
curl http://localhost:8080/scim/v2/ServiceProviderConfig
```

创建用户：

```bash
curl -H "Authorization: Bearer ADMIN_ACCESS_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "userName": "external.alice",
    "active": true,
    "name": { "formatted": "Alice External" },
    "emails": [{ "value": "alice.external@example.com", "primary": true }]
  }' \
  http://localhost:8080/scim/v2/Users
```

列表和过滤：

```bash
curl -H "Authorization: Bearer ADMIN_ACCESS_TOKEN" \
  "http://localhost:8080/scim/v2/Users?filter=userName%20eq%20%22external.alice%22"
```

禁用用户：

```bash
curl -X PATCH \
  -H "Authorization: Bearer ADMIN_ACCESS_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{ "Operations": [{ "op": "replace", "path": "active", "value": false }] }' \
  http://localhost:8080/scim/v2/Users/USER_ID
```

`DELETE /scim/v2/Users/{id}` 不做物理删除，而是执行禁用并清理会话、授权码和 refresh token；归档用户会被拒绝修改。

创建组并同步成员：

```bash
curl -H "Authorization: Bearer ADMIN_ACCESS_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "displayName": "External Contractors",
    "members": [{ "value": "USER_ID", "display": "Alice External" }]
  }' \
  http://localhost:8080/scim/v2/Groups
```

替换组成员：

```bash
curl -X PATCH \
  -H "Authorization: Bearer ADMIN_ACCESS_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{ "Operations": [{ "op": "replace", "path": "members", "value": [{ "value": "USER_ID" }] }] }' \
  http://localhost:8080/scim/v2/Groups/GROUP_ID
```

### Device Flow

设备码授权适合 CLI、电视端、跳板机等不方便直接打开浏览器登录的客户端。客户端需要允许 grant type：

```text
urn:ietf:params:oauth:grant-type:device_code
```

申请设备码：

```bash
curl -u demo-web:demo-secret-change-me \
  -d scope="openid profile email" \
  -d resource="https://api.example/" \
  http://localhost:8080/oauth2/device_authorization
```

返回里会包含 `device_code`、`user_code`、`verification_uri`、`verification_uri_complete`、`expires_in` 和 `interval`。如果请求包含 `resource` 或 `authorization_details`，确认页会展示这些信息，token 签发时沿用同一授权上下文。首次提交用户码只执行查找，不会隐式批准；允许/拒绝必须使用确认页的显式 action 与当前会话 CSRF 令牌。用户确认后，设备端轮询 token：

```bash
curl -u demo-web:demo-secret-change-me \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
  -d device_code=DEVICE_CODE \
  http://localhost:8080/oauth2/token
```

用户尚未确认时返回 `authorization_pending`，轮询过快返回 `slow_down`，授权码过期返回 `expired_token`。

## 关键配置

- `[server]`：监听地址、公网 base URL、是否信任代理/内网穿透转发头。
- `[database]`：数据库类型、连接 URL、连接池大小、是否启动迁移。
- `[oidc]`：issuer、端点路径、token TTL、scope、consent 策略。
- `[security]`：cookie 名称/domain/secure/same_site、CSRF 来源校验开关、session TTL、密码长度、RSA 私钥、key id。
- `[registration]`：注册方式、是否要求验证/授权码、首个用户管理员策略。
- `[verification]`：邮箱/手机号验证码 TTL、投递方式、最大尝试次数。
- `[i18n]`：默认语言和支持语言。
- `[[external_oidc_providers]]`：第三方 OIDC Provider 初始配置。
- `[cors]`：允许的 origin、method、header、credential。
- `[bootstrap]`：可选启动管理员和初始 OIDC 客户端。

## 自动化检查与浏览器 Smoke

[CI](../.github/workflows/ci.yml) 会执行前端类型检查/构建/依赖审计，以及后端格式、Clippy 和全数据库 feature 测试。

`scripts/browser-smoke.mjs` 通过 Chromium DevTools Protocol 检查认证页和用户生命周期。`auth-ui-mock` 还覆盖企业上下文切换、应用策略即时预览，以及 OIDC 连接回到其所属应用策略的管理路径。`lifecycle` 会创建并变更账号，只允许连接回环地址，并要求使用一次性数据库显式确认：

```bash
APP_URL=http://127.0.0.1:8080 \
CDP_URL=http://127.0.0.1:9222 \
SCENARIO=lifecycle \
ALLOW_DESTRUCTIVE_SMOKE=1 \
node scripts/browser-smoke.mjs
```

## 当前验证状态

已执行并通过：

```bash
cargo fmt --all
cargo fmt --all --check
cargo metadata --no-deps --format-version 1
npm --prefix frontend run check
npm --prefix frontend audit --audit-level=moderate
nix-shell --run "SSO_SKIP_FRONTEND_BUILD=1 cargo check"
nix-shell --run "SSO_SKIP_FRONTEND_BUILD=1 cargo check --all-features"
nix-shell --run "SSO_SKIP_FRONTEND_BUILD=1 cargo test --all-features"
nix-shell --run "cargo build --all-features"
nix-shell --run "cargo run"
```

根目录 `cargo run` 已验证会自动构建并嵌入前端，然后启动后端。

运行后已验证：

- `GET /api/health`（兼容存活探针）
- `GET /api/health/live`
- `GET /api/health/ready`（数据库、运行配置与签名密钥就绪检查）
- `GET /.well-known/openid-configuration`
- `GET /oauth2/jwks`
- 嵌入式前端首页 `/`
- 管理员登录 `/api/login`
- 管理概览 `/api/admin/overview`
- 首次启动无用户 -> 注册第一个管理员
- 后台注册策略更新
- 邮箱验证码注册
- 一次性授权码创建、使用、复用拒绝
- 用户更新、详情、登录事件、禁用、启用、归档、归档后删除
- 第三方 OIDC Provider 创建、更新、删除
- 本地 mock 第三方 OIDC start/callback 注册登录
- 第三方 OIDC 邮箱域名发现和最具体 Provider 匹配
- 前端中英多语言构建
- OIDC authorization code -> token -> userinfo 主流程
- 服务账号权限归一化和机器身份 claim
