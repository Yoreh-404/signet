# Signet 应用接入模型

<!-- anchordocs-lifecycle: DISCUSSION -->
<!-- anchordocs-owner: Signet maintainers -->

本文定义 Signet 面向传统网站、现代 Web 前端、API 和机器身份的统一接入模型。
它是设计讨论稿，不替代 OIDC、SAML、CAS、IAP/ForwardAuth 或 SCIM 的协议参考。

## 目标

Signet 的应用接入应同时满足以下约束：

1. 传统网站无需重写账号系统，也能通过反向代理、可信请求头或已有企业协议接入。
2. 现代项目可以使用 OIDC 授权码、PKCE、audience、DPoP、服务账号和细粒度权限。
3. 网站可以声明自己的接入需求，但不能通过可拉取的清单向 Signet 传递长期共享 secret。
4. 登录运行时不依赖网站在线；网站清单只在控制面同步，运行时使用 Signet 的本地快照。
5. 正式契约唯一使用 `signet-application/v3`；v1/v2 application manifest 不再被 Signet 接受。

## 核心边界

Signet 将接入分成四个相互独立的对象：

| 对象 | 负责内容 | 不负责内容 |
| --- | --- | --- |
| `Identity` | 用户、组织、外部身份、MFA、Passkey | 单个网站的 redirect URI |
| `Connection` | OIDC、SAML、CAS、JWT、IAP、SCIM、ForwardAuth | 用户权限解释 |
| `Policy` | scope、audience、permission、role、step-up | 网络传输和回调地址 |
| `Lifecycle` | 注册、轮换、撤销、同步、过期和回滚 | 业务数据本身 |

这四个对象可以在同一个应用中组合，但拥有独立版本和失败策略。应用不再被建模成“一个 OAuth callback”。

## 五种接入档

### `legacy_proxy`

用于无法修改或不值得修改的传统网站。边缘代理完成 Signet 登录，再把经过验证的身份传给上游：

- `X-Signet-Subject`
- `X-Signet-Email`
- `X-Signet-Organization`
- `X-Signet-Roles`
- `X-Signet-Permissions`
- `X-Signet-Assertion`

浏览器直接携带的普通身份 header 一律不可信。代理必须删除入站同名 header，并注入短期、受众限定的内部 assertion。传统站有两种明确的信任终止方式，不能混用：

- **端到端 assertion**：能修改旧站时，由旧站验证 assertion 的 signature、issuer、固定 expected audience、expiry 与 `token_use`，这是优先方案。
- **代理终止兼容**：旧站完全无法修改时，受信反向代理本身就是身份执行点；业务 upstream 必须只在私网/Unix socket/受控服务网中可达，不能绕过代理，代理必须清除浏览器身份头、通过校验证书的 TLS 调用 Signet，再把 ForwardAuth 响应头注入旧站。此时旧站可以继续消费传统明文用户头，但信任的是“唯一可达的受信代理”，不是 header 本身。

两种模式都必须 fail-closed；绝不能在 ForwardAuth/断言校验失败时把请求降级成匿名流量放行。

`legacy_proxy` 的浏览器会话有两种部署边界，不能混淆：

- **同 origin / 共享父域**：反向代理把 Signet 的 IAP 登录端点和登录 UI 暴露在受保护站点可持有 Cookie 的 origin 下，或部署明确且安全的共享 Cookie domain。此时可直接使用 Signet 原生 ForwardAuth，路径最短、延迟最低。共享父域模式会扩大浏览器发送 Session Cookie 的范围，因此业务 upstream 必须剥离 Signet Cookie，只允许应用自己的 Cookie 继续向后传。
- **任意跨顶级域**：浏览器不会把 `sso.example.com` 的 host-only Cookie 发送给 `legacy.other-domain.com`。此时应在旧站前部署 OIDC-capable edge，由 edge 使用 Authorization Code + S256 PKCE 与中央 Signet 建立自己的站点会话，再向旧站注入可信身份。该 edge 可在 v3 contract 中继续使用 `legacy_proxy` profile，但 client `protocol=oidc`；Signet 会强制它是 public client、声明 `openid iap.assert`、禁止 `offline_access`。旧站代码仍然无需实现 OIDC。不要通过扩大 Cookie Domain、复制 Signet session cookie 或把长期 bearer token 暴露给浏览器来伪造“跨域共享会话”。

跨域 edge 不需要复制 Signet 的 RBAC。它的 OIDC client 必须显式获授 `iap.assert` scope；edge 持有的短期 user access token 再调用 `/api/iap/bearer-auth`，Signet 会重新确认 token 对应 client/application lifecycle 仍然有效、token 的 `application_id` 与目标 IAP rule 属于同一个 application，并重新执行该 rule 的组织/角色/权限约束。成功后返回与原生 ForwardAuth 相同的 `X-Signet-Assertion` / identity header 集合。这样 edge 只承担浏览器协议和本地域会话，Identity/Policy authority 仍然只有 Signet 一份。

仓库内正式实现是独立 `signet-edge` Rust sidecar；`scripts/oidc-edge-reference.mjs` 保留为可读的零第三方 Node 参考实现。两者都只提供 `/_signet/start`、`/_signet/callback`、`/_signet/auth`、`/_signet/logout`，**不代理业务流量**。Nginx 基线见 `docs/examples/nginx-oidc-edge.conf`。edge 使用 `__Host-` HttpOnly/Secure/SameSite=Lax 密封 Cookie 保存短期 access token，默认本地会话上限 600 秒且不会超过 Signet access token；业务 upstream 必须剥离该 Cookie。多个 edge 副本只需共享同一组轮换 Cookie keys 即可保持无状态水平扩展。

因此 ForwardAuth 是高性能的**本地边缘适配器**，而不是跨 DNS 边界的 Cookie 传输协议；跨域 SSO 应通过标准授权协议跨边界。

共享父域部署可直接从 [`examples/nginx-forward-auth.conf`](examples/nginx-forward-auth.conf) 起步。模板按“浏览器身份头全部不可信、ForwardAuth 响应头才可信”的方向配置，避免传统反向代理最常见的 header spoofing 误接入。

### `web_oidc`

用于传统服务端 Web 应用：

- Authorization Code。
- 精确 redirect URI。
- 机密客户端优先使用 `private_key_jwt`。
- 无法使用公钥断言时，由运维侧在 Signet 控制台预注册 confidential client；网站清单只能引用该客户端，不能上传 secret。
- 可选 PAR、JAR、JARM、DPoP 和 MFA step-up。

### `spa_oidc`

用于浏览器前端和移动/跨端前端：

- 公有客户端，`token_endpoint_auth_method = none`。
- 强制 S256 PKCE。
- state、nonce、redirect URI 和 issuer 必须由客户端库校验。
- refresh token 采用轮换和撤销策略；不把长期 secret 放在浏览器。

### `api_resource`

用于后端 API 或服务资源：

- token 的 `aud` 必须指向资源服务。
- 按 scope、permission、组织和 role 做授权。
- 高风险资源可强制 DPoP 或 token introspection。
- API 不应把“用户已登录”当成“拥有本 API 权限”。

### `machine_identity`

用于 worker、MCP、任务调度和服务间调用：

- `client_credentials`。
- 优先 `private_key_jwt`，其次使用运维侧预注册的 confidential client。
- subject 与 actor 分离，审计中保留调用服务和代表用户。
- 权限默认最小化，不继承浏览器用户的全部权限。

## v3 声明式契约

代码中的 `signet/backend/src/application_contract.rs` 定义 `signet-application/v3`。
契约由签名 JWS 携带，外层继续兼容现有 `/.well-known/signet-authorization.json` 拉取方式。

顶层信封只包含身份、时间和模块：

```json
{
  "format": "signet-application/v3",
  "application_id": "example-site",
  "revision": 12,
  "version": "2026-08-22",
  "iss": "https://example-site.test",
  "aud": [
    "https://sso.example.com",
    "signet:application:example-site"
  ],
  "iat": 1787400000,
  "exp": 1787400300,
  "modules": {
    "clients": [],
    "connections": [],
    "policies": [],
    "roles": [],
    "lifecycle": {
      "mode": "replace",
      "fail_closed": true,
      "revoke_removed_clients": true,
      "allow_downgrade": false
    }
  },
  "extensions": {}
}
```

### 客户端安全规则

- 每个 Client 必须声明 `protocol`；v3 website-managed Client 当前只支持 `oidc` 和 `jwt`。只有这两类协议拥有真实的 client lifecycle/binding 语义。
- SAML 2.0、CAS、SCIM/LDAP 等应用级适配器放在 `modules.connections`；ForwardAuth/IAP 的代理路由和内部 assertion audience 属于 operator-managed 控制面，不伪装成可由网站声明的 Client。
- `protocol` 决定运行时 Application Binding 使用的传输协议，`profiles` 只描述该 Client 的接入能力，不再隐式推断协议。
- v3 不接受 `client_secret` 字段。
- v3 当前只允许 `none` 和 `private_key_jwt` 两种 token endpoint authentication method。
- `private_key_jwt` 必须携带 `jwks_uri` 或公钥集合；当前 Signet client assertion verifier
  接受 RSA/RS256 公钥。应用私钥只留在 worker 或 Web 服务，不进入清单。
- confidential client 只能由 Signet 运维侧预注册；application contract 不承载共享 secret，v3 的 `credential_ref` 字段在 resolver 完成前拒绝。
- `spa_oidc` 必须声明 authorization code、code response type 和 S256 PKCE。
- `legacy_proxy` 的同域默认接入方式仍是 operator-managed ForwardAuth；它不需要网站发布一个假的 `forward_auth` Client。跨顶级域时可声明 `protocol = oidc` 的 legacy edge client，必须是 public Authorization Code + S256 PKCE client，scope 至少包含 `openid iap.assert` 且不得包含 `offline_access`。确实只能消费旧式 signed JWT 的网站仍可声明 `protocol = jwt`；该兼容档同样使用一次性 Authorization Code + S256 PKCE，再由站点后端换取短期 JWT，JWT 不进入浏览器 URL。
- application-scoped JWT adapter 当前每个应用只允许一个 browser client；`client_id`、精确 `redirect_uris` 和首个 audience 直接从签名 v3 client contract 物化到 runtime module，不能由旁路 connection setting 覆盖。public client 不接受 `client_secret`。
- `machine_identity` 必须声明 `client_credentials`。
- machine identity 只能获得显式 `policy.client_ids` 绑定的 permissions；未绑定的 policy 不会自动授予机器客户端。
- redirect URI 不能使用 wildcard、fragment 或公网 HTTP；本地开发 HTTP 只允许 localhost 地址。

### 模块安全规则

`extensions`、`metadata` 和连接 `settings` 可以扩展，但不能携带 password、token、API key、private key 或 secret 的明文值。只有明确的 `*_ref` 才能出现。

这样既保留前向扩展能力，又避免自由格式 JSON 重新变成 secret 传输通道。

## 传统网站运行路径

```text
Browser
  -> Reverse Proxy / IAP
  -> Signet login + session
  -> short-lived internal assertion
  -> Legacy Website
```

可修改的传统网站只需验证内部 assertion，并将 claims 映射到自己的 session；完全不可修改的网站则由受信代理终止认证并注入兼容 header。两种模式都不需要旧站实现 OIDC，并且必须满足对应的网络/密码学边界：

1. 旧站后端不能存在可绕过受信代理的公网/旁路入口。
2. 能验证 assertion 时，校验 issuer、固定 expected audience、expiry、signature、`token_use` 和 subject。
3. 不能验证 assertion 时，只接受代理清洗并重新注入的身份 header；浏览器原始同名 header 必须在代理处被覆盖/删除。
4. 不从 URL 或未签名 cookie 读取 Signet 身份，并对 logout、session expiry 和 ForwardAuth 故障采用 fail-closed 行为。

当前 ForwardAuth 将该内部 assertion 放在 `X-Signet-Assertion`，使用 Signet 的 RS256/JWKS 签名体系，`token_use=iap_assertion`，audience 固定为 `signet:iap:<immutable-rule-id>`。人类可读的 rule slug 仍保存在 claim 中，但不会承担生命周期隔离：即使旧 rule 被删除后重新创建同名 slug，旧 assertion 也无法匹配新 rule 的 audience。assertion 只投影该 rule 声明并验证通过的权限，不暴露用户在 Signet 控制面的完整权限集合。兼容代理仍可读取 `X-Auth-Request-*` / `X-Forwarded-*`，但这些明文头只能由受信代理从 ForwardAuth 响应生成；外部请求中的同名头必须先删除。默认 assertion TTL 为 30 秒，而 Signet 内部 session+rule 授权微缓存更短（默认 250ms）；缓存到期后若同一 key 已有请求正在刷新，其他并发请求最多再复用 100ms 的旧决定以削平惊群尾延迟。这个 grace 只在主动刷新期间存在，不成为 stale-on-error 或长期授权事实源。

SAML、CAS 和旧式 JWT SSO 仍作为 connection adapter 存在；它们是传输兼容层，不改变 Signet 内部的 Identity/Policy 模型。
`legacy_proxy`/ForwardAuth 的代理路由和内部 assertion audience 属于 Signet 的运维配置，
不通过网站可拉取契约声明，避免把边缘网络信任边界误建模成普通应用 client。

## 现代项目运行路径

| 项目类型 | 推荐 profile | 资源访问 |
| --- | --- | --- |
| AnchorDocs Web | `web_oidc` 或 `spa_oidc` | OIDC access token + API audience |
| Memory Atlas | `api_resource` | introspection/JWT + required scopes |
| Axon Hub | `web_oidc` + `machine_identity` | 用户会话与 worker 身份分离 |
| OCR/后台 worker | `machine_identity` | client credentials + 最小权限 |
| 旧管理后台 | `legacy_proxy` | 同域 ForwardAuth 或跨域 OIDC edge + IAP internal assertion |

项目不需要实现所有协议；只声明实际使用的 profile，Signet 按 profile 生成对应的 endpoint、client policy 和 claims。

## 控制面与数据面

### 控制面

1. 网站发布签名契约。
2. Signet 验证 JWS、issuer、audience、时间、revision 和模块 schema。
3. Signet 计算 desired state 与当前快照的 diff。
4. 通过单个数据库事务 reconcile clients、policies、roles、connections 和同步状态。
5. 保存去 secret 的 last verified snapshot，记录 accepted/rejected revision。

### 数据面

1. OIDC、SAML、CAS、IAP、JWT 和 SCIM 只读取本地快照。
2. 网站暂时不可达不会中断已经验证且未过期的运行时配置。
3. 签名失效、revision 回退或明确撤销时，控制面拒绝新快照。
4. 当前 v3 只接受 `mode=replace`、`fail_closed=true` 和 `allow_downgrade=false`。
   `revoke_removed_clients` 已接入事务 reconcile：默认值为 `true`，迁移阶段可显式设为
   `false` 以保留 Signet 运维侧预注册的 confidential client。`merge` 和 revision 降级要等
   对应的事务语义完成后再开放；短暂网络故障不会清空仍未过期的本地快照。

## v3 一次性切换

Signet 不执行 v1/v2 fallback，也不在同一应用内并行解释两种契约。切换前由部署流水线
完成离线转换、密钥注册和回归验证；切换后仅接受签名的 v3 contract。

- 所有 active client 必须映射到明确的 application binding 和 authorization profile。
- 用户认证上下文按 AuthDomain 复用；consent、授权交易和 token 仍按 client/profile 隔离。
- 共享 secret 不进入 application contract；机密客户端使用运维侧注册的 `private_key_jwt`。
- 旧快照不会被 v3 parser 解释；应用必须发布新的 revision 和 v3 digest。
- 失败时 fail closed，不自动回退到旧权限模型。

## 实现顺序

1. 完成 v3 parser/validator 的单元测试和 JWS 验签测试。
2. 增加 v3 到内部 `VerifiedApplicationManifest` 的纯函数适配器；适配器不得读取网络或数据库。
3. 将 confidential client resolver 独立为 operator-managed credential store，不复用网站 fetch secret。
4. 扩展 `application_discovery` 的 revision/digest/reconcile 流程，删除 v1/v2 fallback。
5. 抽取 AnchorDocs、Axon Hub、Memory Atlas 的重复 manifest producer。
6. 最后实现 `legacy_proxy` assertion/header 契约和端到端测试。

## 验收矩阵

| 场景 | 必须证明 |
| --- | --- |
| 传统网站 | 无代码改造登录、header 防伪、assertion 过期拒绝、logout 生效 |
| SPA | PKCE、state、nonce、issuer、audience 和 refresh rotation |
| 服务端 Web | redirect 精确匹配、private_key_jwt、MFA step-up |
| API | audience、scope、permission、DPoP/introspection |
| Worker | client credentials、actor 审计、最小权限 |
| 同步故障 | 快照继续服务、过期 fail-closed、revision 回退拒绝 |
| secret 安全 | JWS、snapshot、日志和错误响应均不含明文 secret |
