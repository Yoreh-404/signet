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

上游不能只信任可由客户端伪造的普通 header。代理必须删除入站同名 header，并注入短期、受众限定的内部 assertion。上游若无法验证 assertion，应拒绝请求，而不是降级为匿名访问。

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

- 每个 Client 必须声明 `protocol`；当前支持 `oidc`、`saml`、`cas`、`jwt`、`iap` 和 `forward_auth`。
- `protocol` 决定运行时 Application Binding 使用的传输协议，`profiles` 只描述该 Client 的接入能力，不再隐式推断协议。
- v3 不接受 `client_secret` 字段。
- v3 当前只允许 `none` 和 `private_key_jwt` 两种 token endpoint authentication method。
- `private_key_jwt` 必须携带 `jwks_uri` 或公钥集合；当前 Signet client assertion verifier
  接受 RSA/RS256 公钥。应用私钥只留在 worker 或 Web 服务，不进入清单。
- confidential client 只能由 Signet 运维侧预注册；application contract 不承载共享 secret，v3 的 `credential_ref` 字段在 resolver 完成前拒绝。
- `spa_oidc` 必须声明 authorization code、code response type 和 S256 PKCE。
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

传统网站只需验证内部 assertion，并将 claims 映射到自己的 session。它不需要实现 OIDC，但必须：

1. 只接受来自受信代理网络的 assertion。
2. 校验 issuer、audience、expiry、signature 和 subject。
3. 不从 URL、普通客户端 header 或未签名 cookie 读取身份。
4. 对 logout 和 session expiry 采用 fail-closed 行为。

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
| 旧管理后台 | `legacy_proxy` | ForwardAuth/IAP + internal assertion |

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
