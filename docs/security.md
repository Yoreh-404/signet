# 安全指南

生产部署前，应完成本页检查。配置中的开发默认值仅适用于本地运行。

## 公开地址与反向代理

`public_base_url` 和 `oidc.issuer` 必须是外部可访问的 HTTPS 地址。它们会出现在 discovery、OIDC token、回调地址校验和浏览器来源校验中。

仅在反向代理完全受信任且不能被外部网络绕过时，才启用 `trust_proxy_headers`。否则攻击者可以伪造 `Forwarded` 或 `X-Forwarded-*` 请求头，影响外部 URL 和来源 IP 的判断。

## Cookie 与 CORS

- 生产环境设置 `cookie_secure = true`，只通过 HTTPS 发送登录 Cookie。
- `cookie_same_site = "None"` 时，`cookie_secure` 必须为 `true`。
- 需要携带 Cookie 的跨域前端，必须逐项配置 `[cors].allowed_origins`；不能使用 `*`。
- 只允许实际需要的 origin、method 和 header。内置前端已包含所需的 `x-csrf-token` 请求头。
- 本地没有 HTTPS 证书时可临时设置 `SSO_DISABLE_CSRF_ORIGIN_CHECK=true`，仅跳过 `Origin`/`Referer` 来源校验；会话写请求仍要求有效 CSRF token。该开关不要用于生产环境。

## 自建浏览器前端与 CSRF

带登录 Cookie 的写请求要先请求 `GET /api/csrf`，再在 `POST`、`PUT`、`PATCH` 或 `DELETE` 请求中同时携带 Cookie 与 `X-CSRF-Token`。会话改变后应重新获取令牌。

登录、注册、验证码、密码重置和 Passkey 登录等尚未建立会话的公共写接口必须带可信的 `Origin` 或 `Referer`。OIDC token、SCIM、Dynamic Client Registration 和 IAP 等协议端点使用各自的客户端认证或 Bearer token，不应附加浏览器 CSRF token。

完整覆盖范围和兼容性说明见[技术参考中的 CSRF 与跨域安全](technical-reference.md#浏览器-csrf-与跨域安全)。

## 密钥、凭据与备份

- 更换所有示例 client secret、管理员密码、SMTP/Webhook 凭据和第三方身份源密钥。
- 将密钥保存在受控的配置或密钥管理系统中，不要写入镜像或源码仓库。
- 未显式配置 RSA 私钥时，Signet 会生成并存入数据库；因此数据库备份也是 OIDC 签名密钥的备份。
- 轮换密钥前确认 JWKS 保留策略和已签发令牌的有效期。详见[签名密钥轮换](technical-reference.md#签名密钥轮换)。
- 对 SQLite 数据卷或外部数据库执行可恢复的定期备份，并演练恢复流程。

## 运营建议

- 为管理员启用 MFA，并定期审查活跃会话和登录审计。
- 通过最小权限分配后台角色、组织角色和服务账号权限。
- 为外部 OIDC、LDAP、SCIM、IAP 和 Webhook 分别使用最小 scope、受限网络和独立凭据。
- 将 `/api/health/live` 与 `/api/health/ready` 接入监控；后者可发现数据库或签名密钥的就绪问题。
