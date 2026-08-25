# 部署指南

本指南覆盖首次运行和生产部署。Signet 默认使用 SQLite，首次注册成功的用户会成为管理员。

## 运行容器

在要保存数据库的主机上运行：

```bash
docker run --rm -p 8080:8080 \
  -v signet-data:/app/data \
  ghcr.io/yoreh/signet:latest
```

访问 <http://localhost:8080/> 并创建管理员账号。`signet-data` 是 SQLite 数据、会话和自动生成签名密钥的持久化位置；删除它会丢失这些数据。

需要修改配置时，从仓库复制 [`config/default.toml`](../config/default.toml)，修改后挂载到容器。仓库中的示例只监听 `127.0.0.1`；用于容器时请先把 `[server].host` 改为 `"0.0.0.0"`：

```bash
docker run --rm -p 8080:8080 \
  -v "$(pwd)/config/default.toml:/app/config/default.toml:ro" \
  -v signet-data:/app/data \
  ghcr.io/yoreh/signet:latest
```

## 从源码运行

需要 Rust、Node.js 22，以及所选数据库驱动要求的系统库。使用 Nix 的开发环境：

```bash
nix-shell --run "cargo run"
```

`cargo run` 会安装前端依赖、构建前端并把它嵌入服务二进制。浏览器访问 `http://localhost:8080/`。

默认构建使用 SQLite。使用 PostgreSQL 或 MySQL/MariaDB 时，选择对应 Cargo feature，并在部署环境安装其原生客户端库：

```bash
cargo run --no-default-features --features postgres
cargo run --no-default-features --features mysql
```

在配置文件中同步设置 `[database].kind` 和 `[database].url`。完整的数据库示例见[技术参考](technical-reference.md#数据库)。

## 设置公开地址

在应用接入前，`public_base_url` 与 `issuer` 必须是浏览器和应用都能访问的 HTTPS 地址。登录控制台后，可在“运行配置”中保存；设置会立即用于 discovery、令牌 `iss` 和第三方身份源回调地址。

也可为首次启动提供环境变量：

```bash
docker run --rm -p 8080:8080 \
  -e SSO_PUBLIC_BASE_URL=https://sso.example.com \
  -e SSO_ISSUER=https://sso.example.com \
  -v signet-data:/app/data \
  ghcr.io/yoreh/signet:latest
```

如果只设置 `SSO_PUBLIC_BASE_URL`，它也会作为 issuer。`SSO_CONFIG` 可指向另一份配置文件；`SSO_DATABASE_KIND`、`SSO_DATABASE_URL`、`SSO_RSA_PRIVATE_KEY_PEM` 和 `SSO_BOOTSTRAP_ADMIN_PASSWORD` 可覆盖对应设置。

## 网站自动注册

部署可以让网站通过签名的 `/.well-known/signet-authorization.json` 自动加入 Signet。自动注册只接受精确 origin 白名单；首次请求使用 HTTPS challenge，网站必须在签名 JWS 中回显 challenge 和应用元数据，Signet 才会创建应用并在完整 manifest 应用成功后激活它。不会因为网站自行声明域名而获得信任。

Compose 部署可通过 `SSO_AUTO_REGISTRATION_ALLOWLIST_JSON` 提供白名单，例如：

```json
[{"id":"docs","origin":"https://docs.example.com","organization_id":"00000000-0000-4000-8000-000000000001","application_ids":["docs"],"auto_activate":true}]
```

白名单非空时还必须设置 `SSO_DISCOVERY_CHALLENGE_SECRET`，长度至少为 32
字符，并把相同的值注入 Signet 与被发现的网站服务。网站只需验证并回显
Signet 发出的 challenge；真实部署应通过 secret manager 注入该值，不能写入
仓库。`organization_id` 和 `application_ids` 必须由部署方预先分配，不能由网站
在 manifest 中自行扩大。

同时设置 `SSO_AUTO_REGISTRATION_ENABLED=true` 和 `SSO_AUTO_REGISTRATION_STARTUP_SCAN=true` 即可在启动扫描和周期扫描中自动发现；`SSO_AUTO_REGISTRATION_CHALLENGE_TTL_SECONDS`（1–900，默认 300）和 `SSO_AUTO_REGISTRATION_MAX_CONCURRENCY`（1–32，默认 4）可限制挑战有效期和并发抓取数。若通过管理 API 手动触发，重复请求应携带同一个 `idempotency_key`；同一组织中相同 key 绑定不同 origin 或请求时会被拒绝，已完成请求会返回原应用结果。

## 反向代理

将 TLS 终止在可信反向代理上，并把请求转发到 Signet 的 HTTP 监听端口。公网地址应由 `public_base_url` 固定提供；只有代理会正确设置且外部网络不能绕过它时，才开启：

```toml
[server]
trust_proxy_headers = true
```

或设置 `SSO_TRUST_PROXY_HEADERS=true`。开启后，服务会采用 `Forwarded`、`X-Forwarded-*` 和 `Host` 推导外部 URL 与来源 IP。不要在未受信任的直连网络上开启它。

## 上线检查

- 使用 HTTPS，并将 `[security].cookie_secure` 设为 `true`。
- 将 `public_base_url`、`oidc.issuer`、所有 redirect URI 和 CORS origin 改为真实公网地址。
- 替换示例 OIDC client secret、启动管理员密码和第三方身份源密钥；不要把密钥提交进仓库。
- 为邮箱或手机验证配置 SMTP、Webhook 或短信 Provider，开发默认值只写日志。
- 持久化并备份 SQLite 数据卷，或为 PostgreSQL/MySQL 配置定期备份。
- 配置健康检查：`/api/health/live` 用于存活，`/api/health/ready` 会额外检查数据库、运行配置和签名密钥。

Cookie、CORS、CSRF 和密钥轮换的具体约束见[安全指南](security.md)。
