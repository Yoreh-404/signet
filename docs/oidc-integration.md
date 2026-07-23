# OIDC 应用接入

Signet 是 OIDC Provider。应用应使用 discovery 文档读取端点和支持能力，而不是把本地开发地址写死。

## 1. 确认公开地址

先在控制台“运行配置”中设置实际的公网 Base URL 和 Issuer，例如 `https://sso.example.com`。两者通常相同。应用和浏览器必须都能访问该地址。

## 2. 创建客户端

以管理员身份打开控制台，在“OIDC 客户端”中创建一个客户端：

- 填写应用名称和唯一的 client ID。
- 登记精确的 redirect URI，例如 `https://app.example.com/oauth/callback`。
- 为可保密的服务保存 client secret；浏览器或移动端等公有客户端使用 `none` 并启用 PKCE。
- 按需选择 scope、grant type、认证方式和是否要求 MFA/账号选择。

redirect URI 必须精确匹配，不能使用通配符。生产环境不要使用示例配置中的 `demo-secret-change-me`。

## 3. 使用 discovery 配置应用

访问：

```text
https://sso.example.com/.well-known/openid-configuration
```

文档会给出 `authorization_endpoint`、`token_endpoint`、`userinfo_endpoint`、`jwks_uri`、支持的 scope 和其他元数据。大多数 OIDC 客户端库只需要 issuer URL 即可完成配置。

本地验证：

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

## 4. 授权码流程

应用把用户重定向到 authorization endpoint，并在用户登录和同意后收到 `code`。随后由服务端使用 code 向 token endpoint 换取 token。

```text
GET /oauth2/authorize?
  response_type=code&
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth%2Fcallback&
  scope=openid%20profile%20email&
  state=RANDOM_VALUE
```

机密客户端换取 token：

```bash
curl -u YOUR_CLIENT_ID:YOUR_CLIENT_SECRET \
  -d grant_type=authorization_code \
  -d code=AUTHORIZATION_CODE \
  -d redirect_uri=https://app.example.com/oauth/callback \
  https://sso.example.com/oauth2/token
```

公有客户端必须在授权请求中生成 PKCE `code_challenge`，并在换取 token 时提交匹配的 `code_verifier`。务必校验 `state`；使用 OpenID Connect 时也应提交并校验 `nonce`。

## 常见能力

| 需求 | 说明 |
| --- | --- |
| 长期登录 | 申请 `offline_access`，并为客户端启用 refresh token。 |
| API audience | 在授权请求中使用 `resource`，令 access token 的 `aud` 面向资源服务。 |
| 无浏览器设备 | 使用 Device Authorization Grant。 |
| 机器身份 | 为客户端启用 service account 和 `client_credentials`。 |
| 高安全客户端 | 使用 PAR、JAR、JARM、DPoP 或 `private_key_jwt`。 |
| 用户同步 | 使用 SCIM 2.0，单独配置 `resource`、scope 与实时 RBAC。 |

这些能力的参数、边界和完整示例在[技术参考的 OIDC 部分](technical-reference.md#oidc-示例)中维护。有关授权同意、多账号、MFA step-up 和退出通知，也请以该参考为准。
