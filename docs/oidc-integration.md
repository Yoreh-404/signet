# OIDC 应用接入

Signet 是 OIDC Provider。应用应使用 discovery 文档读取端点和支持能力，而不是把本地开发地址写死。

## 1. 确认公开地址

先在控制台“运行配置”中设置实际的公网 Base URL 和 Issuer，例如 `https://sso.example.com`。两者通常相同。应用和浏览器必须都能访问该地址。

## 2. 发布应用契约

应用通过签名的 `signet-application/v3` 契约声明一个或多个客户端：

- 每个客户端声明唯一的 `client_id` 和 `protocol`。
- Web/SPA 客户端登记精确的 redirect URI，并使用 `none` + S256 PKCE。
- 机器客户端使用 `client_credentials` + `private_key_jwt`，在契约中发布公钥 JWKS；私钥只保留在调用方。
- 权限通过客户端绑定的 Profile 和 Policy 声明，不在客户端之间隐式共享。

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

服务端客户端使用私钥签名 assertion 后换取 token：

```bash
curl -d client_id=YOUR_CLIENT_ID \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion=SIGNED_CLIENT_ASSERTION \
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
