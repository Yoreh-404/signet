use crate::{
    AppState,
    audit::{self, AuditOutcome, AuditSink},
    auth::{self, AccountCapabilities},
    auth_flow, authorization_details, csrf,
    db::{
        ClientRecord, DeviceAuthorizationRecord, DeviceAuthorizationStatus, NewDeviceAuthorization,
    },
    error::{AppError, AppResult},
    mfa,
    mfa_policy::MfaDecision,
    network_policy::TrustedNetworkPolicy,
    oidc,
    oidc_client_auth::{ClientAuthFields, ClientAuthForm},
    redirects, util,
};
use axum::{
    Form, Json,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
const DEVICE_CODE_TTL_SECONDS: i64 = 600;
const DEVICE_POLL_INTERVAL_SECONDS: i32 = 5;
const USER_CODE_LEN: usize = 8;
const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub trait DeviceCodeGenerator {
    fn generate(&self) -> DeviceCodes;
}

#[derive(Debug, Clone)]
pub struct DeviceCodes {
    pub device_code: String,
    pub device_code_hash: String,
    pub user_code_display: String,
    pub user_code_hash: String,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RandomDeviceCodeGenerator;

impl DeviceCodeGenerator for RandomDeviceCodeGenerator {
    fn generate(&self) -> DeviceCodes {
        let device_code = util::random_token(48);
        let user_code = random_user_code();
        let user_code_display = format!("{}-{}", &user_code[..4], &user_code[4..]);
        DeviceCodes {
            device_code_hash: util::token_hash(&device_code),
            device_code,
            user_code_hash: util::token_hash(&user_code),
            user_code_display,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct DeviceAuthorizationRequest {
    #[serde(flatten)]
    client_auth: ClientAuthForm,
    scope: Option<String>,
    resource: Option<String>,
    authorization_details: Option<String>,
}

impl ClientAuthFields for DeviceAuthorizationRequest {
    fn client_auth(&self) -> &ClientAuthForm {
        &self.client_auth
    }
}

#[derive(Debug, Serialize)]
pub struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: i32,
}

#[derive(Debug, Deserialize)]
pub struct DevicePageQuery {
    user_code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceForm {
    user_code: String,
    action: Option<String>,
    #[serde(rename = "_csrf")]
    csrf_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceFormAction {
    Lookup,
    Approve,
    Deny,
}

pub async fn device_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(payload): Form<DeviceAuthorizationRequest>,
) -> AppResult<Json<DeviceAuthorizationResponse>> {
    let issuer = state.effective_issuer(&headers).await?;
    let client =
        oidc::authenticate_client_at(&state, &headers, &payload, "/oauth2/device_authorization")
            .await?;
    ensure_device_grant(&client)?;
    let scope = normalize_device_scope(&client, payload.scope.as_deref(), &state)?;
    let resource = oidc::normalize_resource(payload.resource.as_deref())?;
    let authorization_details = authorization_details::normalize_authorization_details_for_client(
        &client,
        payload.authorization_details.as_deref(),
    )?;
    let generator = RandomDeviceCodeGenerator;
    let codes = generator.generate();
    let verification_uri = format!("{}/oauth2/device", issuer.trim_end_matches('/'));
    let verification_uri_complete = format!(
        "{}?user_code={}",
        verification_uri,
        url_encode(&codes.user_code_display)
    );
    state
        .db
        .insert_device_authorization(NewDeviceAuthorization {
            device_code_hash: codes.device_code_hash,
            user_code_hash: codes.user_code_hash,
            user_code_display: codes.user_code_display.clone(),
            client_id: client.client_id.clone(),
            scope: scope.clone(),
            resource: resource.clone(),
            authorization_details: authorization_details.clone(),
            expires_at: util::now_ts() + DEVICE_CODE_TTL_SECONDS,
            interval_seconds: DEVICE_POLL_INTERVAL_SECONDS,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::oauth_event(
            client.client_id,
            "device_authorization.create",
            AuditOutcome::Success,
            serde_json::json!({
                "scope": scope,
                "resource": resource,
                "authorization_details_types": authorization_details::details_types_for_audit(authorization_details.as_deref())?,
            }),
        ))
        .await?;
    Ok(Json(DeviceAuthorizationResponse {
        device_code: codes.device_code,
        user_code: codes.user_code_display,
        verification_uri,
        verification_uri_complete,
        expires_in: DEVICE_CODE_TTL_SECONDS,
        interval: DEVICE_POLL_INTERVAL_SECONDS,
    }))
}

pub async fn device_page(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Query(query): Query<DevicePageQuery>,
) -> AppResult<Response> {
    let Some(user_code) = query
        .user_code
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(device_code_entry_page(None, None).into_response());
    };
    let user_code_hash = user_code_hash(user_code)?;
    let Some(record) = state
        .db
        .find_device_authorization_by_user_code_hash(&user_code_hash)
        .await?
    else {
        return Ok(device_code_entry_page(Some(user_code), Some("授权码无效")).into_response());
    };
    if let Some(message) = user_visible_record_error(&record) {
        return Ok(device_code_entry_page(Some(user_code), Some(message)).into_response());
    }
    let Some(current) = auth::current_user_from_cookie(&state, &jar).await? else {
        return Ok(
            Redirect::to(&device_login_url(&record.user_code_display, false)).into_response(),
        );
    };
    if !current.can_authorize_oauth_client() {
        return Ok(
            device_code_entry_page(Some(user_code), Some("归档账户不能确认设备授权"))
                .into_response(),
        );
    }
    let client = state
        .db
        .find_client_by_client_id(&record.client_id)
        .await?
        .ok_or(AppError::NotFound)?;
    if let Some(response) = enforce_device_mfa(
        &state,
        &current,
        &headers,
        Some(remote_addr),
        &client,
        &record,
    )
    .await?
    {
        return Ok(response);
    }
    let csrf_token = csrf::token_for_current_session(&state, &jar).await?;
    Ok(device_confirm_page(&record, &client, &current.user.email, &csrf_token).into_response())
}

pub async fn device_form(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    Form(payload): Form<DeviceForm>,
) -> AppResult<Response> {
    let action = parse_device_form_action(payload.action.as_deref())?;
    if action == DeviceFormAction::Lookup {
        return Ok(Redirect::to(&device_return_to(&payload.user_code)).into_response());
    }
    let user_code_hash = user_code_hash(&payload.user_code)?;
    let Some(record) = state
        .db
        .find_device_authorization_by_user_code_hash(&user_code_hash)
        .await?
    else {
        return Ok(
            device_code_entry_page(Some(&payload.user_code), Some("授权码无效")).into_response(),
        );
    };
    if let Some(message) = user_visible_record_error(&record) {
        return Ok(device_code_entry_page(Some(&payload.user_code), Some(message)).into_response());
    }
    let Some(current) = auth::current_user_from_cookie(&state, &jar).await? else {
        return Ok(
            Redirect::to(&device_login_url(&record.user_code_display, false)).into_response(),
        );
    };
    auth::ensure_current_account_mutable(&current)?;
    csrf::validate_form_token(&state, &jar, payload.csrf_token.as_deref()).await?;
    if action == DeviceFormAction::Approve {
        let client = state
            .db
            .find_client_by_client_id(&record.client_id)
            .await?
            .ok_or(AppError::NotFound)?;
        if let Some(response) = enforce_device_mfa(
            &state,
            &current,
            &headers,
            Some(remote_addr),
            &client,
            &record,
        )
        .await?
        {
            return Ok(response);
        }
    }
    let transition = if action == DeviceFormAction::Deny {
        state.db.deny_device_authorization(&user_code_hash).await?
    } else {
        state
            .db
            .authorize_device_authorization(&user_code_hash, &current.user.id)
            .await?
    };
    if !transition.changed {
        return Ok(device_code_entry_page(
            Some(&payload.user_code),
            Some(device_authorization_status_message(transition.status)),
        )
        .into_response());
    }
    let record = transition.record;
    state
        .db
        .record_login_event(
            &current.user.id,
            state.request_ip(&headers, Some(remote_addr)).await?,
            util::user_agent(&headers),
            if action == DeviceFormAction::Deny {
                "device_deny"
            } else {
                "device_authorize"
            },
            Some(record.client_id),
            None,
        )
        .await?;
    Ok(device_done_page(action == DeviceFormAction::Approve).into_response())
}

fn parse_device_form_action(value: Option<&str>) -> AppResult<DeviceFormAction> {
    match value {
        Some("lookup") => Ok(DeviceFormAction::Lookup),
        Some("approve") => Ok(DeviceFormAction::Approve),
        Some("deny") => Ok(DeviceFormAction::Deny),
        Some(_) => Err(AppError::BadRequest(
            "invalid device authorization action".to_string(),
        )),
        None => Err(AppError::BadRequest(
            "device authorization action is required".to_string(),
        )),
    }
}

async fn enforce_device_mfa(
    state: &AppState,
    current: &auth::CurrentUser,
    headers: &HeaderMap,
    remote_addr: Option<SocketAddr>,
    client: &ClientRecord,
    record: &DeviceAuthorizationRecord,
) -> AppResult<Option<Response>> {
    let session = state
        .db
        .find_session(&current.session_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let user_has_totp = state.db.find_totp_method(&current.user.id).await?.is_some();
    let policy = state.db.security_policy().await?;
    let policy_requires_mfa =
        policy.requires_mfa_for_ip(state.request_ip(headers, remote_addr).await?.as_deref())?;
    match auth_flow::oidc_authorization_mfa_decision(
        &policy,
        client,
        &session,
        user_has_totp,
        policy_requires_mfa,
    )? {
        MfaDecision::Satisfied => Ok(None),
        MfaDecision::Challenge => {
            let return_to = device_return_to(&record.user_code_display);
            let challenge = state
                .db
                .create_mfa_challenge(
                    &current.user.id,
                    "oidc_login",
                    Some(return_to.clone()),
                    mfa::MFA_CHALLENGE_TTL_SECONDS,
                )
                .await?;
            Ok(Some(
                oidc::mfa_page(&challenge.id, &return_to).into_response(),
            ))
        }
        MfaDecision::SetupRequired => Ok(Some(
            device_code_entry_page(
                Some(&record.user_code_display),
                Some("该请求要求 MFA，但当前账号尚未设置 TOTP"),
            )
            .into_response(),
        )),
    }
}

pub async fn consume_authorized_device_code(
    state: &AppState,
    client: &ClientRecord,
    device_code: &str,
) -> AppResult<DeviceAuthorizationRecord> {
    let device_code_hash = util::token_hash(device_code);
    let Some(record) = state
        .db
        .find_device_authorization_by_device_code_hash(&device_code_hash)
        .await?
    else {
        return Err(oauth_error("invalid_grant", "device code is invalid"));
    };
    if record.client_id != client.client_id {
        return Err(oauth_error(
            "invalid_grant",
            "device code was issued to a different client",
        ));
    }
    let poll = state
        .db
        .poll_device_authorization(&device_code_hash, util::now_ts())
        .await
        .map_err(|error| match error {
            AppError::NotFound => oauth_error("invalid_grant", "device code is invalid"),
            other => other,
        })?;
    match poll.status {
        DeviceAuthorizationStatus::Pending => Err(oauth_error(
            "authorization_pending",
            "device authorization is still pending",
        )),
        DeviceAuthorizationStatus::SlowDown => {
            Err(oauth_error("slow_down", "polling interval is too short"))
        }
        DeviceAuthorizationStatus::Expired => {
            Err(oauth_error("expired_token", "device code has expired"))
        }
        DeviceAuthorizationStatus::Denied => Err(oauth_error(
            "access_denied",
            "device authorization was denied",
        )),
        DeviceAuthorizationStatus::Consumed => Err(oauth_error(
            "invalid_grant",
            "device code has already been consumed",
        )),
        DeviceAuthorizationStatus::Authorized => {
            let consumed = state
                .db
                .consume_device_authorization(&device_code_hash)
                .await
                .map_err(|error| match error {
                    AppError::NotFound => oauth_error("invalid_grant", "device code is invalid"),
                    other => other,
                })?;
            if consumed.changed && consumed.status == DeviceAuthorizationStatus::Consumed {
                Ok(consumed.record)
            } else {
                Err(device_authorization_oauth_error(consumed.status))
            }
        }
    }
}

fn device_authorization_status_message(status: DeviceAuthorizationStatus) -> &'static str {
    match status {
        DeviceAuthorizationStatus::Pending => "授权状态已被其他请求更新",
        DeviceAuthorizationStatus::Authorized => "授权码已确认",
        DeviceAuthorizationStatus::Denied => "授权已被拒绝",
        DeviceAuthorizationStatus::Consumed => "授权码已使用",
        DeviceAuthorizationStatus::Expired => "授权码已过期",
        DeviceAuthorizationStatus::SlowDown => "请求过于频繁，请稍后再试",
    }
}

fn device_authorization_oauth_error(status: DeviceAuthorizationStatus) -> AppError {
    match status {
        DeviceAuthorizationStatus::Expired => {
            oauth_error("expired_token", "device code has expired")
        }
        DeviceAuthorizationStatus::Denied => {
            oauth_error("access_denied", "device authorization was denied")
        }
        DeviceAuthorizationStatus::Consumed => {
            oauth_error("invalid_grant", "device code has already been consumed")
        }
        DeviceAuthorizationStatus::Pending | DeviceAuthorizationStatus::SlowDown => oauth_error(
            "authorization_pending",
            "device authorization is still pending",
        ),
        DeviceAuthorizationStatus::Authorized => {
            oauth_error("invalid_grant", "device code could not be consumed")
        }
    }
}

fn ensure_device_grant(client: &ClientRecord) -> AppResult<()> {
    if client
        .grant_types()?
        .iter()
        .any(|value| value == DEVICE_CODE_GRANT)
    {
        Ok(())
    } else {
        Err(AppError::Oidc(
            "client cannot use device authorization grant".to_string(),
        ))
    }
}

fn normalize_device_scope(
    client: &ClientRecord,
    requested: Option<&str>,
    state: &AppState,
) -> AppResult<String> {
    let requested_scopes =
        util::normalize_scopes(requested, &state.settings.oidc.supported_scopes)?;
    let allowed_scopes = client.scopes()?;
    for scope in &requested_scopes {
        if !allowed_scopes.iter().any(|allowed| allowed == scope) {
            return Err(AppError::Oidc(format!(
                "client is not allowed to request scope: {scope}"
            )));
        }
    }
    Ok(requested_scopes.join(" "))
}

fn user_visible_record_error(record: &DeviceAuthorizationRecord) -> Option<&'static str> {
    let now = util::now_ts();
    if record.expires_at <= now {
        Some("授权码已过期")
    } else if record.consumed_at.is_some() {
        Some("授权码已使用")
    } else if record.denied_at.is_some() {
        Some("授权已被拒绝")
    } else if record.authorized_user_id.is_some() {
        Some("授权码已确认")
    } else {
        None
    }
}

fn device_return_to(user_code: &str) -> String {
    format!("/oauth2/device?user_code={}", url_encode(user_code))
}

fn device_login_url(user_code: &str, force_login: bool) -> String {
    redirects::frontend_login_url(&device_return_to(user_code), None, force_login)
}

fn user_code_hash(value: &str) -> AppResult<String> {
    let normalized = normalize_user_code(value);
    if normalized.len() != USER_CODE_LEN {
        return Err(AppError::BadRequest("invalid user code".to_string()));
    }
    Ok(util::token_hash(&normalized))
}

fn normalize_user_code(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect()
}

fn random_user_code() -> String {
    let mut bytes = [0_u8; USER_CODE_LEN];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|byte| USER_CODE_ALPHABET[usize::from(*byte) % USER_CODE_ALPHABET.len()] as char)
        .collect()
}

fn oauth_error(error: &str, description: &str) -> AppError {
    AppError::oauth(error, description, StatusCode::BAD_REQUEST)
}

fn device_code_entry_page(user_code: Option<&str>, error: Option<&str>) -> Html<String> {
    let value = user_code.map(html_escape).unwrap_or_default();
    let error = error
        .map(|message| format!(r#"<div class="error">{}</div>"#, html_escape(message)))
        .unwrap_or_default();
    Html(format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>设备授权</title>
  {style}
</head>
<body>
  <main>
    <form method="post" action="/oauth2/device">
      <h1>设备授权</h1>
      <p>输入设备上显示的授权码。</p>
      {error}
      <label>授权码</label>
      <input name="user_code" value="{value}" autocomplete="one-time-code" required />
      <input type="hidden" name="action" value="lookup" />
      <button type="submit">继续</button>
    </form>
  </main>
</body>
</html>"#,
        style = page_style(),
    ))
}

fn device_confirm_page(
    record: &DeviceAuthorizationRecord,
    client: &ClientRecord,
    email: &str,
    csrf_token: &str,
) -> Html<String> {
    let user_code = html_escape(&record.user_code_display);
    let client_name = html_escape(&client.client_name);
    let scope = html_escape(&record.scope);
    let email = html_escape(email);
    let csrf_token = html_escape(csrf_token);
    let resource = record
        .resource
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("<dt>资源</dt><dd>{}</dd>", html_escape(value)))
        .unwrap_or_default();
    let authorization_details = record
        .authorization_details
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            format!(
                "<dt>结构化授权</dt><dd><pre>{}</pre></dd>",
                html_escape(value)
            )
        })
        .unwrap_or_default();
    Html(format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>确认设备授权</title>
  {style}
</head>
<body>
  <main>
    <form method="post" action="/oauth2/device">
      <h1>确认设备授权</h1>
      <p><strong>{client_name}</strong> 正在请求使用账号 <strong>{email}</strong> 登录。</p>
	      <dl>
	        <dt>授权码</dt><dd>{user_code}</dd>
	        <dt>权限范围</dt><dd>{scope}</dd>
	        {resource}
	        {authorization_details}
      </dl>
      <input type="hidden" name="user_code" value="{user_code}" />
      <input type="hidden" name="_csrf" value="{csrf_token}" />
      <button type="submit" name="action" value="approve">允许</button>
      <button class="secondary" type="submit" name="action" value="deny">拒绝</button>
    </form>
  </main>
</body>
</html>"#,
        style = page_style(),
    ))
}

fn device_done_page(approved: bool) -> Html<String> {
    let title = if approved {
        "已允许设备登录"
    } else {
        "已拒绝设备登录"
    };
    let message = if approved {
        "现在可以回到设备继续登录。"
    } else {
        "设备端会收到访问被拒绝的结果。"
    };
    Html(format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  {style}
</head>
<body>
  <main>
    <section>
      <h1>{title}</h1>
      <p>{message}</p>
    </section>
  </main>
</body>
</html>"#,
        style = page_style(),
        title = html_escape(title),
        message = html_escape(message),
    ))
}

fn page_style() -> &'static str {
    r#"<style>
    body { font-family: Inter, ui-sans-serif, system-ui, sans-serif; margin: 0; background: #f6f7f9; color: #111827; }
    main { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
    form, section { width: min(420px, 100%); background: white; border: 1px solid #d8dee8; border-radius: 8px; padding: 24px; box-shadow: 0 10px 30px rgba(15, 23, 42, .08); }
    h1 { font-size: 22px; margin: 0 0 8px; }
    p { color: #667085; margin: 0 0 20px; line-height: 1.5; }
    label, dt { display: block; font-weight: 700; font-size: 13px; margin: 14px 0 6px; color: #344054; }
	    dd { margin: 0 0 8px; overflow-wrap: anywhere; }
	    pre { max-height: 160px; overflow: auto; padding: 10px; background: #f2f4f7; border-radius: 6px; font-size: 12px; white-space: pre-wrap; overflow-wrap: anywhere; }
	    input { width: 100%; box-sizing: border-box; padding: 11px 12px; border: 1px solid #c9d1dc; border-radius: 6px; font-size: 15px; }
    button { width: 100%; margin-top: 20px; padding: 11px 14px; border: 0; border-radius: 6px; color: white; background: #0f766e; font-weight: 700; cursor: pointer; }
    button.secondary { margin-top: 10px; color: #344054; background: #eef2f6; }
    .error { margin: 0 0 14px; padding: 10px 12px; border-radius: 6px; border: 1px solid #fecaca; background: #fff1f2; color: #b42318; }
  </style>"#
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_login_url_can_force_fresh_authentication() {
        let url = device_login_url("ABCD-2345", true);
        assert_eq!(
            url,
            "/?auth=login&return_to=%2Foauth2%2Fdevice%3Fuser_code%3DABCD-2345&force_login=1"
        );
    }

    #[test]
    fn device_login_url_defaults_to_regular_login() {
        let url = device_login_url("ABCD-2345", false);
        assert_eq!(
            url,
            "/?auth=login&return_to=%2Foauth2%2Fdevice%3Fuser_code%3DABCD-2345"
        );
    }

    #[test]
    fn device_code_entry_requires_lookup_before_approval() {
        let page = device_code_entry_page(Some("ABCD-2345"), None).0;
        assert!(page.contains("name=\"action\" value=\"lookup\""));
        assert!(parse_device_form_action(None).is_err());
        assert_eq!(
            parse_device_form_action(Some("lookup")).unwrap(),
            DeviceFormAction::Lookup
        );
        assert_eq!(
            parse_device_form_action(Some("approve")).unwrap(),
            DeviceFormAction::Approve
        );
        assert!(parse_device_form_action(Some("unexpected")).is_err());
    }
}
