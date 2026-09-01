use super::ResolvedAuthorizeRequest;
use crate::{
    AppState,
    consent::canonical_scopes,
    db::{ClientRecord, UserRecord},
    error::AppResult,
    html::escape as html_escape,
    oidc_claims::RequestedClaims,
    util::url_encode,
};
use axum::response::Html;
use axum_extra::extract::cookie::CookieJar;

pub(super) trait AuthorizationInteractionRequestStore {
    async fn store_interaction_request(
        &self,
        client_id: &str,
        request: &ResolvedAuthorizeRequest,
    ) -> AppResult<String>;
}

impl AuthorizationInteractionRequestStore for AppState {
    async fn store_interaction_request(
        &self,
        client_id: &str,
        request: &ResolvedAuthorizeRequest,
    ) -> AppResult<String> {
        crate::par::store_interaction_authorization_request(self, client_id, request).await
    }
}

pub(super) fn return_to_request(
    request: &ResolvedAuthorizeRequest,
    strip_login_prompt: bool,
) -> ResolvedAuthorizeRequest {
    let mut request = request.clone();
    if strip_login_prompt {
        request.prompt = prompt_without_login(request.prompt.as_deref());
    }
    request
}

pub(super) fn reauthentication_request(
    request: &ResolvedAuthorizeRequest,
) -> ResolvedAuthorizeRequest {
    let mut request = request.clone();
    request.reauthentication_required = true;
    request.selected_session_id = None;
    request
}

pub(super) fn account_selection_prompted_request(
    request: &ResolvedAuthorizeRequest,
) -> ResolvedAuthorizeRequest {
    let mut request = request.clone();
    request.account_selection_prompted = false;
    request.account_selection_required = true;
    request.reauthentication_required = false;
    request.selected_session_id = None;
    request.selected_user_id = None;
    request
}

pub(super) fn prompt_without_login(prompt: Option<&str>) -> Option<String> {
    let prompt = prompt?
        .split_whitespace()
        .filter(|value| *value != "login")
        .collect::<Vec<_>>()
        .join(" ");
    (!prompt.is_empty()).then_some(prompt)
}

pub(super) fn prompt_without_select_account(prompt: Option<&str>) -> Option<String> {
    let prompt = prompt?
        .split_whitespace()
        .filter(|value| *value != "select_account")
        .collect::<Vec<_>>()
        .join(" ");
    (!prompt.is_empty()).then_some(prompt)
}

pub(super) async fn authorize_return_to_for_interaction(
    store: &impl AuthorizationInteractionRequestStore,
    request: &ResolvedAuthorizeRequest,
    strip_login_prompt: bool,
) -> AppResult<String> {
    let request = return_to_request(request, strip_login_prompt);
    authorization_interaction_return_to(store, &request).await
}

pub(super) async fn authorize_return_to_for_account_selection(
    store: &impl AuthorizationInteractionRequestStore,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<String> {
    let request = account_selection_prompted_request(request);
    authorization_interaction_return_to(store, &request).await
}

async fn authorization_interaction_return_to(
    store: &impl AuthorizationInteractionRequestStore,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<String> {
    let request_uri = store
        .store_interaction_request(&request.client_id, request)
        .await?;
    Ok(format!(
        "/oauth2/authorize?interaction_request={}",
        url_encode(&request_uri)
    ))
}

pub(super) async fn consent_interaction_request(
    state: &AppState,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<String> {
    crate::par::store_interaction_authorization_request(state, &request.client_id, request).await
}

pub(super) async fn consent_page(
    state: &AppState,
    jar: &CookieJar,
    request: &ResolvedAuthorizeRequest,
    client: &ClientRecord,
    user: &UserRecord,
    can_remember_authorization: bool,
    requested_scopes: &[String],
) -> AppResult<Html<String>> {
    let csrf_token = html_escape(&crate::csrf::token_for_current_session(state, jar).await?);
    let client_name = html_escape(&client.client_name);
    let client_id = html_escape(&client.client_id);
    let email = html_escape(&user.email);
    let scope_value = html_escape(&canonical_scopes(requested_scopes));
    let resource = html_escape(request.resource.as_deref().unwrap_or_default());
    let authorization_details_value = request.authorization_details.as_deref().unwrap_or_default();
    let authorization_details = html_escape(authorization_details_value);
    let login_hint = html_escape(request.login_hint.as_deref().unwrap_or_default());
    let authorization_details_preview = if authorization_details_value.trim().is_empty() {
        String::new()
    } else {
        format!(
            "<p>Structured authorization details:</p><pre>{}</pre>",
            html_escape(authorization_details_value)
        )
    };
    let scope_items = requested_scopes
        .iter()
        .map(|scope| format!("<li>{}</li>", html_escape(scope)))
        .collect::<String>();
    let response_type = html_escape(&request.response_type);
    let redirect_uri = html_escape(&request.redirect_uri);
    let prompt = html_escape(request.prompt.as_deref().unwrap_or_default());
    let max_age_value = request.max_age.map(|value| value.to_string());
    let max_age = html_escape(max_age_value.as_deref().unwrap_or_default());
    let acr_values = html_escape(request.acr_values.as_deref().unwrap_or_default());
    let claims_value = request
        .claims
        .as_ref()
        .map(RequestedClaims::to_authorization_parameter)
        .transpose()
        .unwrap_or_default()
        .unwrap_or_default();
    let claims = html_escape(&claims_value);
    let state_value = html_escape(request.state.as_deref().unwrap_or_default());
    let nonce = html_escape(request.nonce.as_deref().unwrap_or_default());
    let code_challenge = html_escape(request.code_challenge.as_deref().unwrap_or_default());
    let code_challenge_method =
        html_escape(request.code_challenge_method.as_deref().unwrap_or_default());
    let response_mode = html_escape(request.response_mode.as_deref().unwrap_or_default());
    let interaction_request = consent_interaction_request(state, request).await?;
    let interaction_request = html_escape(&interaction_request);
    let remember_control = if can_remember_authorization {
        r#"<label><input type="checkbox" name="remember" value="1" checked /> Remember this authorization</label>"#
    } else {
        "<p>This restricted authorization-code session cannot remember authorization.</p>"
    };
    Ok(Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize {client_name}</title>
  <style>
    body {{ font-family: Inter, ui-sans-serif, system-ui, sans-serif; margin: 0; background: #f6f7f9; color: #111827; }}
    main {{ min-height: 100vh; display: grid; place-items: center; padding: 24px; }}
    section {{ width: min(440px, 100%); background: white; border: 1px solid #d8dee8; border-radius: 8px; padding: 24px; box-shadow: 0 10px 30px rgba(15, 23, 42, .08); }}
    h1 {{ font-size: 22px; margin: 0 0 8px; }}
    p {{ color: #667085; margin: 0 0 18px; }}
    ul {{ margin: 0 0 18px; padding-left: 20px; }}
    li {{ margin: 6px 0; }}
    label {{ display: flex; gap: 8px; align-items: center; color: #344054; font-size: 14px; }}
    input[type="checkbox"] {{ width: 16px; height: 16px; }}
    .actions {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 20px; }}
    button {{ min-height: 40px; border: 0; border-radius: 6px; font-weight: 700; cursor: pointer; }}
    .approve {{ order: 2; color: white; background: #0f766e; }}
    .deny {{ order: 1; color: #344054; background: #eef2f7; }}
    small {{ color: #667085; overflow-wrap: anywhere; }}
    pre {{ max-height: 160px; overflow: auto; padding: 10px; background: #f2f4f7; border-radius: 6px; font-size: 12px; white-space: pre-wrap; overflow-wrap: anywhere; }}
  </style>
</head>
<body>
  <main>
    <section>
      <h1>Authorize {client_name}</h1>
      <p>{email} is signed in. This application is requesting access:</p>
      <ul>{scope_items}</ul>
      {authorization_details_preview}
      <small>Client ID: {client_id}</small>
      <form method="post" action="/oauth2/authorize">
        <input type="hidden" name="_csrf" value="{csrf_token}" />
        <input type="hidden" name="response_type" value="{response_type}" />
        <input type="hidden" name="client_id" value="{client_id}" />
        <input type="hidden" name="redirect_uri" value="{redirect_uri}" />
        <input type="hidden" name="scope" value="{scope_value}" />
        <input type="hidden" name="resource" value="{resource}" />
        <input type="hidden" name="authorization_details" value="{authorization_details}" />
        <input type="hidden" name="login_hint" value="{login_hint}" />
        <input type="hidden" name="prompt" value="{prompt}" />
        <input type="hidden" name="max_age" value="{max_age}" />
        <input type="hidden" name="acr_values" value="{acr_values}" />
        <input type="hidden" name="claims" value="{claims}" />
        <input type="hidden" name="state" value="{state_value}" />
        <input type="hidden" name="nonce" value="{nonce}" />
        <input type="hidden" name="code_challenge" value="{code_challenge}" />
        <input type="hidden" name="code_challenge_method" value="{code_challenge_method}" />
        <input type="hidden" name="response_mode" value="{response_mode}" />
        <input type="hidden" name="interaction_request" value="{interaction_request}" />
        {remember_control}
        <div class="actions">
          <button class="approve" type="submit" name="action" value="approve">Allow</button>
          <button class="deny" type="submit" name="action" value="deny">Deny</button>
        </div>
      </form>
    </section>
  </main>
</body>
</html>"#
    )))
}
