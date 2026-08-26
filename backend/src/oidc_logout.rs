use crate::{
    AppState, auth, db::ClientRecord, error::AppResult, html::escape as html_escape, subject, util,
};
use axum::{
    Form,
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Deserialize)]
pub(crate) struct LogoutRequest {
    pub(crate) _csrf: Option<String>,
    pub(crate) id_token_hint: Option<String>,
    pub(crate) logout_hint: Option<String>,
    pub(crate) client_id: Option<String>,
    pub(crate) post_logout_redirect_uri: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) ui_locales: Option<String>,
}

pub(crate) async fn logout_get(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(query): Query<LogoutRequest>,
) -> AppResult<Response> {
    let current = auth::current_user_from_cookie(&state, &jar).await?;
    let redirect =
        validated_post_logout_redirect(&state, &headers, current.as_ref(), &query).await?;
    let Some(current_user) = current.as_ref() else {
        return complete_logout(state, jar, headers, current, redirect).await;
    };
    if logout_hint_authorizes_current_session(&state, &headers, current_user, &query).await? {
        return complete_logout(state, jar, headers, current, redirect).await;
    }

    let csrf_token = crate::csrf::token_for_current_session(&state, &jar).await?;
    let client = logout_request_client(&state, &headers, current.as_ref(), &query).await?;
    Ok(logout_confirmation_page(&query, &csrf_token, client.as_ref()).into_response())
}

pub(crate) async fn logout_post(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Form(payload): Form<LogoutRequest>,
) -> AppResult<Response> {
    let current = auth::current_user_from_cookie(&state, &jar).await?;
    if let Some(current) = current.as_ref()
        && !logout_hint_authorizes_current_session(&state, &headers, current, &payload).await?
    {
        crate::csrf::validate_form_token(&state, &jar, payload._csrf.as_deref()).await?;
    }
    let redirect =
        validated_post_logout_redirect(&state, &headers, current.as_ref(), &payload).await?;
    complete_logout(state, jar, headers, current, redirect).await
}

pub(crate) async fn complete_logout(
    state: AppState,
    jar: CookieJar,
    headers: HeaderMap,
    current: Option<auth::CurrentUser>,
    redirect: Option<Url>,
) -> AppResult<Response> {
    let mut frontchannel_frames = Vec::new();
    if let Some(current) = current.as_ref() {
        let public_session_id = util::session_public_id(&current.session_id);
        frontchannel_frames = match crate::frontchannel_logout::frames_for_user(
            &state,
            &headers,
            &current.user,
            &public_session_id,
        )
        .await
        {
            Ok(frames) => frames,
            Err(err) => {
                tracing::warn!(error = %err, "front-channel logout notification preparation failed");
                Vec::new()
            }
        };
        if let Err(err) = crate::backchannel_logout::notify_user_logout(
            &state,
            &headers,
            &current.user,
            Some(&public_session_id),
        )
        .await
        {
            tracing::warn!(error = %err, "back-channel logout notification failed");
        }
    }
    let mut next_jar = jar.clone();
    if let Some(current) = current.as_ref() {
        state.db.delete_session(&current.session_id).await?;
    }
    if jar.get(&state.settings.security.cookie_name).is_some() {
        next_jar = next_jar.add(auth::expired_session_cookie(&state));
    }
    let redirect_to = redirect
        .as_ref()
        .map(|uri| uri.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let response = if !frontchannel_frames.is_empty() {
        (
            next_jar,
            crate::frontchannel_logout::logout_page(&frontchannel_frames, &redirect_to),
        )
            .into_response()
    } else if let Some(uri) = redirect {
        (next_jar, Redirect::to(uri.as_str())).into_response()
    } else {
        (next_jar, Redirect::to("/")).into_response()
    };
    Ok(response)
}

pub(crate) async fn logout_hint_authorizes_current_session(
    state: &AppState,
    headers: &HeaderMap,
    current: &auth::CurrentUser,
    request: &LogoutRequest,
) -> AppResult<bool> {
    let Some((_client, claims)) =
        validated_logout_hint(state, headers, Some(current), request).await?
    else {
        return Ok(false);
    };
    if let Some(sid) = claims.sid.as_deref() {
        return Ok(sid == util::session_public_id(&current.session_id));
    }
    Ok(true)
}

pub(crate) fn logout_confirmation_page(
    request: &LogoutRequest,
    csrf_token: &str,
    client: Option<&ClientRecord>,
) -> Html<String> {
    let application = client
        .map(|client| format!("<strong>{}</strong>", html_escape(&client.client_name)))
        .unwrap_or_else(|| "the requesting application".to_string());
    let hidden_fields = [
        ("id_token_hint", request.id_token_hint.as_deref()),
        ("logout_hint", request.logout_hint.as_deref()),
        ("client_id", request.client_id.as_deref()),
        (
            "post_logout_redirect_uri",
            request.post_logout_redirect_uri.as_deref(),
        ),
        ("state", request.state.as_deref()),
        ("ui_locales", request.ui_locales.as_deref()),
    ]
    .into_iter()
    .filter_map(|(name, value)| {
        value.map(|value| {
            format!(
                r#"<input type="hidden" name="{}" value="{}" />"#,
                name,
                html_escape(value)
            )
        })
    })
    .collect::<String>();
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Confirm sign out</title>
  <style>
    body {{ font-family: Inter, ui-sans-serif, system-ui, sans-serif; margin: 0; background: #f6f7f9; color: #111827; }}
    main {{ min-height: 100vh; display: grid; place-items: center; padding: 24px; }}
    section {{ width: min(420px, 100%); box-sizing: border-box; background: white; border: 1px solid #d8dee8; border-radius: 12px; padding: 28px; box-shadow: 0 18px 45px rgba(15, 23, 42, .10); }}
    h1 {{ font-size: 24px; margin: 0 0 10px; }}
    p {{ color: #667085; line-height: 1.55; margin: 0 0 22px; }}
    .actions {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
    button, a {{ min-height: 42px; box-sizing: border-box; border-radius: 8px; font-weight: 700; display: inline-flex; align-items: center; justify-content: center; text-decoration: none; }}
    button {{ border: 0; color: white; background: #b42318; cursor: pointer; }}
    a {{ color: #344054; background: #eef2f7; }}
  </style>
</head>
<body>
  <main>
    <section>
      <h1>Sign out?</h1>
      <p>{application} asked to end your SSO session. Confirm to sign out of this browser.</p>
      <form method="post" action="/oauth2/logout">
        <input type="hidden" name="_csrf" value="{}" />
        {hidden_fields}
        <div class="actions">
          <a href="/">Stay signed in</a>
          <button type="submit">Sign out</button>
        </div>
      </form>
    </section>
  </main>
</body>
</html>"#,
        html_escape(csrf_token)
    ))
}

pub(crate) async fn validated_post_logout_redirect(
    state: &AppState,
    headers: &HeaderMap,
    current: Option<&auth::CurrentUser>,
    request: &LogoutRequest,
) -> AppResult<Option<Url>> {
    let Some(uri) = request.post_logout_redirect_uri.as_deref() else {
        return Ok(None);
    };
    let _ = request.logout_hint.as_deref();
    let _ = request.ui_locales.as_deref();
    let Some(client) = logout_request_client(state, headers, current, request).await? else {
        return Ok(None);
    };
    if !client
        .post_logout_redirect_uris()?
        .iter()
        .any(|registered| registered == uri)
    {
        return Ok(None);
    }
    Ok(post_logout_redirect_url(uri, request.state.as_deref()))
}

pub(crate) async fn logout_request_client(
    state: &AppState,
    headers: &HeaderMap,
    current: Option<&auth::CurrentUser>,
    request: &LogoutRequest,
) -> AppResult<Option<ClientRecord>> {
    if request.id_token_hint.is_some() {
        return Ok(validated_logout_hint(state, headers, current, request)
            .await?
            .map(|(client, _claims)| client));
    }

    let Some(client_id) = request.client_id.as_deref() else {
        return Ok(None);
    };
    state.db.find_client_by_client_id(client_id).await
}

pub(crate) async fn validated_logout_hint(
    state: &AppState,
    headers: &HeaderMap,
    current: Option<&auth::CurrentUser>,
    request: &LogoutRequest,
) -> AppResult<Option<(ClientRecord, crate::jwt::TokenClaims)>> {
    let Some(id_token_hint) = request.id_token_hint.as_deref() else {
        return Ok(None);
    };
    let issuers = state.accepted_issuers(headers).await?;
    let issuer_refs = issuers.iter().map(String::as_str).collect::<Vec<_>>();
    let Ok(bootstrap_claims) = state
        .jwt
        .verify_id_token_hint_for_logout_bootstrap(id_token_hint, &issuer_refs)
    else {
        return Ok(None);
    };
    let Some(client) = state
        .db
        .find_client_by_client_id(&bootstrap_claims.client_id)
        .await?
    else {
        return Ok(None);
    };
    if client.is_active != 1 {
        return Ok(None);
    }
    // ID tokens issued by Signet are always audience-bound to the OIDC
    // client. Do not let a syntactically valid signed token for another
    // audience authorize a logout request for this client.
    let audiences = [client.client_id.clone()];
    let Ok(claims) = state.jwt.verify_id_token_hint_with_issuers_and_audiences(
        id_token_hint,
        &issuer_refs,
        &audiences,
    ) else {
        return Ok(None);
    };
    if let Some(current) = current {
        let expected_subject = subject::subject_for_client(&claims.iss, &current.user, &client)?;
        if expected_subject != claims.sub {
            return Ok(None);
        }
    }
    if let Some(client_id) = request.client_id.as_deref()
        && client_id != claims.client_id
    {
        return Ok(None);
    }
    Ok(Some((client, claims)))
}

pub(crate) fn post_logout_redirect_url(uri: &str, state: Option<&str>) -> Option<Url> {
    let mut redirect = Url::parse(uri).ok()?;
    if let Some(state_value) = state {
        redirect.query_pairs_mut().append_pair("state", state_value);
    }
    Some(redirect)
}
