use crate::{
    AppState,
    db::ClientRecord,
    error::{AppError, AppResult},
    oidc::ResolvedAuthorizeRequest,
};
use axum::{
    http::header,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde_json::{Map, Value};
use url::{Url, form_urlencoded};

pub const RESPONSE_MODE_QUERY: &str = "query";
pub const RESPONSE_MODE_FRAGMENT: &str = "fragment";
pub const RESPONSE_MODE_FORM_POST: &str = "form_post";
pub const RESPONSE_MODE_QUERY_JWT: &str = "query.jwt";
pub const RESPONSE_MODE_FRAGMENT_JWT: &str = "fragment.jwt";
pub const RESPONSE_MODE_FORM_POST_JWT: &str = "form_post.jwt";
pub const SUPPORTED_RESPONSE_MODES: &[&str] = &[
    RESPONSE_MODE_QUERY,
    RESPONSE_MODE_FRAGMENT,
    RESPONSE_MODE_FORM_POST,
    RESPONSE_MODE_QUERY_JWT,
    RESPONSE_MODE_FRAGMENT_JWT,
    RESPONSE_MODE_FORM_POST_JWT,
];
pub const SUPPORTED_SIGNING_ALGS: &[&str] = &["RS256"];

const AUTHORIZATION_RESPONSE_TTL_SECONDS: i64 = 120;

pub(crate) fn validate_response_mode(response_mode: Option<&str>) -> AppResult<()> {
    AuthorizationResponseMode::parse(response_mode).map(|_| ())
}

pub(crate) fn authorization_success_response(
    state: &AppState,
    issuer: &str,
    client: &ClientRecord,
    request: &ResolvedAuthorizeRequest,
    code: &str,
) -> AppResult<Response> {
    let mode = AuthorizationResponseMode::parse(request.response_mode.as_deref())?;
    let fields = if mode.is_signed() {
        vec![signed_response_field(
            state,
            issuer,
            &client.client_id,
            success_claims(code, request.state.as_deref()),
        )?]
    } else {
        success_fields(code, request.state.as_deref())
    };
    deliver_response(request, mode.transport(), fields)
}

pub(crate) fn authorization_error_response(
    state: &AppState,
    issuer: &str,
    request: &ResolvedAuthorizeRequest,
    error: &str,
    description: &str,
) -> AppResult<Response> {
    let mode = AuthorizationResponseMode::parse(request.response_mode.as_deref())?;
    let fields = if mode.is_signed() {
        vec![signed_response_field(
            state,
            issuer,
            &request.client_id,
            error_claims(error, description, request.state.as_deref()),
        )?]
    } else {
        error_fields(error, description, request.state.as_deref())
    };
    deliver_response(request, mode.transport(), fields)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationResponseMode {
    Query,
    Fragment,
    FormPost,
    QueryJwt,
    FragmentJwt,
    FormPostJwt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationResponseTransport {
    Query,
    Fragment,
    FormPost,
}

impl AuthorizationResponseMode {
    fn parse(response_mode: Option<&str>) -> AppResult<Self> {
        match normalized_mode(response_mode) {
            None | Some(RESPONSE_MODE_QUERY) => Ok(Self::Query),
            Some(RESPONSE_MODE_FRAGMENT) => Ok(Self::Fragment),
            Some(RESPONSE_MODE_FORM_POST) => Ok(Self::FormPost),
            Some(RESPONSE_MODE_QUERY_JWT) => Ok(Self::QueryJwt),
            Some(RESPONSE_MODE_FRAGMENT_JWT) => Ok(Self::FragmentJwt),
            Some(RESPONSE_MODE_FORM_POST_JWT) => Ok(Self::FormPostJwt),
            Some(value) => Err(AppError::Oidc(format!(
                "unsupported response_mode: {value}"
            ))),
        }
    }

    fn is_signed(self) -> bool {
        matches!(self, Self::QueryJwt | Self::FragmentJwt | Self::FormPostJwt)
    }

    fn transport(self) -> AuthorizationResponseTransport {
        match self {
            Self::Query | Self::QueryJwt => AuthorizationResponseTransport::Query,
            Self::Fragment | Self::FragmentJwt => AuthorizationResponseTransport::Fragment,
            Self::FormPost | Self::FormPostJwt => AuthorizationResponseTransport::FormPost,
        }
    }
}

fn success_fields(code: &str, state: Option<&str>) -> Vec<(&'static str, String)> {
    let mut fields = vec![("code", code.to_string())];
    if let Some(state) = state {
        fields.push(("state", state.to_string()));
    }
    fields
}

fn error_fields(
    error: &str,
    description: &str,
    state: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut fields = vec![
        ("error", error.to_string()),
        ("error_description", description.to_string()),
    ];
    if let Some(state) = state {
        fields.push(("state", state.to_string()));
    }
    fields
}

fn success_claims(code: &str, state: Option<&str>) -> Map<String, Value> {
    let mut claims = Map::new();
    claims.insert("code".to_string(), Value::String(code.to_string()));
    insert_optional(&mut claims, "state", state);
    claims
}

fn error_claims(error: &str, description: &str, state: Option<&str>) -> Map<String, Value> {
    let mut claims = Map::new();
    claims.insert("error".to_string(), Value::String(error.to_string()));
    claims.insert(
        "error_description".to_string(),
        Value::String(description.to_string()),
    );
    insert_optional(&mut claims, "state", state);
    claims
}

fn deliver_response(
    request: &ResolvedAuthorizeRequest,
    transport: AuthorizationResponseTransport,
    fields: Vec<(&'static str, String)>,
) -> AppResult<Response> {
    match transport {
        AuthorizationResponseTransport::Query => query_redirect(request, fields),
        AuthorizationResponseTransport::Fragment => fragment_redirect(request, fields),
        AuthorizationResponseTransport::FormPost => form_post_response(request, fields),
    }
}

fn query_redirect(
    request: &ResolvedAuthorizeRequest,
    fields: Vec<(&'static str, String)>,
) -> AppResult<Response> {
    let mut redirect = redirect_uri(request)?;
    for (key, value) in fields {
        redirect.query_pairs_mut().append_pair(key, &value);
    }
    Ok(Redirect::to(redirect.as_str()).into_response())
}

fn fragment_redirect(
    request: &ResolvedAuthorizeRequest,
    fields: Vec<(&'static str, String)>,
) -> AppResult<Response> {
    let mut redirect = redirect_uri(request)?;
    if redirect.fragment().is_some() {
        return Err(AppError::Oidc(
            "redirect_uri cannot contain a fragment".to_string(),
        ));
    }
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (key, value) in fields {
        serializer.append_pair(key, &value);
    }
    let fragment = serializer.finish();
    redirect.set_fragment(Some(&fragment));
    Ok(Redirect::to(redirect.as_str()).into_response())
}

fn form_post_response(
    request: &ResolvedAuthorizeRequest,
    fields: Vec<(&'static str, String)>,
) -> AppResult<Response> {
    let redirect_uri = redirect_uri(request)?;
    Ok((
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Html(form_post_page(redirect_uri.as_str(), &fields)),
    )
        .into_response())
}

fn signed_response_field(
    state: &AppState,
    issuer: &str,
    audience: &str,
    claims: Map<String, Value>,
) -> AppResult<(&'static str, String)> {
    let response = state.jwt.sign_authorization_response(
        issuer,
        audience,
        AUTHORIZATION_RESPONSE_TTL_SECONDS,
        claims,
    )?;
    Ok(("response", response))
}

fn form_post_page(action: &str, fields: &[(&'static str, String)]) -> String {
    let inputs = fields
        .iter()
        .map(|(key, value)| {
            format!(
                r#"<input type="hidden" name="{}" value="{}" />"#,
                html_escape(key),
                html_escape(value)
            )
        })
        .collect::<String>();
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Continue</title>
</head>
<body onload="document.forms[0].submit()">
  <form method="post" action="{}">
    {}
    <noscript><button type="submit">Continue</button></noscript>
  </form>
</body>
</html>"#,
        html_escape(action),
        inputs
    )
}

fn redirect_uri(request: &ResolvedAuthorizeRequest) -> AppResult<Url> {
    Url::parse(&request.redirect_uri)
        .map_err(|err| AppError::Oidc(format!("invalid redirect_uri: {err}")))
}

fn normalized_mode(response_mode: Option<&str>) -> Option<&str> {
    response_mode
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn insert_optional(claims: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        claims.insert(key.to_string(), Value::String(value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_mode_validation_allows_supported_modes() {
        assert!(validate_response_mode(None).is_ok());
        assert!(validate_response_mode(Some("query")).is_ok());
        assert!(validate_response_mode(Some("fragment")).is_ok());
        assert!(validate_response_mode(Some("form_post")).is_ok());
        assert!(validate_response_mode(Some("query.jwt")).is_ok());
        assert!(validate_response_mode(Some("fragment.jwt")).is_ok());
        assert!(validate_response_mode(Some("form_post.jwt")).is_ok());
        assert!(validate_response_mode(Some("web_message")).is_err());
    }

    #[test]
    fn response_mode_parser_keeps_transport_and_signing_separate() {
        assert_eq!(
            AuthorizationResponseMode::parse(Some("query")).unwrap(),
            AuthorizationResponseMode::Query
        );
        assert_eq!(
            AuthorizationResponseMode::parse(Some("fragment")).unwrap(),
            AuthorizationResponseMode::Fragment
        );
        assert_eq!(
            AuthorizationResponseMode::parse(Some("form_post")).unwrap(),
            AuthorizationResponseMode::FormPost
        );
        assert_eq!(
            AuthorizationResponseMode::parse(Some("query.jwt")).unwrap(),
            AuthorizationResponseMode::QueryJwt
        );
        assert_eq!(
            AuthorizationResponseMode::parse(Some("fragment.jwt")).unwrap(),
            AuthorizationResponseMode::FragmentJwt
        );
        assert_eq!(
            AuthorizationResponseMode::parse(Some("form_post.jwt")).unwrap(),
            AuthorizationResponseMode::FormPostJwt
        );
        let query_jwt = AuthorizationResponseMode::parse(Some("query.jwt")).unwrap();
        assert!(query_jwt.is_signed());
        assert_eq!(query_jwt.transport(), AuthorizationResponseTransport::Query);
        let form_post_jwt = AuthorizationResponseMode::parse(Some("form_post.jwt")).unwrap();
        assert!(form_post_jwt.is_signed());
        assert_eq!(
            form_post_jwt.transport(),
            AuthorizationResponseTransport::FormPost
        );
        let fragment_jwt = AuthorizationResponseMode::parse(Some("fragment.jwt")).unwrap();
        assert!(fragment_jwt.is_signed());
        assert_eq!(
            fragment_jwt.transport(),
            AuthorizationResponseTransport::Fragment
        );
    }

    #[test]
    fn form_post_page_escapes_action_and_values() {
        let page = form_post_page(
            "https://app.example/callback?x=<bad>",
            &[
                ("code", "abc\"123".to_string()),
                ("state", "x&y".to_string()),
            ],
        );
        assert!(page.contains(r#"method="post""#));
        assert!(page.contains(r#"action="https://app.example/callback?x=&lt;bad&gt;""#));
        assert!(page.contains(r#"name="code" value="abc&quot;123""#));
        assert!(page.contains(r#"name="state" value="x&amp;y""#));
    }

    #[test]
    fn fragment_response_encodes_fields() {
        let request = request_with_redirect("https://app.example/callback?existing=1");
        let response = fragment_redirect(
            &request,
            vec![
                ("code", "abc 123".to_string()),
                ("state", "x&y".to_string()),
            ],
        )
        .unwrap();
        let location = response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(
            location,
            "https://app.example/callback?existing=1#code=abc+123&state=x%26y"
        );
    }

    #[test]
    fn fragment_response_rejects_fragmented_redirect_uri() {
        let request = request_with_redirect("https://app.example/callback#existing");
        assert!(fragment_redirect(&request, vec![("code", "abc".to_string())]).is_err());
    }

    fn request_with_redirect(redirect_uri: &str) -> ResolvedAuthorizeRequest {
        ResolvedAuthorizeRequest {
            source: crate::client_policy::AuthorizationRequestSource::Query,
            response_type: "code".to_string(),
            client_id: "client-a".to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: None,
            resource: None,
            authorization_details: None,
            login_hint: None,
            prompt: None,
            max_age: None,
            acr_values: None,
            claims: None,
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            response_mode: None,
            account_selection_prompted: false,
            account_selection_required: false,
            reauthentication_required: false,
            selected_session_id: None,
            selected_user_id: None,
        }
    }
}
