use crate::{
    AppState,
    audit::{self, AuditOutcome, AuditSink},
    client_policy::AuthorizationRequestSource,
    db::NewPushedAuthorizationRequest,
    error::{AppError, AppResult},
    oidc::{self, ResolvedAuthorizeRequest},
    oidc_client_auth::{ClientAuthFields, ClientAuthForm},
    util,
};
use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::{Deserialize, Serialize};

const REQUEST_URI_TTL_SECONDS: i64 = 90;
const INTERACTION_REQUEST_TTL_SECONDS: i64 = 600;
const PAR_REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
const BROWSER_INTERACTION_PREFIX: &str = "urn:gpt-sso:browser-interaction:";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredRequestKind {
    PushedAuthorizationRequest,
    BrowserInteraction,
}

impl StoredRequestKind {
    const fn prefix(self) -> &'static str {
        match self {
            Self::PushedAuthorizationRequest => PAR_REQUEST_URI_PREFIX,
            Self::BrowserInteraction => BROWSER_INTERACTION_PREFIX,
        }
    }

    fn accepts(self, handle: &str) -> bool {
        handle.starts_with(self.prefix())
    }
}

#[derive(Debug, Deserialize)]
pub struct PushedAuthorizationRequest {
    request: Option<String>,
    response_type: Option<String>,
    #[serde(flatten)]
    client_auth: ClientAuthForm,
    redirect_uri: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
    authorization_details: Option<String>,
    login_hint: Option<String>,
    prompt: Option<String>,
    max_age: Option<String>,
    acr_values: Option<String>,
    claims: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    response_mode: Option<String>,
}

impl ClientAuthFields for PushedAuthorizationRequest {
    fn client_auth(&self) -> &ClientAuthForm {
        &self.client_auth
    }
}

#[derive(Debug, Serialize)]
pub struct PushedAuthorizationResponse {
    request_uri: String,
    expires_in: i64,
}

pub async fn pushed_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(payload): Form<PushedAuthorizationRequest>,
) -> AppResult<(StatusCode, Json<PushedAuthorizationResponse>)> {
    let client = oidc::authenticate_client_at(&state, &headers, &payload, "/oauth2/par").await?;
    if let Some(client_id) = payload.client_id()
        && client_id != client.client_id
    {
        return Err(AppError::Oidc("client_id mismatch".to_string()));
    }
    let mut request = if let Some(request_object) = payload.request.as_deref() {
        crate::request_object::resolve_authorization_request_object_for_client(
            &state,
            &headers,
            &client,
            request_object,
        )
        .await?
    } else {
        ResolvedAuthorizeRequest {
            source: AuthorizationRequestSource::PushedAuthorizationRequest,
            response_type: required_form_value(payload.response_type, "response_type")?,
            client_id: client.client_id.clone(),
            redirect_uri: required_form_value(payload.redirect_uri, "redirect_uri")?,
            scope: payload.scope,
            resource: oidc::normalize_resource(payload.resource.as_deref())?,
            authorization_details: payload.authorization_details,
            login_hint: payload.login_hint,
            prompt: payload.prompt,
            max_age: oidc::parse_max_age(payload.max_age.as_deref())?,
            acr_values: oidc::normalize_acr_values_param(payload.acr_values.as_deref())?,
            claims: crate::oidc_claims::RequestedClaims::from_authorization_parameter(
                payload.claims.as_deref(),
            )?,
            state: payload.state,
            nonce: payload.nonce,
            code_challenge: payload.code_challenge,
            code_challenge_method: payload.code_challenge_method,
            response_mode: payload.response_mode,
            account_selection_prompted: false,
            account_selection_required: false,
            reauthentication_required: false,
            selected_session_id: None,
            selected_user_id: None,
        }
    };
    request.source = AuthorizationRequestSource::PushedAuthorizationRequest;
    oidc::validate_authorize_request_for_client(&client, &request)?;
    request.authorization_details =
        crate::authorization_details::normalize_authorization_details_for_client(
            &client,
            request.authorization_details.as_deref(),
        )?;
    let requested_scopes = util::normalize_scopes(
        request.scope.as_deref(),
        &state.settings.oidc.supported_scopes,
    )?;
    oidc::validate_requested_scopes(&client, &requested_scopes)?;

    let request_uri = store_authorization_request(&state, &client.client_id, &request).await?;
    state
        .db
        .record_audit_event(audit::oauth_event(
            client.client_id,
            "par.create",
            AuditOutcome::Success,
            serde_json::json!({
                "scope": requested_scopes.join(" "),
                "authorization_details_types": crate::authorization_details::details_types_for_audit(
                    request.authorization_details.as_deref()
                )?
            }),
        ))
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(PushedAuthorizationResponse {
            request_uri,
            expires_in: REQUEST_URI_TTL_SECONDS,
        }),
    ))
}

pub(crate) async fn store_authorization_request(
    state: &AppState,
    client_id: &str,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<String> {
    store_authorization_request_with_ttl(
        state,
        client_id,
        request,
        REQUEST_URI_TTL_SECONDS,
        StoredRequestKind::PushedAuthorizationRequest,
    )
    .await
}

pub(crate) async fn store_interaction_authorization_request(
    state: &AppState,
    client_id: &str,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<String> {
    store_authorization_request_with_ttl(
        state,
        client_id,
        request,
        INTERACTION_REQUEST_TTL_SECONDS,
        StoredRequestKind::BrowserInteraction,
    )
    .await
}

async fn store_authorization_request_with_ttl(
    state: &AppState,
    client_id: &str,
    request: &ResolvedAuthorizeRequest,
    ttl_seconds: i64,
    kind: StoredRequestKind,
) -> AppResult<String> {
    let request_uri = format!("{}{}", kind.prefix(), util::random_token(32));
    state
        .db
        .insert_pushed_authorization_request(NewPushedAuthorizationRequest {
            request_uri_hash: util::token_hash(&request_uri),
            client_id: client_id.to_string(),
            request_json: serde_json::to_string(request)
                .map_err(|err| AppError::Internal(err.to_string()))?,
            expires_at: util::now_ts() + ttl_seconds,
        })
        .await?;
    Ok(request_uri)
}

fn required_form_value(value: Option<String>, field: &str) -> AppResult<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Oidc(format!("{field} is required")))
}

pub(crate) async fn consume_request_uri(
    state: &AppState,
    request_uri: &str,
) -> AppResult<ResolvedAuthorizeRequest> {
    consume_stored_request(
        state,
        request_uri,
        StoredRequestKind::PushedAuthorizationRequest,
    )
    .await
}

pub(crate) async fn consume_interaction_request(
    state: &AppState,
    interaction_request: &str,
) -> AppResult<ResolvedAuthorizeRequest> {
    consume_stored_request(
        state,
        interaction_request,
        StoredRequestKind::BrowserInteraction,
    )
    .await
}

async fn consume_stored_request(
    state: &AppState,
    handle: &str,
    kind: StoredRequestKind,
) -> AppResult<ResolvedAuthorizeRequest> {
    if !kind.accepts(handle) {
        return Err(map_request_uri_error(AppError::NotFound));
    }
    let record = state
        .db
        .consume_pushed_authorization_request(&util::token_hash(handle))
        .await
        .map_err(map_request_uri_error)?;
    request_from_record(record)
}

fn map_request_uri_error(err: AppError) -> AppError {
    match err {
        AppError::Oidc(description) | AppError::BadRequest(description) => {
            AppError::oauth("invalid_request_uri", &description, StatusCode::BAD_REQUEST)
        }
        AppError::NotFound => AppError::oauth(
            "invalid_request_uri",
            "request_uri is invalid",
            StatusCode::BAD_REQUEST,
        ),
        internal => internal,
    }
}

pub(crate) async fn peek_request_uri(
    state: &AppState,
    request_uri: &str,
) -> AppResult<Option<ResolvedAuthorizeRequest>> {
    peek_stored_request(
        state,
        request_uri,
        StoredRequestKind::PushedAuthorizationRequest,
    )
    .await
}

pub(crate) async fn peek_interaction_request(
    state: &AppState,
    interaction_request: &str,
) -> AppResult<Option<ResolvedAuthorizeRequest>> {
    peek_stored_request(
        state,
        interaction_request,
        StoredRequestKind::BrowserInteraction,
    )
    .await
}

pub(crate) async fn update_interaction_authorization_request(
    state: &AppState,
    interaction_request: &str,
    expected_request: &ResolvedAuthorizeRequest,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<()> {
    if !StoredRequestKind::BrowserInteraction.accepts(interaction_request) {
        return Err(AppError::Unauthorized);
    }
    if expected_request.client_id != request.client_id {
        return Err(AppError::Unauthorized);
    }
    let expected_request_json = serde_json::to_string(expected_request)
        .map_err(|err| AppError::Internal(format!("invalid interaction payload: {err}")))?;
    let request_json = serde_json::to_string(request)
        .map_err(|err| AppError::Internal(format!("invalid interaction payload: {err}")))?;
    state
        .db
        .update_unconsumed_pushed_authorization_request(
            &util::token_hash(interaction_request),
            &request.client_id,
            &expected_request_json,
            &request_json,
        )
        .await?;
    Ok(())
}

async fn peek_stored_request(
    state: &AppState,
    handle: &str,
    kind: StoredRequestKind,
) -> AppResult<Option<ResolvedAuthorizeRequest>> {
    if !kind.accepts(handle) {
        return Ok(None);
    }
    let Some(record) = state
        .db
        .find_pushed_authorization_request(&util::token_hash(handle))
        .await?
    else {
        return Ok(None);
    };
    if record.expires_at < util::now_ts() || record.consumed_at.is_some() {
        return Ok(None);
    }
    request_from_record(record).map(Some)
}

fn request_from_record(
    record: crate::db::PushedAuthorizationRequestRecord,
) -> AppResult<ResolvedAuthorizeRequest> {
    let request = serde_json::from_str::<ResolvedAuthorizeRequest>(&record.request_json)
        .map_err(|err| AppError::Internal(format!("invalid PAR payload: {err}")))?;
    if request.client_id != record.client_id {
        return Err(AppError::oauth(
            "invalid_request_uri",
            "request_uri client binding is invalid",
            StatusCode::BAD_REQUEST,
        ));
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_uri_client_errors_keep_the_oauth_error_code() {
        let mapped = map_request_uri_error(AppError::Oidc("request_uri expired".to_string()));
        assert!(matches!(
            mapped,
            AppError::OAuth {
                ref error,
                ref description,
                status: StatusCode::BAD_REQUEST
            } if error == "invalid_request_uri" && description == "request_uri expired"
        ));
    }

    #[test]
    fn request_uri_internal_errors_are_not_wrapped_with_public_details() {
        let mapped = map_request_uri_error(AppError::Database("private SQL detail".to_string()));
        assert!(matches!(mapped, AppError::Database(_)));
    }

    #[test]
    fn par_and_browser_interaction_handles_have_disjoint_namespaces() {
        let par = format!("{PAR_REQUEST_URI_PREFIX}secret");
        let interaction = format!("{BROWSER_INTERACTION_PREFIX}secret");

        assert!(StoredRequestKind::PushedAuthorizationRequest.accepts(&par));
        assert!(!StoredRequestKind::PushedAuthorizationRequest.accepts(&interaction));
        assert!(StoredRequestKind::BrowserInteraction.accepts(&interaction));
        assert!(!StoredRequestKind::BrowserInteraction.accepts(&par));
    }
}
