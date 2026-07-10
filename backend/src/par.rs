use crate::{
    AppState,
    audit::{self, AuditOutcome, AuditSink},
    client_policy::AuthorizationRequestSource,
    db::NewPushedAuthorizationRequest,
    error::{AppError, AppResult},
    oidc::{self, ClientAuthFields, ResolvedAuthorizeRequest},
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

#[derive(Debug, Deserialize)]
pub struct PushedAuthorizationRequest {
    request: Option<String>,
    response_type: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    client_assertion_type: Option<String>,
    client_assertion: Option<String>,
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
    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn client_secret(&self) -> Option<&str> {
        self.client_secret.as_deref()
    }

    fn client_assertion_type(&self) -> Option<&str> {
        self.client_assertion_type.as_deref()
    }

    fn client_assertion(&self) -> Option<&str> {
        self.client_assertion.as_deref()
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
    if let Some(client_id) = payload.client_id.as_deref() {
        if client_id != client.client_id {
            return Err(AppError::Oidc("client_id mismatch".to_string()));
        }
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
    store_authorization_request_with_ttl(state, client_id, request, REQUEST_URI_TTL_SECONDS).await
}

pub(crate) async fn store_interaction_authorization_request(
    state: &AppState,
    client_id: &str,
    request: &ResolvedAuthorizeRequest,
) -> AppResult<String> {
    store_authorization_request_with_ttl(state, client_id, request, INTERACTION_REQUEST_TTL_SECONDS)
        .await
}

async fn store_authorization_request_with_ttl(
    state: &AppState,
    client_id: &str,
    request: &ResolvedAuthorizeRequest,
    ttl_seconds: i64,
) -> AppResult<String> {
    let request_uri = format!(
        "urn:ietf:params:oauth:request_uri:{}",
        util::random_token(32)
    );
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
    let record = state
        .db
        .consume_pushed_authorization_request(&util::token_hash(request_uri))
        .await
        .map_err(|err| {
            AppError::oauth(
                "invalid_request_uri",
                &err.to_string(),
                StatusCode::BAD_REQUEST,
            )
        })?;
    request_from_record(record)
}

pub(crate) async fn peek_request_uri(
    state: &AppState,
    request_uri: &str,
) -> AppResult<Option<ResolvedAuthorizeRequest>> {
    let Some(record) = state
        .db
        .find_pushed_authorization_request(&util::token_hash(request_uri))
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
