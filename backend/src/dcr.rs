use crate::{
    AppState,
    audit::{self, AuditOutcome, AuditSink},
    client_assertion, client_policy,
    db::{ClientRecord, NewClient},
    device::DEVICE_CODE_GRANT,
    error::{AppError, AppResult},
    subject,
    token_exchange::TOKEN_EXCHANGE_GRANT,
    util,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
};
use serde::{Deserialize, Serialize};
use url::Url;

const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email"];
const DEFAULT_GRANT_TYPES: &[&str] = &["authorization_code"];
const DEFAULT_RESPONSE_TYPES: &[&str] = &["code"];
const DEFAULT_TOKEN_AUTH_METHOD: &str = "client_secret_basic";
// Distinct from the legacy dcr_<base64url> ID space even when the operator
// later disables website registration or switches to legacy DCR.
const WEBSITE_CLIENT_PREFIX: &str = "dcr.website.";

pub(crate) fn is_website_client_id(client_id: &str) -> bool {
    client_id.starts_with(WEBSITE_CLIENT_PREFIX)
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientMetadata {
    pub redirect_uris: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub client_name: Option<String>,
    pub logo_uri: Option<String>,
    pub scope: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub token_endpoint_auth_method: Option<String>,
    pub require_pkce: Option<bool>,
    pub require_pushed_authorization_requests: Option<bool>,
    pub require_s256_pkce: Option<bool>,
    pub require_confidential_client: Option<bool>,
    pub require_dpop: Option<bool>,
    pub require_account_selection: Option<bool>,
    pub trust_email_verified: Option<bool>,
    pub authorization_details_types: Option<Vec<String>>,
    pub subject_type: Option<String>,
    pub sector_identifier_uri: Option<String>,
    pub jwks_uri: Option<String>,
    pub jwks: Option<serde_json::Value>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: Option<bool>,
    pub frontchannel_logout_uri: Option<String>,
    pub frontchannel_logout_session_required: Option<bool>,
    #[serde(flatten)]
    other: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    pub client_id_issued_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub client_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    pub scope: String,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub require_pkce: bool,
    pub require_pushed_authorization_requests: bool,
    pub require_s256_pkce: bool,
    pub require_confidential_client: bool,
    pub require_dpop: bool,
    pub require_account_selection: bool,
    pub trust_email_verified: bool,
    pub authorization_details_types: Vec<String>,
    pub subject_type: String,
    pub sector_identifier_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontchannel_logout_uri: Option<String>,
    pub frontchannel_logout_session_required: bool,
}

pub trait ClientMetadataValidator {
    fn validate_metadata(&self, metadata: &ClientMetadata) -> AppResult<()>;
}

#[derive(Debug, Clone)]
pub struct DynamicClientRegistrar {
    supported_scopes: Vec<String>,
}

impl DynamicClientRegistrar {
    pub fn new(supported_scopes: Vec<String>) -> Self {
        Self { supported_scopes }
    }

    pub fn new_client(
        &self,
        metadata: ClientMetadata,
        existing_secret_hash: Option<String>,
    ) -> AppResult<(NewClient, Option<String>)> {
        self.validate_metadata(&metadata)?;
        let token_endpoint_auth_method = metadata
            .token_endpoint_auth_method
            .unwrap_or_else(|| DEFAULT_TOKEN_AUTH_METHOD.to_string());
        let is_public = token_endpoint_auth_method == "none";
        let uses_public_key_assertion =
            token_endpoint_auth_method == client_assertion::PRIVATE_KEY_JWT;
        let can_reuse_secret = client_assertion::stored_secret_supports_method(
            &token_endpoint_auth_method,
            existing_secret_hash.as_deref(),
        );
        let client_secret = if is_public || uses_public_key_assertion || can_reuse_secret {
            None
        } else {
            Some(util::random_token(32))
        };
        let client_secret_hash = if is_public || uses_public_key_assertion {
            None
        } else {
            match (&client_secret, existing_secret_hash) {
                (Some(secret), _) => {
                    client_assertion::store_client_secret(&token_endpoint_auth_method, secret)?
                }
                (None, existing) => existing,
            }
        };
        let grant_types = metadata.grant_types.unwrap_or_else(|| {
            DEFAULT_GRANT_TYPES
                .iter()
                .map(|value| value.to_string())
                .collect()
        });
        let redirect_uris = metadata.redirect_uris.unwrap_or_default();
        let post_logout_redirect_uris = metadata.post_logout_redirect_uris.unwrap_or_default();
        let logo_uri = normalize_logo_uri(metadata.logo_uri.as_deref())?;
        let response_types = metadata
            .response_types
            .unwrap_or_else(|| default_response_types(&grant_types));
        let scopes = metadata
            .scope
            .as_deref()
            .map(split_scope)
            .unwrap_or_else(|| {
                DEFAULT_SCOPES
                    .iter()
                    .map(|value| value.to_string())
                    .collect()
            });
        let subject_type = metadata
            .subject_type
            .unwrap_or_else(|| subject::SUBJECT_TYPE_PUBLIC.to_string());
        let sector_identifier_uri = metadata.sector_identifier_uri.unwrap_or_default();
        let jwks_uri =
            client_assertion::validate_jwks_uri(metadata.jwks_uri.as_deref().unwrap_or_default())?;
        let jwks = metadata
            .jwks
            .as_ref()
            .map(|value| client_assertion::normalize_jwks_json(&value.to_string()))
            .transpose()?
            .unwrap_or_default();
        let backchannel_logout_session_required = metadata
            .backchannel_logout_session_required
            .unwrap_or(false);
        let backchannel_logout_uri = crate::backchannel_logout::validate_backchannel_logout_config(
            metadata
                .backchannel_logout_uri
                .as_deref()
                .unwrap_or_default(),
            backchannel_logout_session_required,
        )?;
        let frontchannel_logout_session_required = metadata
            .frontchannel_logout_session_required
            .unwrap_or(false);
        let frontchannel_logout_uri =
            crate::frontchannel_logout::validate_frontchannel_logout_config(
                metadata
                    .frontchannel_logout_uri
                    .as_deref()
                    .unwrap_or_default(),
                frontchannel_logout_session_required,
                &redirect_uris,
            )?;
        let require_pkce = metadata.require_pkce.unwrap_or(is_public);
        let require_pushed_authorization_requests = metadata
            .require_pushed_authorization_requests
            .unwrap_or(false);
        let require_s256_pkce = metadata.require_s256_pkce.unwrap_or(false);
        let require_confidential_client = metadata.require_confidential_client.unwrap_or(false);
        let require_dpop = metadata.require_dpop.unwrap_or(false);
        let authorization_details_types = crate::authorization_details::normalize_public_types(
            metadata
                .authorization_details_types
                .clone()
                .unwrap_or_default(),
        )?;
        client_policy::validate_client_security_configuration(
            client_policy::ClientSecurityConfig {
                token_endpoint_auth_method: &token_endpoint_auth_method,
                require_pkce,
                require_s256_pkce,
                require_confidential_client,
                require_pushed_authorization_requests,
                require_dpop,
            },
        )?;
        Ok((
            NewClient {
                client_id: format!("dcr_{}", util::random_token(18)),
                client_secret_hash,
                client_name: metadata
                    .client_name
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| "Dynamic client".to_string()),
                logo_uri,
                organization_id: None,
                redirect_uris,
                post_logout_redirect_uris,
                scopes,
                audience: String::new(),
                grant_types,
                response_types,
                token_endpoint_auth_method,
                require_pkce,
                require_mfa: false,
                require_pushed_authorization_requests,
                require_s256_pkce,
                require_confidential_client,
                require_dpop,
                require_account_selection: metadata.require_account_selection.unwrap_or(false),
                trust_email_verified: metadata.trust_email_verified.unwrap_or(false),
                authorization_details_types,
                subject_type,
                sector_identifier_uri,
                jwks_uri,
                jwks,
                backchannel_logout_uri,
                backchannel_logout_session_required,
                frontchannel_logout_uri,
                frontchannel_logout_session_required,
                service_account_enabled: false,
                service_account_permissions: Vec::new(),
                is_active: true,
            },
            client_secret,
        ))
    }

    pub fn updated_client(
        &self,
        existing: &ClientRecord,
        metadata: ClientMetadata,
    ) -> AppResult<(NewClient, Option<String>)> {
        let (mut client, secret) =
            self.new_client(metadata, existing.client_secret_hash.clone())?;
        client.client_id = existing.client_id.clone();
        client.organization_id = existing.organization_id.clone();
        client.audience = existing.audience.clone();
        Ok((client, secret))
    }
}

impl ClientMetadataValidator for DynamicClientRegistrar {
    fn validate_metadata(&self, metadata: &ClientMetadata) -> AppResult<()> {
        normalize_logo_uri(metadata.logo_uri.as_deref())?;
        let grant_types = metadata.grant_types.clone().unwrap_or_else(|| {
            DEFAULT_GRANT_TYPES
                .iter()
                .map(|value| value.to_string())
                .collect()
        });
        let response_types = metadata
            .response_types
            .clone()
            .unwrap_or_else(|| default_response_types(&grant_types));
        validate_allowed_values(
            &grant_types,
            &[
                "authorization_code",
                "refresh_token",
                "client_credentials",
                DEVICE_CODE_GRANT,
                TOKEN_EXCHANGE_GRANT,
            ],
            "grant_types",
        )?;
        validate_allowed_values(&response_types, &["code"], "response_types")?;
        let token_auth = metadata
            .token_endpoint_auth_method
            .as_deref()
            .unwrap_or(DEFAULT_TOKEN_AUTH_METHOD);
        if !matches!(
            token_auth,
            "client_secret_basic"
                | "client_secret_post"
                | client_assertion::CLIENT_SECRET_JWT
                | client_assertion::PRIVATE_KEY_JWT
                | "none"
        ) {
            return Err(AppError::BadRequest(
                "unsupported token_endpoint_auth_method".to_string(),
            ));
        }
        let jwks_uri = metadata.jwks_uri.as_deref().unwrap_or_default();
        let jwks = metadata
            .jwks
            .as_ref()
            .map(|value| value.to_string())
            .unwrap_or_default();
        client_assertion::validate_key_source(token_auth, jwks_uri, &jwks)?;
        client_policy::validate_client_security_configuration(
            client_policy::ClientSecurityConfig {
                token_endpoint_auth_method: token_auth,
                require_pkce: metadata.require_pkce.unwrap_or(token_auth == "none"),
                require_s256_pkce: metadata.require_s256_pkce.unwrap_or(false),
                require_confidential_client: metadata.require_confidential_client.unwrap_or(false),
                require_pushed_authorization_requests: metadata
                    .require_pushed_authorization_requests
                    .unwrap_or(false),
                require_dpop: metadata.require_dpop.unwrap_or(false),
            },
        )?;
        crate::authorization_details::normalize_public_types(
            metadata
                .authorization_details_types
                .clone()
                .unwrap_or_default(),
        )?;
        crate::backchannel_logout::validate_backchannel_logout_config(
            metadata
                .backchannel_logout_uri
                .as_deref()
                .unwrap_or_default(),
            metadata
                .backchannel_logout_session_required
                .unwrap_or(false),
        )?;
        crate::frontchannel_logout::validate_frontchannel_logout_config(
            metadata
                .frontchannel_logout_uri
                .as_deref()
                .unwrap_or_default(),
            metadata
                .frontchannel_logout_session_required
                .unwrap_or(false),
            metadata.redirect_uris.as_deref().unwrap_or(&[]),
        )?;
        let needs_redirect = grant_types
            .iter()
            .any(|value| value == "authorization_code")
            || response_types.iter().any(|value| value == "code");
        if needs_redirect && metadata.redirect_uris.as_ref().is_none_or(Vec::is_empty) {
            return Err(AppError::BadRequest(
                "redirect_uris is required".to_string(),
            ));
        }
        for uri in metadata
            .redirect_uris
            .iter()
            .flatten()
            .chain(metadata.post_logout_redirect_uris.iter().flatten())
        {
            validate_uri(uri)?;
        }
        subject::validate_subject_config(
            metadata
                .subject_type
                .as_deref()
                .unwrap_or(subject::SUBJECT_TYPE_PUBLIC),
            metadata
                .sector_identifier_uri
                .as_deref()
                .unwrap_or_default(),
        )?;
        let scopes = metadata
            .scope
            .as_deref()
            .map(split_scope)
            .unwrap_or_else(|| {
                DEFAULT_SCOPES
                    .iter()
                    .map(|value| value.to_string())
                    .collect()
            });
        for scope in scopes {
            if !self
                .supported_scopes
                .iter()
                .any(|allowed| allowed == &scope)
            {
                return Err(AppError::BadRequest(format!("unsupported scope: {scope}")));
            }
        }
        Ok(())
    }
}

fn website_origin(uri: &str) -> AppResult<String> {
    let invalid = || AppError::BadRequest("expected an absolute HTTPS callback URI".into());
    let url = Url::parse(uri).map_err(|_| invalid())?;
    if !uri.to_ascii_lowercase().starts_with("https://")
        || uri.contains(|c: char| c.is_whitespace() || c.is_control() || c == '\\')
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(url.origin().ascii_serialization())
}

impl ClientMetadata {
    fn website_profile(mut self, existing: Option<&ClientRecord>) -> AppResult<Self> {
        let callbacks = self.redirect_uris.as_deref().unwrap_or_default();
        let origin = website_origin(
            callbacks
                .first()
                .ok_or_else(|| AppError::BadRequest("redirect_uris is required".into()))?,
        )?;
        for uri in callbacks
            .iter()
            .skip(1)
            .chain(self.post_logout_redirect_uris.iter().flatten())
        {
            if website_origin(uri)? != origin {
                return Err(AppError::BadRequest(
                    "website callbacks must share an origin".into(),
                ));
            }
        }
        if let Some(client) = existing {
            let old = client.redirect_uris()?;
            if old
                .first()
                .map(|uri| website_origin(uri))
                .transpose()?
                .as_ref()
                != Some(&origin)
            {
                return Err(AppError::BadRequest("website origin cannot change".into()));
            }
        }
        if self
            .client_name
            .as_ref()
            .is_some_and(|name| name != &origin)
            || self
                .grant_types
                .as_ref()
                .is_some_and(|v| v.as_slice() != DEFAULT_GRANT_TYPES)
            || self
                .response_types
                .as_ref()
                .is_some_and(|v| v.as_slice() != DEFAULT_RESPONSE_TYPES)
            || self.scope.as_deref().is_some_and(|v| v != "openid")
            || self
                .token_endpoint_auth_method
                .as_deref()
                .is_some_and(|v| v != "none")
            || self
                .subject_type
                .as_deref()
                .is_some_and(|v| v != subject::SUBJECT_TYPE_PAIRWISE)
            || self.require_pkce == Some(false)
            || self.require_s256_pkce == Some(false)
            || self.require_account_selection == Some(true)
            || self.trust_email_verified == Some(true)
            || self.require_confidential_client == Some(true)
            || self.require_dpop == Some(true)
            || self.require_pushed_authorization_requests == Some(true)
            || self
                .authorization_details_types
                .as_ref()
                .is_some_and(|v| !v.is_empty())
            || self.logo_uri.is_some()
            || self.sector_identifier_uri.is_some()
            || self.jwks.is_some()
            || self.jwks_uri.is_some()
            || self.backchannel_logout_uri.is_some()
            || self.frontchannel_logout_uri.is_some()
            || self.backchannel_logout_session_required == Some(true)
            || self.frontchannel_logout_session_required == Some(true)
            || !self.other.is_empty()
        {
            return Err(AppError::BadRequest(
                "unsupported metadata for a public website".into(),
            ));
        }
        self.client_name = Some(origin);
        self.scope = Some("openid".into());
        self.token_endpoint_auth_method = Some("none".into());
        self.subject_type = Some(subject::SUBJECT_TYPE_PAIRWISE.into());
        self.require_pkce = Some(true);
        self.require_s256_pkce = Some(true);
        Ok(self)
    }
}

pub async fn register_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ClientMetadata>,
) -> AppResult<Json<ClientRegistrationResponse>> {
    ensure_dcr_enabled(&state)?;
    let registrar = DynamicClientRegistrar::new(state.settings.oidc.supported_scopes.clone());
    let website = state.settings.oidc.allow_public_website_registration;
    let metadata = if website {
        payload.website_profile(None)?
    } else {
        payload
    };
    let (mut client, client_secret) = registrar.new_client(metadata, None)?;
    if website {
        client.client_id = format!("{WEBSITE_CLIENT_PREFIX}{}", util::random_token(18));
    }
    let registration_access_token = util::random_token(32);
    // Dynamic registration is one aggregate command. A client without its
    // application/profile/binding/registration record is not a usable OIDC
    // connection, so those rows must never become independently visible.
    let client = state
        .db
        .register_dynamic_client_graph(client, util::token_hash(&registration_access_token))
        .await?;
    state
        .db
        .record_audit_event(audit::oauth_event(
            client.client_id.clone(),
            "client.dynamic_register",
            AuditOutcome::Success,
            serde_json::json!({ "client_id": client.client_id.clone() }),
        ))
        .await?;
    Ok(Json(
        client_response(
            &state,
            &headers,
            client,
            client_secret,
            Some(registration_access_token),
        )
        .await?,
    ))
}

pub async fn read_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> AppResult<Json<ClientRegistrationResponse>> {
    ensure_dcr_enabled(&state)?;
    let client = authenticated_registration_client(&state, &headers, &client_id).await?;
    Ok(Json(
        client_response(&state, &headers, client, None, None).await?,
    ))
}

pub async fn update_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Json(payload): Json<ClientMetadata>,
) -> AppResult<Json<ClientRegistrationResponse>> {
    ensure_dcr_enabled(&state)?;
    let existing = authenticated_registration_client(&state, &headers, &client_id).await?;
    let registrar = DynamicClientRegistrar::new(state.settings.oidc.supported_scopes.clone());
    let website = is_website_client_id(&existing.client_id);
    if website && existing.is_active == 0 {
        return Err(AppError::Forbidden);
    }
    let metadata = if website {
        payload.website_profile(Some(&existing))?
    } else {
        payload
    };
    let (client, client_secret) = registrar.updated_client(&existing, metadata)?;
    let client = if website {
        state
            .db
            .update_website_callbacks(
                &existing.id,
                &client.redirect_uris,
                &client.post_logout_redirect_uris,
            )
            .await?
    } else {
        state.db.update_client(&existing.id, client).await?
    };
    state
        .db
        .record_audit_event(audit::oauth_event(
            client.client_id.clone(),
            "client.dynamic_update",
            AuditOutcome::Success,
            serde_json::json!({ "client_id": client.client_id.clone() }),
        ))
        .await?;
    Ok(Json(
        client_response(&state, &headers, client, client_secret, None).await?,
    ))
}

pub async fn delete_client(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> AppResult<StatusCode> {
    ensure_dcr_enabled(&state)?;
    let client = authenticated_registration_client(&state, &headers, &client_id).await?;
    state.db.delete_client(&client.id).await?;
    state
        .db
        .record_audit_event(audit::oauth_event(
            client.client_id.clone(),
            "client.dynamic_delete",
            AuditOutcome::Success,
            serde_json::json!({ "client_id": client.client_id }),
        ))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn authenticate_active_registration(
    state: &AppState,
    headers: &HeaderMap,
    client_id: &str,
) -> AppResult<String> {
    let client = authenticated_registration_client(state, headers, client_id).await?;
    if client.is_active == 0 {
        return Err(AppError::Unauthorized);
    }
    Ok(client.id)
}

async fn authenticated_registration_client(
    state: &AppState,
    headers: &HeaderMap,
    client_id: &str,
) -> AppResult<ClientRecord> {
    let token = bearer_token(headers).ok_or(AppError::Unauthorized)?;
    let client = state
        .db
        .find_client_by_client_id(client_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let registration = state
        .db
        .find_client_registration(&client.id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if registration.registration_access_token_hash != util::token_hash(token) {
        return Err(AppError::Unauthorized);
    }
    Ok(client)
}

async fn client_response(
    state: &AppState,
    headers: &HeaderMap,
    client: ClientRecord,
    client_secret: Option<String>,
    registration_access_token: Option<String>,
) -> AppResult<ClientRegistrationResponse> {
    let issuer = state.effective_issuer(headers).await?;
    let public = client.clone().public()?;
    Ok(ClientRegistrationResponse {
        client_id: public.client_id.clone(),
        client_secret_expires_at: if client_secret.is_some() {
            Some(0)
        } else {
            None
        },
        client_secret,
        client_id_issued_at: public.created_at,
        organization_id: public.organization_id,
        registration_access_token,
        registration_client_uri: Some(format!(
            "{}/connect/register/{}",
            issuer.trim_end_matches('/'),
            public.client_id
        )),
        redirect_uris: public.redirect_uris,
        post_logout_redirect_uris: public.post_logout_redirect_uris,
        client_name: public.client_name,
        logo_uri: (!public.logo_uri.is_empty()).then_some(public.logo_uri),
        scope: public.scopes.join(" "),
        grant_types: public.grant_types,
        response_types: public.response_types,
        token_endpoint_auth_method: public.token_endpoint_auth_method,
        require_pkce: public.require_pkce,
        require_pushed_authorization_requests: public.require_pushed_authorization_requests,
        require_s256_pkce: public.require_s256_pkce,
        require_confidential_client: public.require_confidential_client,
        require_dpop: public.require_dpop,
        require_account_selection: public.require_account_selection,
        trust_email_verified: public.trust_email_verified,
        authorization_details_types: public.authorization_details_types,
        subject_type: public.subject_type,
        sector_identifier_uri: public.sector_identifier_uri,
        jwks_uri: (!public.jwks_uri.is_empty()).then_some(public.jwks_uri),
        jwks: if public.jwks.trim().is_empty() {
            None
        } else {
            Some(
                serde_json::from_str(&public.jwks).map_err(|err| {
                    AppError::Internal(format!("invalid stored client jwks: {err}"))
                })?,
            )
        },
        backchannel_logout_uri: (!public.backchannel_logout_uri.is_empty())
            .then_some(public.backchannel_logout_uri),
        backchannel_logout_session_required: public.backchannel_logout_session_required,
        frontchannel_logout_uri: (!public.frontchannel_logout_uri.is_empty())
            .then_some(public.frontchannel_logout_uri),
        frontchannel_logout_session_required: public.frontchannel_logout_session_required,
    })
}

fn ensure_dcr_enabled(state: &AppState) -> AppResult<()> {
    if state.settings.oidc.allow_dynamic_client_registration
        || state.settings.oidc.allow_public_website_registration
    {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn split_scope(value: &str) -> Vec<String> {
    value
        .split_whitespace()
        .map(|scope| scope.trim().to_string())
        .filter(|scope| !scope.is_empty())
        .collect()
}

fn default_response_types(grant_types: &[String]) -> Vec<String> {
    if grant_types
        .iter()
        .any(|value| value == "authorization_code")
    {
        DEFAULT_RESPONSE_TYPES
            .iter()
            .map(|value| value.to_string())
            .collect()
    } else {
        Vec::new()
    }
}

fn validate_allowed_values(values: &[String], allowed: &[&str], field: &str) -> AppResult<()> {
    for value in values {
        if !allowed.iter().any(|allowed| allowed == value) {
            return Err(AppError::BadRequest(format!(
                "unsupported {field} value: {value}"
            )));
        }
    }
    Ok(())
}

fn validate_uri(value: &str) -> AppResult<()> {
    let parsed = Url::parse(value)
        .map_err(|err| AppError::BadRequest(format!("invalid redirect URI: {err}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(AppError::BadRequest(
            "redirect URI must be absolute http/https".to_string(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(AppError::BadRequest(
            "redirect URI cannot contain a fragment".to_string(),
        ));
    }
    Ok(())
}

fn normalize_logo_uri(value: Option<&str>) -> AppResult<String> {
    let value = value.unwrap_or_default().trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > 2048 {
        return Err(AppError::BadRequest(
            "logo_uri must not exceed 2048 characters".to_string(),
        ));
    }
    let parsed = Url::parse(value)
        .map_err(|err| AppError::BadRequest(format!("logo_uri is invalid: {err}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(AppError::BadRequest(
            "logo_uri must be an absolute http(s) URL".to_string(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(AppError::BadRequest(
            "logo_uri cannot contain a fragment".to_string(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppError::BadRequest(
            "logo_uri cannot include user info".to_string(),
        ));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "sqlite")]
    async fn test_state() -> (AppState, std::path::PathBuf) {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path =
            std::env::temp_dir().join(format!("gpt-sso-dcr-test-{}.sqlite3", uuid::Uuid::new_v4()));
        settings.database.kind = crate::config::DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();
        settings.oidc.allow_dynamic_client_registration = true;
        let db = crate::db::Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        db.seed(&settings).await.unwrap();
        let jwt = crate::jwt::JwtManager::new(&settings).unwrap();
        (AppState::new(settings, db, jwt), path)
    }

    #[test]
    fn redirect_uri_rejects_fragments() {
        assert!(validate_uri("https://app.example/callback").is_ok());
        assert!(validate_uri("https://app.example/callback#fragment").is_err());
    }

    #[test]
    fn logo_uri_is_normalized_and_requires_a_safe_http_url() {
        assert_eq!(
            normalize_logo_uri(Some(" https://assets.example.com/signet.svg ")).unwrap(),
            "https://assets.example.com/signet.svg"
        );
        for logo_uri in [
            "javascript:alert(1)",
            "https://user:secret@assets.example.com/logo.svg",
            "https://assets.example.com/logo.svg#fragment",
        ] {
            assert!(normalize_logo_uri(Some(logo_uri)).is_err());
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn website_registration_pins_identity_and_origin_even_after_switching_modes() {
        let (mut state, path) = test_state().await;
        state.settings.oidc.allow_dynamic_client_registration = false;
        state.settings.oidc.allow_public_website_registration = true;
        let metadata = |uri: &str| {
            serde_json::from_value(serde_json::json!({ "redirect_uris": [uri] })).unwrap()
        };
        let response = register_client(
            State(state.clone()),
            HeaderMap::new(),
            Json(metadata("https://app.test/start")),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(response.client_name, "https://app.test");
        assert_eq!(response.scope, "openid");
        assert_eq!(response.subject_type, "pairwise");
        assert_eq!(response.token_endpoint_auth_method, "none");
        assert!(response.require_pkce && response.require_s256_pkce);
        assert!(response.client_secret.is_none());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", response.registration_access_token.unwrap())
                .parse()
                .unwrap(),
        );
        state.settings.oidc.allow_public_website_registration = false;
        state.settings.oidc.allow_dynamic_client_registration = true;
        for (uri, allowed) in [
            ("https://other.test/end", false),
            ("https://app.test/end", true),
        ] {
            assert_eq!(
                update_client(
                    State(state.clone()),
                    headers.clone(),
                    Path(response.client_id.clone()),
                    Json(metadata(uri))
                )
                .await
                .is_ok(),
                allowed
            );
        }
        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn website_mode_takes_precedence_and_rejects_broader_metadata() {
        let (mut state, path) = test_state().await;
        state.settings.oidc.allow_public_website_registration = true;
        for (key, value) in [
            ("scope", serde_json::json!("openid email")),
            ("redirect_uris", serde_json::json!(["http://app.test/cb"])),
            (
                "post_logout_redirect_uris",
                serde_json::json!(["https://other.test/end"]),
            ),
            ("grant_types", serde_json::json!(["client_credentials"])),
            ("require_s256_pkce", serde_json::json!(false)),
            ("jwks_uri", serde_json::json!("https://app.test/keys")),
            ("client_name", serde_json::json!("Signet Administrator")),
            ("service_account_enabled", serde_json::json!(true)),
        ] {
            let mut metadata = serde_json::json!({"redirect_uris": ["https://app.test/cb"]});
            metadata[key] = value;
            assert!(
                matches!(
                    register_client(
                        State(state.clone()),
                        HeaderMap::new(),
                        Json(serde_json::from_value(metadata).unwrap())
                    )
                    .await,
                    Err(AppError::BadRequest(_))
                ),
                "{key}"
            );
        }
        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn dynamic_client_registration_starts_with_a_locked_signet_application() {
        let (state, path) = test_state().await;
        let payload: ClientMetadata = serde_json::from_value(serde_json::json!({
            "client_name": "Dynamic test client",
            "redirect_uris": ["https://example.test/callback"]
        }))
        .unwrap();

        let response = register_client(State(state.clone()), HeaderMap::new(), Json(payload))
            .await
            .unwrap()
            .0;
        let client = state
            .db
            .find_client_by_client_id(&response.client_id)
            .await
            .unwrap()
            .unwrap();
        let application = state
            .db
            .find_application_for_client(&client.id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            client.organization_id.as_deref(),
            Some(crate::organizations::SIGNET_ORGANIZATION_ID)
        );
        assert_eq!(
            application.access_mode,
            crate::applications::ACCESS_ALL_SIGNET_USERS
        );
        assert_eq!(
            application.registration_mode,
            crate::applications::REGISTRATION_DISABLED
        );
        assert_eq!(application.is_active, 1);

        drop(state);
        let _ = std::fs::remove_file(path);
    }
}
