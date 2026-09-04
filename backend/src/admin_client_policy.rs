use super::admin_client_types::ClientInput;
use crate::{
    backchannel_logout, claim_mapper, client_assertion, client_policy,
    db::{ClientClaimMapperRecord, NewClient, NewClientClaimMapper},
    error::{AppError, AppResult},
    frontchannel_logout, service_accounts, subject,
};
use std::collections::BTreeSet;
use url::Url;

pub(super) fn validate_client_input(payload: &ClientInput) -> AppResult<()> {
    if payload.client_id.trim().is_empty() {
        return Err(AppError::BadRequest("client_id is required".to_string()));
    }
    normalize_client_logo_uri(&payload.logo_uri)?;
    let redirect_uris = normalize_redirect_uri_list(&payload.redirect_uris, "redirect_uri")?;
    let post_logout_redirect_uris = normalize_redirect_uri_list(
        &payload.post_logout_redirect_uris,
        "post_logout_redirect_uri",
    )?;
    if let Some(audience) = payload.audience.as_deref()
        && !audience.trim().is_empty()
        && audience.len() > 2048
    {
        return Err(AppError::BadRequest(
            "audience must be between 1 and 2048 characters".to_string(),
        ));
    }
    let uses_authorization_code = payload
        .grant_types
        .iter()
        .any(|value| value == "authorization_code");
    if uses_authorization_code && redirect_uris.is_empty() {
        return Err(AppError::BadRequest(
            "at least one redirect_uri is required".to_string(),
        ));
    }
    if !payload.scopes.iter().any(|scope| scope == "openid") {
        return Err(AppError::BadRequest(
            "scopes must include openid".to_string(),
        ));
    }
    if uses_authorization_code && !payload.response_types.iter().any(|value| value == "code") {
        return Err(AppError::BadRequest(
            "response_types must include code".to_string(),
        ));
    }
    if payload.service_account_enabled
        && !payload
            .grant_types
            .iter()
            .any(|value| value == "client_credentials")
    {
        return Err(AppError::BadRequest(
            "service accounts require client_credentials grant".to_string(),
        ));
    }
    service_accounts::normalize_permissions(payload.service_account_permissions.clone())?;
    crate::authorization_details::normalize_public_types(
        payload.authorization_details_types.clone(),
    )?;
    if !matches!(
        payload.token_endpoint_auth_method.as_str(),
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
    client_assertion::validate_key_source(
        &payload.token_endpoint_auth_method,
        &payload.jwks_uri,
        &payload.jwks,
    )?;
    client_policy::validate_client_security_configuration(client_policy::ClientSecurityConfig {
        token_endpoint_auth_method: &payload.token_endpoint_auth_method,
        require_pkce: payload.require_pkce,
        require_s256_pkce: payload.require_s256_pkce,
        require_confidential_client: payload.require_confidential_client,
        require_pushed_authorization_requests: payload.require_pushed_authorization_requests,
        require_dpop: payload.require_dpop,
    })?;
    backchannel_logout::validate_backchannel_logout_config(
        &payload.backchannel_logout_uri,
        payload.backchannel_logout_session_required,
    )?;
    frontchannel_logout::validate_frontchannel_logout_config(
        &payload.frontchannel_logout_uri,
        payload.frontchannel_logout_session_required,
        &redirect_uris,
    )?;
    for uri in post_logout_redirect_uris {
        validate_absolute_http_url(&uri, "post_logout_redirect_uri")?;
    }
    subject::validate_subject_config(&payload.subject_type, &payload.sector_identifier_uri)?;
    Ok(())
}

pub(super) fn normalize_redirect_uri_list(
    values: &[String],
    field: &str,
) -> AppResult<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();
    for value in values {
        let value = value.trim().to_string();
        if value.is_empty() {
            continue;
        }
        validate_absolute_http_url(&value, field)?;
        if seen.insert(value.clone()) {
            normalized.push(value);
        }
    }
    Ok(normalized)
}

pub(super) fn validate_absolute_http_url(value: &str, field: &str) -> AppResult<()> {
    let parsed = Url::parse(value)
        .map_err(|err| AppError::BadRequest(format!("{field} is invalid: {err}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(AppError::BadRequest(format!(
            "{field} must be an absolute http(s) URL"
        )));
    }
    if parsed.fragment().is_some() {
        return Err(AppError::BadRequest(format!(
            "{field} cannot contain a fragment"
        )));
    }
    Ok(())
}

pub(super) fn normalize_client_logo_uri(value: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    if value.len() > 2048 {
        return Err(AppError::BadRequest(
            "logo_uri must not exceed 2048 characters".to_string(),
        ));
    }
    validate_absolute_http_url(value, "logo_uri")?;
    let parsed = Url::parse(value)
        .map_err(|err| AppError::BadRequest(format!("logo_uri is invalid: {err}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppError::BadRequest(
            "logo_uri cannot include user info".to_string(),
        ));
    }
    Ok(value.to_string())
}

pub(super) fn client_input_to_claim_mappers(
    payload: &ClientInput,
) -> AppResult<Vec<NewClientClaimMapper>> {
    payload
        .claim_mappers
        .iter()
        .enumerate()
        .map(|(index, mapper)| {
            let sort_order = if mapper.sort_order == 0 {
                index as i32
            } else {
                mapper.sort_order
            };
            let record = ClientClaimMapperRecord {
                id: String::new(),
                client_db_id: String::new(),
                claim_name: mapper.claim_name.trim().to_string(),
                source: mapper.source.trim().to_string(),
                source_value: mapper.source_value.trim().to_string(),
                value_type: mapper.value_type.trim().to_string(),
                include_in_id_token: i32::from(mapper.include_in_id_token),
                include_in_access_token: i32::from(mapper.include_in_access_token),
                include_in_userinfo: i32::from(mapper.include_in_userinfo),
                is_active: i32::from(mapper.is_active),
                sort_order,
                created_at: 0,
                updated_at: 0,
            };
            claim_mapper::validate_mapper_record(&record)?;
            Ok(NewClientClaimMapper {
                claim_name: record.claim_name,
                source: record.source,
                source_value: record.source_value,
                value_type: record.value_type,
                include_in_id_token: mapper.include_in_id_token,
                include_in_access_token: mapper.include_in_access_token,
                include_in_userinfo: mapper.include_in_userinfo,
                is_active: mapper.is_active,
                sort_order,
            })
        })
        .collect()
}

pub(super) fn client_input_to_new(
    payload: ClientInput,
    existing_hash: Option<String>,
    organization_id: Option<String>,
    existing_audience: Option<String>,
) -> AppResult<NewClient> {
    let secret = payload.client_secret.unwrap_or_default();
    let token_auth = payload.token_endpoint_auth_method.as_str();
    let can_reuse_secret =
        client_assertion::stored_secret_supports_method(token_auth, existing_hash.as_deref());
    let client_secret_hash = match token_auth {
        "none" | client_assertion::PRIVATE_KEY_JWT => None,
        _ if !secret.is_empty() => client_assertion::store_client_secret(token_auth, &secret)?,
        _ if can_reuse_secret => existing_hash,
        _ => {
            return Err(AppError::BadRequest(
                "client_secret is required for secret-based client authentication".to_string(),
            ));
        }
    };
    let jwks_uri = client_assertion::validate_jwks_uri(&payload.jwks_uri)?;
    let jwks = client_assertion::normalize_jwks_json(&payload.jwks)?;
    let logo_uri = normalize_client_logo_uri(&payload.logo_uri)?;
    let service_account_permissions =
        service_accounts::normalize_permissions(payload.service_account_permissions)?;
    let backchannel_logout_uri = backchannel_logout::validate_backchannel_logout_config(
        &payload.backchannel_logout_uri,
        payload.backchannel_logout_session_required,
    )?;
    let redirect_uris = normalize_redirect_uri_list(&payload.redirect_uris, "redirect_uri")?;
    let post_logout_redirect_uris = normalize_redirect_uri_list(
        &payload.post_logout_redirect_uris,
        "post_logout_redirect_uri",
    )?;
    let frontchannel_logout_uri = frontchannel_logout::validate_frontchannel_logout_config(
        &payload.frontchannel_logout_uri,
        payload.frontchannel_logout_session_required,
        &redirect_uris,
    )?;
    Ok(NewClient {
        client_id: payload.client_id,
        client_secret_hash,
        client_name: payload.client_name,
        logo_uri,
        organization_id,
        redirect_uris,
        post_logout_redirect_uris,
        scopes: payload.scopes,
        audience: payload
            .audience
            .or(existing_audience)
            .unwrap_or_default()
            .trim()
            .to_string(),
        grant_types: payload.grant_types,
        response_types: payload.response_types,
        token_endpoint_auth_method: payload.token_endpoint_auth_method,
        require_pkce: payload.require_pkce,
        require_mfa: payload.require_mfa,
        require_pushed_authorization_requests: payload.require_pushed_authorization_requests,
        require_s256_pkce: payload.require_s256_pkce,
        require_confidential_client: payload.require_confidential_client,
        require_dpop: payload.require_dpop,
        require_account_selection: payload.require_account_selection,
        trust_email_verified: payload.trust_email_verified,
        authorization_details_types: crate::authorization_details::normalize_public_types(
            payload.authorization_details_types,
        )?,
        subject_type: payload.subject_type,
        sector_identifier_uri: payload.sector_identifier_uri,
        jwks_uri,
        jwks,
        backchannel_logout_uri,
        backchannel_logout_session_required: payload.backchannel_logout_session_required,
        frontchannel_logout_uri,
        frontchannel_logout_session_required: payload.frontchannel_logout_session_required,
        service_account_enabled: payload.service_account_enabled,
        service_account_permissions,
        is_active: payload.is_active,
    })
}
