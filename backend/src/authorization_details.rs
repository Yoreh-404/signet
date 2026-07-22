use crate::{
    db::ClientRecord,
    error::{AppError, AppResult},
    util,
};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const MAX_DETAILS_BYTES: usize = 8192;
const MAX_DETAILS: usize = 32;
const MAX_OBJECT_FIELDS: usize = 64;
const MAX_ARRAY_ITEMS: usize = 64;
const MAX_STRING_BYTES: usize = 2048;
const MAX_DEPTH: usize = 8;

pub const CLAIM_NAME: &str = "authorization_details";

pub trait AuthorizationDetailsTypePolicy {
    fn allows_type(&self, detail_type: &str) -> bool;
}

#[derive(Debug, Clone)]
pub struct AllowedAuthorizationDetailsTypes {
    types: BTreeSet<String>,
}

impl AllowedAuthorizationDetailsTypes {
    pub fn new(types: Vec<String>) -> AppResult<Self> {
        Ok(Self {
            types: normalize_authorization_details_types(types)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
}

impl AuthorizationDetailsTypePolicy for AllowedAuthorizationDetailsTypes {
    fn allows_type(&self, detail_type: &str) -> bool {
        self.types.contains(detail_type)
    }
}

pub fn normalize_authorization_details_types(values: Vec<String>) -> AppResult<BTreeSet<String>> {
    let mut normalized = BTreeSet::new();
    for value in values {
        let value = normalize_type_name(&value).ok_or_else(|| {
            AppError::BadRequest(
                "authorization_details_types must contain non-empty visible ASCII tokens"
                    .to_string(),
            )
        })?;
        normalized.insert(value);
    }
    Ok(normalized)
}

pub fn normalize_authorization_details_for_client(
    client: &ClientRecord,
    raw: Option<&str>,
) -> AppResult<Option<String>> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let policy = AllowedAuthorizationDetailsTypes::new(client.authorization_details_types()?)?;
    normalize_authorization_details(raw, &policy)
}

pub fn normalize_authorization_details(
    raw: &str,
    policy: &impl AuthorizationDetailsTypePolicy,
) -> AppResult<Option<String>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    if raw.len() > MAX_DETAILS_BYTES {
        return Err(AppError::Oidc(
            "authorization_details is too large".to_string(),
        ));
    }
    let value: Value = serde_json::from_str(raw)
        .map_err(|err| AppError::Oidc(format!("authorization_details is invalid JSON: {err}")))?;
    validate_authorization_details_value(&value, policy)?;
    Ok(Some(serde_json::to_string(&value).map_err(|err| {
        AppError::Internal(format!("failed to encode authorization_details: {err}"))
    })?))
}

pub fn merge_authorization_details(
    issued: Option<String>,
    requested: Option<String>,
    client: &ClientRecord,
) -> AppResult<Option<String>> {
    let requested = normalize_authorization_details_for_client(client, requested.as_deref())?;
    match (issued, requested) {
        (Some(issued), Some(requested)) if issued != requested => Err(AppError::Oidc(
            "authorization_details does not match the issued authorization".to_string(),
        )),
        (Some(issued), _) => Ok(Some(issued)),
        (None, Some(_)) => Err(AppError::Oidc(
            "authorization_details cannot be added at the token endpoint".to_string(),
        )),
        (None, None) => Ok(None),
    }
}

pub fn authorization_details_json(canonical: Option<&str>) -> AppResult<Option<Value>> {
    canonical
        .map(|value| {
            serde_json::from_str::<Value>(value).map_err(|err| {
                AppError::Internal(format!("stored authorization_details is invalid: {err}"))
            })
        })
        .transpose()
}

pub fn insert_claim(
    claims: &mut Map<String, Value>,
    authorization_details: Option<&str>,
) -> AppResult<()> {
    if let Some(value) = authorization_details_json(authorization_details)? {
        claims.insert(CLAIM_NAME.to_string(), value);
    }
    Ok(())
}

fn validate_authorization_details_value(
    value: &Value,
    policy: &impl AuthorizationDetailsTypePolicy,
) -> AppResult<()> {
    let details = value
        .as_array()
        .ok_or_else(|| AppError::Oidc("authorization_details must be a JSON array".to_string()))?;
    if details.is_empty() {
        return Err(AppError::Oidc(
            "authorization_details must not be empty".to_string(),
        ));
    }
    if details.len() > MAX_DETAILS {
        return Err(AppError::Oidc(
            "authorization_details contains too many entries".to_string(),
        ));
    }
    for detail in details {
        let object = detail.as_object().ok_or_else(|| {
            AppError::Oidc("each authorization_details entry must be an object".to_string())
        })?;
        let detail_type = object
            .get("type")
            .and_then(Value::as_str)
            .and_then(normalize_type_name)
            .ok_or_else(|| {
                AppError::Oidc("each authorization_details entry requires a valid type".to_string())
            })?;
        if !policy.allows_type(&detail_type) {
            return Err(AppError::Oidc(format!(
                "authorization_details type is not allowed for this client: {detail_type}"
            )));
        }
        validate_json_limits(detail, 0)?;
    }
    Ok(())
}

fn validate_json_limits(value: &Value, depth: usize) -> AppResult<()> {
    if depth > MAX_DEPTH {
        return Err(AppError::Oidc(
            "authorization_details nesting is too deep".to_string(),
        ));
    }
    match value {
        Value::Array(values) => {
            if values.len() > MAX_ARRAY_ITEMS {
                return Err(AppError::Oidc(
                    "authorization_details array contains too many items".to_string(),
                ));
            }
            for value in values {
                validate_json_limits(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            if values.len() > MAX_OBJECT_FIELDS {
                return Err(AppError::Oidc(
                    "authorization_details object contains too many fields".to_string(),
                ));
            }
            for value in values.values() {
                validate_json_limits(value, depth + 1)?;
            }
        }
        Value::String(value) if value.len() > MAX_STRING_BYTES => {
            return Err(AppError::Oidc(
                "authorization_details string value is too large".to_string(),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn normalize_type_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_whitespace)
        || !value.chars().all(|ch| ch.is_ascii_graphic())
    {
        None
    } else {
        Some(value.to_string())
    }
}

pub fn supported_types_from_clients(clients: &[ClientRecord]) -> AppResult<Vec<String>> {
    let mut types = BTreeSet::new();
    for client in clients {
        types.extend(client.authorization_details_types()?);
    }
    Ok(types.into_iter().collect())
}

pub fn public_types(values: Vec<String>) -> AppResult<Vec<String>> {
    Ok(normalize_authorization_details_types(values)?
        .into_iter()
        .collect())
}

pub fn detail_count(canonical: Option<&str>) -> AppResult<usize> {
    Ok(authorization_details_json(canonical)?
        .and_then(|value| value.as_array().map(Vec::len))
        .unwrap_or(0))
}

pub fn details_for_audit(canonical: Option<&str>) -> AppResult<Value> {
    authorization_details_json(canonical).map(|value| value.unwrap_or(Value::Null))
}

pub fn details_types_for_audit(canonical: Option<&str>) -> AppResult<Vec<String>> {
    let Some(value) = authorization_details_json(canonical)? else {
        return Ok(Vec::new());
    };
    Ok(value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|detail| detail.get("type").and_then(Value::as_str))
        .filter_map(normalize_type_name)
        .collect())
}

pub fn normalize_public_types(values: Vec<String>) -> AppResult<Vec<String>> {
    public_types(values)
}

pub fn details_hash(canonical: Option<&str>) -> Option<String> {
    canonical.map(util::token_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Policy(&'static [&'static str]);

    impl AuthorizationDetailsTypePolicy for Policy {
        fn allows_type(&self, detail_type: &str) -> bool {
            self.0.contains(&detail_type)
        }
    }

    #[test]
    fn normalizes_valid_authorization_details() {
        let raw = r#"[{"type":"resource_access","actions":["read"],"locations":["https://api.example/"]}]"#;
        let value = normalize_authorization_details(raw, &Policy(&["resource_access"]))
            .unwrap()
            .unwrap();
        assert!(value.contains("resource_access"));
    }

    #[test]
    fn rejects_unknown_or_missing_types() {
        assert!(
            normalize_authorization_details(r#"[{"type":"unknown"}]"#, &Policy(&["known"]))
                .is_err()
        );
        assert!(
            normalize_authorization_details(r#"[{"actions":["read"]}]"#, &Policy(&["known"]))
                .is_err()
        );
    }

    #[test]
    fn merge_prevents_token_endpoint_escalation() {
        let client = client(vec!["resource_access".to_string()]);
        assert!(
            merge_authorization_details(
                None,
                Some(r#"[{"type":"resource_access"}]"#.to_string()),
                &client,
            )
            .is_err()
        );
    }

    fn client(types: Vec<String>) -> ClientRecord {
        ClientRecord {
            id: "client-db-id".to_string(),
            client_id: "demo-web".to_string(),
            client_secret_hash: None,
            client_name: "Demo".to_string(),
            logo_uri: String::new(),
            organization_id: None,
            redirect_uris: "[]".to_string(),
            post_logout_redirect_uris: "[]".to_string(),
            scopes: "[]".to_string(),
            grant_types: "[]".to_string(),
            response_types: "[]".to_string(),
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: 1,
            require_mfa: 0,
            require_pushed_authorization_requests: 0,
            require_s256_pkce: 0,
            require_confidential_client: 0,
            require_dpop: 0,
            require_account_selection: 0,
            trust_email_verified: 0,
            authorization_details_types: serde_json::to_string(&types).unwrap(),
            subject_type: "public".to_string(),
            sector_identifier_uri: String::new(),
            jwks_uri: String::new(),
            jwks: String::new(),
            backchannel_logout_uri: String::new(),
            backchannel_logout_session_required: 0,
            frontchannel_logout_uri: String::new(),
            frontchannel_logout_session_required: 0,
            service_account_enabled: 0,
            service_account_permissions: "[]".to_string(),
            is_active: 1,
            created_at: 1,
            updated_at: 1,
        }
    }
}
