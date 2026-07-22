use crate::{
    assurance,
    db::{ClientRecord, UserRecord},
    error::{AppError, AppResult},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const SUPPORTED_CLAIMS: &[&str] = &[
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "acr",
    "amr",
    "email",
    "email_verified",
    "name",
    "preferred_username",
    "sid",
];

pub trait EmailVerifiedClaimPolicy {
    fn email_verified(&self, user: &UserRecord, client: &ClientRecord) -> bool;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultEmailVerifiedClaimPolicy;

impl EmailVerifiedClaimPolicy for DefaultEmailVerifiedClaimPolicy {
    fn email_verified(&self, user: &UserRecord, client: &ClientRecord) -> bool {
        user.email_verified_at.is_some() || client.trust_email_verified == 1
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestedClaims {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub id_token: BTreeMap<String, ClaimRequest>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub userinfo: BTreeMap<String, ClaimRequest>,
}

impl RequestedClaims {
    pub fn from_authorization_parameter(value: Option<&str>) -> AppResult<Option<Self>> {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        let raw = serde_json::from_str::<RawRequestedClaims>(value)
            .map_err(|err| AppError::Oidc(format!("invalid claims parameter: {err}")))?;
        Self::from_raw(raw).map(Some)
    }

    pub fn from_request_object_value(value: Option<Value>) -> AppResult<Option<Self>> {
        let Some(value) = value else {
            return Ok(None);
        };
        let raw = serde_json::from_value::<RawRequestedClaims>(value)
            .map_err(|err| AppError::Oidc(format!("invalid request object claims: {err}")))?;
        Self::from_raw(raw).map(Some)
    }

    pub fn to_authorization_parameter(&self) -> AppResult<String> {
        serde_json::to_string(self)
            .map_err(|err| AppError::Internal(format!("failed to encode claims parameter: {err}")))
    }

    pub fn essential_id_token_values(&self, claim: &str) -> Vec<String> {
        self.id_token
            .get(claim)
            .filter(|request| request.essential)
            .map(ClaimRequest::string_values)
            .unwrap_or_default()
    }

    pub fn requested_assurance(
        &self,
        acr_values: Option<&str>,
    ) -> AppResult<assurance::RequestedAssurance> {
        assurance::RequestedAssurance::new(
            acr_values,
            self.essential_id_token_values("acr"),
            self.essential_id_token_values("amr"),
        )
    }

    fn from_raw(raw: RawRequestedClaims) -> AppResult<Self> {
        if raw.id_token.is_none() && raw.userinfo.is_none() {
            return Err(AppError::Oidc(
                "claims parameter must contain id_token or userinfo".to_string(),
            ));
        }
        let id_token = normalize_claim_map(raw.id_token, "id_token")?;
        let userinfo = normalize_claim_map(raw.userinfo, "userinfo")?;
        Ok(Self { id_token, userinfo })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimRequest {
    #[serde(default, skip_serializing_if = "is_false")]
    pub essential: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<Value>>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl ClaimRequest {
    fn string_values(&self) -> Vec<String> {
        self.values
            .iter()
            .flatten()
            .chain(self.value.iter())
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    }
}

#[derive(Debug, Deserialize)]
struct RawRequestedClaims {
    id_token: Option<BTreeMap<String, Option<ClaimRequest>>>,
    userinfo: Option<BTreeMap<String, Option<ClaimRequest>>>,
}

fn normalize_claim_map(
    claims: Option<BTreeMap<String, Option<ClaimRequest>>>,
    target: &str,
) -> AppResult<BTreeMap<String, ClaimRequest>> {
    let mut normalized = BTreeMap::new();
    for (name, request) in claims.unwrap_or_default() {
        let name = name.trim().to_string();
        if name.is_empty() {
            return Err(AppError::Oidc(format!(
                "{target} claims parameter contains an empty claim name"
            )));
        }
        let request = request.unwrap_or(ClaimRequest {
            essential: false,
            value: None,
            values: None,
        });
        if request.essential && !SUPPORTED_CLAIMS.iter().any(|claim| claim == &name) {
            return Err(AppError::Oidc(format!(
                "unsupported essential {target} claim: {name}"
            )));
        }
        if name == "acr" {
            assurance::parse_acr_values(Some(&request.string_values().join(" ")))?;
        }
        normalized.insert(name, request);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{ClientRecord, UserRecord};

    #[test]
    fn claims_parameter_accepts_supported_essential_claims() {
        let claims = RequestedClaims::from_authorization_parameter(Some(
            r#"{"id_token":{"acr":{"essential":true,"values":["urn:gpt-sso:acr:loa:2"]},"email":null},"userinfo":{"name":null}}"#,
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            claims.essential_id_token_values("acr"),
            vec![assurance::ACR_MFA.to_string()]
        );
        assert!(claims.id_token.contains_key("email"));
        assert!(claims.userinfo.contains_key("name"));
    }

    #[test]
    fn claims_parameter_rejects_unsupported_essential_claims() {
        assert!(
            RequestedClaims::from_authorization_parameter(Some(
                r#"{"id_token":{"unknown":{"essential":true}}}"#
            ))
            .is_err()
        );
    }

    #[test]
    fn nonessential_unknown_claims_are_preserved_for_future_mappers() {
        let claims = RequestedClaims::from_authorization_parameter(Some(
            r#"{"userinfo":{"tenant_color":null}}"#,
        ))
        .unwrap()
        .unwrap();
        assert!(claims.userinfo.contains_key("tenant_color"));
    }

    #[test]
    fn request_object_claims_use_json_object_form() {
        let value = serde_json::json!({
            "id_token": {
                "amr": { "essential": true, "values": ["otp"] }
            }
        });
        let claims = RequestedClaims::from_request_object_value(Some(value))
            .unwrap()
            .unwrap();
        assert_eq!(claims.essential_id_token_values("amr"), vec!["otp"]);
    }

    #[test]
    fn email_verified_policy_can_trust_selected_clients() {
        let mut user = user(None);
        let mut client = client(0);
        assert!(!DefaultEmailVerifiedClaimPolicy.email_verified(&user, &client));

        client.trust_email_verified = 1;
        assert!(DefaultEmailVerifiedClaimPolicy.email_verified(&user, &client));

        user.email_verified_at = Some(1);
        client.trust_email_verified = 0;
        assert!(DefaultEmailVerifiedClaimPolicy.email_verified(&user, &client));
    }

    fn user(email_verified_at: Option<i64>) -> UserRecord {
        UserRecord {
            id: "user-id".to_string(),
            email: "user@example.com".to_string(),
            username: "user".to_string(),
            display_name: None,
            phone: None,
            password_hash: "hash".to_string(),
            email_verified_at,
            phone_verified_at: None,
            is_admin: 0,
            is_active: 1,
            archived_at: None,
            registration_source: "local".to_string(),
            last_login_at: None,
            last_login_ip: None,
            last_oidc_client_id: None,
            last_login_method: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn client(trust_email_verified: i32) -> ClientRecord {
        ClientRecord {
            id: "client-db-id".to_string(),
            client_id: "client".to_string(),
            client_secret_hash: None,
            client_name: "Client".to_string(),
            logo_uri: String::new(),
            organization_id: None,
            redirect_uris: "[]".to_string(),
            post_logout_redirect_uris: "[]".to_string(),
            scopes: "[]".to_string(),
            grant_types: "[]".to_string(),
            response_types: "[]".to_string(),
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: 0,
            require_mfa: 0,
            require_pushed_authorization_requests: 0,
            require_s256_pkce: 0,
            require_confidential_client: 0,
            require_dpop: 0,
            require_account_selection: 0,
            trust_email_verified,
            authorization_details_types: "[]".to_string(),
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
