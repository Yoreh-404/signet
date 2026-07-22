use crate::{
    db::SessionRecord,
    error::{AppError, AppResult},
    mfa_policy,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const ACR_PASSWORD: &str = "urn:gpt-sso:acr:loa:1";
pub const ACR_MFA: &str = "urn:gpt-sso:acr:loa:2";
pub const SUPPORTED_ACR_VALUES: &[&str] = &[ACR_PASSWORD, ACR_MFA];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestedAssurance {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acr_values: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub essential_acr_values: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub essential_amr_values: Vec<String>,
}

impl RequestedAssurance {
    pub fn new(
        acr_values: Option<&str>,
        essential_acr_values: Vec<String>,
        essential_amr_values: Vec<String>,
    ) -> AppResult<Self> {
        Ok(Self {
            acr_values: parse_acr_values(acr_values)?,
            essential_acr_values: normalize_acr_values(essential_acr_values)?,
            essential_amr_values: normalize_amr_values(essential_amr_values),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.acr_values.is_empty()
            && self.essential_acr_values.is_empty()
            && self.essential_amr_values.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthenticationAssurance {
    pub acr: String,
    pub amr: Vec<String>,
}

pub trait SessionAuthenticationAssurance {
    fn authentication_assurance(&self) -> AuthenticationAssurance;
}

impl SessionAuthenticationAssurance for SessionRecord {
    fn authentication_assurance(&self) -> AuthenticationAssurance {
        let amr = amr_values(self.login_method.as_deref());
        let acr = if mfa_policy::session_satisfies_mfa(self) {
            ACR_MFA
        } else {
            ACR_PASSWORD
        };
        AuthenticationAssurance {
            acr: acr.to_string(),
            amr,
        }
    }
}

pub trait AssurancePolicy {
    fn requires_mfa(&self, request: &RequestedAssurance) -> bool;
    fn select_acr(
        &self,
        session: &AuthenticationAssurance,
        request: &RequestedAssurance,
    ) -> AppResult<String>;
    fn assert_amr(
        &self,
        session: &AuthenticationAssurance,
        request: &RequestedAssurance,
    ) -> AppResult<()>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultAssurancePolicy;

impl AssurancePolicy for DefaultAssurancePolicy {
    fn requires_mfa(&self, request: &RequestedAssurance) -> bool {
        request
            .essential_acr_values
            .iter()
            .all(|value| value == ACR_MFA)
            && !request.essential_acr_values.is_empty()
            || request.acr_values.iter().all(|value| value == ACR_MFA)
                && !request.acr_values.is_empty()
            || request
                .essential_amr_values
                .iter()
                .any(|value| value == "mfa" || value == "otp" || value == "hwk")
    }

    fn select_acr(
        &self,
        session: &AuthenticationAssurance,
        request: &RequestedAssurance,
    ) -> AppResult<String> {
        if !request.essential_acr_values.is_empty() {
            if request
                .essential_acr_values
                .iter()
                .any(|value| session_satisfies_acr(session, value))
            {
                return preferred_satisfied_acr(session, &request.essential_acr_values);
            }
            return Err(AppError::Oidc(
                "requested essential acr cannot be satisfied".to_string(),
            ));
        }
        if !request.acr_values.is_empty() {
            return preferred_satisfied_acr(session, &request.acr_values);
        }
        Ok(session.acr.clone())
    }

    fn assert_amr(
        &self,
        session: &AuthenticationAssurance,
        request: &RequestedAssurance,
    ) -> AppResult<()> {
        if request.essential_amr_values.is_empty() {
            return Ok(());
        }
        if request
            .essential_amr_values
            .iter()
            .any(|value| session.amr.iter().any(|amr| amr == value))
        {
            Ok(())
        } else {
            Err(AppError::Oidc(
                "requested essential amr cannot be satisfied".to_string(),
            ))
        }
    }
}

pub fn insert_id_token_assurance_claims(
    claims: &mut Map<String, Value>,
    assurance: &AuthenticationAssurance,
    request: &RequestedAssurance,
) -> AppResult<()> {
    let policy = DefaultAssurancePolicy;
    let acr = policy.select_acr(assurance, request)?;
    policy.assert_amr(assurance, request)?;
    claims.insert("acr".to_string(), Value::String(acr));
    claims.insert(
        "amr".to_string(),
        Value::Array(
            assurance
                .amr
                .iter()
                .cloned()
                .map(Value::String)
                .collect::<Vec<_>>(),
        ),
    );
    Ok(())
}

pub fn parse_acr_values(value: Option<&str>) -> AppResult<Vec<String>> {
    let values = value
        .unwrap_or_default()
        .split_whitespace()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    normalize_acr_values(values)
}

fn normalize_acr_values(values: Vec<String>) -> AppResult<Vec<String>> {
    let mut normalized = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if !SUPPORTED_ACR_VALUES
            .iter()
            .any(|supported| supported == &value)
        {
            return Err(AppError::Oidc(format!("unsupported acr value: {value}")));
        }
        if !normalized.iter().any(|existing| existing == value) {
            normalized.push(value.to_string());
        }
    }
    Ok(normalized)
}

fn normalize_amr_values(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .fold(Vec::new(), |mut acc, value| {
            if !acc.iter().any(|existing| existing == &value) {
                acc.push(value);
            }
            acc
        })
}

fn preferred_satisfied_acr(
    session: &AuthenticationAssurance,
    requested: &[String],
) -> AppResult<String> {
    requested
        .iter()
        .find(|value| session_satisfies_acr(session, value))
        .cloned()
        .ok_or_else(|| AppError::Oidc("requested acr cannot be satisfied".to_string()))
}

fn session_satisfies_acr(session: &AuthenticationAssurance, requested: &str) -> bool {
    session.acr == requested || session.acr == ACR_MFA && requested == ACR_PASSWORD
}

fn amr_values(login_method: Option<&str>) -> Vec<String> {
    match login_method.unwrap_or_default() {
        "passkey" | "oidc_passkey" => values(&["hwk", "mfa"]),
        "totp" | "ldap_totp" | "oidc_totp" => values(&["otp", "mfa"]),
        "recovery_code" | "ldap_recovery_code" | "oidc_recovery_code" => {
            values(&["mfa", "recovery"])
        }
        "oidc_ldap" | "ldap" => values(&["pwd", "federated"]),
        "external_oidc" | "oidc_external" => values(&["federated"]),
        "authorization_code" => values(&["temporary"]),
        "trial_enrollment" => values(&["trial_enrollment"]),
        "" => values(&["pwd"]),
        _ => values(&["pwd"]),
    }
}

fn values(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(method: Option<&str>) -> SessionRecord {
        SessionRecord {
            id: "session-id".to_string(),
            user_id: "user-id".to_string(),
            csrf_token: "csrf".to_string(),
            ip_address: None,
            user_agent: None,
            login_method: method.map(str::to_string),
            expires_at: 100,
            created_at: 1,
        }
    }

    #[test]
    fn acr_values_are_validated_and_deduplicated() {
        assert_eq!(
            parse_acr_values(Some(&format!("{ACR_MFA} {ACR_PASSWORD} {ACR_MFA}"))).unwrap(),
            vec![ACR_MFA.to_string(), ACR_PASSWORD.to_string()]
        );
        assert!(parse_acr_values(Some("urn:unknown")).is_err());
    }

    #[test]
    fn session_assurance_maps_mfa_methods() {
        let assurance = session(Some("oidc_totp")).authentication_assurance();
        assert_eq!(assurance.acr, ACR_MFA);
        assert_eq!(assurance.amr, vec!["otp".to_string(), "mfa".to_string()]);
    }

    #[test]
    fn assurance_policy_requires_mfa_for_mfa_only_acr() {
        let request = RequestedAssurance::new(Some(ACR_MFA), Vec::new(), Vec::new()).unwrap();
        assert!(DefaultAssurancePolicy.requires_mfa(&request));

        let request = RequestedAssurance::new(
            Some(&format!("{ACR_MFA} {ACR_PASSWORD}")),
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        assert!(!DefaultAssurancePolicy.requires_mfa(&request));
    }

    #[test]
    fn mfa_session_can_satisfy_lower_acr() {
        let session = session(Some("passkey")).authentication_assurance();
        let request = RequestedAssurance::new(Some(ACR_PASSWORD), Vec::new(), Vec::new()).unwrap();
        assert_eq!(
            DefaultAssurancePolicy
                .select_acr(&session, &request)
                .unwrap(),
            ACR_PASSWORD
        );
    }
}
