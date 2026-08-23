//! Application-centric identity and authorization boundaries.
//!
//! These types are intentionally protocol-neutral.  A protocol client selects
//! an application and an authorization profile, while the authenticated user
//! context may be reused only inside the application's authentication domain.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthDomain {
    pub id: String,
    pub application_id: String,
    pub assurance_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationAuthContext {
    pub id: String,
    pub auth_domain_id: String,
    pub user_id: String,
    pub acr: String,
    pub amr: Vec<String>,
    pub authenticated_at: i64,
    pub expires_at: i64,
}

impl ApplicationAuthContext {
    pub fn can_satisfy(&self, required_acr: Option<&str>, now: i64) -> bool {
        self.expires_at >= now && required_acr.is_none_or(|required| required == self.acr)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientBinding {
    pub application_id: String,
    pub client_db_id: String,
    pub protocol: String,
    pub authorization_profile_id: String,
    pub auth_domain_id: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRequestContext {
    pub application_id: String,
    pub client_db_id: String,
    pub auth_domain_id: String,
    pub authorization_profile_id: String,
    pub auth_context_id: Option<String>,
}

impl ClientBinding {
    pub fn request_context(&self, auth_context_id: Option<String>) -> Option<ClientRequestContext> {
        if !self.is_active {
            return None;
        }
        Some(ClientRequestContext {
            application_id: self.application_id.clone(),
            client_db_id: self.client_db_id.clone(),
            auth_domain_id: self.auth_domain_id.clone(),
            authorization_profile_id: self.authorization_profile_id.clone(),
            auth_context_id,
        })
    }
}

pub fn may_reuse_auth_context(
    context: &ApplicationAuthContext,
    binding: &ClientBinding,
    required_acr: Option<&str>,
    now: i64,
) -> bool {
    binding.is_active
        && context.auth_domain_id == binding.auth_domain_id
        && context.can_satisfy(required_acr, now)
}

pub fn transaction_is_bound_to_client(
    request: &ClientRequestContext,
    application_id: &str,
    client_db_id: &str,
    authorization_profile_id: &str,
) -> bool {
    request.application_id == application_id
        && request.client_db_id == client_db_id
        && request.authorization_profile_id == authorization_profile_id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(domain: &str, acr: &str) -> ApplicationAuthContext {
        ApplicationAuthContext {
            id: "ctx".into(),
            auth_domain_id: domain.into(),
            user_id: "user".into(),
            acr: acr.into(),
            amr: vec!["pwd".into()],
            authenticated_at: 10,
            expires_at: 100,
        }
    }

    fn binding(domain: &str, profile: &str) -> ClientBinding {
        ClientBinding {
            application_id: "app".into(),
            client_db_id: "client".into(),
            protocol: "oidc".into(),
            authorization_profile_id: profile.into(),
            auth_domain_id: domain.into(),
            is_active: true,
        }
    }

    #[test]
    fn reuses_context_inside_same_auth_domain() {
        assert!(may_reuse_auth_context(
            &context("domain", "loa1"),
            &binding("domain", "p1"),
            Some("loa1"),
            50
        ));
    }

    #[test]
    fn does_not_reuse_context_across_auth_domains() {
        assert!(!may_reuse_auth_context(
            &context("domain-a", "loa1"),
            &binding("domain-b", "p1"),
            None,
            50
        ));
    }

    #[test]
    fn step_up_is_required_for_stronger_acr() {
        assert!(!may_reuse_auth_context(
            &context("domain", "loa1"),
            &binding("domain", "p1"),
            Some("loa2"),
            50
        ));
    }

    #[test]
    fn transaction_keeps_client_and_profile_binding() {
        let request = binding("domain", "p1")
            .request_context(Some("ctx".into()))
            .unwrap();
        assert!(transaction_is_bound_to_client(
            &request, "app", "client", "p1"
        ));
        assert!(!transaction_is_bound_to_client(
            &request,
            "app",
            "other-client",
            "p1"
        ));
        assert!(!transaction_is_bound_to_client(
            &request, "app", "client", "p2"
        ));
    }
}
