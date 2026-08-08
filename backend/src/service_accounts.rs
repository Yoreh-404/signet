use crate::{access::Permission, db::ClientRecord, error::AppResult};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub trait ServiceAccountProfile {
    fn service_account_enabled(&self) -> bool;
    fn service_account_permissions(&self) -> AppResult<Vec<String>>;
    fn service_account_subject(&self) -> String;
    fn service_account_claims(&self) -> AppResult<Map<String, Value>>;
}

impl ServiceAccountProfile for ClientRecord {
    fn service_account_enabled(&self) -> bool {
        self.service_account_enabled == 1
    }

    fn service_account_permissions(&self) -> AppResult<Vec<String>> {
        normalize_permissions(crate::util::from_json::<Vec<String>>(
            &self.service_account_permissions,
        )?)
    }

    fn service_account_subject(&self) -> String {
        format!("service-account:{}", self.client_id)
    }

    fn service_account_claims(&self) -> AppResult<Map<String, Value>> {
        let permissions = if self.service_account_enabled() {
            self.service_account_permissions()?
        } else {
            Vec::new()
        };
        let mut claims = Map::new();
        claims.insert("service_account".to_string(), Value::Bool(true));
        claims.insert(
            "permissions".to_string(),
            Value::Array(permissions.into_iter().map(Value::String).collect()),
        );
        Ok(claims)
    }
}

pub fn normalize_permissions(values: Vec<String>) -> AppResult<Vec<String>> {
    let mut permissions = BTreeSet::new();
    for value in values {
        let permission = value.trim();
        if permission.is_empty() {
            continue;
        }
        permissions.insert(Permission::try_from(permission)?.as_str().to_string());
    }
    Ok(permissions.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_record(enabled: bool, permissions: Vec<&str>) -> ClientRecord {
        ClientRecord {
            id: "client-db-id".to_string(),
            client_id: "reports-worker".to_string(),
            client_secret_hash: None,
            client_name: "Reports worker".to_string(),
            logo_uri: String::new(),
            organization_id: None,
            redirect_uris: "[]".to_string(),
            post_logout_redirect_uris: "[]".to_string(),
            scopes: "[]".to_string(),
            audience: String::new(),
            grant_types: "[\"client_credentials\"]".to_string(),
            response_types: "[]".to_string(),
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            require_pkce: 0,
            require_mfa: 0,
            require_pushed_authorization_requests: 0,
            require_s256_pkce: 0,
            require_confidential_client: 0,
            require_dpop: 0,
            require_account_selection: 0,
            trust_email_verified: 0,
            authorization_details_types: "[]".to_string(),
            subject_type: crate::subject::SUBJECT_TYPE_PUBLIC.to_string(),
            sector_identifier_uri: String::new(),
            jwks_uri: String::new(),
            jwks: String::new(),
            backchannel_logout_uri: String::new(),
            backchannel_logout_session_required: 0,
            frontchannel_logout_uri: String::new(),
            frontchannel_logout_session_required: 0,
            service_account_enabled: i32::from(enabled),
            service_account_permissions: crate::util::to_json(
                &permissions
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
            is_active: 1,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn service_account_permissions_are_normalized_and_validated() {
        assert_eq!(
            normalize_permissions(vec![
                " users.read ".to_string(),
                "clients.manage".to_string(),
                "users.read".to_string(),
            ])
            .unwrap(),
            vec!["clients.manage".to_string(), "users.read".to_string()]
        );
        assert!(normalize_permissions(vec!["missing.permission".to_string()]).is_err());
    }

    #[test]
    fn service_account_profile_builds_machine_identity_claims() {
        let client = client_record(true, vec!["users.read", "clients.manage", "users.read"]);

        assert!(client.service_account_enabled());
        assert_eq!(
            client.service_account_subject(),
            "service-account:reports-worker"
        );
        assert_eq!(
            client.service_account_permissions().unwrap(),
            vec!["clients.manage".to_string(), "users.read".to_string()]
        );

        let claims = client.service_account_claims().unwrap();
        assert_eq!(claims.get("service_account"), Some(&Value::Bool(true)));
        assert_eq!(
            claims.get("permissions"),
            Some(&Value::Array(vec![
                Value::String("clients.manage".to_string()),
                Value::String("users.read".to_string())
            ]))
        );
    }

    #[test]
    fn disabled_service_account_is_not_enabled() {
        let client = client_record(false, vec!["users.read"]);

        assert!(!client.service_account_enabled());
    }
}
