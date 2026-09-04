use super::{
    FORMAT, NormalizedProfile, NormalizedRole,
    normalization::{
        normalize_authorization_bindings, normalize_contract_profiles, normalize_contract_protocols,
    },
};
use serde_json::json;
use std::collections::BTreeMap;

fn default_profiles() -> BTreeMap<String, NormalizedProfile> {
    BTreeMap::from([(
        "default".to_string(),
        NormalizedProfile {
            permissions: Vec::new(),
            roles: vec![NormalizedRole {
                key: "member".to_string(),
                name: "member".to_string(),
                description: None,
                permissions: vec!["app:read".to_string()],
                is_default: true,
            }],
        },
    )])
}

#[test]
fn repeated_client_protocol_kinds_share_one_normalized_module() {
    let client_protocols = BTreeMap::from([
        ("web-a".to_string(), "oidc".to_string()),
        ("web-b".to_string(), "oidc".to_string()),
    ]);

    let protocols =
        normalize_contract_protocols(&[], &client_protocols, "https://axon.example").unwrap();

    assert_eq!(
        protocols["oauth2_oidc"]["client_ids"],
        json!(["web-a", "web-b"])
    );
    assert!(protocols.get("oidc").is_none());
}

#[test]
fn unknown_default_role_is_rejected() {
    let error =
        normalize_authorization_bindings(&json!({"default_role": "admin"}), &default_profiles())
            .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("undeclared default-profile role")
    );
}

#[test]
fn unknown_group_role_is_rejected() {
    let error = normalize_authorization_bindings(
        &json!({
            "group_mappings": [{"group": "engineering", "role": "admin"}]
        }),
        &default_profiles(),
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("undeclared default-profile role")
    );
}

#[test]
fn unknown_organization_role_is_rejected() {
    let error = normalize_authorization_bindings(
        &json!({
            "organization_role_mappings": {"organization-admin": "admin"}
        }),
        &default_profiles(),
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("undeclared default-profile role")
    );
}

#[test]
fn duplicate_default_roles_are_rejected_by_profile_normalization() {
    let contract = serde_json::from_value::<super::ApplicationContract>(json!({
        "format": FORMAT,
        "application_id": "axon",
        "revision": 1,
        "version": "v1",
        "iss": "https://axon.example",
        "aud": ["https://sso.example"],
        "iat": 100,
        "exp": 300,
        "modules": {
            "roles": [
                {
                    "role_id": "member",
                    "permissions": ["app:read"],
                    "default_role": true
                },
                {
                    "role_id": "admin",
                    "permissions": ["app:write"],
                    "default_role": true
                }
            ]
        }
    }))
    .unwrap();

    let error = normalize_contract_profiles(&contract).unwrap_err();

    assert!(error.to_string().contains("more than one default role"));
}
