use super::{
    FORMAT, NormalizedProfile, NormalizedRole,
    normalization::{
        normalize_authorization_bindings, normalize_contract_profiles, normalize_contract_protocols,
    },
};
use crate::application_contract::{ClientContract, ConnectionContract, IntegrationProfile};
use serde_json::{Map, json};
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
        normalize_contract_protocols(&[], &[], &client_protocols, "https://axon.example").unwrap();

    assert_eq!(
        protocols["oauth2_oidc"]["client_ids"],
        json!(["web-a", "web-b"])
    );
    assert!(protocols.get("oidc").is_none());
}

#[test]
fn legacy_proxy_jwt_client_materializes_runtime_fields_from_v3_contract() {
    let client = ClientContract {
        client_id: "legacy-jwt".to_string(),
        protocol: "jwt".to_string(),
        display_name: "Legacy JWT".to_string(),
        profiles: vec![IntegrationProfile::LegacyProxy],
        redirect_uris: vec!["https://legacy.example.test/auth/callback".to_string()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_string(), "profile".to_string()],
        audiences: vec!["https://legacy.example.test".to_string()],
        grant_types: vec!["authorization_code".to_string()],
        response_types: vec!["code".to_string()],
        token_endpoint_auth_method: "none".to_string(),
        credential_ref: None,
        jwks_uri: None,
        jwks: None,
        require_pkce: true,
        require_s256_pkce: true,
        require_mfa: false,
        require_dpop: false,
        active: true,
        metadata: Map::new(),
    };
    let client_protocols = BTreeMap::from([("legacy-jwt".to_string(), "jwt".to_string())]);
    let connection = ConnectionContract {
        connection_id: "legacy-jwt-settings".to_string(),
        kind: "jwt".to_string(),
        required: false,
        settings: Map::from_iter([
            ("client_id".to_string(), json!("must-not-win")),
            ("client_ids".to_string(), json!(["must-not-win"])),
            (
                "redirect_uris".to_string(),
                json!(["https://wrong.example.test/callback"]),
            ),
            ("audience".to_string(), json!("https://wrong.example.test")),
            ("client_type".to_string(), json!("confidential")),
            ("enabled".to_string(), json!(false)),
            ("token_ttl_seconds".to_string(), json!(120)),
        ]),
    };

    let protocols = normalize_contract_protocols(
        &[connection],
        std::slice::from_ref(&client),
        &client_protocols,
        "https://legacy.example.test",
    )
    .unwrap();

    assert_eq!(protocols["jwt"]["enabled"], json!(true));
    assert_eq!(protocols["jwt"]["client_ids"], json!(["legacy-jwt"]));
    assert_eq!(protocols["jwt"]["client_id"], json!("legacy-jwt"));
    assert_eq!(protocols["jwt"]["client_type"], json!("public"));
    assert_eq!(
        protocols["jwt"]["redirect_uris"],
        json!(["https://legacy.example.test/auth/callback"])
    );
    assert_eq!(
        protocols["jwt"]["audience"],
        json!("https://legacy.example.test")
    );
    assert_eq!(protocols["jwt"]["token_ttl_seconds"], json!(120));
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
