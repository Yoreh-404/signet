use super::{
    MAX_CLIENT_ID_LENGTH, MAX_SCOPE_LENGTH, NormalizedAuthorizationMappings,
    NormalizedGroupMapping, NormalizedOrganizationRoleMapping, NormalizedPermission,
    NormalizedProfile, NormalizedRole,
};
use crate::{
    application_contract::{ApplicationContract, ClientContract, IntegrationProfile},
    db::NewClient,
    error::{AppError, AppResult},
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::pure::{
    normalize_display_text, normalize_permission_key, normalize_string_list, normalize_url_list,
    visible_text,
};

#[derive(Default)]
pub(super) struct PolicyEffects {
    permissions: Vec<String>,
    require_mfa: bool,
    require_dpop: bool,
}

#[derive(Default)]
pub(super) struct PolicyEffectsIndex {
    all_permissions: Vec<String>,
    by_client_id: BTreeMap<String, PolicyEffects>,
}

pub(super) fn index_policy_effects(
    policies: &[crate::application_contract::PolicyContract],
) -> PolicyEffectsIndex {
    let mut index = PolicyEffectsIndex::default();
    for policy in policies {
        index
            .all_permissions
            .extend(policy.permissions.iter().cloned());
        for client_id in &policy.client_ids {
            let effects = index.by_client_id.entry(client_id.clone()).or_default();
            effects
                .permissions
                .extend(policy.permissions.iter().cloned());
            effects.require_mfa |= policy.require_mfa;
            effects.require_dpop |= policy.require_dpop;
        }
    }
    index
}

pub(super) fn normalize_contract_client(
    client: &ClientContract,
    organization_id: &str,
    policy_effects: &PolicyEffectsIndex,
) -> AppResult<NewClient> {
    let client_id = visible_text(&client.client_id, MAX_CLIENT_ID_LENGTH, "client_id")?;
    let client_name = if client.display_name.trim().is_empty() {
        client_id.clone()
    } else {
        normalize_display_text(&client.display_name, 160, "client_name")?
    };
    let auth_method = client.token_endpoint_auth_method.trim();
    if !matches!(auth_method, "none" | "private_key_jwt") {
        return Err(AppError::BadRequest(
            "v3 clients cannot transport shared secrets".to_string(),
        ));
    }
    let jwks = client
        .jwks
        .as_ref()
        .filter(|value| !value.is_null())
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| AppError::BadRequest("client jwks is invalid".to_string()))?
        .unwrap_or_default();
    let audiences = normalize_string_list(&client.audiences, 2048, "audience")?;
    let scopes = normalize_string_list(&client.scopes, MAX_SCOPE_LENGTH, "scope")?;
    let grant_types = normalize_string_list(&client.grant_types, 128, "grant_type")?;
    let response_types = normalize_string_list(&client.response_types, 128, "response_type")?;
    let service_account_enabled = client
        .profiles
        .contains(&IntegrationProfile::MachineIdentity);
    let client_effects = policy_effects.by_client_id.get(&client.client_id);
    let service_account_permissions = client_effects
        .map(|effects| effects.permissions.iter().cloned())
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let client_require_mfa =
        client.require_mfa || client_effects.is_some_and(|effects| effects.require_mfa);
    let client_require_dpop =
        client.require_dpop || client_effects.is_some_and(|effects| effects.require_dpop);
    let logo_uri = client
        .metadata
        .get("logo_uri")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    Ok(NewClient {
        client_id,
        client_secret_hash: None,
        client_name,
        logo_uri,
        organization_id: Some(organization_id.to_string()),
        redirect_uris: normalize_url_list(&client.redirect_uris, "redirect_uri")?,
        post_logout_redirect_uris: normalize_url_list(
            &client.post_logout_redirect_uris,
            "post_logout_redirect_uri",
        )?,
        scopes,
        audience: audiences.first().cloned().unwrap_or_default(),
        grant_types,
        response_types,
        token_endpoint_auth_method: auth_method.to_string(),
        require_pkce: client.require_pkce,
        require_mfa: client_require_mfa,
        require_pushed_authorization_requests: false,
        require_s256_pkce: client.require_s256_pkce,
        require_confidential_client: auth_method != "none",
        require_dpop: client_require_dpop,
        require_account_selection: false,
        trust_email_verified: false,
        authorization_details_types: Vec::new(),
        subject_type: if service_account_enabled {
            "pairwise".to_string()
        } else {
            "public".to_string()
        },
        sector_identifier_uri: String::new(),
        jwks_uri: client.jwks_uri.clone().unwrap_or_default(),
        jwks,
        backchannel_logout_uri: String::new(),
        backchannel_logout_session_required: false,
        frontchannel_logout_uri: String::new(),
        frontchannel_logout_session_required: false,
        service_account_enabled,
        service_account_permissions,
        is_active: client.active,
    })
}

pub(super) fn normalize_client_protocol(value: &str) -> AppResult<String> {
    let protocol = visible_text(value, 64, "client protocol")?.to_ascii_lowercase();
    if !matches!(
        protocol.as_str(),
        "oidc" | "saml" | "cas" | "jwt" | "iap" | "forward_auth"
    ) {
        return Err(AppError::BadRequest(
            "v3 client protocol is unsupported".to_string(),
        ));
    }
    Ok(protocol)
}

#[cfg(test)]
pub(super) fn normalize_contract_profiles(
    contract: &ApplicationContract,
) -> AppResult<BTreeMap<String, NormalizedProfile>> {
    let policy_effects = index_policy_effects(&contract.modules.policies);
    normalize_contract_profiles_with_effects(contract, &policy_effects)
}

pub(super) fn normalize_contract_profiles_with_effects(
    contract: &ApplicationContract,
    policy_effects: &PolicyEffectsIndex,
) -> AppResult<BTreeMap<String, NormalizedProfile>> {
    let all_permission_keys = policy_effects
        .all_permissions
        .iter()
        .cloned()
        .chain(
            contract
                .modules
                .roles
                .iter()
                .flat_map(|role| role.permissions.iter().cloned()),
        )
        .map(|permission| normalize_permission_key(&permission))
        .collect::<AppResult<BTreeSet<_>>>()?;
    let build_profile = |allowed_permissions: &BTreeSet<String>| -> AppResult<NormalizedProfile> {
        let permissions = allowed_permissions
            .iter()
            .map(|key| {
                Ok(NormalizedPermission {
                    key: key.clone(),
                    label: key.rsplit(':').next().unwrap_or(key).to_string(),
                    description: None,
                })
            })
            .collect::<AppResult<Vec<_>>>()?;
        let mut roles = Vec::new();
        for role in &contract.modules.roles {
            let normalized_role_permissions = role
                .permissions
                .iter()
                .map(|permission| normalize_permission_key(permission))
                .collect::<AppResult<Vec<_>>>()?;
            if normalized_role_permissions
                .iter()
                .any(|permission| !allowed_permissions.contains(permission))
            {
                continue;
            }
            let key = visible_text(&role.role_id, 128, "role_id")?;
            roles.push(NormalizedRole {
                key: key.clone(),
                name: key,
                description: None,
                permissions: normalized_role_permissions,
                is_default: role.default_role,
            });
        }
        if roles.iter().filter(|role| role.is_default).count() > 1 {
            return Err(AppError::BadRequest(
                "v3 profile declares more than one default role".to_string(),
            ));
        }
        Ok(NormalizedProfile { permissions, roles })
    };

    let application_profile = build_profile(&all_permission_keys)?;
    let mut profiles = BTreeMap::new();
    profiles.insert("default".to_string(), application_profile);
    for client in &contract.modules.clients {
        let is_machine_identity = client
            .profiles
            .contains(&IntegrationProfile::MachineIdentity);
        let mut allowed_permissions = if is_machine_identity {
            BTreeSet::new()
        } else {
            all_permission_keys.clone()
        };
        allowed_permissions.extend(
            policy_effects
                .by_client_id
                .get(&client.client_id)
                .into_iter()
                .flat_map(|effects| effects.permissions.iter().cloned())
                .map(|permission| normalize_permission_key(&permission))
                .collect::<AppResult<BTreeSet<_>>>()?,
        );
        profiles.insert(
            client.client_id.clone(),
            build_profile(&allowed_permissions)?,
        );
    }
    Ok(profiles)
}

pub(super) fn contract_authorization_module(
    _profiles: &BTreeMap<String, NormalizedProfile>,
) -> AppResult<Value> {
    let object = serde_json::json!({
        "inherit_enterprise_roles": true,
        "permissions": [],
        "denied_permissions": [],
        "claims": []
    })
    .as_object()
    .cloned()
    .ok_or_else(|| AppError::Internal("failed to build authorization module".to_string()))?;
    normalize_module("authorization", &object, "")
}

pub(super) fn normalize_contract_protocols(
    connections: &[crate::application_contract::ConnectionContract],
    client_protocols: &BTreeMap<String, String>,
    expected_issuer: &str,
) -> AppResult<Value> {
    let mut protocols = serde_json::Map::new();
    let mut clients_by_protocol = BTreeMap::<String, Vec<String>>::new();
    for (client_id, protocol) in client_protocols {
        let module_key = protocol_module_key(protocol);
        clients_by_protocol
            .entry(module_key.to_string())
            .or_default()
            .push(client_id.clone());
    }
    for (module_key, client_ids) in clients_by_protocol {
        protocols.insert(
            module_key,
            serde_json::json!({"enabled": true, "client_ids": client_ids}),
        );
    }
    for connection in connections {
        let key = match connection.kind.as_str() {
            "saml2" => "saml2",
            "cas" => "cas",
            "jwt" => "jwt",
            "scim" | "ldap" => continue,
            other if connection.required => {
                return Err(AppError::BadRequest(format!(
                    "v3 connection kind {other} is not supported"
                )));
            }
            _ => continue,
        };
        let mut value = connection.settings.clone();
        value.insert("enabled".to_string(), Value::Bool(true));
        value.insert(
            "connection_id".to_string(),
            Value::String(connection.connection_id.clone()),
        );
        let protocol = protocols
            .entry(key.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        let Some(protocol) = protocol.as_object_mut() else {
            return Err(AppError::Internal(
                "protocol module entry is not an object".to_string(),
            ));
        };
        for (field, field_value) in value {
            protocol.insert(field, field_value);
        }
    }
    normalize_module("protocols", &protocols, expected_issuer)
}

fn protocol_module_key(protocol: &str) -> &str {
    match protocol {
        "oidc" => "oauth2_oidc",
        "saml" => "saml2",
        other => other,
    }
}

pub(super) fn normalize_directory_sync(
    connections: &[crate::application_contract::ConnectionContract],
    expected_issuer: &str,
) -> AppResult<Value> {
    let scim = connections
        .iter()
        .filter(|connection| connection.kind == "scim")
        .collect::<Vec<_>>();
    let ldap = connections
        .iter()
        .filter(|connection| connection.kind == "ldap")
        .collect::<Vec<_>>();
    if scim.len() > 1 {
        return Err(AppError::BadRequest(
            "v3 declares more than one SCIM connection".to_string(),
        ));
    }
    let object = serde_json::json!({
        "enabled": !scim.is_empty() || !ldap.is_empty(),
        "scim_enabled": !scim.is_empty(),
        "ldap_provider_ids": ldap.iter().filter_map(|connection| connection.settings.get("provider_id").and_then(Value::as_str)).collect::<Vec<_>>(),
        "scim_audience": scim.first().and_then(|connection| connection.settings.get("audience")).and_then(Value::as_str).unwrap_or_default()
    });
    normalize_module(
        "directory_sync",
        object
            .as_object()
            .ok_or_else(|| AppError::Internal("failed to build directory sync".to_string()))?,
        expected_issuer,
    )
}

pub(super) fn normalize_module(
    module_key: &str,
    object: &Map<String, Value>,
    expected_issuer: &str,
) -> AppResult<Value> {
    let mut object = object.clone();
    if module_key == "protocols" {
        object.insert(
            "website_url".to_string(),
            Value::String(expected_issuer.to_string()),
        );
    }
    let value = Value::Object(object);
    crate::applications::normalize_module_config(module_key, value)
}

pub(super) fn validate_protocol_client_bindings(
    protocols: &Value,
    clients: &[NewClient],
) -> AppResult<()> {
    let known = clients
        .iter()
        .map(|client| client.client_id.as_str())
        .collect::<BTreeSet<_>>();
    let Some(protocols) = protocols.as_object() else {
        return Err(AppError::BadRequest(
            "protocols module must be an object".to_string(),
        ));
    };
    for protocol in protocols.values() {
        let Some(client_ids) = protocol
            .as_object()
            .and_then(|object| object.get("client_ids"))
            .and_then(Value::as_array)
        else {
            continue;
        };
        for client_id in client_ids.iter().filter_map(Value::as_str) {
            if !known.contains(client_id) {
                return Err(AppError::BadRequest(
                    "protocols references an undeclared client".to_string(),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn normalize_authorization_bindings(
    authorization: &Value,
    profiles: &BTreeMap<String, NormalizedProfile>,
) -> AppResult<NormalizedAuthorizationMappings> {
    let object = authorization.as_object().ok_or_else(|| {
        AppError::BadRequest("application discovery authorization must be an object".to_string())
    })?;
    let default_profile = profiles.get("default").ok_or_else(|| {
        AppError::BadRequest("application discovery must declare a default profile".to_string())
    })?;
    let default_roles = default_profile
        .roles
        .iter()
        .map(|role| role.key.as_str())
        .collect::<BTreeSet<_>>();
    let role_name = |value: &Value| {
        let role = value.as_str().ok_or_else(|| {
            AppError::BadRequest("authorization role mappings must contain strings".to_string())
        })?;
        let role = visible_text(role, 128, "authorization role")?;
        if !default_roles.contains(role.as_str()) {
            return Err(AppError::BadRequest(
                "authorization references an undeclared default-profile role".to_string(),
            ));
        }
        Ok(role)
    };
    if let Some(default_role) = object.get("default_role") {
        role_name(default_role)?;
    }

    let mut group_mappings = Vec::new();
    if let Some(value) = object.get("group_mappings") {
        let values = value.as_array().ok_or_else(|| {
            AppError::BadRequest("authorization group_mappings must be a list".to_string())
        })?;
        if values.len() > 512 {
            return Err(AppError::BadRequest(
                "authorization group_mappings is too large".to_string(),
            ));
        }
        for value in values {
            let mapping = value.as_object().ok_or_else(|| {
                AppError::BadRequest(
                    "authorization group_mappings entries must be objects".to_string(),
                )
            })?;
            let group = mapping
                .get("group")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AppError::BadRequest("authorization group mappings require a group".to_string())
                })
                .and_then(|value| visible_text(value, 255, "authorization group"))?;
            let role = mapping
                .get("role")
                .ok_or_else(|| {
                    AppError::BadRequest("authorization group mappings require a role".to_string())
                })
                .and_then(&role_name)?;
            group_mappings.push(NormalizedGroupMapping { group, role });
        }
    }

    let mut organization_role_mappings = Vec::new();
    if let Some(value) = object.get("organization_role_mappings") {
        let mappings = value.as_object().ok_or_else(|| {
            AppError::BadRequest(
                "authorization organization_role_mappings must be an object".to_string(),
            )
        })?;
        if mappings.len() > 32 {
            return Err(AppError::BadRequest(
                "authorization organization_role_mappings is too large".to_string(),
            ));
        }
        for (organization_role, role) in mappings {
            organization_role_mappings.push(NormalizedOrganizationRoleMapping {
                organization_role: visible_text(organization_role, 64, "organization role")?,
                role: role_name(role)?,
            });
        }
    }

    for field in [
        "user_roles",
        "group_roles",
        "organization_roles",
        "user_assignments",
        "role_assignments",
        "user_role_assignments",
        "group_role_assignments",
        "organization_role_assignments",
        "assignments",
    ] {
        if object.contains_key(field) {
            return Err(AppError::BadRequest(
                "v3 authorization contracts cannot declare user role assignments".to_string(),
            ));
        }
    }

    Ok(NormalizedAuthorizationMappings {
        group_mappings,
        organization_role_mappings,
    })
}
