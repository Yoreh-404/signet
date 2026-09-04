use super::{ApplicationModuleRecord, ApplicationRecord};
use crate::error::{AppError, AppResult};
use serde_json::{Map, Value};

pub(super) fn authorization_config(
    module: Option<ApplicationModuleRecord>,
) -> AppResult<Map<String, Value>> {
    let Some(module) = module.filter(|module| module.is_enabled == 1) else {
        return Ok(Map::new());
    };
    let value = serde_json::from_str::<Value>(&module.config_json).map_err(|err| {
        AppError::Internal(format!("application module config is invalid: {err}"))
    })?;
    let normalized = crate::applications::normalize_module_config("authorization", value)?;
    normalized
        .as_object()
        .cloned()
        .ok_or_else(|| AppError::Internal("application module config is not an object".to_string()))
}

pub(super) fn protocol_key(protocol: &str) -> &str {
    match protocol {
        "oidc" | "oauth2_oidc" => "oauth2_oidc",
        "saml" | "saml2" => "saml2",
        other => other,
    }
}

pub(super) fn protocol_module_enabled(
    module: Option<ApplicationModuleRecord>,
    protocol: Option<&str>,
) -> AppResult<bool> {
    let Some(protocol) = protocol else {
        return Ok(false);
    };
    let Some(module) = module else {
        return Ok(true);
    };
    if module.is_enabled != 1 {
        return Ok(false);
    }
    let value = serde_json::from_str::<Value>(&module.config_json).map_err(|err| {
        AppError::Internal(format!("application module config is invalid: {err}"))
    })?;
    let normalized = crate::applications::normalize_module_config("protocols", value)?;
    let Some(protocol_config) = normalized
        .get(protocol_key(protocol))
        .and_then(Value::as_object)
    else {
        return Ok(false);
    };
    Ok(protocol_config
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(true))
}

pub(super) fn application_runtime_active(
    application: &ApplicationRecord,
    organization_active: bool,
    discovery_runtime_active: bool,
) -> bool {
    application.is_active == 1 && organization_active && discovery_runtime_active
}
