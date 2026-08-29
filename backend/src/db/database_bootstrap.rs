use super::{BootstrapClient, ClientRecord};
use crate::error::{AppError, AppResult};

pub(super) fn client_secret_hash(
    client: &BootstrapClient,
    existing: Option<&ClientRecord>,
) -> AppResult<Option<String>> {
    let auth_method = client.token_endpoint_auth_method.as_str();
    let existing_hash = existing.and_then(|record| record.client_secret_hash.as_deref());
    if !client.rotate_secret
        && let Some(existing_hash) = existing_hash
    {
        if matches!(
            auth_method,
            "none" | crate::client_assertion::PRIVATE_KEY_JWT
        ) || crate::client_assertion::stored_secret_supports_method(
            auth_method,
            Some(existing_hash),
        ) {
            return Ok(Some(existing_hash.to_string()));
        }
        return Err(AppError::Configuration(format!(
            "bootstrap client {} has an existing client_secret incompatible with {}, set rotate_secret=true to replace it",
            client.client_id, auth_method
        )));
    }
    if matches!(
        auth_method,
        "none" | crate::client_assertion::PRIVATE_KEY_JWT
    ) {
        return Ok(None);
    }

    let configured_secret = client
        .client_secret_env
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|env_name| {
            std::env::var(env_name).map_err(|err| {
                AppError::Configuration(format!(
                    "bootstrap client {} references unusable client_secret_env {env_name}: {err}",
                    client.client_id
                ))
            })
        })
        .transpose()?
        .or_else(|| (!client.client_secret.is_empty()).then(|| client.client_secret.clone()));
    let Some(configured_secret) = configured_secret.filter(|secret| !secret.is_empty()) else {
        return Err(AppError::Configuration(format!(
            "bootstrap client {} requires client_secret or client_secret_env",
            client.client_id
        )));
    };
    crate::client_assertion::store_client_secret(auth_method, &configured_secret)
}
