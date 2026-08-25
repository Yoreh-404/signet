//! Shared OAuth/OIDC client authentication.
//!
//! Endpoint payloads deliberately own their protocol-specific fields, but
//! client authentication is one cross-cutting concern. Keeping the four
//! credential fields and their runtime gate in one module prevents token,
//! PAR, device, introspection, and revocation endpoints from drifting apart.

use crate::{
    AppState, applications, client_assertion,
    db::ClientRecord,
    error::{AppError, AppResult},
    oidc, util,
};
use axum::http::{HeaderMap, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ClientAuthForm {
    pub(crate) client_id: Option<String>,
    pub(crate) client_secret: Option<String>,
    pub(crate) client_assertion_type: Option<String>,
    pub(crate) client_assertion: Option<String>,
}

pub(crate) trait ClientAuthFields {
    fn client_auth(&self) -> &ClientAuthForm;

    fn client_id(&self) -> Option<&str> {
        self.client_auth().client_id.as_deref()
    }

    /// Some token grants validate the application boundary after consuming
    /// the grant. Those endpoints opt out of the early gate but still use the
    /// exact same credential validation here.
    fn defers_application_runtime_gate(&self) -> bool {
        false
    }
}

enum PresentedClientAuth {
    None {
        client_id: String,
    },
    Basic {
        client_id: String,
        secret: String,
    },
    Post {
        client_id: String,
        secret: String,
    },
    Assertion {
        client_id: String,
        assertion_type: Option<String>,
        assertion: String,
    },
}

impl PresentedClientAuth {
    fn client_id(&self) -> &str {
        match self {
            Self::None { client_id }
            | Self::Basic { client_id, .. }
            | Self::Post { client_id, .. }
            | Self::Assertion { client_id, .. } => client_id,
        }
    }
}

pub(crate) async fn authenticate_client_at<T: ClientAuthFields>(
    state: &AppState,
    headers: &HeaderMap,
    payload: &T,
    endpoint_path: &str,
) -> AppResult<ClientRecord> {
    let credentials = presented_client_auth(headers, payload)?;
    let client = state
        .db
        .find_client_by_client_id(credentials.client_id())
        .await?
        .ok_or(AppError::Unauthorized)?;
    if client.is_active != 1 {
        return Err(AppError::Unauthorized);
    }
    let credential_matches_method = match client.token_endpoint_auth_method.as_str() {
        "none" => matches!(&credentials, PresentedClientAuth::None { .. }),
        "client_secret_basic" => matches!(&credentials, PresentedClientAuth::Basic { .. }),
        "client_secret_post" => matches!(&credentials, PresentedClientAuth::Post { .. }),
        client_assertion::CLIENT_SECRET_JWT | client_assertion::PRIVATE_KEY_JWT => {
            matches!(&credentials, PresentedClientAuth::Assertion { .. })
        }
        _ => false,
    };
    if !credential_matches_method {
        return Err(AppError::Unauthorized);
    }
    match credentials {
        PresentedClientAuth::None { .. } => {}
        PresentedClientAuth::Basic { secret, .. } | PresentedClientAuth::Post { secret, .. } => {
            let Some(hash) = &client.client_secret_hash else {
                return Err(AppError::Unauthorized);
            };
            if !util::verify_password(hash, &secret) {
                return Err(AppError::Unauthorized);
            }
        }
        PresentedClientAuth::Assertion {
            assertion_type,
            assertion,
            ..
        } => {
            let audiences = client_auth_audiences(state, headers, endpoint_path).await?;
            match client.token_endpoint_auth_method.as_str() {
                client_assertion::CLIENT_SECRET_JWT => {
                    client_assertion::authenticate_client_secret_jwt(
                        state,
                        &client,
                        assertion_type.as_deref(),
                        Some(&assertion),
                        &audiences,
                    )
                    .await?;
                }
                client_assertion::PRIVATE_KEY_JWT => {
                    client_assertion::authenticate_private_key_jwt(
                        state,
                        &client,
                        assertion_type.as_deref(),
                        Some(&assertion),
                        &audiences,
                    )
                    .await?;
                }
                _ => return Err(AppError::Unauthorized),
            }
        }
    }
    if service_client_endpoint_request(&client, endpoint_path) {
        applications::authorize_client_for_service_token(state, &client)
            .await
            .map_err(|_| AppError::Unauthorized)?;
    } else if !payload.defers_application_runtime_gate() {
        applications::authorize_application_client(state, &client, "oauth2_oidc")
            .await
            .map_err(|_| AppError::Unauthorized)?;
    }
    if client.require_confidential_client == 1 && client.token_endpoint_auth_method == "none" {
        return Err(AppError::Unauthorized);
    }
    Ok(client)
}

/// Service-only applications disable interactive OIDC, but an explicitly
/// enabled client-credentials client may still introspect its machine tokens.
pub(crate) fn service_client_endpoint_request(client: &ClientRecord, endpoint_path: &str) -> bool {
    endpoint_path == "/oauth2/introspect"
        && client.service_account_enabled == 1
        && client.grant_types().ok().is_some_and(|grant_types| {
            grant_types
                .iter()
                .any(|grant| grant == "client_credentials")
        })
}

fn presented_client_auth<T: ClientAuthFields>(
    headers: &HeaderMap,
    payload: &T,
) -> AppResult<PresentedClientAuth> {
    let form = payload.client_auth();
    let has_form_auth = form.client_id.is_some()
        || form.client_secret.is_some()
        || form.client_assertion_type.is_some()
        || form.client_assertion.is_some();
    if let Some(header) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        && let Some(encoded) = header.strip_prefix("Basic ")
    {
        if has_form_auth {
            return Err(AppError::Unauthorized);
        }
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| AppError::Unauthorized)?;
        let decoded = String::from_utf8(decoded).map_err(|_| AppError::Unauthorized)?;
        let (client_id, client_secret) = decoded.split_once(':').ok_or(AppError::Unauthorized)?;
        return Ok(PresentedClientAuth::Basic {
            client_id: url_decode(client_id),
            secret: url_decode(client_secret),
        });
    }
    if let Some(assertion) = form.client_assertion.as_deref() {
        if form.client_secret.is_some() {
            return Err(AppError::Unauthorized);
        }
        let client_id = form
            .client_id
            .clone()
            .map(Ok)
            .unwrap_or_else(|| client_assertion::client_id_from_assertion(assertion))?;
        return Ok(PresentedClientAuth::Assertion {
            client_id,
            assertion_type: form.client_assertion_type.clone(),
            assertion: assertion.to_string(),
        });
    }
    if let Some(secret) = form.client_secret.as_deref() {
        let client_id = form.client_id.clone().ok_or(AppError::Unauthorized)?;
        return Ok(PresentedClientAuth::Post {
            client_id,
            secret: secret.to_string(),
        });
    }
    if form.client_assertion_type.is_some() {
        return Err(AppError::Unauthorized);
    }
    Ok(PresentedClientAuth::None {
        client_id: form.client_id.clone().ok_or(AppError::Unauthorized)?,
    })
}

pub(crate) fn diagnostic_client_id<T: ClientAuthFields>(
    headers: &HeaderMap,
    payload: &T,
) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .and_then(|decoded| {
            decoded
                .split_once(':')
                .map(|(client_id, _)| url_decode(client_id))
        })
        .or_else(|| payload.client_id().map(ToOwned::to_owned))
}

async fn client_auth_audiences(
    state: &AppState,
    headers: &HeaderMap,
    endpoint_path: &str,
) -> AppResult<Vec<String>> {
    let mut audiences = state
        .accepted_issuers(headers)
        .await?
        .into_iter()
        .map(|issuer| oidc::absolute(&issuer, endpoint_path))
        .collect::<Vec<_>>();
    audiences.sort();
    audiences.dedup();
    Ok(audiences)
}

fn url_decode(value: &str) -> String {
    url::form_urlencoded::parse(value.as_bytes())
        .map(|(key, _)| key.into_owned())
        .next()
        .unwrap_or_else(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    struct TestFields(ClientAuthForm);

    impl ClientAuthFields for TestFields {
        fn client_auth(&self) -> &ClientAuthForm {
            &self.0
        }
    }

    #[test]
    fn client_auth_rejects_mixed_basic_and_form_credentials() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic ZGVtby1jbGllbnQ6c2VjcmV0"),
        );
        let fields = TestFields(ClientAuthForm {
            client_id: Some("demo-client".to_string()),
            ..Default::default()
        });
        assert!(matches!(
            presented_client_auth(&headers, &fields),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn client_auth_distinguishes_post_and_unauthenticated_forms() {
        let post = TestFields(ClientAuthForm {
            client_id: Some("demo-client".to_string()),
            client_secret: Some("secret".to_string()),
            ..Default::default()
        });
        assert!(matches!(
            presented_client_auth(&HeaderMap::new(), &post),
            Ok(PresentedClientAuth::Post { .. })
        ));

        let none = TestFields(ClientAuthForm {
            client_id: Some("demo-client".to_string()),
            ..Default::default()
        });
        assert!(matches!(
            presented_client_auth(&HeaderMap::new(), &none),
            Ok(PresentedClientAuth::None { .. })
        ));
    }
}
