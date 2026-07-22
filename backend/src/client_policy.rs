use crate::{
    db::ClientRecord,
    error::{AppError, AppResult},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationRequestSource {
    #[default]
    Query,
    RequestObject,
    PushedAuthorizationRequest,
}

pub trait AuthorizationRequestSecurityView {
    fn source(&self) -> AuthorizationRequestSource;
    fn code_challenge(&self) -> Option<&str>;
    fn code_challenge_method(&self) -> Option<&str>;
}

pub trait ClientSecurityPolicy {
    fn validate_authorization_request<R: AuthorizationRequestSecurityView>(
        &self,
        client: &ClientRecord,
        request: &R,
    ) -> AppResult<()>;

    fn validate_token_binding(&self, client: &ClientRecord, dpop_present: bool) -> AppResult<()>;

    fn validate_client_configuration(&self, input: ClientSecurityConfig<'_>) -> AppResult<()>;
}

#[derive(Debug, Clone, Copy)]
pub struct ClientSecurityConfig<'a> {
    pub token_endpoint_auth_method: &'a str,
    pub require_pkce: bool,
    pub require_s256_pkce: bool,
    pub require_confidential_client: bool,
    pub require_pushed_authorization_requests: bool,
    pub require_dpop: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultClientSecurityPolicy;

impl ClientSecurityPolicy for DefaultClientSecurityPolicy {
    fn validate_authorization_request<R: AuthorizationRequestSecurityView>(
        &self,
        client: &ClientRecord,
        request: &R,
    ) -> AppResult<()> {
        if client.require_pushed_authorization_requests == 1
            && request.source() != AuthorizationRequestSource::PushedAuthorizationRequest
        {
            return Err(AppError::Oidc(
                "this client requires pushed authorization requests".to_string(),
            ));
        }
        if client.require_s256_pkce == 1 {
            if request.code_challenge().is_none() {
                return Err(AppError::Oidc(
                    "PKCE is required for this client".to_string(),
                ));
            }
            if request.code_challenge_method() != Some("S256") {
                return Err(AppError::Oidc("this client requires PKCE S256".to_string()));
            }
        }
        Ok(())
    }

    fn validate_token_binding(&self, client: &ClientRecord, dpop_present: bool) -> AppResult<()> {
        if client.require_dpop == 1 && !dpop_present {
            return Err(AppError::oauth(
                "use_dpop_nonce",
                "this client requires a valid DPoP proof",
                axum::http::StatusCode::UNAUTHORIZED,
            ));
        }
        Ok(())
    }

    fn validate_client_configuration(&self, input: ClientSecurityConfig<'_>) -> AppResult<()> {
        if input.require_s256_pkce && !input.require_pkce {
            return Err(AppError::BadRequest(
                "require_s256_pkce requires require_pkce".to_string(),
            ));
        }
        if input.require_confidential_client && input.token_endpoint_auth_method == "none" {
            return Err(AppError::BadRequest(
                "require_confidential_client cannot be used with public clients".to_string(),
            ));
        }
        let _ = (
            input.require_pushed_authorization_requests,
            input.require_dpop,
        );
        Ok(())
    }
}

pub fn validate_client_security_configuration(input: ClientSecurityConfig<'_>) -> AppResult<()> {
    DefaultClientSecurityPolicy.validate_client_configuration(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Request {
        source: AuthorizationRequestSource,
        challenge: Option<&'static str>,
        method: Option<&'static str>,
    }

    impl AuthorizationRequestSecurityView for Request {
        fn source(&self) -> AuthorizationRequestSource {
            self.source
        }

        fn code_challenge(&self) -> Option<&str> {
            self.challenge
        }

        fn code_challenge_method(&self) -> Option<&str> {
            self.method
        }
    }

    #[test]
    fn par_policy_rejects_direct_authorization_requests() {
        let mut client = client();
        client.require_pushed_authorization_requests = 1;

        assert!(
            DefaultClientSecurityPolicy
                .validate_authorization_request(
                    &client,
                    &Request {
                        source: AuthorizationRequestSource::Query,
                        challenge: Some("abc"),
                        method: Some("S256")
                    },
                )
                .is_err()
        );
        assert!(
            DefaultClientSecurityPolicy
                .validate_authorization_request(
                    &client,
                    &Request {
                        source: AuthorizationRequestSource::PushedAuthorizationRequest,
                        challenge: Some("abc"),
                        method: Some("S256")
                    },
                )
                .is_ok()
        );
    }

    #[test]
    fn s256_policy_rejects_plain_or_missing_pkce() {
        let mut client = client();
        client.require_s256_pkce = 1;

        assert!(
            DefaultClientSecurityPolicy
                .validate_authorization_request(
                    &client,
                    &Request {
                        source: AuthorizationRequestSource::Query,
                        challenge: None,
                        method: None
                    },
                )
                .is_err()
        );
        assert!(
            DefaultClientSecurityPolicy
                .validate_authorization_request(
                    &client,
                    &Request {
                        source: AuthorizationRequestSource::Query,
                        challenge: Some("abc"),
                        method: Some("plain")
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn configuration_policy_rejects_incoherent_flags() {
        assert!(
            validate_client_security_configuration(ClientSecurityConfig {
                token_endpoint_auth_method: "none",
                require_pkce: false,
                require_s256_pkce: true,
                require_confidential_client: false,
                require_pushed_authorization_requests: false,
                require_dpop: false,
            })
            .is_err()
        );
        assert!(
            validate_client_security_configuration(ClientSecurityConfig {
                token_endpoint_auth_method: "none",
                require_pkce: true,
                require_s256_pkce: true,
                require_confidential_client: true,
                require_pushed_authorization_requests: false,
                require_dpop: false,
            })
            .is_err()
        );
    }

    fn client() -> ClientRecord {
        ClientRecord {
            id: "client-db-id".to_string(),
            client_id: "demo-web".to_string(),
            client_secret_hash: None,
            client_name: "Demo".to_string(),
            logo_uri: String::new(),
            organization_id: None,
            redirect_uris: "[]".to_string(),
            post_logout_redirect_uris: "[]".to_string(),
            scopes: "[]".to_string(),
            grant_types: "[]".to_string(),
            response_types: "[]".to_string(),
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: 1,
            require_mfa: 0,
            require_pushed_authorization_requests: 0,
            require_s256_pkce: 0,
            require_confidential_client: 0,
            require_dpop: 0,
            require_account_selection: 0,
            trust_email_verified: 0,
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
