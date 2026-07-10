use crate::db::{ClientRecord, SessionRecord};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaDecision {
    Satisfied,
    Challenge,
    SetupRequired,
}

pub trait OidcMfaPolicy {
    fn login_decision(
        &self,
        client: Option<&ClientRecord>,
        user_has_totp: bool,
        policy_requires_mfa: bool,
    ) -> MfaDecision;

    fn authorization_decision(
        &self,
        client: &ClientRecord,
        session: &SessionRecord,
        user_has_totp: bool,
        policy_requires_mfa: bool,
    ) -> MfaDecision;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultOidcMfaPolicy;

impl OidcMfaPolicy for DefaultOidcMfaPolicy {
    fn login_decision(
        &self,
        client: Option<&ClientRecord>,
        user_has_totp: bool,
        policy_requires_mfa: bool,
    ) -> MfaDecision {
        if user_has_totp {
            return MfaDecision::Challenge;
        }
        if policy_requires_mfa || client.is_some_and(client_requires_mfa) {
            MfaDecision::SetupRequired
        } else {
            MfaDecision::Satisfied
        }
    }

    fn authorization_decision(
        &self,
        client: &ClientRecord,
        session: &SessionRecord,
        user_has_totp: bool,
        policy_requires_mfa: bool,
    ) -> MfaDecision {
        if !(policy_requires_mfa || client_requires_mfa(client)) || session_satisfies_mfa(session) {
            return MfaDecision::Satisfied;
        }
        if user_has_totp {
            MfaDecision::Challenge
        } else {
            MfaDecision::SetupRequired
        }
    }
}

pub fn client_requires_mfa(client: &ClientRecord) -> bool {
    client.require_mfa == 1
}

pub fn session_satisfies_mfa(session: &SessionRecord) -> bool {
    matches!(
        session.login_method.as_deref(),
        Some(
            "totp"
                | "recovery_code"
                | "passkey"
                | "ldap_totp"
                | "ldap_recovery_code"
                | "oidc_totp"
                | "oidc_recovery_code"
                | "oidc_passkey"
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(require_mfa: i32) -> ClientRecord {
        ClientRecord {
            id: "client-db-id".to_string(),
            client_id: "demo-web".to_string(),
            client_secret_hash: None,
            client_name: "Demo".to_string(),
            organization_id: None,
            redirect_uris: "[]".to_string(),
            post_logout_redirect_uris: "[]".to_string(),
            scopes: "[]".to_string(),
            grant_types: "[]".to_string(),
            response_types: "[]".to_string(),
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: 1,
            require_mfa,
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
    fn optional_user_mfa_challenges_on_login() {
        assert_eq!(
            DefaultOidcMfaPolicy.login_decision(None, true, false),
            MfaDecision::Challenge
        );
    }

    #[test]
    fn required_client_mfa_blocks_users_without_totp() {
        assert_eq!(
            DefaultOidcMfaPolicy.login_decision(Some(&client(1)), false, false),
            MfaDecision::SetupRequired
        );
    }

    #[test]
    fn network_mfa_blocks_users_without_totp() {
        assert_eq!(
            DefaultOidcMfaPolicy.login_decision(Some(&client(0)), false, true),
            MfaDecision::SetupRequired
        );
    }

    #[test]
    fn required_client_mfa_accepts_mfa_authenticated_session() {
        assert_eq!(
            DefaultOidcMfaPolicy.authorization_decision(
                &client(1),
                &session(Some("oidc_totp")),
                false,
                false
            ),
            MfaDecision::Satisfied
        );
    }

    #[test]
    fn required_client_mfa_steps_up_plain_session() {
        assert_eq!(
            DefaultOidcMfaPolicy.authorization_decision(
                &client(1),
                &session(Some("oidc_login")),
                true,
                false
            ),
            MfaDecision::Challenge
        );
    }

    #[test]
    fn network_mfa_steps_up_plain_session() {
        assert_eq!(
            DefaultOidcMfaPolicy.authorization_decision(
                &client(0),
                &session(Some("oidc_login")),
                true,
                true
            ),
            MfaDecision::Challenge
        );
    }

    #[test]
    fn passkey_session_satisfies_mfa() {
        assert!(session_satisfies_mfa(&session(Some("passkey"))));
        assert!(session_satisfies_mfa(&session(Some("oidc_passkey"))));
    }
}
