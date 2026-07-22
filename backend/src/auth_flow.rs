use crate::{
    captcha::LoginCaptchaPolicy,
    db::{ClientRecord, LoginFailureSummary, SecurityPolicyRecord, SessionRecord, UserRecord},
    error::{AppError, AppResult},
    mfa_policy::{DefaultOidcMfaPolicy, MfaDecision, OidcMfaPolicy},
    security_policy::{self, AccessRiskContext, AccessRiskPolicy, AccessSurface, LoginLockPolicy},
    util,
};

#[derive(Debug, Clone, Copy)]
pub struct AuthFlowContext<'a> {
    pub surface: AccessSurface,
    pub subject: Option<&'a str>,
    pub ip_address: Option<&'a str>,
    pub security_policy: &'a SecurityPolicyRecord,
    pub login_failure_summary: Option<LoginFailureSummary>,
    pub user: Option<&'a UserRecord>,
    pub client: Option<&'a ClientRecord>,
    pub session: Option<&'a SessionRecord>,
    pub user_has_totp: Option<bool>,
    pub policy_requires_mfa: Option<bool>,
    pub now: i64,
}

pub trait AuthStage {
    fn name(&self) -> &'static str;
    fn evaluate(&self, context: &AuthFlowContext<'_>) -> AppResult<()>;
}

pub trait AuthDecisionStage {
    type Decision;

    fn name(&self) -> &'static str;
    fn decide(&self, context: &AuthFlowContext<'_>) -> AppResult<Self::Decision>;
}

#[derive(Default)]
pub struct AuthFlow {
    stages: Vec<Box<dyn AuthStage + Send + Sync>>,
}

impl AuthFlow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stage(mut self, stage: impl AuthStage + Send + Sync + 'static) -> Self {
        self.stages.push(Box::new(stage));
        self
    }

    pub fn evaluate(&self, context: &AuthFlowContext<'_>) -> AppResult<()> {
        for stage in &self.stages {
            stage.evaluate(context)?;
        }
        Ok(())
    }

    pub fn stage_names(&self) -> Vec<&'static str> {
        self.stages.iter().map(|stage| stage.name()).collect()
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AccessRiskStage;

impl AuthStage for AccessRiskStage {
    fn name(&self) -> &'static str {
        "access_risk"
    }

    fn evaluate(&self, context: &AuthFlowContext<'_>) -> AppResult<()> {
        context
            .security_policy
            .evaluate_access_risk(AccessRiskContext {
                surface: context.surface,
                ip_address: context.ip_address,
                subject: context.subject,
            })
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LoginLockStage;

impl AuthStage for LoginLockStage {
    fn name(&self) -> &'static str {
        "login_lock"
    }

    fn evaluate(&self, context: &AuthFlowContext<'_>) -> AppResult<()> {
        if context.surface != AccessSurface::Login {
            return Ok(());
        }
        let summary = context
            .login_failure_summary
            .ok_or_else(|| AppError::Configuration("login lock summary is missing".to_string()))?;
        let state = context.security_policy.lock_state(summary, context.now);
        if state.locked {
            Err(AppError::Unauthorized)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LoginAccountStatusStage;

impl AuthStage for LoginAccountStatusStage {
    fn name(&self) -> &'static str {
        "login_account_status"
    }

    fn evaluate(&self, context: &AuthFlowContext<'_>) -> AppResult<()> {
        let user = context
            .user
            .ok_or_else(|| AppError::Configuration("login account is missing".to_string()))?;
        if user.is_active == 1 && user.archived_at.is_none() {
            Ok(())
        } else {
            Err(AppError::Unauthorized)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcMfaFlowKind {
    Login,
    Authorization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginCaptchaDecision {
    NotRequired,
    ChallengeRequired,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LoginCaptchaStage;

impl AuthDecisionStage for LoginCaptchaStage {
    type Decision = LoginCaptchaDecision;

    fn name(&self) -> &'static str {
        "login_captcha"
    }

    fn decide(&self, context: &AuthFlowContext<'_>) -> AppResult<Self::Decision> {
        let summary = context.login_failure_summary.ok_or_else(|| {
            AppError::Configuration("login captcha summary is missing".to_string())
        })?;
        if context.security_policy.requires_login_captcha(summary) {
            Ok(LoginCaptchaDecision::ChallengeRequired)
        } else {
            Ok(LoginCaptchaDecision::NotRequired)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OidcMfaStage {
    kind: OidcMfaFlowKind,
}

impl OidcMfaStage {
    pub fn login() -> Self {
        Self {
            kind: OidcMfaFlowKind::Login,
        }
    }

    pub fn authorization() -> Self {
        Self {
            kind: OidcMfaFlowKind::Authorization,
        }
    }
}

impl AuthDecisionStage for OidcMfaStage {
    type Decision = MfaDecision;

    fn name(&self) -> &'static str {
        match self.kind {
            OidcMfaFlowKind::Login => "oidc_login_mfa",
            OidcMfaFlowKind::Authorization => "oidc_authorization_mfa",
        }
    }

    fn decide(&self, context: &AuthFlowContext<'_>) -> AppResult<Self::Decision> {
        let user_has_totp = context
            .user_has_totp
            .ok_or_else(|| AppError::Configuration("MFA user state is missing".to_string()))?;
        let policy_requires_mfa = context
            .policy_requires_mfa
            .ok_or_else(|| AppError::Configuration("MFA policy state is missing".to_string()))?;
        Ok(match self.kind {
            OidcMfaFlowKind::Login => DefaultOidcMfaPolicy.login_decision(
                context.client,
                user_has_totp,
                policy_requires_mfa,
            ),
            OidcMfaFlowKind::Authorization => {
                let client = context
                    .client
                    .ok_or_else(|| AppError::Configuration("OIDC client is missing".to_string()))?;
                let session = context.session.ok_or_else(|| {
                    AppError::Configuration("OIDC session is missing".to_string())
                })?;
                DefaultOidcMfaPolicy.authorization_decision(
                    client,
                    session,
                    user_has_totp,
                    policy_requires_mfa,
                )
            }
        })
    }
}

pub fn login_entry_flow() -> AuthFlow {
    AuthFlow::new().stage(AccessRiskStage).stage(LoginLockStage)
}

pub fn registration_entry_flow() -> AuthFlow {
    AuthFlow::new().stage(AccessRiskStage)
}

pub fn access_risk_flow() -> AuthFlow {
    AuthFlow::new().stage(AccessRiskStage)
}

pub fn login_account_flow() -> AuthFlow {
    AuthFlow::new().stage(LoginAccountStatusStage)
}

pub fn login_entry_context<'a>(
    security_policy: &'a SecurityPolicyRecord,
    subject: &'a str,
    ip_address: Option<&'a str>,
    login_failure_summary: LoginFailureSummary,
) -> AuthFlowContext<'a> {
    AuthFlowContext {
        surface: AccessSurface::Login,
        subject: Some(subject),
        ip_address,
        security_policy,
        login_failure_summary: Some(login_failure_summary),
        user: None,
        client: None,
        session: None,
        user_has_totp: None,
        policy_requires_mfa: None,
        now: util::now_ts(),
    }
}

pub fn registration_entry_context<'a>(
    security_policy: &'a SecurityPolicyRecord,
    subject: Option<&'a str>,
    ip_address: Option<&'a str>,
) -> AuthFlowContext<'a> {
    access_risk_context(
        security_policy,
        AccessSurface::Registration,
        subject,
        ip_address,
    )
}

pub fn access_risk_context<'a>(
    security_policy: &'a SecurityPolicyRecord,
    surface: AccessSurface,
    subject: Option<&'a str>,
    ip_address: Option<&'a str>,
) -> AuthFlowContext<'a> {
    AuthFlowContext {
        surface,
        subject,
        ip_address,
        security_policy,
        login_failure_summary: None,
        user: None,
        client: None,
        session: None,
        user_has_totp: None,
        policy_requires_mfa: None,
        now: util::now_ts(),
    }
}

pub fn login_account_context<'a>(
    security_policy: &'a SecurityPolicyRecord,
    user: &'a UserRecord,
) -> AuthFlowContext<'a> {
    AuthFlowContext {
        surface: AccessSurface::Login,
        subject: Some(&user.email),
        ip_address: None,
        security_policy,
        login_failure_summary: None,
        user: Some(user),
        client: None,
        session: None,
        user_has_totp: None,
        policy_requires_mfa: None,
        now: util::now_ts(),
    }
}

pub fn oidc_login_mfa_context<'a>(
    security_policy: &'a SecurityPolicyRecord,
    client: Option<&'a ClientRecord>,
    user_has_totp: bool,
    policy_requires_mfa: bool,
) -> AuthFlowContext<'a> {
    AuthFlowContext {
        surface: AccessSurface::Login,
        subject: None,
        ip_address: None,
        security_policy,
        login_failure_summary: None,
        user: None,
        client,
        session: None,
        user_has_totp: Some(user_has_totp),
        policy_requires_mfa: Some(policy_requires_mfa),
        now: util::now_ts(),
    }
}

pub fn oidc_authorization_mfa_context<'a>(
    security_policy: &'a SecurityPolicyRecord,
    client: &'a ClientRecord,
    session: &'a SessionRecord,
    user_has_totp: bool,
    policy_requires_mfa: bool,
) -> AuthFlowContext<'a> {
    AuthFlowContext {
        surface: AccessSurface::Login,
        subject: None,
        ip_address: None,
        security_policy,
        login_failure_summary: None,
        user: None,
        client: Some(client),
        session: Some(session),
        user_has_totp: Some(user_has_totp),
        policy_requires_mfa: Some(policy_requires_mfa),
        now: util::now_ts(),
    }
}

pub fn assert_not_locked(
    policy: &SecurityPolicyRecord,
    summary: LoginFailureSummary,
) -> AppResult<()> {
    let context = login_entry_context(policy, "", None, summary);
    LoginLockStage.evaluate(&context)
}

pub fn assert_login_account_allowed(
    policy: &SecurityPolicyRecord,
    user: &UserRecord,
) -> AppResult<()> {
    login_account_flow().evaluate(&login_account_context(policy, user))
}

pub fn login_captcha_decision(
    policy: &SecurityPolicyRecord,
    subject: &str,
    ip_address: Option<&str>,
    summary: LoginFailureSummary,
) -> AppResult<LoginCaptchaDecision> {
    LoginCaptchaStage.decide(&login_entry_context(policy, subject, ip_address, summary))
}

pub fn oidc_login_mfa_decision(
    policy: &SecurityPolicyRecord,
    client: Option<&ClientRecord>,
    user_has_totp: bool,
    policy_requires_mfa: bool,
) -> AppResult<MfaDecision> {
    OidcMfaStage::login().decide(&oidc_login_mfa_context(
        policy,
        client,
        user_has_totp,
        policy_requires_mfa,
    ))
}

pub fn oidc_authorization_mfa_decision(
    policy: &SecurityPolicyRecord,
    client: &ClientRecord,
    session: &SessionRecord,
    user_has_totp: bool,
    policy_requires_mfa: bool,
) -> AppResult<MfaDecision> {
    OidcMfaStage::authorization().decide(&oidc_authorization_mfa_context(
        policy,
        client,
        session,
        user_has_totp,
        policy_requires_mfa,
    ))
}

pub fn normalize_login_subject(value: &str) -> String {
    security_policy::normalize_login_subject(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SecurityPolicyRecord {
        SecurityPolicyRecord {
            id: "default".to_string(),
            password_min_length: 8,
            password_require_uppercase: 0,
            password_require_lowercase: 0,
            password_require_digit: 0,
            password_require_symbol: 0,
            password_reject_user_info: 1,
            login_lockout_enabled: 1,
            max_failed_login_attempts: 2,
            failure_window_seconds: 900,
            lockout_seconds: 900,
            trusted_ip_cidrs: "[]".to_string(),
            require_mfa_outside_trusted_networks: 0,
            allowed_ip_cidrs: "[]".to_string(),
            blocked_ip_cidrs: "[]".to_string(),
            allowed_email_domains: "[]".to_string(),
            blocked_email_domains: "[]".to_string(),
            captcha_enabled: 0,
            captcha_after_failed_attempts: 3,
            captcha_ttl_seconds: 300,
            updated_at: 1,
        }
    }

    fn user(is_active: i32, archived_at: Option<i64>) -> UserRecord {
        UserRecord {
            id: "user-id".to_string(),
            email: "user@example.com".to_string(),
            username: "user".to_string(),
            display_name: None,
            phone: None,
            password_hash: "hash".to_string(),
            email_verified_at: None,
            phone_verified_at: None,
            is_admin: 0,
            is_active,
            archived_at,
            registration_source: "local".to_string(),
            last_login_at: None,
            last_login_ip: None,
            last_oidc_client_id: None,
            last_login_method: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn client(require_mfa: i32) -> ClientRecord {
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
    fn login_entry_flow_runs_risk_before_lockout() {
        let mut policy = policy();
        policy.blocked_email_domains = util::to_json(&vec!["example.com".to_string()]).unwrap();
        let summary = LoginFailureSummary {
            count: 2,
            latest_at: Some(util::now_ts()),
        };
        let context = login_entry_context(&policy, "user@example.com", Some("192.0.2.10"), summary);

        assert!(matches!(
            login_entry_flow().evaluate(&context),
            Err(AppError::Forbidden)
        ));
        assert_eq!(
            login_entry_flow().stage_names(),
            vec!["access_risk", "login_lock"]
        );
    }

    #[test]
    fn login_entry_flow_locks_after_failed_attempt_limit() {
        let policy = policy();
        let summary = LoginFailureSummary {
            count: 2,
            latest_at: Some(util::now_ts()),
        };
        let context = login_entry_context(&policy, "user@example.com", Some("192.0.2.10"), summary);

        assert!(matches!(
            login_entry_flow().evaluate(&context),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn login_account_flow_rejects_disabled_or_archived_users() {
        let policy = policy();
        assert!(assert_login_account_allowed(&policy, &user(1, None)).is_ok());
        assert!(matches!(
            assert_login_account_allowed(&policy, &user(0, None)),
            Err(AppError::Unauthorized)
        ));
        assert!(matches!(
            assert_login_account_allowed(&policy, &user(1, Some(100))),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn login_captcha_stage_requires_challenge_at_threshold() {
        let mut policy = policy();
        policy.captcha_enabled = 1;
        policy.captcha_after_failed_attempts = 2;
        let summary = LoginFailureSummary {
            count: 2,
            latest_at: Some(util::now_ts()),
        };
        assert_eq!(
            login_captcha_decision(&policy, "user@example.com", Some("192.0.2.10"), summary)
                .unwrap(),
            LoginCaptchaDecision::ChallengeRequired
        );
    }

    #[test]
    fn oidc_login_mfa_stage_challenges_when_account_has_totp() {
        assert_eq!(
            oidc_login_mfa_decision(&policy(), Some(&client(0)), true, false).unwrap(),
            MfaDecision::Challenge
        );
    }

    #[test]
    fn oidc_login_mfa_stage_requires_setup_when_policy_requires_mfa_without_totp() {
        assert_eq!(
            oidc_login_mfa_decision(&policy(), Some(&client(0)), false, true).unwrap(),
            MfaDecision::SetupRequired
        );
    }

    #[test]
    fn oidc_authorization_mfa_stage_accepts_mfa_session() {
        assert_eq!(
            oidc_authorization_mfa_decision(
                &policy(),
                &client(1),
                &session(Some("oidc_totp")),
                false,
                false,
            )
            .unwrap(),
            MfaDecision::Satisfied
        );
    }

    #[test]
    fn oidc_authorization_mfa_stage_steps_up_plain_session() {
        assert_eq!(
            oidc_authorization_mfa_decision(
                &policy(),
                &client(1),
                &session(Some("oidc_login")),
                true,
                false,
            )
            .unwrap(),
            MfaDecision::Challenge
        );
    }
}
