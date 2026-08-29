use crate::{
    AppState,
    db::{SessionRecord, UserRecord},
    error::{AppError, AppResult},
    util,
};
use serde::Serialize;

#[derive(Clone)]
pub struct CurrentUser {
    pub user: UserRecord,
    pub session_id: String,
    pub session_kind: AccountSessionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountSessionKind {
    Standard,
    TemporaryAuthorizationCode,
    TrialEnrollment,
}

pub const AUTHORIZATION_CODE_SESSION_TTL_SECONDS: i64 = 15 * 60;

pub fn authorization_code_session_ttl_seconds(
    state: &AppState,
    code_expires_at: Option<i64>,
) -> AppResult<i64> {
    let mut ttl = state
        .settings
        .security
        .session_ttl_seconds
        .min(AUTHORIZATION_CODE_SESSION_TTL_SECONDS);
    if let Some(expires_at) = code_expires_at {
        ttl = ttl.min(expires_at.saturating_sub(util::now_ts()));
    }
    if ttl <= 0 {
        return Err(AppError::Unauthorized);
    }
    Ok(ttl)
}

impl AccountSessionKind {
    pub(crate) fn for_active_user(
        user: &UserRecord,
        has_authorization_code_redemption: bool,
    ) -> Option<Self> {
        if user.is_active != 1 {
            return None;
        }
        if user.archived_at.is_some() {
            has_authorization_code_redemption.then_some(Self::TemporaryAuthorizationCode)
        } else {
            Some(Self::Standard)
        }
    }

    pub(crate) fn for_session(
        user: &UserRecord,
        session: &SessionRecord,
        has_authorization_code_redemption: bool,
    ) -> Option<Self> {
        Self::for_active_user(user, has_authorization_code_redemption).map(|kind| {
            if session.login_method.as_deref() == Some("authorization_code") {
                Self::TemporaryAuthorizationCode
            } else {
                kind
            }
        })
    }

    pub(crate) fn for_session_with_trial_enrollment(
        user: &UserRecord,
        session: &SessionRecord,
        has_authorization_code_redemption: bool,
        is_trial_enrollment: bool,
    ) -> Option<Self> {
        if is_trial_enrollment {
            (user.is_active == 1 && user.archived_at.is_none()).then_some(Self::TrialEnrollment)
        } else {
            Self::for_session(user, session, has_authorization_code_redemption)
        }
    }
}

pub trait AccountCapabilities {
    fn account_session_kind(&self) -> AccountSessionKind;

    fn is_temporary_authorization_code_session(&self) -> bool {
        self.account_session_kind() == AccountSessionKind::TemporaryAuthorizationCode
    }

    fn is_restricted_login_code_session(&self) -> bool {
        self.account_session_kind() != AccountSessionKind::Standard
    }

    fn can_mutate_account(&self) -> bool {
        self.account_session_kind() == AccountSessionKind::Standard
    }

    fn can_authorize_oauth_client(&self) -> bool {
        self.can_mutate_account()
    }
}

impl AccountCapabilities for CurrentUser {
    fn account_session_kind(&self) -> AccountSessionKind {
        self.session_kind
    }
}
