use crate::{
    error::{AppError, AppResult},
    util,
};
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::UserRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationCodeType {
    Registration,
    Login,
}

impl AuthorizationCodeType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Login => "login",
        }
    }

    pub fn parse(value: &str) -> AppResult<Self> {
        match value {
            "registration" => Ok(Self::Registration),
            "login" => Ok(Self::Login),
            _ => Err(AppError::Configuration(format!(
                "unknown authorization code type: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginCodeLevel {
    AccountRecovery,
    AdminUniversal,
    TrialEnrollment,
}

impl LoginCodeLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountRecovery => "account_recovery",
            Self::AdminUniversal => "admin_universal",
            Self::TrialEnrollment => "trial_enrollment",
        }
    }

    pub fn parse(value: &str) -> AppResult<Self> {
        match value {
            "account_recovery" => Ok(Self::AccountRecovery),
            "admin_universal" => Ok(Self::AdminUniversal),
            "trial_enrollment" => Ok(Self::TrialEnrollment),
            _ => Err(AppError::Configuration(format!(
                "unknown login authorization code type: {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewInvitation {
    pub code_type: AuthorizationCodeType,
    pub login_code_level: LoginCodeLevel,
    pub allowed_client_ids: Vec<String>,
    pub organization_id: Option<String>,
    pub organization_role: Option<String>,
    pub description: Option<String>,
    pub authorized_email: Option<String>,
    pub authorized_username: Option<String>,
    pub authorized_user_id: Option<String>,
    pub authorized_display_name: Option<String>,
    pub expires_at: Option<i64>,
    pub max_uses: Option<i32>,
    pub is_active: bool,
    pub created_by: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InvitationUpdate<'a> {
    pub id: &'a str,
    pub description: Option<String>,
    pub authorized_email: Option<String>,
    pub authorized_username: Option<String>,
    pub authorized_display_name: Option<String>,
    pub expires_at: Option<i64>,
    pub max_uses: Option<i32>,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct AccountRecoveryCodeRedemption {
    pub invitation_id: String,
    pub user: UserRecord,
    pub code_expires_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct InvitationRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    #[serde(skip)]
    pub code_hash: String,
    #[diesel(sql_type = Text)]
    pub code_prefix: String,
    #[diesel(sql_type = Nullable<Text>)]
    #[serde(skip)]
    pub code_reveal_key_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    #[serde(skip)]
    pub code_reveal_ciphertext: Option<String>,
    #[diesel(sql_type = Text)]
    pub code_type: String,
    #[diesel(sql_type = Text)]
    pub login_code_level: String,
    #[diesel(sql_type = Text)]
    pub allowed_client_ids: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub organization_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub organization_role: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorized_email: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorized_username: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    #[serde(skip)]
    pub authorized_user_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub authorized_display_name: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<Integer>)]
    pub max_uses: Option<i32>,
    #[diesel(sql_type = Integer)]
    pub uses_count: i32,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Nullable<Text>)]
    pub created_by: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicInvitationRedemption {
    pub id: String,
    pub user_id: String,
    pub user_email: Option<String>,
    pub user_username: Option<String>,
    pub redeemed_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct InvitationRedemptionRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub invitation_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_email: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_username: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub redeemed_at: i64,
}

impl InvitationRedemptionRecord {
    pub fn public(self) -> PublicInvitationRedemption {
        PublicInvitationRedemption {
            id: self.id,
            user_id: self.user_id,
            user_email: self.user_email,
            user_username: self.user_username,
            redeemed_at: self.redeemed_at,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicInvitation {
    pub id: String,
    pub code_prefix: String,
    pub can_reveal: bool,
    pub code_type: AuthorizationCodeType,
    pub login_code_level: LoginCodeLevel,
    pub allowed_client_ids: Vec<String>,
    pub organization_id: Option<String>,
    pub organization_role: Option<String>,
    pub description: Option<String>,
    pub authorized_email: Option<String>,
    pub authorized_username: Option<String>,
    pub authorized_display_name: Option<String>,
    pub expires_at: Option<i64>,
    pub max_uses: Option<i32>,
    pub uses_count: i32,
    pub is_active: bool,
    pub created_by: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl InvitationRecord {
    pub fn authorization_code_type(&self) -> AppResult<AuthorizationCodeType> {
        AuthorizationCodeType::parse(&self.code_type)
    }

    pub fn login_code_level(&self) -> AppResult<LoginCodeLevel> {
        LoginCodeLevel::parse(&self.login_code_level)
    }

    pub fn allowed_client_ids(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.allowed_client_ids).map_err(|err| {
            AppError::Configuration(format!(
                "authorization code client allowlist is invalid: {err}"
            ))
        })
    }

    pub fn public(self) -> AppResult<PublicInvitation> {
        let code_type = self.authorization_code_type()?;
        let login_code_level = self.login_code_level()?;
        let allowed_client_ids = self.allowed_client_ids()?;
        let can_reveal = self.code_reveal_key_id.is_some() && self.code_reveal_ciphertext.is_some();
        Ok(PublicInvitation {
            id: self.id,
            code_prefix: self.code_prefix,
            can_reveal,
            code_type,
            login_code_level,
            allowed_client_ids,
            organization_id: self.organization_id,
            organization_role: self.organization_role,
            description: self.description,
            authorized_email: self.authorized_email,
            authorized_username: self.authorized_username,
            authorized_display_name: self.authorized_display_name,
            expires_at: self.expires_at,
            max_uses: self.max_uses,
            uses_count: self.uses_count,
            is_active: self.is_active == 1,
            created_by: self.created_by,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct TrialEnrollmentRecord {
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub invitation_id: String,
    #[diesel(sql_type = Text)]
    pub organization_id: String,
    #[diesel(sql_type = Text)]
    pub organization_role: String,
    #[diesel(sql_type = Text)]
    pub allowed_client_ids: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub revoked_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

impl TrialEnrollmentRecord {
    pub fn allowed_client_ids(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.allowed_client_ids).map_err(|err| {
            AppError::Configuration(format!(
                "trial enrollment client allowlist is invalid: {err}"
            ))
        })
    }

    pub fn allows_client(&self, client_id: &str) -> AppResult<bool> {
        Ok(self.allowed_client_id_set()?.contains(client_id))
    }

    fn allowed_client_id_set(&self) -> AppResult<HashSet<String>> {
        util::from_json(&self.allowed_client_ids).map_err(|err| {
            AppError::Configuration(format!(
                "trial enrollment client allowlist is invalid: {err}"
            ))
        })
    }

    pub fn is_active_at(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|expires_at| expires_at >= now)
    }
}

#[derive(Debug, Clone)]
pub struct NewTrialEnrollmentUser {
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub password_hash: String,
}

#[derive(Debug, Clone)]
pub struct TrialEnrollmentCodeRedemption {
    pub invitation_id: String,
    pub user: UserRecord,
    pub code_expires_at: Option<i64>,
    pub organization_id: String,
}
