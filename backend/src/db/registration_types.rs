use diesel::sql_types::{BigInt, Integer, Text};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, diesel::QueryableByName, Serialize, Deserialize)]
pub struct RegistrationSettingsRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Integer)]
    pub allow_password_registration: i32,
    #[diesel(sql_type = Integer)]
    pub require_email_verification: i32,
    #[diesel(sql_type = Integer)]
    pub require_phone_verification: i32,
    #[diesel(sql_type = Integer)]
    pub allow_external_oidc_registration: i32,
    #[diesel(sql_type = Integer)]
    pub require_invitation: i32,
    #[diesel(sql_type = Integer)]
    pub first_user_direct_admin: i32,
    #[diesel(sql_type = Integer)]
    pub default_user_active: i32,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicRegistrationSettings {
    pub allow_password_registration: bool,
    pub require_email_verification: bool,
    pub require_phone_verification: bool,
    pub allow_external_oidc_registration: bool,
    pub require_invitation: bool,
    pub first_user_direct_admin: bool,
    pub default_user_active: bool,
}

pub const FIRST_REGISTERED_USER_IS_ADMIN: bool = true;

pub fn registered_user_is_admin(first_user: bool) -> bool {
    first_user && FIRST_REGISTERED_USER_IS_ADMIN
}

impl RegistrationSettingsRecord {
    pub fn public(&self) -> PublicRegistrationSettings {
        PublicRegistrationSettings {
            allow_password_registration: self.allow_password_registration == 1,
            require_email_verification: self.require_email_verification == 1,
            require_phone_verification: self.require_phone_verification == 1,
            allow_external_oidc_registration: self.allow_external_oidc_registration == 1,
            require_invitation: self.require_invitation == 1,
            first_user_direct_admin: FIRST_REGISTERED_USER_IS_ADMIN,
            default_user_active: self.default_user_active == 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewRegistrationSettings {
    pub allow_password_registration: bool,
    pub require_email_verification: bool,
    pub require_phone_verification: bool,
    pub allow_external_oidc_registration: bool,
    pub require_invitation: bool,
    pub first_user_direct_admin: bool,
    pub default_user_active: bool,
}
