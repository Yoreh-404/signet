use diesel::sql_types::{BigInt, Integer, Nullable, Text};

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct PermissionRow {
    #[diesel(sql_type = Text)]
    pub permission: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct CountRow {
    #[diesel(sql_type = BigInt)]
    pub count: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct TotalRow {
    #[diesel(sql_type = BigInt)]
    pub total: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct GroupMemberLifecycleRow {
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub archived_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct GroupMemberIdRow {
    #[diesel(sql_type = Text)]
    pub user_id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct StringIdRow {
    #[diesel(sql_type = Text)]
    pub id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct ApplicationDiscoveryMigrationRow {
    #[diesel(sql_type = Text)]
    pub application_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub protocols_config_json: Option<String>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct UserEmailIdRow {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub email: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct UserIdentityConflictRow {
    #[diesel(sql_type = Text)]
    pub email: String,
    #[diesel(sql_type = Text)]
    pub username: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct BrowserContextAccountOptionRow {
    #[diesel(sql_type = Text)]
    pub account_id: String,
    #[diesel(sql_type = Text)]
    pub account_browser_context_id: String,
    #[diesel(sql_type = Text)]
    pub account_user_id: String,
    #[diesel(sql_type = Text)]
    pub account_session_id: String,
    #[diesel(sql_type = BigInt)]
    pub account_added_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub account_last_selected_at: Option<i64>,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub user_email: String,
    #[diesel(sql_type = Text)]
    pub user_username: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_display_name: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_phone: Option<String>,
    #[diesel(sql_type = Text)]
    pub user_password_hash: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub user_email_verified_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub user_phone_verified_at: Option<i64>,
    #[diesel(sql_type = Integer)]
    pub user_is_admin: i32,
    #[diesel(sql_type = Integer)]
    pub user_is_active: i32,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub user_archived_at: Option<i64>,
    #[diesel(sql_type = Text)]
    pub user_registration_source: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub user_last_login_at: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_last_login_ip: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_last_oidc_client_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub user_last_login_method: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub user_created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub user_updated_at: i64,
    #[diesel(sql_type = Text)]
    pub session_id: String,
    #[diesel(sql_type = Text)]
    pub session_user_id: String,
    #[diesel(sql_type = Text)]
    pub session_csrf_token: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub session_ip_address: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub session_user_agent: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub session_login_method: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub session_expires_at: i64,
    #[diesel(sql_type = BigInt)]
    pub session_created_at: i64,
    #[diesel(sql_type = Nullable<Text>)]
    pub trial_user_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub trial_invitation_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub trial_organization_id: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub trial_organization_role: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub trial_allowed_client_ids: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub trial_expires_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub trial_revoked_at: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub trial_created_at: Option<i64>,
    #[diesel(sql_type = Integer)]
    pub has_authorization_code_redemption: i32,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct ApplicationAuthorizationProfileCountRow {
    #[diesel(sql_type = Text)]
    pub profile_id: String,
    #[diesel(sql_type = BigInt)]
    pub permission_count: i64,
    #[diesel(sql_type = BigInt)]
    pub role_count: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(crate) struct UpdatedAtRow {
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}
