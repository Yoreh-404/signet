use crate::db::PublicInvitation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub(super) struct OrganizationOptionResponse {
    pub(super) id: String,
    pub(super) slug: String,
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) is_active: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct OrganizationInput {
    pub(super) slug: String,
    pub(super) name: String,
    pub(super) description: Option<String>,
    #[serde(default)]
    pub(super) allowed_email_domains: Vec<String>,
    pub(super) is_active: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct OrganizationMemberPayload {
    #[serde(default)]
    pub(super) user_id: Option<String>,
    #[serde(default)]
    pub(super) email: Option<String>,
    pub(super) role: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct OrganizationMembersInput {
    pub(super) members: Vec<OrganizationMemberPayload>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OrganizationMemberInvitationInput {
    pub(super) email: String,
    #[serde(default)]
    pub(super) display_name: Option<String>,
    #[serde(default)]
    pub(super) description: Option<String>,
    pub(super) expires_at: i64,
    #[serde(default = "super::default_organization_role")]
    pub(super) organization_role: String,
    #[serde(default = "super::default_true")]
    pub(super) is_active: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct OrganizationMemberInvitationCreateResponse {
    pub(super) invitation: PublicInvitation,
    pub(super) code: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct OrganizationResponse {
    pub(crate) id: String,
    pub(crate) slug: String,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) description: Option<String>,
    pub(crate) allowed_email_domains: Vec<String>,
    pub(crate) is_active: bool,
    pub(crate) member_count: i64,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct OrganizationMemberResponse {
    pub(crate) organization_id: String,
    pub(crate) user_id: String,
    pub(crate) role: String,
    pub(crate) email: String,
    pub(crate) username: String,
    pub(crate) display_name: Option<String>,
    pub(crate) is_active: bool,
    pub(crate) archived_at: Option<i64>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}
