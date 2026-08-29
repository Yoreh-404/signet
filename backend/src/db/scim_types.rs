use diesel::sql_types::{Nullable, Text};

use super::scim::ScimUserMutationScope;

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ScimGroupMemberRecord {
    #[diesel(sql_type = Text)]
    pub group_id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub username: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GroupPatchPlan {
    pub application_id: Option<String>,
    pub group_id: String,
    pub name: String,
    pub description: Option<String>,
    pub member_ids: Vec<String>,
    pub create: bool,
    pub expected_version: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ScimUserMutationPlan {
    pub id: String,
    pub expected_version: String,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub is_admin: bool,
    pub is_active: bool,
    pub password_hash: Option<String>,
    pub scope: Option<ScimUserMutationScope>,
}
