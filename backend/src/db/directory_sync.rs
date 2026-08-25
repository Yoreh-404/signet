//! Transaction-scoped directory synchronization persistence.
//!
//! The LDAP connector produces a complete, validated snapshot.  This module
//! is the only place that publishes that snapshot: all account, membership,
//! group, and mapping changes share one database transaction.  Keeping the
//! aggregate here avoids leaking provider protocol details into the generic
//! database methods and prevents a failed reconcile from leaving a half-sync.

use super::{
    CountRow, Db, DirectorySyncGroupRecord, DirectorySyncMembershipRecord, DirectorySyncRunRecord,
    LinkedIdentityRecord, UserRecord, UserRegistrationSource, bind_text_list, blocking, ph,
    select_user_sql,
};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
    organizations::ROLE_MEMBER,
    util,
};
use diesel::{
    Connection, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};
use std::collections::{BTreeMap, BTreeSet};

// Keep every variable-length read well below SQLite's default variable limit
// while leaving the same query shape usable by PostgreSQL and MySQL. Queries
// with fixed arguments add those arguments to this budget explicitly.
const DIRECTORY_SYNC_BATCH_SIZE: usize = 400;
const DIRECTORY_SYNC_WRITE_BATCH_SIZE: usize = 32;

#[derive(Debug, Clone)]
pub struct DirectorySyncUserPlan {
    pub subject: String,
    pub dn: String,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    /// Existing directory identities do not need a password hash.  The DB
    /// aggregate generates one only when this row becomes a new local user.
    pub password_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DirectorySyncGroupPlan {
    pub external_id: String,
    pub display_name: String,
    pub member_subjects: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DirectorySyncSnapshotPlan {
    pub users: Vec<DirectorySyncUserPlan>,
    pub groups: Vec<DirectorySyncGroupPlan>,
}

#[derive(Debug, Clone)]
pub struct DirectorySyncApplyContext {
    pub application_id: String,
    pub provider_id: String,
    pub run_id: String,
    pub provider_key: String,
    pub organization_id: String,
    pub provider_display_name: String,
    pub reactivate_users: bool,
    /// Control-plane revisions captured before the LDAP snapshot.  The
    /// production runner supplies these so disabling or moving a resource
    /// while LDAP is being read fences the publish transaction.  `None` is
    /// retained for backend-neutral fixture callers that model only the
    /// persistence aggregate.
    pub expected_application_updated_at: Option<i64>,
    pub expected_provider_updated_at: Option<i64>,
    pub expected_organization_updated_at: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct DirectorySyncApplyStats {
    pub total_seen: i64,
    pub created_count: i64,
    pub updated_count: i64,
    pub disabled_count: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct ArchivedGroupMemberRow {
    #[diesel(sql_type = Text)]
    group_id: String,
    #[diesel(sql_type = Text)]
    user_id: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    archived_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct UserIdentityKeyRow {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    email: String,
    #[diesel(sql_type = Text)]
    username: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct UserIdRow {
    #[diesel(sql_type = Text)]
    user_id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct ProviderUserSubjectRow {
    #[diesel(sql_type = Text)]
    user_id: String,
    #[diesel(sql_type = Text)]
    external_subject: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
struct OrganizationMemberUpdatedAtRow {
    #[diesel(sql_type = Text)]
    user_id: String,
    #[diesel(sql_type = BigInt)]
    updated_at: i64,
}

#[derive(Debug, Clone, Copy)]
enum UserIdentityColumn {
    Email,
    Username,
}

impl UserIdentityColumn {
    fn sql(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Username => "username",
        }
    }
}

#[derive(Debug, Clone)]
struct PendingUserUpdate {
    user: UserRecord,
}

#[derive(Debug, Clone)]
struct PendingLinkedIdentity {
    user_id: String,
    provider_key: String,
    subject: String,
    email: String,
}

#[derive(Debug, Clone)]
struct PendingMembership {
    user_id: String,
    managed: bool,
    existing: bool,
}

#[derive(Debug, Clone)]
struct PendingGroup {
    external_id: String,
    group_id: String,
    display_name: String,
    member_ids: Vec<String>,
    is_new: bool,
}

fn text_placeholders(kind: DatabaseKind, start: usize, count: usize) -> String {
    (start..start + count)
        .map(|index| ph(kind, index))
        .collect::<Vec<_>>()
        .join(", ")
}

macro_rules! load_linked_identities_by_subjects {
    ($conn:expr, $kind:expr, $provider_key:expr, $subjects:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let provider_key = $provider_key;
        let subjects = $subjects;
    let mut identities = BTreeMap::new();
    for chunk in subjects.chunks(DIRECTORY_SYNC_BATCH_SIZE) {
        if chunk.is_empty() {
            continue;
        }
        let mut values = Vec::with_capacity(chunk.len() + 1);
        values.push(provider_key.to_string());
        values.extend(chunk.iter().cloned());
        let sql = format!(
            "SELECT id, user_id, provider_slug, external_subject, external_email, created_at, updated_at FROM linked_identities WHERE provider_slug = {} AND external_subject IN ({})",
            ph(kind, 1),
            text_placeholders(kind, 2, chunk.len())
        );
        let rows = bind_text_list(conn, sql_query(sql), &values)
            .load::<LinkedIdentityRecord>(conn)
            .map_err(AppError::from)?;
        for identity in rows {
            identities.insert(identity.external_subject.clone(), identity);
        }
    }
        Ok::<BTreeMap<String, LinkedIdentityRecord>, AppError>(identities)
    }};
}

macro_rules! load_users_by_ids {
    ($conn:expr, $kind:expr, $user_ids:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let user_ids = $user_ids;
        let mut users = BTreeMap::new();
        for chunk in user_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let sql = format!(
                "{} WHERE id IN ({})",
                select_user_sql(),
                text_placeholders(kind, 1, chunk.len())
            );
            let rows = bind_text_list(conn, sql_query(sql), chunk)
                .load::<UserRecord>(conn)
                .map_err(AppError::from)?;
            for user in rows {
                users.insert(user.id.clone(), user);
            }
        }
        Ok::<BTreeMap<String, UserRecord>, AppError>(users)
    }};
}

macro_rules! load_user_identity_rows {
    ($conn:expr, $kind:expr, $column:expr, $values:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let column = $column;
        let values = $values;
        let mut rows = Vec::new();
        for chunk in values.chunks(DIRECTORY_SYNC_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let sql = format!(
                "SELECT id, email, username FROM users WHERE {} IN ({})",
                column.sql(),
                text_placeholders(kind, 1, chunk.len())
            );
            rows.extend(
                bind_text_list(conn, sql_query(sql), chunk)
                    .load::<UserIdentityKeyRow>(conn)
                    .map_err(AppError::from)?,
            );
        }
        Ok::<Vec<UserIdentityKeyRow>, AppError>(rows)
    }};
}

macro_rules! load_identity_owner_maps {
    ($conn:expr, $kind:expr, $emails:expr, $usernames:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let emails = $emails;
        let usernames = $usernames;
        let mut email_owners = BTreeMap::new();
        let mut username_owners = BTreeMap::new();
        for (column, values) in [
            (UserIdentityColumn::Email, emails),
            (UserIdentityColumn::Username, usernames),
        ] {
            for row in load_user_identity_rows!(conn, kind, column, values)? {
                email_owners.insert(row.email.clone(), row.id.clone());
                username_owners.insert(row.username.clone(), row.id);
            }
        }
        Ok::<(BTreeMap<String, String>, BTreeMap<String, String>), AppError>((
            email_owners,
            username_owners,
        ))
    }};
}

macro_rules! load_organization_member_ids {
    ($conn:expr, $kind:expr, $organization_id:expr, $user_ids:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let organization_id = $organization_id;
        let user_ids = $user_ids;
    let mut member_ids = BTreeSet::new();
    for chunk in user_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE - 1) {
        if chunk.is_empty() {
            continue;
        }
        let mut values = vec![organization_id.to_string()];
        values.extend(chunk.iter().cloned());
        let sql = format!(
            "SELECT user_id FROM organization_members WHERE organization_id = {} AND user_id IN ({})",
            ph(kind, 1),
            text_placeholders(kind, 2, chunk.len())
        );
        for row in bind_text_list(conn, sql_query(sql), &values)
            .load::<UserIdRow>(conn)
            .map_err(AppError::from)?
        {
            member_ids.insert(row.user_id);
        }
    }
        Ok::<BTreeSet<String>, AppError>(member_ids)
    }};
}

macro_rules! load_provider_subjects_by_user_ids {
    ($conn:expr, $kind:expr, $provider_key:expr, $user_ids:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let provider_key = $provider_key;
        let user_ids = $user_ids;
    let mut subjects_by_user = BTreeMap::<String, BTreeSet<String>>::new();
    for chunk in user_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE - 1) {
        if chunk.is_empty() {
            continue;
        }
        let mut values = vec![provider_key.to_string()];
        values.extend(chunk.iter().cloned());
        let sql = format!(
            "SELECT user_id, external_subject FROM linked_identities WHERE provider_slug = {} AND user_id IN ({})",
            ph(kind, 1),
            text_placeholders(kind, 2, chunk.len())
        );
        for row in bind_text_list(conn, sql_query(sql), &values)
            .load::<ProviderUserSubjectRow>(conn)
            .map_err(AppError::from)?
        {
            subjects_by_user
                .entry(row.user_id)
                .or_default()
                .insert(row.external_subject);
        }
    }
        Ok::<BTreeMap<String, BTreeSet<String>>, AppError>(subjects_by_user)
    }};
}

macro_rules! load_organization_member_updated_at {
    ($conn:expr, $kind:expr, $organization_id:expr, $user_ids:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let organization_id = $organization_id;
        let user_ids = $user_ids;
    let mut updated_at_by_user = BTreeMap::new();
    for chunk in user_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE - 1) {
        if chunk.is_empty() {
            continue;
        }
        let mut values = vec![organization_id.to_string()];
        values.extend(chunk.iter().cloned());
        let sql = format!(
            "SELECT user_id, updated_at FROM organization_members WHERE organization_id = {} AND user_id IN ({})",
            ph(kind, 1),
            text_placeholders(kind, 2, chunk.len())
        );
        for row in bind_text_list(conn, sql_query(sql), &values)
            .load::<OrganizationMemberUpdatedAtRow>(conn)
            .map_err(AppError::from)?
        {
            updated_at_by_user.insert(row.user_id, row.updated_at);
        }
    }
        Ok::<BTreeMap<String, i64>, AppError>(updated_at_by_user)
    }};
}

macro_rules! load_other_managed_owner_ids {
    ($conn:expr, $kind:expr, $application_id:expr, $provider_id:expr, $organization_id:expr, $user_ids:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let application_id = $application_id;
        let provider_id = $provider_id;
        let organization_id = $organization_id;
        let user_ids = $user_ids;
    let mut owner_ids = BTreeSet::new();
    for chunk in user_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE - 3) {
        if chunk.is_empty() {
            continue;
        }
        let mut values = chunk.to_vec();
        values.push(organization_id.to_string());
        values.push(application_id.to_string());
        values.push(provider_id.to_string());
        let sql = format!(
            "SELECT directory_sync_memberships.user_id AS user_id FROM directory_sync_memberships INNER JOIN applications ON applications.id = directory_sync_memberships.application_id WHERE directory_sync_memberships.user_id IN ({}) AND directory_sync_memberships.managed = 1 AND applications.organization_id = {} AND NOT (directory_sync_memberships.application_id = {} AND directory_sync_memberships.provider_id = {}) GROUP BY directory_sync_memberships.user_id",
            text_placeholders(kind, 1, chunk.len()),
            ph(kind, chunk.len() + 1),
            ph(kind, chunk.len() + 2),
            ph(kind, chunk.len() + 3)
        );
        for row in bind_text_list(conn, sql_query(sql), &values)
            .load::<UserIdRow>(conn)
            .map_err(AppError::from)?
        {
            owner_ids.insert(row.user_id);
        }
    }
        Ok::<BTreeSet<String>, AppError>(owner_ids)
    }};
}

macro_rules! load_group_mappings_by_external_ids {
    ($conn:expr, $kind:expr, $application_id:expr, $provider_id:expr, $external_ids:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let application_id = $application_id;
        let provider_id = $provider_id;
        let external_ids = $external_ids;
    let mut mappings = BTreeMap::new();
    for chunk in external_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE - 2) {
        if chunk.is_empty() {
            continue;
        }
        let mut values = vec![application_id.to_string(), provider_id.to_string()];
        values.extend(chunk.iter().cloned());
        let sql = format!(
            "SELECT application_id, provider_id, external_id, group_id, last_seen_at, created_at, updated_at FROM directory_sync_groups WHERE application_id = {} AND provider_id = {} AND external_id IN ({})",
            ph(kind, 1),
            ph(kind, 2),
            text_placeholders(kind, 3, chunk.len())
        );
        for mapping in bind_text_list(conn, sql_query(sql), &values)
            .load::<DirectorySyncGroupRecord>(conn)
            .map_err(AppError::from)?
        {
            mappings.insert(mapping.external_id.clone(), mapping);
        }
    }
        Ok::<BTreeMap<String, DirectorySyncGroupRecord>, AppError>(mappings)
    }};
}

macro_rules! load_archived_group_members_by_group_ids {
    ($conn:expr, $kind:expr, $organization_id:expr, $group_ids:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let organization_id = $organization_id;
        let group_ids = $group_ids;
    let mut archived_by_group = BTreeMap::<String, BTreeSet<String>>::new();
    for chunk in group_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE - 1) {
        if chunk.is_empty() {
            continue;
        }
        let mut values = vec![organization_id.to_string()];
        values.extend(chunk.iter().cloned());
        let sql = format!(
            "SELECT group_members.group_id AS group_id, users.id AS user_id, users.archived_at FROM users INNER JOIN group_members ON group_members.user_id = users.id INNER JOIN organization_members ON organization_members.user_id = users.id WHERE organization_members.organization_id = {} AND group_members.group_id IN ({})",
            ph(kind, 1),
            text_placeholders(kind, 2, chunk.len())
        );
        for row in bind_text_list(conn, sql_query(sql), &values)
            .load::<ArchivedGroupMemberRow>(conn)
            .map_err(AppError::from)?
        {
            if row.archived_at.is_some() {
                archived_by_group
                    .entry(row.group_id)
                    .or_default()
                    .insert(row.user_id);
            }
        }
    }
        Ok::<BTreeMap<String, BTreeSet<String>>, AppError>(archived_by_group)
    }};
}

fn ensure_preloaded_identity_available(
    email_owners: &BTreeMap<String, String>,
    username_owners: &BTreeMap<String, String>,
    email: &str,
    username: &str,
    exclude_user_id: Option<&str>,
) -> AppResult<()> {
    let email_taken = email_owners
        .get(email)
        .is_some_and(|owner| Some(owner.as_str()) != exclude_user_id);
    let username_taken = username_owners
        .get(username)
        .is_some_and(|owner| Some(owner.as_str()) != exclude_user_id);
    if email_taken || username_taken {
        return Err(AppError::BadRequest(
            "user email or username already exists".to_string(),
        ));
    }
    Ok(())
}

fn replace_identity_owner(
    owners: &mut BTreeMap<String, String>,
    old_value: &str,
    new_value: &str,
    user_id: &str,
) {
    if old_value != new_value && owners.get(old_value).is_some_and(|owner| owner == user_id) {
        owners.remove(old_value);
    }
    owners.insert(new_value.to_string(), user_id.to_string());
}

macro_rules! delete_application_group_binding {
    ($conn:expr, $kind:expr, $application_id:expr, $group_id:expr $(,)?) => {{
        let role_sql = format!(
            "DELETE FROM application_profile_group_roles WHERE profile_id IN (SELECT id FROM application_authorization_profiles WHERE application_id = {}) AND group_id = {}",
            ph($kind, 1),
            ph($kind, 2)
        );
        sql_query(role_sql)
            .bind::<Text, _>($application_id.to_string())
            .bind::<Text, _>($group_id.to_string())
            .execute($conn)
            .map_err(AppError::from)?;
        let binding_sql = format!(
            "DELETE FROM application_scim_groups WHERE application_id = {} AND group_id = {}",
            ph($kind, 1),
            ph($kind, 2)
        );
        sql_query(binding_sql)
            .bind::<Text, _>($application_id.to_string())
            .bind::<Text, _>($group_id.to_string())
            .execute($conn)
            .map_err(AppError::from)?;
        let scim_sql = format!(
            "SELECT COUNT(*) AS count FROM application_scim_groups WHERE group_id = {}",
            ph($kind, 1)
        );
        let scim_references = sql_query(scim_sql)
            .bind::<Text, _>($group_id.to_string())
            .get_result::<CountRow>($conn)
            .map_err(AppError::from)?
            .count;
        let profile_role_ref_sql = format!(
            "SELECT COUNT(*) AS count FROM application_profile_group_roles WHERE group_id = {}",
            ph($kind, 1)
        );
        let profile_role_references = sql_query(profile_role_ref_sql)
            .bind::<Text, _>($group_id.to_string())
            .get_result::<CountRow>($conn)
            .map_err(AppError::from)?
            .count;
        let directory_ref_sql = format!(
            "SELECT COUNT(*) AS count FROM directory_sync_groups WHERE group_id = {}",
            ph($kind, 1)
        );
        let directory_references = sql_query(directory_ref_sql)
            .bind::<Text, _>($group_id.to_string())
            .get_result::<CountRow>($conn)
            .map_err(AppError::from)?
            .count;
        if scim_references == 0
            && profile_role_references == 0
            && directory_references == 0
        {
            for table in ["group_members", "group_roles"] {
                let sql = format!("DELETE FROM {table} WHERE group_id = {}", ph($kind, 1));
                sql_query(sql)
                    .bind::<Text, _>($group_id.to_string())
                    .execute($conn)
                    .map_err(AppError::from)?;
            }
            let delete_group_sql = format!("DELETE FROM access_groups WHERE id = {}", ph($kind, 1));
            sql_query(delete_group_sql)
                .bind::<Text, _>($group_id.to_string())
                .execute($conn)
                .map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

fn case_expression(kind: DatabaseKind, start: usize, count: usize) -> (String, usize) {
    let end = start + count * 2;
    let expression = (0..count)
        .map(|offset| {
            format!(
                "WHEN {} THEN {}",
                ph(kind, start + offset * 2),
                ph(kind, start + offset * 2 + 1)
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    (expression, end)
}

macro_rules! clear_auth_state_batch {
    ($conn:expr, $kind:expr, $user_ids:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let user_ids = $user_ids;
        for chunk in user_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            for table in ["session_credentials", "browser_context_accounts"] {
                let sql = format!(
                    "DELETE FROM {table} WHERE session_id IN (SELECT id FROM sessions WHERE user_id IN ({}))",
                    text_placeholders(kind, 1, chunk.len())
                );
                bind_text_list(conn, sql_query(sql), chunk)
                    .execute(conn)
                    .map_err(AppError::from)?;
            }
            for (table, column) in [
                ("sessions", "user_id"),
                ("authorization_codes", "user_id"),
                ("oidc_login_grants", "user_id"),
                ("refresh_tokens", "user_id"),
                ("device_authorizations", "authorized_user_id"),
                ("webauthn_challenges", "user_id"),
            ] {
                let sql = format!(
                    "DELETE FROM {table} WHERE {column} IN ({})",
                    text_placeholders(kind, 1, chunk.len())
                );
                bind_text_list(conn, sql_query(sql), chunk)
                    .execute(conn)
                    .map_err(AppError::from)?;
            }
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! clear_application_bindings_batch {
    ($conn:expr, $kind:expr, $user_ids:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let user_ids = $user_ids;
        for chunk in user_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let sql = format!(
                "DELETE FROM application_identity_bindings WHERE user_id IN ({})",
                text_placeholders(kind, 1, chunk.len())
            );
            bind_text_list(conn, sql_query(sql), chunk)
                .execute(conn)
                .map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! clear_factor_bindings_batch {
    ($conn:expr, $kind:expr, $user_ids:expr, $factor_type:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let user_ids = $user_ids;
        for chunk in user_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE - 1) {
            if chunk.is_empty() {
                continue;
            }
            let sql = format!(
                "DELETE FROM application_identity_bindings WHERE user_id IN ({}) AND factor_type = {}",
                text_placeholders(kind, 1, chunk.len()),
                ph(kind, chunk.len() + 1)
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            for user_id in chunk {
                query = query.bind::<Text, _>(user_id.clone());
            }
            query = query.bind::<Text, _>($factor_type.to_string());
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! update_users_batch {
    ($conn:expr, $kind:expr, $updates:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let updates = $updates;
        for chunk in updates.chunks(DIRECTORY_SYNC_WRITE_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let mut next = 1;
            let (email_case, after_email) = case_expression(kind, next, chunk.len());
            next = after_email;
            let (username_case, after_username) = case_expression(kind, next, chunk.len());
            next = after_username;
            let (display_name_case, after_display_name) =
                case_expression(kind, next, chunk.len());
            next = after_display_name;
            let (phone_case, after_phone) = case_expression(kind, next, chunk.len());
            next = after_phone;
            let (email_verified_case, after_email_verified) =
                case_expression(kind, next, chunk.len());
            next = after_email_verified;
            let (phone_verified_case, after_phone_verified) =
                case_expression(kind, next, chunk.len());
            next = after_phone_verified;
            let (active_case, after_active) = case_expression(kind, next, chunk.len());
            next = after_active;
            let now_placeholder = ph(kind, next);
            next += 1;
            let ids = text_placeholders(kind, next, chunk.len());
            let sql = format!(
                "UPDATE users SET email = CASE id {email_case} ELSE email END, username = CASE id {username_case} ELSE username END, display_name = CASE id {display_name_case} ELSE display_name END, phone = CASE id {phone_case} ELSE phone END, email_verified_at = CASE id {email_verified_case} ELSE email_verified_at END, phone_verified_at = CASE id {phone_verified_case} ELSE phone_verified_at END, is_active = CASE id {active_case} ELSE is_active END, updated_at = {now_placeholder} WHERE id IN ({ids})"
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            for update in chunk {
                query = query
                    .bind::<Text, _>(update.user.id.clone())
                    .bind::<Text, _>(update.user.email.clone());
            }
            for update in chunk {
                query = query
                    .bind::<Text, _>(update.user.id.clone())
                    .bind::<Text, _>(update.user.username.clone());
            }
            for update in chunk {
                query = query
                    .bind::<Text, _>(update.user.id.clone())
                    .bind::<Nullable<Text>, _>(update.user.display_name.clone());
            }
            for update in chunk {
                query = query
                    .bind::<Text, _>(update.user.id.clone())
                    .bind::<Nullable<Text>, _>(update.user.phone.clone());
            }
            for update in chunk {
                query = query
                    .bind::<Text, _>(update.user.id.clone())
                    .bind::<Nullable<BigInt>, _>(update.user.email_verified_at);
            }
            for update in chunk {
                query = query
                    .bind::<Text, _>(update.user.id.clone())
                    .bind::<Nullable<BigInt>, _>(update.user.phone_verified_at);
            }
            for update in chunk {
                query = query
                    .bind::<Text, _>(update.user.id.clone())
                    .bind::<Integer, _>(update.user.is_active);
            }
            query = query.bind::<BigInt, _>($now);
            for update in chunk {
                query = query.bind::<Text, _>(update.user.id.clone());
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! insert_users_batch {
    ($conn:expr, $kind:expr, $users:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let users = $users;
        for chunk in users.chunks(DIRECTORY_SYNC_WRITE_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let mut next = 1;
            let rows = chunk
                .iter()
                .map(|_| {
                    let row = format!(
                        "({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, '{}', {}, {}, {}, {}, {}, {})",
                        ph(kind, next),
                        ph(kind, next + 1),
                        ph(kind, next + 2),
                        ph(kind, next + 3),
                        ph(kind, next + 4),
                        ph(kind, next + 5),
                        ph(kind, next + 6),
                        ph(kind, next + 7),
                        ph(kind, next + 8),
                        ph(kind, next + 9),
                        ph(kind, next + 10),
                        UserRegistrationSource::Local.as_str(),
                        ph(kind, next + 11),
                        ph(kind, next + 12),
                        ph(kind, next + 13),
                        ph(kind, next + 14),
                        ph(kind, next + 15),
                        ph(kind, next + 16),
                    );
                    next += 17;
                    row
                })
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "INSERT INTO users (id, email, username, display_name, phone, password_hash, email_verified_at, phone_verified_at, is_admin, is_active, archived_at, registration_source, last_login_at, last_login_ip, last_oidc_client_id, last_login_method, created_at, updated_at) VALUES {rows}"
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            for user in chunk {
                query = query
                    .bind::<Text, _>(user.id.clone())
                    .bind::<Text, _>(user.email.clone())
                    .bind::<Text, _>(user.username.clone())
                    .bind::<Nullable<Text>, _>(user.display_name.clone())
                    .bind::<Nullable<Text>, _>(user.phone.clone())
                    .bind::<Text, _>(user.password_hash.clone())
                    .bind::<Nullable<BigInt>, _>(user.email_verified_at)
                    .bind::<Nullable<BigInt>, _>(user.phone_verified_at)
                    .bind::<Integer, _>(user.is_admin)
                    .bind::<Integer, _>(user.is_active)
                    .bind::<Nullable<BigInt>, _>(user.archived_at)
                    .bind::<Nullable<BigInt>, _>(user.last_login_at)
                    .bind::<Nullable<Text>, _>(user.last_login_ip.clone())
                    .bind::<Nullable<Text>, _>(user.last_oidc_client_id.clone())
                    .bind::<Nullable<Text>, _>(user.last_login_method.clone())
                    .bind::<BigInt, _>(user.created_at)
                    .bind::<BigInt, _>(user.updated_at);
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! insert_linked_identities_batch {
    ($conn:expr, $kind:expr, $identities:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let identities = $identities;
        for chunk in identities.chunks(DIRECTORY_SYNC_WRITE_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let rows = chunk
                .iter()
                .enumerate()
                .map(|(offset, _)| {
                    let start = offset * 7 + 1;
                    format!(
                        "({}, {}, {}, {}, {}, {}, {})",
                        ph(kind, start),
                        ph(kind, start + 1),
                        ph(kind, start + 2),
                        ph(kind, start + 3),
                        ph(kind, start + 4),
                        ph(kind, start + 5),
                        ph(kind, start + 6),
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "INSERT INTO linked_identities (id, user_id, provider_slug, external_subject, external_email, created_at, updated_at) VALUES {rows}"
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            for identity in chunk {
                query = query
                    .bind::<Text, _>(uuid::Uuid::new_v4().to_string())
                    .bind::<Text, _>(identity.user_id.clone())
                    .bind::<Text, _>(identity.provider_key.clone())
                    .bind::<Text, _>(identity.subject.clone())
                    .bind::<Nullable<Text>, _>(Some(identity.email.clone()))
                    .bind::<BigInt, _>($now)
                    .bind::<BigInt, _>($now);
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! insert_organization_members_batch {
    ($conn:expr, $kind:expr, $organization_id:expr, $user_ids:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let organization_id = $organization_id;
        let user_ids = $user_ids;
        for chunk in user_ids.chunks(DIRECTORY_SYNC_WRITE_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let rows = chunk
                .iter()
                .enumerate()
                .map(|(offset, _)| {
                    let start = offset * 7 + 1;
                    format!(
                        "SELECT {}, {}, {}, {}, {} WHERE NOT EXISTS (SELECT 1 FROM organization_members WHERE organization_id = {} AND user_id = {})",
                        ph(kind, start),
                        ph(kind, start + 1),
                        ph(kind, start + 2),
                        ph(kind, start + 3),
                        ph(kind, start + 4),
                        ph(kind, start + 5),
                        ph(kind, start + 6),
                    )
                })
                .collect::<Vec<_>>()
                .join(" UNION ALL ");
            let sql = format!(
                "INSERT INTO organization_members (organization_id, user_id, role, created_at, updated_at) {rows}"
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            for user_id in chunk {
                query = query
                    .bind::<Text, _>(organization_id.to_string())
                    .bind::<Text, _>(user_id.clone())
                    .bind::<Text, _>(ROLE_MEMBER)
                    .bind::<BigInt, _>($now)
                    .bind::<BigInt, _>($now)
                    .bind::<Text, _>(organization_id.to_string())
                    .bind::<Text, _>(user_id.clone());
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! update_sync_memberships_batch {
    ($conn:expr, $kind:expr, $application_id:expr, $provider_id:expr, $user_ids:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let user_ids = $user_ids;
        for chunk in user_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE - 2) {
            if chunk.is_empty() {
                continue;
            }
            let sql = format!(
                "UPDATE directory_sync_memberships SET last_seen_at = {}, updated_at = {} WHERE application_id = {} AND provider_id = {} AND user_id IN ({})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                text_placeholders(kind, 5, chunk.len()),
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            query = query
                .bind::<BigInt, _>($now)
                .bind::<BigInt, _>($now)
                .bind::<Text, _>($application_id.to_string())
                .bind::<Text, _>($provider_id.to_string());
            for user_id in chunk {
                query = query.bind::<Text, _>(user_id.clone());
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! insert_sync_memberships_batch {
    ($conn:expr, $kind:expr, $application_id:expr, $provider_id:expr, $memberships:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let memberships = $memberships;
        for chunk in memberships.chunks(DIRECTORY_SYNC_WRITE_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let rows = chunk
                .iter()
                .enumerate()
                .map(|(offset, _)| {
                    let start = offset * 7 + 1;
                    format!(
                        "({}, {}, {}, {}, {}, {}, {})",
                        ph(kind, start),
                        ph(kind, start + 1),
                        ph(kind, start + 2),
                        ph(kind, start + 3),
                        ph(kind, start + 4),
                        ph(kind, start + 5),
                        ph(kind, start + 6),
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "INSERT INTO directory_sync_memberships (application_id, provider_id, user_id, managed, last_seen_at, created_at, updated_at) VALUES {rows}"
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            for membership in chunk {
                query = query
                    .bind::<Text, _>($application_id.to_string())
                    .bind::<Text, _>($provider_id.to_string())
                    .bind::<Text, _>(membership.user_id.clone())
                    .bind::<Integer, _>(i32::from(membership.managed))
                    .bind::<BigInt, _>($now)
                    .bind::<BigInt, _>($now)
                    .bind::<BigInt, _>($now);
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! delete_sync_memberships_batch {
    ($conn:expr, $kind:expr, $application_id:expr, $provider_id:expr, $user_ids:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let user_ids = $user_ids;
        for chunk in user_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE - 2) {
            if chunk.is_empty() {
                continue;
            }
            let sql = format!(
                "DELETE FROM directory_sync_memberships WHERE application_id = {} AND provider_id = {} AND user_id IN ({})",
                ph(kind, 1),
                ph(kind, 2),
                text_placeholders(kind, 3, chunk.len()),
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            query = query
                .bind::<Text, _>($application_id.to_string())
                .bind::<Text, _>($provider_id.to_string());
            for user_id in chunk {
                query = query.bind::<Text, _>(user_id.clone());
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! delete_organization_memberships_batch {
    ($conn:expr, $kind:expr, $organization_id:expr, $members:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let members = $members;
        for chunk in members.chunks(DIRECTORY_SYNC_WRITE_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let predicates = chunk
                .iter()
                .enumerate()
                .map(|(offset, _)| {
                    let start = offset * 2 + 2;
                    format!(
                        "(user_id = {} AND updated_at = {})",
                        ph(kind, start),
                        ph(kind, start + 1)
                    )
                })
                .collect::<Vec<_>>()
                .join(" OR ");
            let sql = format!(
                "DELETE FROM organization_members WHERE organization_id = {} AND ({predicates})",
                ph(kind, 1)
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            query = query.bind::<Text, _>($organization_id.to_string());
            for (user_id, updated_at) in chunk {
                query = query
                    .bind::<Text, _>(user_id.clone())
                    .bind::<BigInt, _>(*updated_at);
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! insert_groups_batch {
    ($conn:expr, $kind:expr, $groups:expr, $provider_display_name:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let groups = $groups;
        for chunk in groups.chunks(DIRECTORY_SYNC_WRITE_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let rows = chunk
                .iter()
                .enumerate()
                .map(|(offset, _)| {
                    let start = offset * 5 + 1;
                    format!(
                        "({}, {}, {}, {}, {})",
                        ph(kind, start),
                        ph(kind, start + 1),
                        ph(kind, start + 2),
                        ph(kind, start + 3),
                        ph(kind, start + 4),
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "INSERT INTO access_groups (id, name, description, created_at, updated_at) VALUES {rows}"
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            for group in chunk {
                query = query
                    .bind::<Text, _>(group.group_id.clone())
                    .bind::<Text, _>(group.display_name.clone())
                    .bind::<Nullable<Text>, _>(Some(format!(
                        "Synchronized from {}",
                        $provider_display_name
                    )))
                    .bind::<BigInt, _>($now)
                    .bind::<BigInt, _>($now);
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! insert_application_scim_groups_batch {
    ($conn:expr, $kind:expr, $application_id:expr, $groups:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let groups = $groups;
        for chunk in groups.chunks(DIRECTORY_SYNC_WRITE_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let rows = chunk
                .iter()
                .enumerate()
                .map(|(offset, _)| {
                    let start = offset * 3 + 1;
                    format!(
                        "({}, {}, {})",
                        ph(kind, start),
                        ph(kind, start + 1),
                        ph(kind, start + 2),
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "INSERT INTO application_scim_groups (application_id, group_id, created_at) VALUES {rows}"
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            for group in chunk {
                query = query
                    .bind::<Text, _>($application_id.to_string())
                    .bind::<Text, _>(group.group_id.clone())
                    .bind::<BigInt, _>($now);
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! update_groups_batch {
    ($conn:expr, $kind:expr, $groups:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let groups = $groups;
        for chunk in groups.chunks(DIRECTORY_SYNC_WRITE_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let (name_case, after_case) = case_expression(kind, 1, chunk.len());
            let ids = text_placeholders(kind, after_case + 1, chunk.len());
            let now_placeholder = ph(kind, after_case);
            let sql = format!(
                "UPDATE access_groups SET name = CASE id {name_case} ELSE name END, updated_at = {now_placeholder} WHERE id IN ({ids})"
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            for group in chunk {
                query = query
                    .bind::<Text, _>(group.group_id.clone())
                    .bind::<Text, _>(group.display_name.clone());
            }
            query = query.bind::<BigInt, _>($now);
            for group in chunk {
                query = query.bind::<Text, _>(group.group_id.clone());
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! replace_group_members_batch {
    ($conn:expr, $kind:expr, $organization_id:expr, $groups:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let groups = $groups;
        let group_ids = groups
            .iter()
            .map(|group| group.group_id.clone())
            .collect::<Vec<_>>();
        if !group_ids.is_empty() {
            for chunk in group_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE - 1) {
                let sql = format!(
                    "DELETE FROM group_members WHERE group_id IN ({}) AND user_id IN (SELECT user_id FROM organization_members WHERE organization_id = {})",
                    text_placeholders(kind, 1, chunk.len()),
                    ph(kind, chunk.len() + 1),
                );
                let mut query = bind_text_list(conn, sql_query(sql), chunk);
                query = query.bind::<Text, _>($organization_id.to_string());
                query.execute(conn).map_err(AppError::from)?;
            }
        }

        let mut pairs = Vec::new();
        for group in groups {
            for user_id in &group.member_ids {
                pairs.push(group.group_id.clone());
                pairs.push(user_id.clone());
            }
        }
        for chunk in pairs.chunks(DIRECTORY_SYNC_BATCH_SIZE - 2) {
            if chunk.is_empty() {
                continue;
            }
            let rows = (0..chunk.len() / 2)
                .map(|offset| {
                    let start = offset * 2 + 1;
                    format!("({}, {})", ph(kind, start), ph(kind, start + 1))
                })
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!("INSERT INTO group_members (group_id, user_id) VALUES {rows}");
            bind_text_list(conn, sql_query(sql), chunk)
                .execute(conn)
                .map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! update_group_mappings_batch {
    ($conn:expr, $kind:expr, $application_id:expr, $provider_id:expr, $groups:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let groups = $groups;
        let updates = groups
            .iter()
            .filter(|group| !group.is_new)
            .collect::<Vec<_>>();
        for chunk in updates.chunks(DIRECTORY_SYNC_WRITE_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let (group_case, after_case) = case_expression(kind, 1, chunk.len());
            let last_seen_placeholder = ph(kind, after_case);
            let updated_placeholder = ph(kind, after_case + 1);
            let application_placeholder = ph(kind, after_case + 2);
            let provider_placeholder = ph(kind, after_case + 3);
            let external_ids = text_placeholders(kind, after_case + 4, chunk.len());
            let sql = format!(
                "UPDATE directory_sync_groups SET group_id = CASE external_id {group_case} ELSE group_id END, last_seen_at = {last_seen_placeholder}, updated_at = {updated_placeholder} WHERE application_id = {application_placeholder} AND provider_id = {provider_placeholder} AND external_id IN ({external_ids})",
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            for group in chunk {
                query = query
                    .bind::<Text, _>(group.external_id.clone())
                    .bind::<Text, _>(group.group_id.clone());
            }
            query = query
                .bind::<BigInt, _>($now)
                .bind::<BigInt, _>($now)
                .bind::<Text, _>($application_id.to_string())
                .bind::<Text, _>($provider_id.to_string());
            for group in chunk {
                query = query.bind::<Text, _>(group.external_id.clone());
            }
            query.execute(conn).map_err(AppError::from)?;
        }

        let inserts = groups
            .iter()
            .filter(|group| group.is_new)
            .collect::<Vec<_>>();
        for chunk in inserts.chunks(DIRECTORY_SYNC_WRITE_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }
            let rows = chunk
                .iter()
                .enumerate()
                .map(|(offset, _)| {
                    let start = offset * 7 + 1;
                    format!(
                        "({}, {}, {}, {}, {}, {}, {})",
                        ph(kind, start),
                        ph(kind, start + 1),
                        ph(kind, start + 2),
                        ph(kind, start + 3),
                        ph(kind, start + 4),
                        ph(kind, start + 5),
                        ph(kind, start + 6),
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "INSERT INTO directory_sync_groups (application_id, provider_id, external_id, group_id, last_seen_at, created_at, updated_at) VALUES {rows}"
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            for group in chunk {
                query = query
                    .bind::<Text, _>($application_id.to_string())
                    .bind::<Text, _>($provider_id.to_string())
                    .bind::<Text, _>(group.external_id.clone())
                    .bind::<Text, _>(group.group_id.clone())
                    .bind::<BigInt, _>($now)
                    .bind::<BigInt, _>($now)
                    .bind::<BigInt, _>($now);
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

impl Db {
    /// Finalizes a run and its checkpoint only while this run still owns a
    /// live lease.  The ownership check, checkpoint update, run update, and
    /// lease release share one transaction so an expired worker cannot publish
    /// a success (or regress a newer worker's checkpoint).
    pub async fn finalize_directory_sync_run(
        &self,
        application_id: &str,
        provider_id: &str,
        run_id: &str,
        status: &str,
        total_seen: i64,
        created_count: i64,
        updated_count: i64,
        disabled_count: i64,
        error: Option<String>,
        cursor: Option<String>,
    ) -> AppResult<DirectorySyncRunRecord> {
        let application_id = application_id.to_string();
        let provider_id = provider_id.to_string();
        let run_id = run_id.to_string();
        let status = status.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<DirectorySyncRunRecord, AppError, _>(|conn| {
                let update_run_sql = format!(
                    "UPDATE directory_sync_runs SET status = {}, total_seen = {}, created_count = {}, updated_count = {}, disabled_count = {}, error = {}, cursor = {}, finished_at = {} WHERE id = {} AND application_id = {} AND provider_id = {} AND status = 'running' AND EXISTS (SELECT 1 FROM directory_sync_leases WHERE application_id = {} AND provider_id = {} AND owner_run_id = {} AND expires_at >= {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                    ph(kind, 10),
                    ph(kind, 11),
                    ph(kind, 12),
                    ph(kind, 13),
                    ph(kind, 14),
                    ph(kind, 15)
                );
                let finalized = sql_query(update_run_sql)
                    .bind::<Text, _>(&status)
                    .bind::<BigInt, _>(total_seen)
                    .bind::<BigInt, _>(created_count)
                    .bind::<BigInt, _>(updated_count)
                    .bind::<BigInt, _>(disabled_count)
                    .bind::<Nullable<Text>, _>(&error)
                    .bind::<Nullable<Text>, _>(&cursor)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&run_id)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .bind::<Text, _>(&run_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if finalized != 1 {
                    return Err(AppError::BadRequest(
                        "directory synchronization lease was lost".to_string(),
                    ));
                }

                if status == "succeeded" {
                    let update_checkpoint_sql = format!(
                        "UPDATE directory_sync_checkpoints SET cursor = {}, last_success_at = {}, consecutive_failures = {}, updated_at = {} WHERE application_id = {} AND provider_id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                        ph(kind, 6)
                    );
                    let updated = sql_query(update_checkpoint_sql)
                        .bind::<Nullable<Text>, _>(&cursor)
                        .bind::<BigInt, _>(now)
                        .bind::<Integer, _>(0)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(&provider_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                    if updated == 0 {
                        let insert_checkpoint_sql = format!(
                            "INSERT INTO directory_sync_checkpoints (application_id, provider_id, cursor, last_success_at, consecutive_failures, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                            ph(kind, 1),
                            ph(kind, 2),
                            ph(kind, 3),
                            ph(kind, 4),
                            ph(kind, 5),
                            ph(kind, 6)
                        );
                        sql_query(insert_checkpoint_sql)
                            .bind::<Text, _>(&application_id)
                            .bind::<Text, _>(&provider_id)
                            .bind::<Nullable<Text>, _>(&cursor)
                            .bind::<BigInt, _>(now)
                            .bind::<Integer, _>(0)
                            .bind::<BigInt, _>(now)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                } else {
                    let update_checkpoint_sql = format!(
                        "UPDATE directory_sync_checkpoints SET consecutive_failures = consecutive_failures + 1, updated_at = {} WHERE application_id = {} AND provider_id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3)
                    );
                    let updated = sql_query(update_checkpoint_sql)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(&provider_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                    if updated == 0 {
                        let insert_checkpoint_sql = format!(
                            "INSERT INTO directory_sync_checkpoints (application_id, provider_id, cursor, last_success_at, consecutive_failures, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                            ph(kind, 1),
                            ph(kind, 2),
                            ph(kind, 3),
                            ph(kind, 4),
                            ph(kind, 5),
                            ph(kind, 6)
                        );
                        sql_query(insert_checkpoint_sql)
                            .bind::<Text, _>(&application_id)
                            .bind::<Text, _>(&provider_id)
                            .bind::<Nullable<Text>, _>(None::<String>)
                            .bind::<BigInt, _>(0)
                            .bind::<Integer, _>(1)
                            .bind::<BigInt, _>(now)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                }

                let release_sql = format!(
                    "DELETE FROM directory_sync_leases WHERE application_id = {} AND provider_id = {} AND owner_run_id = {} AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                let released = sql_query(release_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .bind::<Text, _>(&run_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if released != 1 {
                    return Err(AppError::BadRequest(
                        "directory synchronization lease was lost".to_string(),
                    ));
                }

                let select_sql = format!(
                    "SELECT id, application_id, provider_id, status, total_seen, created_count, updated_count, disabled_count, error, cursor, started_at, finished_at FROM directory_sync_runs WHERE id = {}",
                    ph(kind, 1)
                );
                sql_query(select_sql)
                    .bind::<Text, _>(&run_id)
                    .get_result::<DirectorySyncRunRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    /// Publishes one complete directory snapshot atomically.
    pub async fn apply_directory_sync_snapshot(
        &self,
        context: DirectorySyncApplyContext,
        snapshot: DirectorySyncSnapshotPlan,
    ) -> AppResult<DirectorySyncApplyStats> {
        let DirectorySyncApplyContext {
            application_id,
            provider_id,
            run_id,
            provider_key,
            organization_id,
            provider_display_name,
            reactivate_users,
            expected_application_updated_at,
            expected_provider_updated_at,
            expected_organization_updated_at,
        } = context;
        let now = util::now_ts();
        let total_seen = snapshot.users.len() as i64;

        with_conn!(self, |conn, kind| {
            conn.transaction::<DirectorySyncApplyStats, AppError, _>(|conn| {
                // Fence a worker at the same transaction boundary that will
                // publish the snapshot. A renew performed before this call is
                // not sufficient: another worker may have reclaimed the
                // lease while the caller was preparing the plan.
                let renew_sql = format!(
                    "UPDATE directory_sync_leases SET heartbeat_at = {}, expires_at = {} WHERE application_id = {} AND provider_id = {} AND owner_run_id = {} AND expires_at >= {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6)
                );
                let renewed = sql_query(renew_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now + super::DIRECTORY_SYNC_LEASE_TTL_SECONDS)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .bind::<Text, _>(&run_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if renewed != 1 {
                    return Err(AppError::BadRequest(
                        "directory synchronization lease was lost".to_string(),
                    ));
                }
                if let (
                    Some(application_updated_at),
                    Some(provider_updated_at),
                    Some(organization_updated_at),
                ) = (
                    expected_application_updated_at,
                    expected_provider_updated_at,
                    expected_organization_updated_at,
                ) {
                    let control_plane_sql = format!(
                        "SELECT COUNT(*) AS count FROM applications INNER JOIN organizations ON organizations.id = applications.organization_id INNER JOIN ldap_providers ON ldap_providers.id = {} WHERE applications.id = {} AND applications.organization_id = {} AND applications.is_active = 1 AND organizations.is_active = 1 AND applications.updated_at = {} AND organizations.updated_at = {} AND ldap_providers.is_active = 1 AND ldap_providers.updated_at = {} AND (ldap_providers.organization_id = {} OR ldap_providers.organization_id IS NULL)",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5),
                        ph(kind, 6),
                        ph(kind, 7),
                    );
                    let control_plane_is_current = sql_query(control_plane_sql)
                        .bind::<Text, _>(&provider_id)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(&organization_id)
                        .bind::<BigInt, _>(application_updated_at)
                        .bind::<BigInt, _>(organization_updated_at)
                        .bind::<BigInt, _>(provider_updated_at)
                        .bind::<Text, _>(&organization_id)
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count
                        == 1;
                    if !control_plane_is_current {
                        return Err(AppError::BadRequest(
                            "directory synchronization control-plane state changed while the snapshot was in flight".to_string(),
                        ));
                    }
                }
                let mut stats = DirectorySyncApplyStats {
                    total_seen,
                    ..DirectorySyncApplyStats::default()
                };
                let mut seen_subjects = BTreeSet::new();
                for directory_user in &snapshot.users {
                    if !seen_subjects.insert(directory_user.subject.clone()) {
                        return Err(AppError::BadRequest(
                            "directory sync contains duplicate user subjects".to_string(),
                        ));
                    }
                }
                let mut seen_groups = BTreeSet::new();
                for directory_group in &snapshot.groups {
                    if !seen_groups.insert(directory_group.external_id.clone()) {
                        return Err(AppError::BadRequest(
                            "directory sync contains duplicate group subjects".to_string(),
                        ));
                    }
                }

                // All identity and account reads happen before the first
                // mutation. Each helper chunks its IN list so this remains
                // valid for SQLite, PostgreSQL, and MySQL parameter limits.
                let subjects = snapshot
                    .users
                    .iter()
                    .map(|directory_user| directory_user.subject.clone())
                    .collect::<Vec<_>>();
                let identities_by_subject = load_linked_identities_by_subjects!(
                    conn,
                    kind,
                    &provider_key,
                    &subjects,
                )?;
                let identity_user_ids = identities_by_subject
                    .values()
                    .map(|identity| identity.user_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let mut users_by_id = load_users_by_ids!(conn, kind, &identity_user_ids)?;
                let mut organization_member_ids = load_organization_member_ids!(
                    conn,
                    kind,
                    &organization_id,
                    &identity_user_ids,
                )?;
                let candidate_emails = snapshot
                    .users
                    .iter()
                    .map(|directory_user| directory_user.email.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let candidate_usernames = snapshot
                    .users
                    .iter()
                    .map(|directory_user| directory_user.username.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let (mut email_owners, mut username_owners) = load_identity_owner_maps!(
                    conn,
                    kind,
                    &candidate_emails,
                    &candidate_usernames,
                )?;
                let existing_memberships_sql = format!(
                    "SELECT application_id, provider_id, user_id, managed, last_seen_at, created_at, updated_at FROM directory_sync_memberships WHERE application_id = {} AND provider_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let existing_memberships = sql_query(existing_memberships_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .load::<DirectorySyncMembershipRecord>(conn)
                    .map_err(AppError::from)?;
                let existing_membership_user_ids = existing_memberships
                    .iter()
                    .map(|membership| membership.user_id.clone())
                    .collect::<BTreeSet<_>>();
                let mut local_users_by_subject = BTreeMap::new();
                let mut local_users_by_dn = BTreeMap::new();
                let mut pending_updates = Vec::new();
                let mut pending_inserts = Vec::new();
                let mut pending_identities = Vec::new();
                let mut pending_organization_members = Vec::new();
                let mut pending_memberships = Vec::new();
                let mut inactive_user_ids = Vec::new();
                let mut email_factor_user_ids = Vec::new();
                let mut phone_factor_user_ids = Vec::new();

                for directory_user in &snapshot.users {
                    let (user, created, had_membership) =
                        if let Some(identity) = identities_by_subject.get(&directory_user.subject)
                        {
                            let current = users_by_id
                                .get(&identity.user_id)
                                .cloned()
                                .ok_or(AppError::Unauthorized)?;
                        if current.archived_at.is_some() {
                            return Err(AppError::BadRequest(
                                "directory sync cannot reactivate archived accounts".to_string(),
                            ));
                        }
                        ensure_preloaded_identity_available(
                            &email_owners,
                            &username_owners,
                            &directory_user.email,
                            &directory_user.username,
                            Some(&current.id),
                        )?;

                        let is_active = reactivate_users || current.is_active == 1;
                        let email_changed = current.email != directory_user.email;
                        let phone_changed = current.phone != directory_user.phone;
                        if !is_active {
                            inactive_user_ids.push(current.id.clone());
                        } else {
                            if email_changed {
                                email_factor_user_ids.push(current.id.clone());
                            }
                            if phone_changed {
                                phone_factor_user_ids.push(current.id.clone());
                            }
                        }
                        let mut user = current.clone();
                        user.email = directory_user.email.clone();
                        user.username = directory_user.username.clone();
                        user.display_name = directory_user.display_name.clone();
                        user.phone = directory_user.phone.clone();
                        user.email_verified_at = (!email_changed)
                            .then_some(current.email_verified_at)
                            .flatten();
                        user.phone_verified_at = (!phone_changed)
                            .then_some(current.phone_verified_at)
                            .flatten();
                        user.is_active = i32::from(is_active);
                        user.updated_at = now;
                        pending_updates.push(PendingUserUpdate { user: user.clone() });
                        replace_identity_owner(
                            &mut email_owners,
                            &current.email,
                            &user.email,
                            &user.id,
                        );
                        replace_identity_owner(
                            &mut username_owners,
                            &current.username,
                            &user.username,
                            &user.id,
                        );
                        users_by_id.insert(user.id.clone(), user.clone());
                        let had_membership = organization_member_ids.contains(&user.id);
                        (user, false, had_membership)
                    } else {
                        ensure_preloaded_identity_available(
                            &email_owners,
                            &username_owners,
                            &directory_user.email,
                            &directory_user.username,
                            None,
                        )?;
                        let user_id = uuid::Uuid::new_v4().to_string();
                        let password_hash = match directory_user.password_hash.clone() {
                            Some(password_hash) => password_hash,
                            None => util::hash_password(&util::random_token(32))?,
                        };
                        let user = UserRecord {
                            id: user_id.clone(),
                            email: directory_user.email.clone(),
                            username: directory_user.username.clone(),
                            display_name: directory_user.display_name.clone(),
                            phone: directory_user.phone.clone(),
                            password_hash,
                            email_verified_at: Some(now),
                            phone_verified_at: None,
                            is_admin: 0,
                            is_active: 1,
                            archived_at: None,
                            registration_source: UserRegistrationSource::Local
                                .as_str()
                                .to_string(),
                            last_login_at: None,
                            last_login_ip: None,
                            last_oidc_client_id: None,
                            last_login_method: None,
                            created_at: now,
                            updated_at: now,
                        };
                        pending_inserts.push(user.clone());
                        pending_identities.push(PendingLinkedIdentity {
                            user_id: user_id.clone(),
                            provider_key: provider_key.clone(),
                            subject: directory_user.subject.clone(),
                            email: directory_user.email.clone(),
                        });
                        users_by_id.insert(user.id.clone(), user.clone());
                        email_owners.insert(user.email.clone(), user.id.clone());
                        username_owners.insert(user.username.clone(), user.id.clone());
                        (user, true, false)
                    };

                    if !had_membership {
                        pending_organization_members.push(user.id.clone());
                        organization_member_ids.insert(user.id.clone());
                    }
                    pending_memberships.push(PendingMembership {
                        user_id: user.id.clone(),
                        managed: !had_membership,
                        existing: existing_membership_user_ids.contains(&user.id),
                    });
                    if created {
                        stats.created_count += 1;
                    } else {
                        stats.updated_count += 1;
                    }
                    local_users_by_subject.insert(directory_user.subject.clone(), user.id.clone());
                    local_users_by_dn.insert(directory_user.dn.clone(), user.id);
                }

                clear_auth_state_batch!(conn, kind, &inactive_user_ids)?;
                clear_application_bindings_batch!(conn, kind, &inactive_user_ids)?;
                clear_factor_bindings_batch!(
                    conn,
                    kind,
                    &email_factor_user_ids,
                    crate::applications::FACTOR_EMAIL,
                )?;
                clear_factor_bindings_batch!(
                    conn,
                    kind,
                    &phone_factor_user_ids,
                    crate::applications::FACTOR_PHONE,
                )?;
                update_users_batch!(conn, kind, &pending_updates, now)?;
                insert_users_batch!(conn, kind, &pending_inserts)?;
                insert_linked_identities_batch!(conn, kind, &pending_identities, now)?;
                insert_organization_members_batch!(
                    conn,
                    kind,
                    &organization_id,
                    &pending_organization_members,
                    now,
                )?;
                let existing_membership_writes = pending_memberships
                    .iter()
                    .filter(|membership| membership.existing)
                    .map(|membership| membership.user_id.clone())
                    .collect::<Vec<_>>();
                let new_membership_writes = pending_memberships
                    .iter()
                    .filter(|membership| !membership.existing)
                    .cloned()
                    .collect::<Vec<_>>();
                update_sync_memberships_batch!(
                    conn,
                    kind,
                    &application_id,
                    &provider_id,
                    &existing_membership_writes,
                    now,
                )?;
                insert_sync_memberships_batch!(
                    conn,
                    kind,
                    &application_id,
                    &provider_id,
                    &new_membership_writes,
                    now,
                )?;

                let membership_user_ids = existing_memberships
                    .iter()
                    .map(|membership| membership.user_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let provider_subjects_by_user = load_provider_subjects_by_user_ids!(
                    conn,
                    kind,
                    &provider_key,
                    &membership_user_ids,
                )?;
                let stale_memberships = existing_memberships
                    .into_iter()
                    .filter(|membership| {
                        !provider_subjects_by_user
                            .get(&membership.user_id)
                            .is_some_and(|subjects| {
                                subjects
                                    .iter()
                                    .any(|subject| seen_subjects.contains(subject))
                            })
                    })
                    .collect::<Vec<_>>();
                let managed_stale_user_ids = stale_memberships
                    .iter()
                    .filter(|membership| membership.managed == 1)
                    .map(|membership| membership.user_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let member_updated_at_by_user = load_organization_member_updated_at!(
                    conn,
                    kind,
                    &organization_id,
                    &managed_stale_user_ids,
                )?;
                let other_owner_ids = load_other_managed_owner_ids!(
                    conn,
                    kind,
                    &application_id,
                    &provider_id,
                    &organization_id,
                    &managed_stale_user_ids,
                )?;
                let mut stale_membership_user_ids = Vec::new();
                let mut stale_organization_members = Vec::new();
                for membership in &stale_memberships {
                    if membership.managed == 1 {
                        if !other_owner_ids.contains(&membership.user_id)
                            && let Some(expected_updated_at) =
                                member_updated_at_by_user.get(&membership.user_id).copied()
                            && expected_updated_at <= membership.last_seen_at
                        {
                            stale_organization_members
                                .push((membership.user_id.clone(), expected_updated_at));
                        }
                        stats.disabled_count += 1;
                    }
                    stale_membership_user_ids.push(membership.user_id.clone());
                }
                delete_organization_memberships_batch!(
                    conn,
                    kind,
                    &organization_id,
                    &stale_organization_members,
                )?;
                delete_sync_memberships_batch!(
                    conn,
                    kind,
                    &application_id,
                    &provider_id,
                    &stale_membership_user_ids,
                )?;

                let external_ids = snapshot
                    .groups
                    .iter()
                    .map(|directory_group| directory_group.external_id.clone())
                    .collect::<Vec<_>>();
                let group_mappings_by_external_id = load_group_mappings_by_external_ids!(
                    conn,
                    kind,
                    &application_id,
                    &provider_id,
                    &external_ids,
                )?;
                let existing_group_mappings_sql = format!(
                    "SELECT application_id, provider_id, external_id, group_id, last_seen_at, created_at, updated_at FROM directory_sync_groups WHERE application_id = {} AND provider_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                let existing_group_mappings = sql_query(existing_group_mappings_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&provider_id)
                    .load::<DirectorySyncGroupRecord>(conn)
                    .map_err(AppError::from)?;
                let mapped_group_ids = group_mappings_by_external_id
                    .values()
                    .map(|mapping| mapping.group_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let archived_members_by_group = load_archived_group_members_by_group_ids!(
                    conn,
                    kind,
                    &organization_id,
                    &mapped_group_ids,
                )?;

                let mut pending_groups = Vec::with_capacity(snapshot.groups.len());
                for directory_group in &snapshot.groups {
                    let (group_id, is_new) = if let Some(mapping) =
                        group_mappings_by_external_id.get(&directory_group.external_id)
                    {
                        (mapping.group_id.clone(), false)
                    } else {
                        (uuid::Uuid::new_v4().to_string(), true)
                    };
                    let member_ids = directory_group
                        .member_subjects
                        .iter()
                        .filter_map(|subject| {
                            local_users_by_subject
                                .get(subject)
                                .or_else(|| local_users_by_dn.get(subject))
                                .cloned()
                        })
                        .collect::<BTreeSet<_>>();
                    if let Some(archived_members) = archived_members_by_group.get(&group_id)
                        && let Some(user_id) = archived_members
                            .iter()
                            .find(|user_id| !member_ids.contains(*user_id))
                    {
                        return Err(AppError::BadRequest(format!(
                            "archived group member cannot be removed: {}",
                            user_id
                        )));
                    }
                    pending_groups.push(PendingGroup {
                        external_id: directory_group.external_id.clone(),
                        group_id,
                        display_name: directory_group.display_name.clone(),
                        member_ids: member_ids.into_iter().collect(),
                        is_new,
                    });
                }

                let new_groups = pending_groups
                    .iter()
                    .filter(|group| group.is_new)
                    .cloned()
                    .collect::<Vec<_>>();
                insert_groups_batch!(
                    conn,
                    kind,
                    &new_groups,
                    &provider_display_name,
                    now,
                )?;
                insert_application_scim_groups_batch!(
                    conn,
                    kind,
                    &application_id,
                    &new_groups,
                    now,
                )?;
                replace_group_members_batch!(
                    conn,
                    kind,
                    &organization_id,
                    &pending_groups,
                )?;
                update_groups_batch!(conn, kind, &pending_groups, now)?;
                update_group_mappings_batch!(
                    conn,
                    kind,
                    &application_id,
                    &provider_id,
                    &pending_groups,
                    now,
                )?;

                let stale_mappings = existing_group_mappings
                    .into_iter()
                    .filter(|mapping| !seen_groups.contains(&mapping.external_id))
                    .collect::<Vec<_>>();
                let stale_external_ids = stale_mappings
                    .iter()
                    .map(|mapping| mapping.external_id.clone())
                    .collect::<Vec<_>>();
                for chunk in stale_external_ids.chunks(DIRECTORY_SYNC_BATCH_SIZE - 2) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let sql = format!(
                        "DELETE FROM directory_sync_groups WHERE application_id = {} AND provider_id = {} AND external_id IN ({})",
                        ph(kind, 1),
                        ph(kind, 2),
                        text_placeholders(kind, 3, chunk.len()),
                    );
                    let mut query = sql_query(sql).into_boxed::<_>();
                    query = query
                        .bind::<Text, _>(application_id.clone())
                        .bind::<Text, _>(provider_id.clone());
                    for external_id in chunk {
                        query = query.bind::<Text, _>(external_id.clone());
                    }
                    query.execute(conn).map_err(AppError::from)?;
                }
                for mapping in stale_mappings {
                    delete_application_group_binding!(
                        conn,
                        kind,
                        &application_id,
                        &mapping.group_id,
                    )?;
                }
                Ok(stats)
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_sync_placeholders_are_backend_specific_and_bounded() {
        assert_eq!(
            text_placeholders(DatabaseKind::Postgres, 2, 3),
            "$2, $3, $4"
        );
        assert_eq!(text_placeholders(DatabaseKind::Sqlite, 2, 3), "?, ?, ?");
        assert_eq!(text_placeholders(DatabaseKind::Mysql, 2, 3), "?, ?, ?");
        for kind in [
            DatabaseKind::Sqlite,
            DatabaseKind::Postgres,
            DatabaseKind::Mysql,
        ] {
            assert_eq!(
                text_placeholders(kind, 1, DIRECTORY_SYNC_BATCH_SIZE)
                    .split(", ")
                    .count(),
                DIRECTORY_SYNC_BATCH_SIZE
            );
        }
    }

    #[test]
    fn preloaded_identity_ownership_preserves_exclusion_and_updates() {
        let mut email_owners =
            BTreeMap::from([("old@example.test".to_string(), "user-1".to_string())]);
        let mut username_owners = BTreeMap::from([("old-user".to_string(), "user-1".to_string())]);
        ensure_preloaded_identity_available(
            &email_owners,
            &username_owners,
            "old@example.test",
            "old-user",
            Some("user-1"),
        )
        .unwrap();
        assert!(
            ensure_preloaded_identity_available(
                &email_owners,
                &username_owners,
                "old@example.test",
                "other-user",
                Some("user-2"),
            )
            .is_err()
        );

        replace_identity_owner(
            &mut email_owners,
            "old@example.test",
            "new@example.test",
            "user-1",
        );
        replace_identity_owner(&mut username_owners, "old-user", "new-user", "user-1");
        assert!(!email_owners.contains_key("old@example.test"));
        assert_eq!(
            email_owners.get("new@example.test"),
            Some(&"user-1".to_string())
        );
        assert!(!username_owners.contains_key("old-user"));
        assert_eq!(username_owners.get("new-user"), Some(&"user-1".to_string()));
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite_directory_sync_db() -> (Db, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "signet-directory-sync-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let db = super::super::connect_sqlite(&crate::config::DatabaseSettings {
            kind: DatabaseKind::Sqlite,
            url: path.to_string_lossy().into_owned(),
            pool_size: 1,
            run_migrations: true,
        })
        .unwrap();
        db.migrate().await.unwrap();
        (db, path)
    }

    #[cfg(feature = "sqlite")]
    async fn directory_sync_fixture(
        db: &Db,
        organization_slug: &str,
        application_slug: &str,
    ) -> (String, String) {
        let organization = db
            .insert_organization(super::super::NewOrganization {
                slug: organization_slug.to_string(),
                name: format!("{organization_slug} organization"),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let application = db
            .insert_application(super::super::NewApplication {
                organization_id: organization.id.clone(),
                slug: application_slug.to_string(),
                name: format!("{application_slug} application"),
                description: None,
                access_mode: crate::applications::ACCESS_ALL_SIGNET_USERS.to_string(),
                registration_mode: crate::applications::REGISTRATION_DISABLED.to_string(),
                account_selection_mode: crate::applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
                unique_identity_factors: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        (organization.id, application.id)
    }

    #[cfg(feature = "sqlite")]
    fn directory_sync_user(index: usize) -> DirectorySyncUserPlan {
        DirectorySyncUserPlan {
            subject: format!("subject-{index}"),
            dn: format!("uid=user-{index},ou=people,dc=example,dc=test"),
            email: format!("user-{index}@example.test"),
            username: format!("user-{index}"),
            display_name: Some(format!("User {index}")),
            phone: None,
            password_hash: Some("test-password-hash".to_string()),
        }
    }

    #[cfg(feature = "sqlite")]
    fn directory_sync_context(
        application_id: &str,
        organization_id: &str,
        run_id: &str,
    ) -> DirectorySyncApplyContext {
        DirectorySyncApplyContext {
            application_id: application_id.to_string(),
            provider_id: "provider-1".to_string(),
            run_id: run_id.to_string(),
            provider_key: "ldap:provider-1".to_string(),
            organization_id: organization_id.to_string(),
            provider_display_name: "Directory Provider".to_string(),
            reactivate_users: false,
            expected_application_updated_at: None,
            expected_provider_updated_at: None,
            expected_organization_updated_at: None,
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn directory_sync_snapshot_batches_users_groups_and_group_members() {
        let (db, path) = sqlite_directory_sync_db().await;
        let (organization_id, application_id) =
            directory_sync_fixture(&db, "batch-sync-org", "batch-sync-app").await;
        let run = db
            .start_directory_sync_run(&application_id, "provider-1")
            .await
            .unwrap();
        let user_count = DIRECTORY_SYNC_BATCH_SIZE + 3;
        let users = (0..user_count).map(directory_sync_user).collect::<Vec<_>>();
        let users_for_retry = users.clone();
        let subjects = users
            .iter()
            .map(|user| user.subject.clone())
            .collect::<Vec<_>>();
        let mut groups = vec![DirectorySyncGroupPlan {
            external_id: "large-membership".to_string(),
            display_name: "Large Membership".to_string(),
            member_subjects: subjects,
        }];
        for index in 0..DIRECTORY_SYNC_BATCH_SIZE + 3 {
            groups.push(DirectorySyncGroupPlan {
                external_id: format!("empty-group-{index}"),
                display_name: format!("Empty Group {index}"),
                member_subjects: Vec::new(),
            });
        }
        let groups_for_retry = groups.clone();

        let stats = db
            .apply_directory_sync_snapshot(
                directory_sync_context(&application_id, &organization_id, &run.id),
                DirectorySyncSnapshotPlan { users, groups },
            )
            .await
            .unwrap();
        assert_eq!(stats.total_seen, user_count as i64);
        assert_eq!(stats.created_count, user_count as i64);
        assert_eq!(stats.updated_count, 0);
        assert_eq!(
            db.list_directory_sync_memberships(&application_id, "provider-1")
                .await
                .unwrap()
                .len(),
            user_count
        );
        let mappings = db
            .list_directory_sync_groups(&application_id, "provider-1")
            .await
            .unwrap();
        assert_eq!(mappings.len(), DIRECTORY_SYNC_BATCH_SIZE + 4);
        let large_group_id = mappings
            .iter()
            .find(|mapping| mapping.external_id == "large-membership")
            .unwrap()
            .group_id
            .clone();
        assert_eq!(
            db.list_group_members(&large_group_id).await.unwrap().len(),
            user_count
        );

        let retry_stats = db
            .apply_directory_sync_snapshot(
                directory_sync_context(&application_id, &organization_id, &run.id),
                DirectorySyncSnapshotPlan {
                    users: users_for_retry,
                    groups: groups_for_retry,
                },
            )
            .await
            .unwrap();
        assert_eq!(retry_stats.created_count, 0);
        assert_eq!(retry_stats.updated_count, user_count as i64);
        assert_eq!(retry_stats.disabled_count, 0);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn directory_sync_generates_password_hash_only_for_new_users() {
        let (db, path) = sqlite_directory_sync_db().await;
        let (organization_id, application_id) =
            directory_sync_fixture(&db, "hash-sync-org", "hash-sync-app").await;
        let run = db
            .start_directory_sync_run(&application_id, "provider-1")
            .await
            .unwrap();
        let first = DirectorySyncUserPlan {
            subject: "hash-subject".to_string(),
            dn: "uid=hash-user,ou=people,dc=example,dc=test".to_string(),
            email: "hash-user@example.test".to_string(),
            username: "hash-user".to_string(),
            display_name: Some("Hash User".to_string()),
            phone: None,
            password_hash: None,
        };
        db.apply_directory_sync_snapshot(
            directory_sync_context(&application_id, &organization_id, &run.id),
            DirectorySyncSnapshotPlan {
                users: vec![first.clone()],
                groups: Vec::new(),
            },
        )
        .await
        .unwrap();
        let created = db.find_user_by_email(&first.email).await.unwrap().unwrap();
        assert!(created.password_hash.starts_with("$argon2"));
        let original_hash = created.password_hash.clone();

        let mut updated = first;
        updated.display_name = Some("Updated Hash User".to_string());
        updated.password_hash = None;
        let stats = db
            .apply_directory_sync_snapshot(
                directory_sync_context(&application_id, &organization_id, &run.id),
                DirectorySyncSnapshotPlan {
                    users: vec![updated],
                    groups: Vec::new(),
                },
            )
            .await
            .unwrap();
        assert_eq!(stats.created_count, 0);
        assert_eq!(stats.updated_count, 1);
        let after_update = db
            .find_user_by_email("hash-user@example.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_update.password_hash, original_hash);

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn directory_sync_finalize_cannot_publish_after_lease_reclaim() {
        let (db, path) = sqlite_directory_sync_db().await;
        let (_organization_id, application_id) =
            directory_sync_fixture(&db, "fence-sync-org", "fence-sync-app").await;
        let old_run = db
            .start_directory_sync_run(&application_id, "provider-1")
            .await
            .unwrap();
        let expired_at = util::now_ts() - 1;
        let application_id_for_expiry = application_id.clone();
        with_conn!(db.clone(), |conn, kind| {
            let sql = format!(
                "UPDATE directory_sync_leases SET expires_at = {} WHERE application_id = {} AND provider_id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<BigInt, _>(expired_at)
                .bind::<Text, _>(&application_id_for_expiry)
                .bind::<Text, _>("provider-1")
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();
        let new_run = db
            .start_directory_sync_run(&application_id, "provider-1")
            .await
            .unwrap();
        let result = db
            .finalize_directory_sync_run(
                &application_id,
                "provider-1",
                &old_run.id,
                "succeeded",
                1,
                1,
                0,
                0,
                None,
                Some("stale".to_string()),
            )
            .await;
        assert!(matches!(
            result,
            Err(AppError::BadRequest(message)) if message.contains("lease")
        ));
        let runs = db
            .list_directory_sync_runs(&application_id, 20)
            .await
            .unwrap();
        assert_eq!(
            runs.iter().find(|run| run.id == old_run.id).unwrap().status,
            "failed"
        );
        assert_eq!(
            runs.iter().find(|run| run.id == new_run.id).unwrap().status,
            "running"
        );
        db.finish_directory_sync_run(&new_run.id, "failed", 0, 0, 0, 0, None, None)
            .await
            .unwrap();

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn directory_sync_preserves_archived_members_and_tenant_boundary() {
        let (db, path) = sqlite_directory_sync_db().await;
        let (organization_id, application_id) =
            directory_sync_fixture(&db, "archive-sync-org", "archive-sync-app").await;
        let (other_organization_id, _) =
            directory_sync_fixture(&db, "other-sync-org", "other-sync-app").await;
        let archived_main = db
            .insert_user(super::super::NewUser {
                email: "archived-main@example.test".to_string(),
                username: "archived-main".to_string(),
                display_name: None,
                phone: None,
                password_hash: "test-password-hash".to_string(),
                email_verified_at: None,
                phone_verified_at: None,
                is_admin: false,
                is_active: false,
                archived_at: Some(util::now_ts() - 10),
            })
            .await
            .unwrap();
        db.upsert_organization_member(
            &organization_id,
            &archived_main.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
        db.insert_linked_identity(
            &archived_main.id,
            "ldap:provider-1",
            "archived-main-subject",
            Some(archived_main.email.clone()),
        )
        .await
        .unwrap();

        let archived_other = db
            .insert_user(super::super::NewUser {
                email: "archived-other@example.test".to_string(),
                username: "archived-other".to_string(),
                display_name: None,
                phone: None,
                password_hash: "test-password-hash".to_string(),
                email_verified_at: None,
                phone_verified_at: None,
                is_admin: false,
                is_active: false,
                archived_at: Some(util::now_ts() - 10),
            })
            .await
            .unwrap();
        db.upsert_organization_member(
            &other_organization_id,
            &archived_other.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();

        let archived_group = db
            .insert_application_scim_group(
                &application_id,
                super::super::NewGroup {
                    name: "Archived Group".to_string(),
                    description: None,
                },
            )
            .await
            .unwrap();
        db.replace_group_members(&archived_group.id, vec![archived_main.id.clone()])
            .await
            .unwrap();
        db.upsert_directory_sync_group(
            &application_id,
            "provider-1",
            "archived-group",
            &archived_group.id,
            util::now_ts(),
        )
        .await
        .unwrap();

        let other_tenant_group = db
            .insert_application_scim_group(
                &application_id,
                super::super::NewGroup {
                    name: "Other Tenant Group".to_string(),
                    description: None,
                },
            )
            .await
            .unwrap();
        db.replace_group_members(&other_tenant_group.id, vec![archived_other.id.clone()])
            .await
            .unwrap();
        db.upsert_directory_sync_group(
            &application_id,
            "provider-1",
            "other-tenant-group",
            &other_tenant_group.id,
            util::now_ts(),
        )
        .await
        .unwrap();

        let run = db
            .start_directory_sync_run(&application_id, "provider-1")
            .await
            .unwrap();
        let archived_user_result = db
            .apply_directory_sync_snapshot(
                directory_sync_context(&application_id, &organization_id, &run.id),
                DirectorySyncSnapshotPlan {
                    users: vec![DirectorySyncUserPlan {
                        subject: "archived-main-subject".to_string(),
                        dn: "uid=archived-main,ou=people".to_string(),
                        email: archived_main.email.clone(),
                        username: archived_main.username.clone(),
                        display_name: None,
                        phone: None,
                        password_hash: Some("test-password-hash".to_string()),
                    }],
                    groups: Vec::new(),
                },
            )
            .await;
        assert!(matches!(
            archived_user_result,
            Err(AppError::BadRequest(message)) if message.contains("archived accounts")
        ));

        let archived_group_result = db
            .apply_directory_sync_snapshot(
                directory_sync_context(&application_id, &organization_id, &run.id),
                DirectorySyncSnapshotPlan {
                    users: Vec::new(),
                    groups: vec![DirectorySyncGroupPlan {
                        external_id: "archived-group".to_string(),
                        display_name: "Archived Group".to_string(),
                        member_subjects: Vec::new(),
                    }],
                },
            )
            .await;
        assert!(matches!(
            archived_group_result,
            Err(AppError::BadRequest(message)) if message.contains("archived group member")
        ));

        let tenant_result = db
            .apply_directory_sync_snapshot(
                directory_sync_context(&application_id, &organization_id, &run.id),
                DirectorySyncSnapshotPlan {
                    users: Vec::new(),
                    groups: vec![DirectorySyncGroupPlan {
                        external_id: "other-tenant-group".to_string(),
                        display_name: "Other Tenant Group".to_string(),
                        member_subjects: Vec::new(),
                    }],
                },
            )
            .await
            .unwrap();
        assert_eq!(tenant_result.disabled_count, 0);
        assert_eq!(
            db.list_group_members(&other_tenant_group.id)
                .await
                .unwrap()
                .iter()
                .map(|user| user.id.as_str())
                .collect::<Vec<_>>(),
            vec![archived_other.id.as_str()]
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
