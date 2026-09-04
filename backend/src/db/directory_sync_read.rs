//! Batch read helpers used by directory synchronization writes.

#[allow(unused_imports)]
use super::directory_sync_sql::text_placeholders;
#[allow(unused_imports)]
use super::{LinkedIdentityRecord, UserRecord, bind_text_list, ph, select_user_sql};
#[allow(unused_imports)]
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
};
#[allow(unused_imports)]
use diesel::{
    RunQueryDsl, sql_query,
    sql_types::{BigInt, Nullable, Text},
};
#[allow(unused_imports)]
use std::collections::{BTreeMap, BTreeSet};

pub(super) const DIRECTORY_SYNC_BATCH_SIZE: usize = 400;

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(super) struct ArchivedGroupMemberRow {
    #[diesel(sql_type = Text)]
    pub(super) group_id: String,
    #[diesel(sql_type = Text)]
    pub(super) user_id: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub(super) archived_at: Option<i64>,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(super) struct UserIdentityKeyRow {
    #[diesel(sql_type = Text)]
    pub(super) id: String,
    #[diesel(sql_type = Text)]
    pub(super) email: String,
    #[diesel(sql_type = Text)]
    pub(super) username: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(super) struct UserIdRow {
    #[diesel(sql_type = Text)]
    pub(super) user_id: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(super) struct ProviderUserSubjectRow {
    #[diesel(sql_type = Text)]
    pub(super) user_id: String,
    #[diesel(sql_type = Text)]
    pub(super) external_subject: String,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub(super) struct OrganizationMemberUpdatedAtRow {
    #[diesel(sql_type = Text)]
    pub(super) user_id: String,
    #[diesel(sql_type = BigInt)]
    pub(super) updated_at: i64,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum UserIdentityColumn {
    Email,
    Username,
}

impl UserIdentityColumn {
    pub(super) fn sql(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Username => "username",
        }
    }
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
        if emails.len() + usernames.len() <= DIRECTORY_SYNC_BATCH_SIZE {
            let mut values = Vec::with_capacity(emails.len() + usernames.len());
            values.extend_from_slice(emails);
            values.extend_from_slice(usernames);
            let email_clause = if emails.is_empty() {
                None
            } else {
                Some(format!(
                    "email IN ({})",
                    text_placeholders(kind, 1, emails.len())
                ))
            };
            let username_clause = if usernames.is_empty() {
                None
            } else {
                Some(format!(
                    "username IN ({})",
                    text_placeholders(kind, emails.len() + 1, usernames.len())
                ))
            };
            let clauses = [email_clause, username_clause]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" OR ");
            if !clauses.is_empty() {
                let sql = format!("SELECT id, email, username FROM users WHERE {clauses}");
                for row in bind_text_list(conn, sql_query(sql), &values)
                    .load::<UserIdentityKeyRow>(conn)
                    .map_err(AppError::from)?
                {
                    email_owners.insert(row.email.clone(), row.id.clone());
                    username_owners.insert(row.username.clone(), row.id);
                }
            }
        } else {
            for (column, values) in [
                (UserIdentityColumn::Email, emails),
                (UserIdentityColumn::Username, usernames),
            ] {
                for row in load_user_identity_rows!(conn, kind, column, values)? {
                    email_owners.insert(row.email.clone(), row.id.clone());
                    username_owners.insert(row.username.clone(), row.id);
                }
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
