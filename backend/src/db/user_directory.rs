//! Read-only user directory queries.
//!
//! The public methods remain inherent on `Db`; this module owns their query
//! implementations and directory-specific SQL helpers.

use super::{
    CountRow, Db, UserAssignmentStateRecord, UserDirectoryCursor, UserDirectoryCursorPage,
    UserEmailIdRow, UserIdentityConflictRow, UserListFilter, UserListFilters,
    UserListLinkedIdentityFilter, UserListLoginRegion, UserListPage, UserListRoleFilter,
    UserListScope, UserOptionRecord, UserRecord, bind_text_list, blocking, dedupe_nonempty, ph,
    placeholders, select_user_sql,
};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
};
use diesel::{
    OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, diesel::QueryableByName)]
struct UserOverviewCountRow {
    #[diesel(sql_type = BigInt)]
    total: i64,
    #[diesel(sql_type = BigInt)]
    active: i64,
}

impl UserListScope {
    fn where_sql(self) -> &'static str {
        match self {
            UserListScope::Live => "WHERE archived_at IS NULL",
            UserListScope::Active => "WHERE archived_at IS NULL AND is_active = 1",
            UserListScope::Disabled => "WHERE archived_at IS NULL AND is_active = 0",
            UserListScope::Archived => "WHERE archived_at IS NOT NULL",
            UserListScope::AuthorizationCode => "WHERE registration_source = 'authorization_code'",
            UserListScope::All => "",
        }
    }

    fn order_sql(self) -> &'static str {
        match self {
            UserListScope::Archived => "archived_at DESC, created_at DESC, id ASC",
            UserListScope::AuthorizationCode | UserListScope::All => {
                "archived_at IS NOT NULL ASC, is_active DESC, created_at DESC, id ASC"
            }
            UserListScope::Live | UserListScope::Active | UserListScope::Disabled => {
                "is_active DESC, created_at DESC, id ASC"
            }
        }
    }

    fn qualified_predicate_sql(self) -> &'static str {
        match self {
            UserListScope::Live => "users.archived_at IS NULL",
            UserListScope::Active => "users.archived_at IS NULL AND users.is_active = 1",
            UserListScope::Disabled => "users.archived_at IS NULL AND users.is_active = 0",
            UserListScope::Archived => "users.archived_at IS NOT NULL",
            UserListScope::AuthorizationCode => "users.registration_source = 'authorization_code'",
            UserListScope::All => "1 = 1",
        }
    }

    fn qualified_order_sql(self) -> &'static str {
        match self {
            UserListScope::Archived => {
                "users.archived_at DESC, users.created_at DESC, users.id ASC"
            }
            UserListScope::AuthorizationCode | UserListScope::All => {
                "users.archived_at IS NOT NULL ASC, users.is_active DESC, users.created_at DESC, users.id ASC"
            }
            UserListScope::Live | UserListScope::Active | UserListScope::Disabled => {
                "users.is_active DESC, users.created_at DESC, users.id ASC"
            }
        }
    }
}
/// Administrative directory responses never need the password hash.  Keep
/// the legacy `UserRecord` shape for the SCIM/identity paths that still need a
/// complete account record, but make the directory projection substitute a
/// typed empty value so the hash column is not read from storage at all.
fn select_user_directory_sql() -> &'static str {
    "SELECT users.id, users.email, users.username, users.display_name, users.phone, '' AS password_hash, users.email_verified_at, users.phone_verified_at, users.is_admin, users.is_active, users.archived_at, users.registration_source, users.last_login_at, users.last_login_ip, users.last_oidc_client_id, users.last_login_method, users.created_at, users.updated_at FROM users"
}
#[derive(Debug, Clone)]
struct UserListSqlParams {
    organization_id: Option<String>,
    search: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    exact_username: Option<String>,
    exact_email: Option<String>,
    exact_id: Option<String>,
    active: Option<i32>,
    role_mode: i32,
    role_name: Option<String>,
    linked_identity_mode: i32,
    created_from: Option<i64>,
    created_to: Option<i64>,
    last_login_from: Option<i64>,
    last_login_to: Option<i64>,
    login_region_mode: i32,
}

impl UserListSqlParams {
    fn from_filters(filters: &UserListFilters, exact_filter: Option<&UserListFilter>) -> Self {
        let (exact_username, exact_email, exact_id, active) = match exact_filter {
            Some(UserListFilter::UserName(value)) => (Some(value.clone()), None, None, None),
            Some(UserListFilter::Email(value)) => (None, Some(value.clone()), None, None),
            Some(UserListFilter::Id(value)) => (None, None, Some(value.clone()), None),
            Some(UserListFilter::Active(value)) => (None, None, None, Some(i32::from(*value))),
            None => (None, None, None, None),
        };
        let (role_mode, role_name) = match &filters.role {
            UserListRoleFilter::Any => (0, None),
            UserListRoleFilter::Admin => (1, None),
            UserListRoleFilter::User => (2, None),
            UserListRoleFilter::Named(value) => (3, Some(value.clone())),
        };
        let linked_identity_mode = match filters.linked_identity {
            UserListLinkedIdentityFilter::All => 0,
            UserListLinkedIdentityFilter::Linked => 1,
            UserListLinkedIdentityFilter::Unlinked => 2,
        };
        let login_region_mode = match filters.login_region {
            UserListLoginRegion::All => 0,
            UserListLoginRegion::Domestic => 1,
            UserListLoginRegion::Overseas => 2,
        };

        Self {
            organization_id: filters.organization_id.clone(),
            search: filters.search.as_deref().map(contains_like_pattern),
            email: filters.email.as_deref().map(contains_like_pattern),
            phone: filters.phone.as_deref().map(contains_like_pattern),
            exact_username,
            exact_email,
            exact_id,
            active,
            role_mode,
            role_name,
            linked_identity_mode,
            created_from: filters.created_from,
            created_to: filters.created_to,
            last_login_from: filters.last_login_from,
            last_login_to: filters.last_login_to,
            login_region_mode,
        }
    }
}

fn contains_like_pattern(value: &str) -> String {
    let mut pattern = String::with_capacity(value.len() + 2);
    pattern.push('%');
    for ch in value.chars() {
        if matches!(ch, '!' | '%' | '_') {
            pattern.push('!');
        }
        pattern.push(ch);
    }
    pattern.push('%');
    pattern
}

fn domestic_login_ip_sql() -> &'static str {
    "(LOWER(COALESCE(users.last_login_ip, '')) LIKE 'cn:%' OR LOWER(COALESCE(users.last_login_ip, '')) = 'localhost' OR LOWER(COALESCE(users.last_login_ip, '')) = '::1' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '127.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '10.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '192.168.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.16.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.17.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.18.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.19.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.20.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.21.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.22.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.23.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.24.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.25.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.26.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.27.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.28.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.29.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.30.%' OR LOWER(COALESCE(users.last_login_ip, '')) LIKE '172.31.%')"
}

fn user_list_predicate_sql(kind: DatabaseKind) -> String {
    let domestic_ip = domestic_login_ip_sql();
    format!(
        "({} IS NULL OR EXISTS (SELECT 1 FROM organization_members WHERE organization_members.organization_id = {} AND organization_members.user_id = users.id)) \
         AND ({} IS NULL OR (LOWER(COALESCE(users.email, '')) LIKE LOWER({}) ESCAPE '!' OR LOWER(COALESCE(users.username, '')) LIKE LOWER({}) ESCAPE '!' OR LOWER(COALESCE(users.display_name, '')) LIKE LOWER({}) ESCAPE '!' OR LOWER(COALESCE(users.phone, '')) LIKE LOWER({}) ESCAPE '!')) \
         AND ({} IS NULL OR LOWER(users.email) LIKE LOWER({}) ESCAPE '!') \
         AND ({} IS NULL OR LOWER(COALESCE(users.phone, '')) LIKE LOWER({}) ESCAPE '!') \
         AND ({} IS NULL OR LOWER(users.username) = LOWER({})) \
         AND ({} IS NULL OR LOWER(users.email) = LOWER({})) \
         AND ({} IS NULL OR users.id = {}) \
         AND ({} IS NULL OR users.is_active = {}) \
         AND CASE {} WHEN 0 THEN 1 WHEN 1 THEN CASE WHEN users.is_admin = 1 THEN 1 ELSE 0 END WHEN 2 THEN CASE WHEN users.is_admin = 0 THEN 1 ELSE 0 END WHEN 3 THEN CASE WHEN EXISTS (SELECT 1 FROM roles AS role_filter WHERE role_filter.name = {} AND (EXISTS (SELECT 1 FROM user_roles AS role_user_roles WHERE role_user_roles.user_id = users.id AND role_user_roles.role_id = role_filter.id) OR EXISTS (SELECT 1 FROM group_members AS role_group_members INNER JOIN group_roles AS role_group_roles ON role_group_roles.group_id = role_group_members.group_id WHERE role_group_members.user_id = users.id AND role_group_roles.role_id = role_filter.id))) THEN 1 ELSE 0 END ELSE 0 END = 1 \
         AND CASE {} WHEN 0 THEN 1 WHEN 1 THEN CASE WHEN EXISTS (SELECT 1 FROM linked_identities WHERE linked_identities.user_id = users.id) THEN 1 ELSE 0 END WHEN 2 THEN CASE WHEN NOT EXISTS (SELECT 1 FROM linked_identities WHERE linked_identities.user_id = users.id) THEN 1 ELSE 0 END ELSE 0 END = 1 \
         AND ({} IS NULL OR users.created_at >= {}) \
         AND ({} IS NULL OR users.created_at < {}) \
         AND ({} IS NULL OR users.last_login_at >= {}) \
         AND ({} IS NULL OR users.last_login_at < {}) \
         AND CASE {} WHEN 0 THEN 1 WHEN 1 THEN CASE WHEN {} THEN 1 ELSE 0 END WHEN 2 THEN CASE WHEN users.last_login_ip IS NOT NULL AND NOT ({}) THEN 1 ELSE 0 END ELSE 0 END = 1",
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
        ph(kind, 15),
        ph(kind, 16),
        ph(kind, 17),
        ph(kind, 18),
        ph(kind, 19),
        ph(kind, 20),
        ph(kind, 21),
        ph(kind, 22),
        ph(kind, 23),
        ph(kind, 24),
        ph(kind, 25),
        ph(kind, 26),
        ph(kind, 27),
        ph(kind, 28),
        ph(kind, 29),
        ph(kind, 30),
        ph(kind, 31),
        domestic_ip,
        domestic_ip,
    )
}

macro_rules! bind_user_list_predicate {
    ($query:expr, $params:expr) => {{
        $query
            .bind::<Nullable<Text>, _>($params.organization_id.clone())
            .bind::<Nullable<Text>, _>($params.organization_id.clone())
            .bind::<Nullable<Text>, _>($params.search.clone())
            .bind::<Nullable<Text>, _>($params.search.clone())
            .bind::<Nullable<Text>, _>($params.search.clone())
            .bind::<Nullable<Text>, _>($params.search.clone())
            .bind::<Nullable<Text>, _>($params.search.clone())
            .bind::<Nullable<Text>, _>($params.email.clone())
            .bind::<Nullable<Text>, _>($params.email.clone())
            .bind::<Nullable<Text>, _>($params.phone.clone())
            .bind::<Nullable<Text>, _>($params.phone.clone())
            .bind::<Nullable<Text>, _>($params.exact_username.clone())
            .bind::<Nullable<Text>, _>($params.exact_username.clone())
            .bind::<Nullable<Text>, _>($params.exact_email.clone())
            .bind::<Nullable<Text>, _>($params.exact_email.clone())
            .bind::<Nullable<Text>, _>($params.exact_id.clone())
            .bind::<Nullable<Text>, _>($params.exact_id.clone())
            .bind::<Nullable<Integer>, _>($params.active)
            .bind::<Nullable<Integer>, _>($params.active)
            .bind::<Integer, _>($params.role_mode)
            .bind::<Nullable<Text>, _>($params.role_name.clone())
            .bind::<Integer, _>($params.linked_identity_mode)
            .bind::<Nullable<BigInt>, _>($params.created_from)
            .bind::<Nullable<BigInt>, _>($params.created_from)
            .bind::<Nullable<BigInt>, _>($params.created_to)
            .bind::<Nullable<BigInt>, _>($params.created_to)
            .bind::<Nullable<BigInt>, _>($params.last_login_from)
            .bind::<Nullable<BigInt>, _>($params.last_login_from)
            .bind::<Nullable<BigInt>, _>($params.last_login_to)
            .bind::<Nullable<BigInt>, _>($params.last_login_to)
            .bind::<Integer, _>($params.login_region_mode)
    }};
}

impl Db {
    pub async fn find_user_by_email(&self, email: &str) -> AppResult<Option<UserRecord>> {
        let email = email.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE email = {}", select_user_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(email)
                .get_result::<UserRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    /// Resolves email selectors with one bounded projection. Callers that
    /// already performed authorization should use this for bulk member
    /// editing instead of hydrating a full `UserRecord` per email.
    pub async fn find_user_ids_by_emails(
        &self,
        emails: &[String],
    ) -> AppResult<BTreeMap<String, String>> {
        let emails = dedupe_nonempty(emails.to_vec());
        if emails.is_empty() {
            return Ok(BTreeMap::new());
        }
        with_conn!(self, |conn, kind| {
            let placeholders = placeholders(kind, 1, emails.len());
            let sql = format!("SELECT id, email FROM users WHERE email IN ({placeholders})");
            let rows = bind_text_list(&mut conn, sql_query(sql), &emails)
                .load::<UserEmailIdRow>(&mut conn)
                .map_err(AppError::from)?;
            Ok(rows.into_iter().map(|row| (row.email, row.id)).collect())
        })
    }

    /// Finds existing identity conflicts for a whole provisioning batch using
    /// one minimal projection. The caller can report email and username
    /// conflicts per input row without issuing two queries per candidate.
    pub async fn find_existing_user_identities(
        &self,
        emails: &[String],
        usernames: &[String],
    ) -> AppResult<(BTreeSet<String>, BTreeSet<String>)> {
        let emails = dedupe_nonempty(emails.to_vec());
        let usernames = dedupe_nonempty(usernames.to_vec());
        if emails.is_empty() && usernames.is_empty() {
            return Ok((BTreeSet::new(), BTreeSet::new()));
        }
        with_conn!(self, |conn, kind| {
            let mut predicates = Vec::new();
            if !emails.is_empty() {
                let placeholders = placeholders(kind, 1, emails.len());
                predicates.push(format!("email IN ({placeholders})"));
            }
            if !usernames.is_empty() {
                let start = emails.len() + 1;
                let placeholders = placeholders(kind, start, usernames.len());
                predicates.push(format!("username IN ({placeholders})"));
            }
            let sql = format!(
                "SELECT email, username FROM users WHERE {}",
                predicates.join(" OR ")
            );
            let mut values = emails;
            values.extend(usernames);
            let rows = bind_text_list(&mut conn, sql_query(sql), &values)
                .load::<UserIdentityConflictRow>(&mut conn)
                .map_err(AppError::from)?;
            Ok(rows.into_iter().fold(
                (BTreeSet::new(), BTreeSet::new()),
                |(mut existing_emails, mut existing_usernames), row| {
                    existing_emails.insert(row.email);
                    existing_usernames.insert(row.username);
                    (existing_emails, existing_usernames)
                },
            ))
        })
    }

    pub async fn find_user_by_username(&self, username: &str) -> AppResult<Option<UserRecord>> {
        let username = username.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE username = {}", select_user_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(username)
                .get_result::<UserRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_user_by_id(&self, id: &str) -> AppResult<Option<UserRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<UserRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_scim_user_in_scope(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> AppResult<Option<UserRecord>> {
        let user_id = user_id.to_string();
        let organization_id = organization_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE users.id = {} AND EXISTS (SELECT 1 FROM organization_members WHERE organization_members.organization_id = {} AND organization_members.user_id = users.id)",
                select_user_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(organization_id)
                .get_result::<UserRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    /// Resolves a bounded set of account ids with a non-sensitive selector.
    /// Password hashes, login IPs, and authentication metadata are not read
    /// from the database, which makes this suitable for admin assignment
    /// preflight checks.
    pub async fn find_users_by_ids(&self, ids: &[String]) -> AppResult<Vec<UserOptionRecord>> {
        const MAX_USER_SELECTOR_IDS: usize = 900;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids = ids
            .iter()
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        if ids.len() > MAX_USER_SELECTOR_IDS {
            return Err(AppError::BadRequest(
                "too many user ids in selector request".to_string(),
            ));
        }
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, email, username, display_name FROM users WHERE id IN ({}) ORDER BY id ASC",
                placeholders(kind, 1, ids.len())
            );
            bind_text_list(&mut conn, sql_query(sql), &ids)
                .load::<UserOptionRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Resolves account lifecycle state for a bounded assignment set without
    /// hydrating a full UserRecord.  This is the batch counterpart to the
    /// selector projection above and keeps password/security columns out of
    /// admin preflight queries.
    pub async fn find_user_assignment_states(
        &self,
        ids: &[String],
    ) -> AppResult<Vec<UserAssignmentStateRecord>> {
        const MAX_ASSIGNMENT_IDS: usize = 900;
        let ids = ids
            .iter()
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        if ids.len() > MAX_ASSIGNMENT_IDS {
            return Err(AppError::BadRequest(
                "too many user ids in assignment request".to_string(),
            ));
        }
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, archived_at FROM users WHERE id IN ({}) ORDER BY id ASC",
                placeholders(kind, 1, ids.len())
            );
            bind_text_list(&mut conn, sql_query(sql), &ids)
                .load::<UserAssignmentStateRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_users(&self, scope: UserListScope) -> AppResult<Vec<UserRecord>> {
        with_conn!(self, |conn, kind| {
            let _ = kind;
            let sql = format!(
                "{} {} ORDER BY {}",
                select_user_sql(),
                scope.where_sql(),
                scope.order_sql()
            );
            sql_query(sql)
                .load::<UserRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    async fn fetch_user_list_page(
        &self,
        scope: UserListScope,
        filters: UserListFilters,
        exact_filter: Option<&UserListFilter>,
        offset: usize,
        limit: usize,
        select_sql: &'static str,
    ) -> AppResult<UserListPage> {
        let params = UserListSqlParams::from_filters(&filters, exact_filter);
        let offset_value = i64::try_from(offset).unwrap_or(i64::MAX);
        let limit_value = i64::try_from(limit).unwrap_or(i64::MAX);
        with_conn!(self, |conn, kind| {
            let predicates = user_list_predicate_sql(kind);
            let scope_predicate = scope.qualified_predicate_sql();
            let count_sql = format!(
                "SELECT COUNT(*) AS count FROM users WHERE {predicates} AND {scope_predicate}"
            );
            let count = bind_user_list_predicate!(sql_query(count_sql), &params)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count;
            let page_sql = format!(
                "{} WHERE {predicates} AND {scope_predicate} ORDER BY {} LIMIT {} OFFSET {}",
                select_sql,
                scope.order_sql(),
                ph(kind, 32),
                ph(kind, 33),
            );
            let users = bind_user_list_predicate!(sql_query(page_sql), &params)
                .bind::<BigInt, _>(limit_value)
                .bind::<BigInt, _>(offset_value)
                .load::<UserRecord>(&mut conn)
                .map_err(AppError::from)?;
            Ok(UserListPage {
                total: count,
                offset,
                limit,
                users,
            })
        })
    }

    /// Reads one bounded user page and its total in the same connection. This
    /// compatibility shape is used by SCIM and keeps its exact-match filters;
    /// the administrative directory uses `list_admin_users_page` below.
    pub async fn list_users_page(
        &self,
        scope: UserListScope,
        organization_id: Option<&str>,
        filter: Option<UserListFilter>,
        offset: usize,
        limit: usize,
    ) -> AppResult<(i64, Vec<UserRecord>)> {
        let filters = UserListFilters {
            organization_id: organization_id.map(str::to_string),
            ..Default::default()
        };
        let page = self
            .fetch_user_list_page(
                scope,
                filters,
                filter.as_ref(),
                offset,
                limit,
                select_user_sql(),
            )
            .await?;
        Ok((page.total, page.users))
    }

    /// Administrative user-directory read model. Every filter is evaluated in
    /// SQL and the same predicate is used for the total and page queries.
    pub async fn list_admin_users_page(
        &self,
        scope: UserListScope,
        filters: UserListFilters,
        offset: usize,
        limit: usize,
    ) -> AppResult<UserListPage> {
        self.fetch_user_list_page(
            scope,
            filters,
            None,
            offset,
            limit,
            select_user_directory_sql(),
        )
        .await
    }

    /// Reads an administrative user page with a stable keyset cursor.  This
    /// deliberately omits COUNT and OFFSET: deep pages remain bounded even
    /// when earlier rows are inserted or removed between requests.
    pub async fn list_admin_users_page_after(
        &self,
        scope: UserListScope,
        filters: UserListFilters,
        cursor: Option<UserDirectoryCursor>,
        limit: usize,
    ) -> AppResult<UserDirectoryCursorPage> {
        let limit = limit.clamp(1, 200);
        let page_limit = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
        let params = UserListSqlParams::from_filters(&filters, None);
        with_conn!(self, |conn, kind| {
            let predicates = user_list_predicate_sql(kind);
            let scope_predicate = scope.qualified_predicate_sql();
            let (cursor_predicate, limit_index) = match cursor.as_ref() {
                None => (String::new(), 32),
                Some(_cursor) => match scope {
                    UserListScope::Archived => (
                        format!(
                            " AND (users.archived_at < {} OR (users.archived_at = {} AND (users.created_at < {} OR (users.created_at = {} AND users.id > {}))))",
                            ph(kind, 32),
                            ph(kind, 33),
                            ph(kind, 34),
                            ph(kind, 35),
                            ph(kind, 36),
                        ),
                        37,
                    ),
                    UserListScope::AuthorizationCode | UserListScope::All => (
                        format!(
                            " AND ((CASE WHEN users.archived_at IS NOT NULL THEN 1 ELSE 0 END) > {} OR ((CASE WHEN users.archived_at IS NOT NULL THEN 1 ELSE 0 END) = {} AND (users.is_active < {} OR (users.is_active = {} AND (users.created_at < {} OR (users.created_at = {} AND users.id > {}))))))",
                            ph(kind, 32),
                            ph(kind, 33),
                            ph(kind, 34),
                            ph(kind, 35),
                            ph(kind, 36),
                            ph(kind, 37),
                            ph(kind, 38),
                        ),
                        39,
                    ),
                    UserListScope::Live | UserListScope::Active | UserListScope::Disabled => (
                        format!(
                            " AND (users.is_active < {} OR (users.is_active = {} AND (users.created_at < {} OR (users.created_at = {} AND users.id > {}))))",
                            ph(kind, 32),
                            ph(kind, 33),
                            ph(kind, 34),
                            ph(kind, 35),
                            ph(kind, 36),
                        ),
                        37,
                    ),
                },
            };
            let page_sql = format!(
                "{} WHERE {predicates} AND {scope_predicate}{cursor_predicate} ORDER BY {} LIMIT {}",
                select_user_directory_sql(),
                scope.qualified_order_sql(),
                ph(kind, limit_index),
            );
            let query = bind_user_list_predicate!(sql_query(page_sql), &params);
            let users = match cursor.as_ref() {
                None => query
                    .bind::<BigInt, _>(page_limit)
                    .load::<UserRecord>(&mut conn)
                    .map_err(AppError::from)?,
                Some(cursor) => match scope {
                    UserListScope::Archived => query
                        .bind::<BigInt, _>(cursor.archived_at.ok_or_else(|| {
                            AppError::BadRequest(
                                "archived user cursor is missing archived_at".to_string(),
                            )
                        })?)
                        .bind::<BigInt, _>(cursor.archived_at.ok_or_else(|| {
                            AppError::BadRequest(
                                "archived user cursor is missing archived_at".to_string(),
                            )
                        })?)
                        .bind::<BigInt, _>(cursor.created_at)
                        .bind::<BigInt, _>(cursor.created_at)
                        .bind::<Text, _>(&cursor.id)
                        .bind::<BigInt, _>(page_limit)
                        .load::<UserRecord>(&mut conn)
                        .map_err(AppError::from)?,
                    UserListScope::AuthorizationCode | UserListScope::All => query
                        .bind::<Integer, _>(i32::from(cursor.archived))
                        .bind::<Integer, _>(i32::from(cursor.archived))
                        .bind::<Integer, _>(cursor.is_active)
                        .bind::<Integer, _>(cursor.is_active)
                        .bind::<BigInt, _>(cursor.created_at)
                        .bind::<BigInt, _>(cursor.created_at)
                        .bind::<Text, _>(&cursor.id)
                        .bind::<BigInt, _>(page_limit)
                        .load::<UserRecord>(&mut conn)
                        .map_err(AppError::from)?,
                    UserListScope::Live | UserListScope::Active | UserListScope::Disabled => query
                        .bind::<Integer, _>(cursor.is_active)
                        .bind::<Integer, _>(cursor.is_active)
                        .bind::<BigInt, _>(cursor.created_at)
                        .bind::<BigInt, _>(cursor.created_at)
                        .bind::<Text, _>(&cursor.id)
                        .bind::<BigInt, _>(page_limit)
                        .load::<UserRecord>(&mut conn)
                        .map_err(AppError::from)?,
                },
            };
            let mut users = users;
            let has_more = users.len() > limit;
            if has_more {
                users.pop();
            }
            let next_cursor =
                has_more
                    .then(|| users.last())
                    .flatten()
                    .map(|user| UserDirectoryCursor {
                        archived: user.archived_at.is_some(),
                        archived_at: user.archived_at,
                        is_active: user.is_active,
                        created_at: user.created_at,
                        id: user.id.clone(),
                    });
            Ok(UserDirectoryCursorPage {
                limit,
                users,
                next_cursor,
            })
        })
    }

    /// Returns a bounded, non-sensitive projection for account selectors.
    /// This intentionally does not reuse `list_admin_users_page`: selector
    /// consumers do not need a count, pagination metadata, password hash, or
    /// login/security fields, and should not pay to hydrate them.
    pub async fn list_user_options(
        &self,
        scope: UserListScope,
        organization_id: Option<&str>,
        search: Option<&str>,
        limit: usize,
    ) -> AppResult<Vec<UserOptionRecord>> {
        let organization_id = organization_id.map(str::to_string);
        let search = search.map(contains_like_pattern);
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        with_conn!(self, |conn, kind| {
            // Every occurrence receives its own placeholder index.  This is
            // required for SQLite/MySQL, where `?` placeholders are positional
            // even when the same logical value appears more than once.
            let sql = format!(
                "SELECT users.id, users.email, users.username, users.display_name FROM users WHERE ({} IS NULL OR EXISTS (SELECT 1 FROM organization_members WHERE organization_members.organization_id = {} AND organization_members.user_id = users.id)) AND ({} IS NULL OR (LOWER(COALESCE(users.email, '')) LIKE LOWER({}) ESCAPE '!' OR LOWER(COALESCE(users.username, '')) LIKE LOWER({}) ESCAPE '!' OR LOWER(COALESCE(users.display_name, '')) LIKE LOWER({}) ESCAPE '!' OR LOWER(COALESCE(users.phone, '')) LIKE LOWER({}) ESCAPE '!')) AND {} ORDER BY users.email ASC, users.id ASC LIMIT {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                scope.qualified_predicate_sql(),
                ph(kind, 8),
            );
            sql_query(sql)
                .bind::<Nullable<Text>, _>(organization_id.clone())
                .bind::<Nullable<Text>, _>(organization_id)
                .bind::<Nullable<Text>, _>(search.clone())
                .bind::<Nullable<Text>, _>(search.clone())
                .bind::<Nullable<Text>, _>(search.clone())
                .bind::<Nullable<Text>, _>(search.clone())
                .bind::<Nullable<Text>, _>(search)
                .bind::<BigInt, _>(limit)
                .load::<UserOptionRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Lists users that are members of one organization.
    ///
    /// Organization-scoped integrations must use this query instead of
    /// loading the global user list and filtering it in application code. The
    /// membership predicate stays in the same SQL statement as the user
    /// status predicate, which keeps both the result set and its count
    /// bounded by the tenant boundary.
    pub async fn list_users_for_organization(
        &self,
        organization_id: &str,
        scope: UserListScope,
    ) -> AppResult<Vec<UserRecord>> {
        let organization_id = organization_id.to_string();
        // `organization_members` has its own timestamps. Qualify every user
        // predicate/order column here so the tenant query remains valid after
        // the JOIN and cannot accidentally sort or filter on membership rows.
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} INNER JOIN organization_members ON organization_members.user_id = users.id WHERE organization_members.organization_id = {} AND {} ORDER BY {}",
                select_user_sql(),
                ph(kind, 1),
                scope.qualified_predicate_sql(),
                scope.qualified_order_sql()
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .load::<UserRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn user_belongs_to_organization(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> AppResult<bool> {
        let organization_id = organization_id.to_string();
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM organization_members WHERE organization_id = {} AND user_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .bind::<Text, _>(user_id)
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count > 0)
                .map_err(AppError::from)
        })
    }

    pub async fn count_users(&self, scope: UserListScope) -> AppResult<i64> {
        with_conn!(self, |conn, _kind| {
            let sql = if scope.where_sql().is_empty() {
                "SELECT COUNT(*) AS count FROM users".to_string()
            } else {
                format!("SELECT COUNT(*) AS count FROM users {}", scope.where_sql())
            };
            sql_query(sql)
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count)
                .map_err(AppError::from)
        })
    }

    pub async fn count_user_overview(&self) -> AppResult<(i64, i64)> {
        with_conn!(self, |conn, _kind| {
            sql_query(
                "SELECT COUNT(*) AS total, COUNT(CASE WHEN archived_at IS NULL AND is_active = 1 THEN 1 END) AS active FROM users",
            )
            .get_result::<UserOverviewCountRow>(&mut conn)
            .map(|row| (row.total, row.active))
            .map_err(AppError::from)
        })
    }

    pub async fn user_count(&self) -> AppResult<i64> {
        self.count_users(UserListScope::All).await
    }
}
