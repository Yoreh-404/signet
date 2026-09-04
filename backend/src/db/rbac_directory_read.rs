use super::{CountRow, Db, GroupListFilter, GroupRecord, ScimGroupMemberRecord, blocking, ph};
use crate::{
    config::DatabaseKind,
    error::{AppError, AppResult},
};
use diesel::{
    OptionalExtension, RunQueryDsl, sql_query, sql_types::BigInt, sql_types::Nullable,
    sql_types::Text,
};

impl Db {
    /// Reads a bounded group page.  `application_id = None` means the global
    /// directory; otherwise visibility is enforced through the application
    /// SCIM binding in SQL.
    pub async fn list_groups_page(
        &self,
        application_id: Option<&str>,
        filter: Option<GroupListFilter>,
        offset: usize,
        limit: usize,
    ) -> AppResult<(i64, Vec<GroupRecord>)> {
        let application_id = application_id.map(str::to_string);
        let (display_name, id) = match filter {
            Some(GroupListFilter::DisplayName(value)) => (Some(value), None),
            Some(GroupListFilter::Id(value)) => (None, Some(value)),
            None => (None, None),
        };
        let offset = i64::try_from(offset).unwrap_or(i64::MAX);
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        with_conn!(self, |conn, kind| {
            let application_param = ph(kind, 1);
            let application_value = ph(kind, 2);
            let display_name_param = ph(kind, 3);
            let display_name_value = ph(kind, 4);
            let id_param = ph(kind, 5);
            let id_value = ph(kind, 6);
            let predicates = format!(
                "({application_param} IS NULL OR EXISTS (SELECT 1 FROM application_scim_groups WHERE application_scim_groups.application_id = {application_value} AND application_scim_groups.group_id = access_groups.id)) AND ({display_name_param} IS NULL OR LOWER(access_groups.name) = LOWER({display_name_value})) AND ({id_param} IS NULL OR access_groups.id = {id_value})"
            );
            let count_sql =
                format!("SELECT COUNT(*) AS count FROM access_groups WHERE {predicates}");
            let count = sql_query(count_sql)
                .bind::<Nullable<Text>, _>(application_id.clone())
                .bind::<Nullable<Text>, _>(application_id.clone())
                .bind::<Nullable<Text>, _>(display_name.clone())
                .bind::<Nullable<Text>, _>(display_name.clone())
                .bind::<Nullable<Text>, _>(id.clone())
                .bind::<Nullable<Text>, _>(id.clone())
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count;
            let sql = format!(
                "SELECT access_groups.id, access_groups.name, access_groups.description, access_groups.created_at, access_groups.updated_at, access_groups.version FROM access_groups WHERE {predicates} ORDER BY access_groups.name ASC LIMIT {} OFFSET {}",
                ph(kind, 7),
                ph(kind, 8),
            );
            let groups = sql_query(sql)
                .bind::<Nullable<Text>, _>(application_id.clone())
                .bind::<Nullable<Text>, _>(application_id)
                .bind::<Nullable<Text>, _>(display_name.clone())
                .bind::<Nullable<Text>, _>(display_name)
                .bind::<Nullable<Text>, _>(id.clone())
                .bind::<Nullable<Text>, _>(id)
                .bind::<BigInt, _>(limit)
                .bind::<BigInt, _>(offset)
                .load::<GroupRecord>(&mut conn)
                .map_err(AppError::from)?;
            Ok((count, groups))
        })
    }

    /// Returns only the fields needed to render SCIM group members for the
    /// current page of groups.  The page is selected in a subquery, so this is
    /// one set-based read instead of one member query per group.
    pub async fn list_scim_group_member_refs_page(
        &self,
        application_id: Option<&str>,
        filter: Option<GroupListFilter>,
        offset: usize,
        limit: usize,
    ) -> AppResult<Vec<ScimGroupMemberRecord>> {
        let application_id = application_id.map(str::to_string);
        let (display_name, id) = match filter {
            Some(GroupListFilter::DisplayName(value)) => (Some(value), None),
            Some(GroupListFilter::Id(value)) => (None, Some(value)),
            None => (None, None),
        };
        let offset = i64::try_from(offset).unwrap_or(i64::MAX);
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        with_conn!(self, |conn, kind| {
            let application_param = ph(kind, 1);
            let application_value = ph(kind, 2);
            let display_name_param = ph(kind, 3);
            let display_name_value = ph(kind, 4);
            let id_param = ph(kind, 5);
            let id_value = ph(kind, 6);
            let predicates = format!(
                "({application_param} IS NULL OR EXISTS (SELECT 1 FROM application_scim_groups WHERE application_scim_groups.application_id = {application_value} AND application_scim_groups.group_id = access_groups.id)) AND ({display_name_param} IS NULL OR LOWER(access_groups.name) = LOWER({display_name_value})) AND ({id_param} IS NULL OR access_groups.id = {id_value})"
            );
            let page_subquery = format!(
                "SELECT access_groups.id FROM access_groups WHERE {predicates} ORDER BY access_groups.name ASC LIMIT {} OFFSET {}",
                ph(kind, 7),
                ph(kind, 8),
            );
            let application_scope_param = ph(kind, 9);
            let application_scope_value = ph(kind, 10);
            let organization_scope = format!(
                "({application_scope_param} IS NULL OR EXISTS (SELECT 1 FROM application_scim_groups AS scoped_groups INNER JOIN applications AS scoped_applications ON scoped_applications.id = scoped_groups.application_id INNER JOIN organization_members AS scoped_members ON scoped_members.organization_id = scoped_applications.organization_id AND scoped_members.user_id = users.id WHERE scoped_groups.application_id = {application_scope_value} AND scoped_groups.group_id = group_members.group_id))"
            );
            let sql = format!(
                "SELECT group_members.group_id, users.id AS user_id, users.username, users.display_name FROM users INNER JOIN group_members ON users.id = group_members.user_id WHERE group_members.group_id IN ({page_subquery}) AND {organization_scope} ORDER BY group_members.group_id ASC, users.email ASC"
            );
            sql_query(sql)
                .bind::<Nullable<Text>, _>(application_id.clone())
                .bind::<Nullable<Text>, _>(application_id.clone())
                .bind::<Nullable<Text>, _>(display_name.clone())
                .bind::<Nullable<Text>, _>(display_name.clone())
                .bind::<Nullable<Text>, _>(id.clone())
                .bind::<Nullable<Text>, _>(id.clone())
                .bind::<BigInt, _>(limit)
                .bind::<BigInt, _>(offset)
                .bind::<Nullable<Text>, _>(application_id.clone())
                .bind::<Nullable<Text>, _>(application_id)
                .load::<ScimGroupMemberRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_groups(&self) -> AppResult<Vec<GroupRecord>> {
        with_conn!(self, |conn, _kind| {
            sql_query("SELECT id, name, description, created_at, updated_at, version FROM access_groups ORDER BY name ASC")
                .load::<GroupRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Returns groups that can be used as application authorization subjects.
    /// The organization boundary is evaluated in SQL and the result is a
    /// narrow group projection, avoiding the old `list_groups` plus one
    /// `list_group_members` query per group pattern.
    pub async fn find_group_by_id(&self, id: &str) -> AppResult<Option<GroupRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, name, description, created_at, updated_at, version FROM access_groups WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<GroupRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }
}
