//! Organization aggregate mutations.
//!
//! Organization metadata, membership, and the selected management context
//! are one ownership boundary. These helpers keep their audit event in the
//! same transaction as the aggregate write so a partially-created tenant can
//! never be observed as successfully provisioned.

use super::{
    AppError, AuditEventRecord, CountRow, DatabaseKind, Db, GroupMemberIdRow, NewOrganization,
    OrganizationMemberInput, OrganizationMemberRecord, OrganizationRecord, bind_text_list,
    blocking, dedupe_organization_members, ph, placeholders, select_organization_sql,
};
use crate::{audit::AuditEvent, util};
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};
use std::collections::BTreeSet;

impl Db {
    /// Creates a tenant, grants its creator the owner role, selects it as the
    /// creator's active context, and records one audit event atomically.
    pub async fn create_organization_with_owner_and_audit(
        &self,
        organization: NewOrganization,
        owner_user_id: &str,
        event: AuditEvent,
    ) -> crate::error::AppResult<OrganizationRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let owner_user_id = owner_user_id.to_string();
        let now = util::now_ts();
        let allowed_email_domains = util::to_json(&organization.allowed_email_domains)?;
        let mut event = event;
        if event.target_id.is_none() {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        let (organization, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(OrganizationRecord, AuditEventRecord), AppError, _>(|conn| {
                let insert_sql = format!(
                    "INSERT INTO organizations (id, slug, name, kind, description, allowed_email_domains, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(organization.slug)
                    .bind::<Text, _>(organization.name)
                    .bind::<Text, _>(organization.kind)
                    .bind::<Nullable<Text>, _>(organization.description)
                    .bind::<Text, _>(allowed_email_domains)
                    .bind::<Integer, _>(i32::from(organization.is_active))
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let member_sql = format!(
                    "INSERT INTO organization_members (organization_id, user_id, role, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                );
                sql_query(member_sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&owner_user_id)
                    .bind::<Text, _>(crate::organizations::ROLE_OWNER)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let context_count_sql = format!(
                    "SELECT COUNT(*) AS count FROM user_organization_contexts WHERE user_id = {}",
                    ph(kind, 1)
                );
                let has_context = sql_query(context_count_sql)
                    .bind::<Text, _>(&owner_user_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    > 0;
                if has_context {
                    let update_context_sql = format!(
                        "UPDATE user_organization_contexts SET organization_id = {}, updated_at = {} WHERE user_id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                    );
                    sql_query(update_context_sql)
                        .bind::<Text, _>(&id)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&owner_user_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                } else {
                    let insert_context_sql = format!(
                        "INSERT INTO user_organization_contexts (user_id, organization_id, updated_at) VALUES ({}, {}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                    );
                    sql_query(insert_context_sql)
                        .bind::<Text, _>(&owner_user_id)
                        .bind::<Text, _>(&id)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                let select_sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
                let organization = sql_query(select_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<OrganizationRecord>(conn)
                    .map_err(AppError::from)?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((organization, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(organization)
    }

    /// Creates a managed organization and its audit event atomically.
    pub async fn insert_organization_with_audit(
        &self,
        organization: NewOrganization,
        event: AuditEvent,
    ) -> crate::error::AppResult<OrganizationRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let allowed_email_domains = util::to_json(&organization.allowed_email_domains)?;
        let mut event = event;
        if event.target_id.is_none() {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        let (organization, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(OrganizationRecord, AuditEventRecord), AppError, _>(|conn| {
                let insert_sql = format!(
                    "INSERT INTO organizations (id, slug, name, kind, description, allowed_email_domains, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(organization.slug)
                    .bind::<Text, _>(organization.name)
                    .bind::<Text, _>(organization.kind)
                    .bind::<Nullable<Text>, _>(organization.description)
                    .bind::<Text, _>(allowed_email_domains)
                    .bind::<Integer, _>(i32::from(organization.is_active))
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
                let organization = sql_query(select_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<OrganizationRecord>(conn)
                    .map_err(AppError::from)?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((organization, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(organization)
    }

    /// Updates organization metadata with the system-organization guard and
    /// audit event evaluated on the same connection as the update.
    pub async fn update_organization_with_audit(
        &self,
        id: &str,
        organization: NewOrganization,
        event: AuditEvent,
    ) -> crate::error::AppResult<OrganizationRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        let allowed_email_domains = util::to_json(&organization.allowed_email_domains)?;
        let mut event = event;
        if event.target_id.is_none() {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        let (organization, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(OrganizationRecord, AuditEventRecord), AppError, _>(|conn| {
                let current_sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
                let current = sql_query(current_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<OrganizationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                if current.kind == crate::organizations::ORGANIZATION_KIND_SYSTEM {
                    return Err(AppError::Forbidden);
                }
                let update_sql = format!(
                    "UPDATE organizations SET slug = {}, name = {}, description = {}, allowed_email_domains = {}, is_active = {}, updated_at = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                );
                sql_query(update_sql)
                    .bind::<Text, _>(organization.slug)
                    .bind::<Text, _>(organization.name)
                    .bind::<Nullable<Text>, _>(organization.description)
                    .bind::<Text, _>(allowed_email_domains)
                    .bind::<Integer, _>(i32::from(organization.is_active))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let select_sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
                let organization = sql_query(select_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<OrganizationRecord>(conn)
                    .map_err(AppError::from)?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((organization, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(organization)
    }

    /// Replaces an organization's roster and releases application-local
    /// identity bindings for removed members in the same transaction as the
    /// membership diff and audit event.
    pub async fn replace_organization_members_with_audit(
        &self,
        organization_id: &str,
        members: Vec<OrganizationMemberInput>,
        event: AuditEvent,
    ) -> crate::error::AppResult<()> {
        let organization_id = organization_id.to_string();
        let members = dedupe_organization_members(members);
        let now = util::now_ts();
        let mut event = event;
        if event.target_id.is_none() {
            event.target_id = Some(organization_id.clone());
        }
        let webhook_db = self.clone();
        let audit_event = with_conn!(self, |conn, kind| {
            conn.transaction::<AuditEventRecord, AppError, _>(|conn| {
                let organization_sql = format!(
                    "SELECT COUNT(*) AS count FROM organizations WHERE id = {}",
                    ph(kind, 1)
                );
                let exists = sql_query(organization_sql)
                    .bind::<Text, _>(&organization_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    > 0;
                if !exists {
                    return Err(AppError::NotFound);
                }

                let requested_user_ids = members
                    .iter()
                    .map(|member| member.user_id.clone())
                    .collect::<Vec<_>>();
                if !requested_user_ids.is_empty() {
                    let placeholders = placeholders(kind, 1, requested_user_ids.len());
                    let user_sql = format!("SELECT id AS user_id FROM users WHERE id IN ({placeholders})");
                    let valid_ids = bind_text_list(conn, sql_query(user_sql), &requested_user_ids)
                        .load::<GroupMemberIdRow>(conn)
                        .map_err(AppError::from)?
                        .into_iter()
                        .map(|row| row.user_id)
                        .collect::<BTreeSet<_>>();
                    if let Some(missing_id) = requested_user_ids
                        .iter()
                        .find(|user_id| !valid_ids.contains(*user_id))
                    {
                        return Err(AppError::BadRequest(format!("unknown user: {missing_id}")));
                    }
                }

                let existing_sql = format!(
                    "SELECT organization_id, user_id, role, created_at, updated_at FROM organization_members WHERE organization_id = {}",
                    ph(kind, 1)
                );
                let existing_ids = sql_query(existing_sql)
                    .bind::<Text, _>(&organization_id)
                    .load::<OrganizationMemberRecord>(conn)
                    .map_err(AppError::from)?
                    .into_iter()
                    .map(|member| member.user_id)
                    .collect::<BTreeSet<_>>();
                let replacement_ids = members
                    .iter()
                    .map(|member| member.user_id.clone())
                    .collect::<BTreeSet<_>>();
                let removed_ids = existing_ids
                    .difference(&replacement_ids)
                    .cloned()
                    .collect::<Vec<_>>();
                if !removed_ids.is_empty() {
                    let placeholders = placeholders(kind, 1, removed_ids.len());
                    let binding_sql = format!(
                        "DELETE FROM application_identity_bindings WHERE user_id IN ({placeholders}) AND application_id IN (SELECT id FROM applications WHERE organization_id = {})",
                        ph(kind, removed_ids.len() + 1)
                    );
                    let mut values = removed_ids;
                    values.push(organization_id.clone());
                    bind_text_list(conn, sql_query(binding_sql), &values)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                let delete_sql = format!(
                    "DELETE FROM organization_members WHERE organization_id = {}",
                    ph(kind, 1)
                );
                sql_query(delete_sql)
                    .bind::<Text, _>(&organization_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if !members.is_empty() {
                    let placeholders = (1..=members.len() * 3)
                        .map(|index| ph(kind, index))
                        .collect::<Vec<_>>();
                    let values_sql = placeholders
                        .chunks(3)
                        .map(|row| format!("({}, {}, {}, {now}, {now})", row[0], row[1], row[2]))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let insert_sql = format!(
                        "INSERT INTO organization_members (organization_id, user_id, role, created_at, updated_at) VALUES {values_sql}"
                    );
                    let mut values = Vec::with_capacity(members.len() * 3);
                    for member in &members {
                        values.push(organization_id.clone());
                        values.push(member.user_id.clone());
                        values.push(member.role.clone());
                    }
                    bind_text_list(conn, sql_query(insert_sql), &values)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                insert_audit_event_on_conn!(conn, kind, event)
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(())
    }
}
