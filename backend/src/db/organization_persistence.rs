use super::{
    AppError, AppResult, AuditEventRecord, AuthorizationCodeType, CountRow, DatabaseKind, Db,
    GroupMemberIdRow, LoginCodeLevel, NewOrganization, ORGANIZATION_KIND_SYSTEM,
    OrganizationMemberCountRecord, OrganizationMemberInput, OrganizationMemberRecord,
    OrganizationMemberWithUserRecord, OrganizationRecord, SIGNET_ORGANIZATION_ID,
    SIGNET_ORGANIZATION_SLUG, UserOrganizationRecord, bind_text_list, blocking,
    dedupe_organization_members, ph, placeholders, select_organization_sql,
};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};
use std::collections::{BTreeMap, BTreeSet};

impl Db {
    pub async fn list_organizations(&self) -> AppResult<Vec<OrganizationRecord>> {
        with_conn!(self, |conn, _kind| {
            let sql = format!(
                "{} ORDER BY is_active DESC, slug ASC",
                select_organization_sql()
            );
            sql_query(sql)
                .load::<OrganizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Ensures the one platform-owned organization exists. Existing deployments
    /// that already used the reserved `signet` slug are adopted rather than
    /// failing their upgrade; new deployments receive the stable identifier.
    pub async fn ensure_signet_organization(&self) -> AppResult<OrganizationRecord> {
        with_conn!(self, |conn, kind| {
            let existing_by_id =
                format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
            if let Some(existing) = sql_query(existing_by_id)
                .bind::<Text, _>(SIGNET_ORGANIZATION_ID)
                .get_result::<OrganizationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
            {
                if existing.kind != ORGANIZATION_KIND_SYSTEM {
                    let update = format!(
                        "UPDATE organizations SET kind = {} WHERE id = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(update)
                        .bind::<Text, _>(ORGANIZATION_KIND_SYSTEM)
                        .bind::<Text, _>(SIGNET_ORGANIZATION_ID)
                        .execute(&mut conn)
                        .map_err(AppError::from)?;
                    let sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
                    return sql_query(sql)
                        .bind::<Text, _>(SIGNET_ORGANIZATION_ID)
                        .get_result::<OrganizationRecord>(&mut conn)
                        .map_err(AppError::from);
                }
                return Ok(existing);
            }

            let existing_slug =
                format!("{} WHERE slug = {}", select_organization_sql(), ph(kind, 1));
            if let Some(existing) = sql_query(existing_slug)
                .bind::<Text, _>(SIGNET_ORGANIZATION_SLUG)
                .get_result::<OrganizationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
            {
                let update = format!(
                    "UPDATE organizations SET kind = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(update)
                    .bind::<Text, _>(ORGANIZATION_KIND_SYSTEM)
                    .bind::<Text, _>(&existing.id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
                let sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
                return sql_query(sql)
                    .bind::<Text, _>(existing.id)
                    .get_result::<OrganizationRecord>(&mut conn)
                    .map_err(AppError::from);
            }

            let now = util::now_ts();
            let insert = format!(
                "INSERT INTO organizations (id, slug, name, kind, description, allowed_email_domains, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
                ph(kind, 9)
            );
            sql_query(insert)
                .bind::<Text, _>(SIGNET_ORGANIZATION_ID)
                .bind::<Text, _>(SIGNET_ORGANIZATION_SLUG)
                .bind::<Text, _>("Signet")
                .bind::<Text, _>(ORGANIZATION_KIND_SYSTEM)
                .bind::<Nullable<Text>, _>(Some("Signet platform administration".to_string()))
                .bind::<Text, _>("[]")
                .bind::<Integer, _>(1)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(SIGNET_ORGANIZATION_ID)
                .get_result::<OrganizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn upsert_organization_member(
        &self,
        organization_id: &str,
        user_id: &str,
        role: &str,
    ) -> AppResult<()> {
        let organization_id = organization_id.to_string();
        let user_id = user_id.to_string();
        let role = role.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let count_sql = format!(
                "SELECT COUNT(*) AS count FROM organization_members WHERE organization_id = {} AND user_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            let exists = sql_query(count_sql)
                .bind::<Text, _>(&organization_id)
                .bind::<Text, _>(&user_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                > 0;
            if exists {
                let sql = format!(
                    "UPDATE organization_members SET role = {}, updated_at = {} WHERE organization_id = {} AND user_id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(sql)
                    .bind::<Text, _>(role)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(organization_id)
                    .bind::<Text, _>(user_id)
                    .execute(&mut conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            } else {
                let sql = format!(
                    "INSERT INTO organization_members (organization_id, user_id, role, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(sql)
                    .bind::<Text, _>(organization_id)
                    .bind::<Text, _>(user_id)
                    .bind::<Text, _>(role)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            }
        })
    }

    pub async fn list_organization_member_counts(&self) -> AppResult<BTreeMap<String, i64>> {
        with_conn!(self, |conn, _kind| {
            sql_query(
                "SELECT organization_id, COUNT(*) AS member_count FROM organization_members GROUP BY organization_id",
            )
            .load::<OrganizationMemberCountRecord>(&mut conn)
            .map(|counts| {
                counts
                    .into_iter()
                    .map(|count| (count.organization_id, count.member_count))
                    .collect()
            })
            .map_err(AppError::from)
        })
    }

    pub async fn count_organization_members(&self, organization_id: &str) -> AppResult<i64> {
        let organization_id = organization_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM organization_members WHERE organization_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count)
                .map_err(AppError::from)
        })
    }

    pub async fn find_organization_by_id(&self, id: &str) -> AppResult<Option<OrganizationRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<OrganizationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_organization(
        &self,
        organization: NewOrganization,
    ) -> AppResult<OrganizationRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let allowed_email_domains = util::to_json(&organization.allowed_email_domains)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO organizations (id, slug, name, kind, description, allowed_email_domains, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
                ph(kind, 9)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(organization.slug)
                .bind::<Text, _>(organization.name)
                .bind::<Text, _>(organization.kind)
                .bind::<Nullable<Text>, _>(organization.description)
                .bind::<Text, _>(allowed_email_domains)
                .bind::<Integer, _>(i32::from(organization.is_active))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<OrganizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_organization(
        &self,
        id: &str,
        organization: NewOrganization,
    ) -> AppResult<OrganizationRecord> {
        if self
            .find_organization_by_id(id)
            .await?
            .is_some_and(|existing| existing.kind == ORGANIZATION_KIND_SYSTEM)
        {
            return Err(AppError::Forbidden);
        }
        let id = id.to_string();
        let now = util::now_ts();
        let allowed_email_domains = util::to_json(&organization.allowed_email_domains)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE organizations SET slug = {}, name = {}, description = {}, allowed_email_domains = {}, is_active = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(organization.slug)
                .bind::<Text, _>(organization.name)
                .bind::<Nullable<Text>, _>(organization.description)
                .bind::<Text, _>(allowed_email_domains)
                .bind::<Integer, _>(i32::from(organization.is_active))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                return Err(AppError::NotFound);
            }
            let sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<OrganizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_organization(&self, id: &str) -> AppResult<()> {
        self.delete_organization_mutation(id, None).await
    }

    pub async fn delete_organization_with_audit(
        &self,
        id: &str,
        event: crate::audit::AuditEvent,
    ) -> AppResult<()> {
        self.delete_organization_mutation(id, Some(event)).await
    }

    async fn delete_organization_mutation(
        &self,
        id: &str,
        mut audit: Option<crate::audit::AuditEvent>,
    ) -> AppResult<()> {
        let id = id.to_string();
        let now = util::now_ts();
        if let Some(event) = audit.as_mut()
            && event.target_id.is_none()
        {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        with_conn!(self, |conn, kind| {
            let audit_event = conn.transaction::<Option<AuditEventRecord>, AppError, _>(|conn| {
                let organization_sql = format!(
                    "{} WHERE id = {}",
                    select_organization_sql(),
                    ph(kind, 1)
                );
                let organization = sql_query(organization_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<OrganizationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                if organization.kind == ORGANIZATION_KIND_SYSTEM {
                    return Err(AppError::Forbidden);
                }
                let application_count_sql = format!(
                    "SELECT COUNT(*) AS count FROM applications WHERE organization_id = {}",
                    ph(kind, 1)
                );
                if sql_query(application_count_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    > 0
                {
                    return Err(AppError::BadRequest(
                        "organization cannot be deleted while it owns applications; transfer or delete its applications first"
                            .to_string(),
                    ));
                }
                let sql = format!(
                    "UPDATE clients SET organization_id = NULL, updated_at = {} WHERE organization_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                for table in [
                    "user_organization_contexts",
                    "application_discovery_idempotency",
                ] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE organization_id = {}",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                // A tenant-owned identity source must not become a
                // platform-wide source merely because its tenant was
                // deleted. Provider slugs are reusable, so their identity
                // links and in-flight states must be removed with the source.
                for table in ["linked_identities", "external_oidc_states"] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE provider_slug IN (SELECT slug FROM external_oidc_providers WHERE organization_id = {})",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!(
                    "DELETE FROM external_oidc_providers WHERE organization_id = {}",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let ldap_provider_key_expression = match kind {
                    DatabaseKind::Sqlite | DatabaseKind::Postgres => "'ldap:' || slug",
                    DatabaseKind::Mysql => "CONCAT('ldap:', slug)",
                };
                let ldap_identity_sql = format!(
                    "DELETE FROM linked_identities WHERE provider_slug IN (SELECT {ldap_provider_key_expression} FROM ldap_providers WHERE organization_id = {})",
                    ph(kind, 1)
                );
                sql_query(ldap_identity_sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                for table in [
                    "directory_sync_leases",
                    "directory_sync_checkpoints",
                    "directory_sync_memberships",
                    "directory_sync_groups",
                    "directory_sync_runs",
                ] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE provider_id IN (SELECT id FROM ldap_providers WHERE organization_id = {})",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!(
                    "DELETE FROM ldap_providers WHERE organization_id = {}",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                // Trial-enrollment authorization codes cannot survive without
                // their one required organization.  Remove their outstanding
                // grants before deleting the codes, then revoke every trial
                // account that was created for this organization below.
                let sql = format!(
                    "DELETE FROM oidc_login_grants WHERE invitation_id IN (SELECT id FROM invitations WHERE organization_id = {} AND code_type = {} AND login_code_level = {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                    .bind::<Text, _>(LoginCodeLevel::TrialEnrollment.as_str())
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "DELETE FROM invitations WHERE organization_id = {} AND code_type = {} AND login_code_level = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                    .bind::<Text, _>(LoginCodeLevel::TrialEnrollment.as_str())
                    .execute(conn)
                    .map_err(AppError::from)?;
                // Normal-account enterprise invitations are also tied to
                // this tenant. They may not be redeemed into an enterprise
                // that no longer exists.
                let sql = format!(
                    "DELETE FROM invitations WHERE organization_id = {} AND code_type = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(AuthorizationCodeType::Registration.as_str())
                    .execute(conn)
                    .map_err(AppError::from)?;
                revoke_trial_enrollment_auth_state_for_organization!(conn, kind, &id);
                let sql = format!(
                    "UPDATE trial_enrollments SET revoked_at = {} WHERE organization_id = {} AND revoked_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                // The public API only permits an organization on trial
                // enrollment codes.  Clear it from any pre-existing legacy
                // or malformed records instead of deleting an otherwise
                // independent authorization code.
                let sql = format!(
                    "UPDATE invitations SET organization_id = NULL, organization_role = NULL, updated_at = {} WHERE organization_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "DELETE FROM organization_members WHERE organization_id = {}",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!("DELETE FROM organizations WHERE id = {}", ph(kind, 1));
                let affected = sql_query(sql)
                    .bind::<Text, _>(id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::NotFound);
                }
                audit
                    .take()
                    .map(|event| insert_audit_event_on_conn!(conn, kind, event))
                    .transpose()
            })?;
            if let Some(audit_event) = audit_event {
                crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
            }
            Ok(())
        })
    }

    pub async fn replace_organization_members(
        &self,
        organization_id: &str,
        members: Vec<OrganizationMemberInput>,
    ) -> AppResult<()> {
        let organization_id = organization_id.to_string();
        let members = dedupe_organization_members(members);
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let sql = format!(
                    "SELECT COUNT(*) AS count FROM organizations WHERE id = {}",
                    ph(kind, 1)
                );
                let count = sql_query(sql)
                    .bind::<Text, _>(&organization_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count;
                if count == 0 {
                    return Err(AppError::NotFound);
                }

                let requested_user_ids = members
                    .iter()
                    .map(|member| member.user_id.clone())
                    .collect::<Vec<_>>();
                if !requested_user_ids.is_empty() {
                    let placeholders = placeholders(kind, 1, requested_user_ids.len());
                    let sql = format!(
                        "SELECT id AS user_id FROM users WHERE id IN ({placeholders})"
                    );
                    let valid_ids = bind_text_list(conn, sql_query(sql), &requested_user_ids)
                        .load::<GroupMemberIdRow>(conn)
                        .map_err(AppError::from)?
                        .into_iter()
                        .map(|row| row.user_id)
                        .collect::<BTreeSet<_>>();
                    if let Some(missing_id) = requested_user_ids
                        .iter()
                        .find(|user_id| !valid_ids.contains(*user_id))
                    {
                        return Err(AppError::BadRequest(format!(
                            "unknown user: {missing_id}"
                        )));
                    }
                }

                let existing_members_sql = format!(
                    "SELECT organization_id, user_id, role, created_at, updated_at FROM organization_members WHERE organization_id = {}",
                    ph(kind, 1)
                );
                let existing_member_ids = sql_query(existing_members_sql)
                    .bind::<Text, _>(&organization_id)
                    .load::<OrganizationMemberRecord>(conn)
                    .map_err(AppError::from)?
                    .into_iter()
                    .map(|member| member.user_id)
                    .collect::<BTreeSet<_>>();
                let replacement_member_ids = members
                    .iter()
                    .map(|member| member.user_id.clone())
                    .collect::<BTreeSet<_>>();

                // A user who leaves the enterprise must immediately release
                // only their own application-local identity leases. Keeping
                // the leases of members who remain avoids a roster edit
                // opening a uniqueness bypass for those accounts.
                let removed_user_ids = existing_member_ids
                    .difference(&replacement_member_ids)
                    .cloned()
                    .collect::<Vec<_>>();
                if !removed_user_ids.is_empty() {
                    let placeholders = placeholders(kind, 1, removed_user_ids.len());
                    let bindings_sql = format!(
                        "DELETE FROM application_identity_bindings WHERE user_id IN ({placeholders}) AND application_id IN (SELECT id FROM applications WHERE organization_id = {})",
                        ph(kind, removed_user_ids.len() + 1)
                    );
                    let mut values = removed_user_ids;
                    values.push(organization_id.clone());
                    bind_text_list(conn, sql_query(bindings_sql), &values)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                let sql = format!(
                    "DELETE FROM organization_members WHERE organization_id = {}",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&organization_id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                if !members.is_empty() {
                    let placeholders = (1..=members.len() * 3)
                        .map(|index| ph(kind, index))
                        .collect::<Vec<_>>();
                    let sql = format!(
                        "INSERT INTO organization_members (organization_id, user_id, role, created_at, updated_at) VALUES {}",
                        placeholders
                            .chunks(3)
                            .map(|row| {
                                format!(
                                    "({}, {}, {}, {now}, {now})",
                                    row[0], row[1], row[2]
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    let mut values = Vec::with_capacity(members.len() * 3);
                    for member in members {
                        values.push(organization_id.clone());
                        values.push(member.user_id);
                        values.push(member.role);
                    }
                    bind_text_list(conn, sql_query(sql), &values)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                Ok(())
            })
        })
    }

    pub async fn list_organization_members(
        &self,
        organization_id: &str,
    ) -> AppResult<Vec<OrganizationMemberWithUserRecord>> {
        let organization_id = organization_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT organization_members.organization_id, organization_members.user_id, organization_members.role, organization_members.created_at AS membership_created_at, organization_members.updated_at AS membership_updated_at, users.email, users.username, users.display_name, users.is_active, users.archived_at FROM organization_members INNER JOIN users ON users.id = organization_members.user_id WHERE organization_members.organization_id = {} ORDER BY organization_members.role ASC, users.email ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .load::<OrganizationMemberWithUserRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_user_organizations(
        &self,
        user_id: &str,
    ) -> AppResult<Vec<UserOrganizationRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT organizations.id, organizations.slug, organizations.name, COALESCE(organizations.kind, 'tenant') AS kind, organizations.description, organizations.is_active, organization_members.role, organization_members.created_at AS membership_created_at, organization_members.updated_at AS membership_updated_at FROM organization_members INNER JOIN organizations ON organizations.id = organization_members.organization_id WHERE organization_members.user_id = {} ORDER BY organizations.is_active DESC, organizations.slug ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<UserOrganizationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Returns the persisted management-tenant context, falling back to the
    /// user's first active enterprise. The context is a convenience for the
    /// console only; every scoped endpoint independently verifies membership.
    pub async fn active_user_organization(
        &self,
        user_id: &str,
    ) -> AppResult<Option<UserOrganizationRecord>> {
        let user_id = user_id.to_string();
        let context_user_id = user_id.clone();
        let selected = with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT organizations.id, organizations.slug, organizations.name, COALESCE(organizations.kind, 'tenant') AS kind, organizations.description, organizations.is_active, organization_members.role, organization_members.created_at AS membership_created_at, organization_members.updated_at AS membership_updated_at FROM user_organization_contexts INNER JOIN organization_members ON organization_members.user_id = user_organization_contexts.user_id AND organization_members.organization_id = user_organization_contexts.organization_id INNER JOIN organizations ON organizations.id = organization_members.organization_id WHERE user_organization_contexts.user_id = {} AND organizations.is_active = 1",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(context_user_id)
                .get_result::<UserOrganizationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })?;
        if selected.is_some() {
            return Ok(selected);
        }
        Ok(self
            .list_user_organizations(&user_id)
            .await?
            .into_iter()
            .find(|organization| organization.is_active == 1))
    }

    pub async fn set_active_user_organization(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> AppResult<UserOrganizationRecord> {
        let user_id = user_id.to_string();
        let organization_id = organization_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let membership_sql = format!(
                "SELECT organizations.id, organizations.slug, organizations.name, COALESCE(organizations.kind, 'tenant') AS kind, organizations.description, organizations.is_active, organization_members.role, organization_members.created_at AS membership_created_at, organization_members.updated_at AS membership_updated_at FROM organization_members INNER JOIN organizations ON organizations.id = organization_members.organization_id WHERE organization_members.user_id = {} AND organization_members.organization_id = {} AND organizations.is_active = 1",
                ph(kind, 1),
                ph(kind, 2)
            );
            let organization = sql_query(membership_sql)
                .bind::<Text, _>(&user_id)
                .bind::<Text, _>(&organization_id)
                .get_result::<UserOrganizationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
                .ok_or(AppError::Forbidden)?;
            let exists_sql = format!(
                "SELECT COUNT(*) AS count FROM user_organization_contexts WHERE user_id = {}",
                ph(kind, 1)
            );
            let exists = sql_query(exists_sql)
                .bind::<Text, _>(&user_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                > 0;
            if exists {
                let update_sql = format!(
                    "UPDATE user_organization_contexts SET organization_id = {}, updated_at = {} WHERE user_id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                sql_query(update_sql)
                    .bind::<Text, _>(&organization_id)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&user_id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            } else {
                let insert_sql = format!(
                    "INSERT INTO user_organization_contexts (user_id, organization_id, updated_at) VALUES ({}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3)
                );
                sql_query(insert_sql)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&organization_id)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            Ok(organization)
        })
    }
}
