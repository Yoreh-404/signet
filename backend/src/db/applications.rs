//! Persistence for application-owned protocol graphs, modules, discovery, and bindings.
//!
//! The public methods remain inherent on Db; this module only owns their
//! physical implementation so callers and transaction semantics are unchanged.

use super::{
    ApplicationAuthContextRecord, ApplicationAuthDomainRecord,
    ApplicationAuthorizationProfileRecord, ApplicationClientBindingRecord,
    ApplicationIdentityBindingRecord, ApplicationMemberRecord, ApplicationMemberWithUserRecord,
    ApplicationModuleRecord, ApplicationOidcClientRecord, ApplicationRecord, AuditEventRecord,
    ClientRecord, CountRow, DatabaseKind, Db, InvitationRecord, NewApplication,
    NewApplicationAuthContext, NewApplicationAuthorizationProfile, NewApplicationMember,
    StringIdRow, application_slug_base, application_slug_collision_candidate, bind_text_list,
    blocking, ph, placeholders, select_application_authorization_profile_sql,
    select_application_client_binding_sql, select_application_identity_binding_sql,
    select_application_member_sql, select_application_module_sql, select_application_sql,
    select_client_sql, select_invitation_sql,
};
#[cfg(test)]
use super::{
    AuthorizationCodeType, DatabaseSettings, LoginCodeLevel, NewInvitation, NewOrganization,
    connect_sqlite,
};
use crate::error::{AppError, AppResult};
use crate::util;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use diesel::{Connection, OptionalExtension, RunQueryDsl};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn cached_profile_role_id<F>(
    cache: &mut BTreeMap<(String, String), Option<String>>,
    profile_id: &str,
    role_key: &str,
    load: F,
) -> AppResult<Option<String>>
where
    F: FnOnce() -> AppResult<Option<String>>,
{
    let cache_key = (profile_id.to_string(), role_key.to_string());
    if let Some(role_id) = cache.get(&cache_key) {
        return Ok(role_id.clone());
    }
    let role_id = load()?;
    cache.insert(cache_key, role_id.clone());
    Ok(role_id)
}

macro_rules! find_active_application_by_slug_on_conn {
    ($conn:expr, $kind:expr, $slug:expr) => {{
        let sql = format!(
            "{} WHERE slug = {} AND is_active = 1 AND organization_id IN (SELECT id FROM organizations WHERE is_active = 1) ORDER BY organization_id ASC",
            select_application_sql(),
            ph($kind, 1)
        );
        let applications = sql_query(sql)
            .bind::<Text, _>($slug)
            .load::<ApplicationRecord>($conn)
            .map_err(AppError::from)?;
        match applications.as_slice() {
            [] => Ok(None),
            [application] => Ok(Some(application.clone())),
            _ => Err(AppError::BadRequest(
                "application slug is ambiguous; use an organization-specific URL".to_string(),
            )),
        }
    }};
}

/// Creates the locked compatibility aggregate for a protocol client while
/// the owning application deletion transaction is still open. Keeping this
/// primitive on the same connection makes the "client is never unowned"
/// invariant durable across process crashes and avoids post-commit repair
/// races.
macro_rules! insert_locked_compatibility_application_on_conn {
    ($conn:expr, $kind:expr, $client:expr, $organization_id:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let client = $client;
        let organization_id = $organization_id;
        let now = $now;
        let slug = allocate_application_slug_on_conn!(
            conn,
            kind,
            organization_id,
            &client.client_id,
        );
        let application_id = uuid::Uuid::new_v4().to_string();
        let application = NewApplication {
            organization_id: organization_id.to_string(),
            slug,
            name: client.client_name.clone(),
            description: Some(format!(
                "Locked compatibility application for OIDC client {}.",
                client.client_id
            )),
            access_mode: crate::applications::ACCESS_ALL_SIGNET_USERS.to_string(),
            registration_mode: crate::applications::REGISTRATION_DISABLED.to_string(),
            account_selection_mode: if client.require_account_selection == 1 {
                crate::applications::ACCOUNT_SELECTION_REQUIRED.to_string()
            } else {
                crate::applications::ACCOUNT_SELECTION_OPTIONAL.to_string()
            },
            unique_identity_factors: Vec::new(),
            is_active: true,
        };
        let created = insert_application_on_conn!(conn, kind, &application_id, application, now)?;
        let auth_domain_id = format!("auth-domain:{application_id}");
        let auth_domain_sql = format!(
            "INSERT INTO application_auth_domains (id, application_id, assurance_policy, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
            ph(kind, 1),
            ph(kind, 2),
            ph(kind, 3),
            ph(kind, 4),
            ph(kind, 5),
            ph(kind, 6)
        );
        sql_query(auth_domain_sql)
            .bind::<Text, _>(&auth_domain_id)
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>("default")
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(conn)
            .map_err(AppError::from)?;
        let binding_sql = format!(
            "INSERT INTO application_client_bindings (application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
            ph(kind, 1),
            ph(kind, 2),
            ph(kind, 3),
            ph(kind, 4),
            ph(kind, 5),
            ph(kind, 6),
            ph(kind, 7),
            ph(kind, 8)
        );
        sql_query(binding_sql)
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>(&client.id)
            .bind::<Text, _>("oidc")
            .bind::<Text, _>("default")
            .bind::<Text, _>(&auth_domain_id)
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(now)
            .bind::<BigInt, _>(now)
            .execute(conn)
            .map_err(AppError::from)?;
        Ok::<ApplicationRecord, AppError>(created)
    }};
}

impl Db {
    pub async fn list_applications(
        &self,
        organization_id: Option<&str>,
    ) -> AppResult<Vec<ApplicationRecord>> {
        let organization_id = organization_id.map(ToOwned::to_owned);
        with_conn!(self, |conn, kind| {
            if let Some(organization_id) = organization_id {
                let sql = format!(
                    "{} WHERE organization_id = {} ORDER BY is_active DESC, name ASC",
                    select_application_sql(),
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(organization_id)
                    .load::<ApplicationRecord>(&mut conn)
                    .map_err(AppError::from)
            } else {
                let sql = format!(
                    "{} ORDER BY organization_id ASC, is_active DESC, name ASC",
                    select_application_sql()
                );
                sql_query(sql)
                    .load::<ApplicationRecord>(&mut conn)
                    .map_err(AppError::from)
            }
        })
    }
}

impl Db {
    pub async fn find_application_by_slug_in_organization(
        &self,
        organization_id: &str,
        slug: &str,
    ) -> AppResult<Option<ApplicationRecord>> {
        let organization_id = organization_id.to_string();
        let slug = slug.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE organization_id = {} AND slug = {}",
                select_application_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .bind::<Text, _>(slug)
                .get_result::<ApplicationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_by_id(&self, id: &str) -> AppResult<Option<ApplicationRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_application_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ApplicationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }
}

impl Db {
    pub async fn find_active_application_by_slug(
        &self,
        slug: &str,
    ) -> AppResult<Option<ApplicationRecord>> {
        let slug = slug.to_string();
        with_conn!(self, |conn, kind| {
            find_active_application_by_slug_on_conn!(&mut conn, kind, &slug)
        })
    }

    pub async fn find_active_application_by_slug_with_module(
        &self,
        slug: &str,
        module_key: &str,
    ) -> AppResult<Option<(ApplicationRecord, Option<ApplicationModuleRecord>)>> {
        let slug = slug.to_string();
        let module_key = module_key.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<Option<(ApplicationRecord, Option<ApplicationModuleRecord>)>, AppError, _>(
                |conn| {
                    let Some(application) =
                        find_active_application_by_slug_on_conn!(conn, kind, &slug)?
                    else {
                        return Ok(None);
                    };
                    let module_sql = format!(
                        "{} WHERE application_id = {} AND module_key = {}",
                        select_application_module_sql(),
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    let module = sql_query(module_sql)
                        .bind::<Text, _>(&application.id)
                        .bind::<Text, _>(&module_key)
                        .get_result::<ApplicationModuleRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?;
                    Ok(Some((application, module)))
                },
            )
        })
    }

    pub async fn find_application_for_client(
        &self,
        client_db_id: &str,
    ) -> AppResult<Option<ApplicationRecord>> {
        if let Some(application) = self
            .find_application_for_client_binding(client_db_id)
            .await?
        {
            return Ok(Some(application));
        }
        let Some(client) = self.find_client_by_id(client_db_id).await? else {
            return Ok(None);
        };
        self.ensure_application_for_client(&client).await?;
        self.find_application_for_client_binding(client_db_id).await
    }

    pub(crate) async fn find_application_for_client_binding(
        &self,
        client_db_id: &str,
    ) -> AppResult<Option<ApplicationRecord>> {
        let client_db_id = client_db_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id IN (SELECT application_id FROM application_client_bindings WHERE client_db_id = {} AND is_active = 1)",
                select_application_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_db_id)
                .get_result::<ApplicationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_auth_domain(
        &self,
        application_id: &str,
    ) -> AppResult<Option<ApplicationAuthDomainRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, application_id, assurance_policy, is_active, created_at, updated_at FROM application_auth_domains WHERE application_id = {}",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .get_result::<ApplicationAuthDomainRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_auth_context(
        &self,
        auth_domain_id: &str,
        user_id: &str,
    ) -> AppResult<Option<ApplicationAuthContextRecord>> {
        let auth_domain_id = auth_domain_id.to_string();
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, auth_domain_id, user_id, acr, amr, authenticated_at, expires_at, revoked_at, created_at, updated_at FROM application_auth_contexts WHERE auth_domain_id = {} AND user_id = {} AND revoked_at IS NULL ORDER BY authenticated_at DESC LIMIT 1",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(auth_domain_id)
                .bind::<Text, _>(user_id)
                .get_result::<ApplicationAuthContextRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_application_auth_context(
        &self,
        context: NewApplicationAuthContext,
    ) -> AppResult<ApplicationAuthContextRecord> {
        let now = util::now_ts();
        let amr = serde_json::to_string(&context.amr)
            .map_err(|err| AppError::Internal(err.to_string()))?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO application_auth_contexts (id, auth_domain_id, user_id, acr, amr, authenticated_at, expires_at, revoked_at, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
                ph(kind, 9),
                ph(kind, 10)
            );
            sql_query(sql)
                .bind::<Text, _>(&context.id)
                .bind::<Text, _>(&context.auth_domain_id)
                .bind::<Text, _>(&context.user_id)
                .bind::<Text, _>(&context.acr)
                .bind::<Text, _>(amr)
                .bind::<BigInt, _>(context.authenticated_at)
                .bind::<BigInt, _>(context.expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let select_sql = format!(
                "SELECT id, auth_domain_id, user_id, acr, amr, authenticated_at, expires_at, revoked_at, created_at, updated_at FROM application_auth_contexts WHERE id = {}",
                ph(kind, 1)
            );
            sql_query(select_sql)
                .bind::<Text, _>(context.id)
                .get_result::<ApplicationAuthContextRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_application_client_bindings(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<ApplicationClientBindingRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings WHERE application_id = {} ORDER BY created_at ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ApplicationClientBindingRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_client_binding(
        &self,
        client_db_id: &str,
    ) -> AppResult<Option<ApplicationClientBindingRecord>> {
        let client_db_id = client_db_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE client_db_id = {}",
                select_application_client_binding_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_db_id)
                .get_result::<ApplicationClientBindingRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_oidc_client(
        &self,
        application_id: &str,
        client_db_id: &str,
    ) -> AppResult<Option<ApplicationOidcClientRecord>> {
        let application_id = application_id.to_string();
        let client_db_id = client_db_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT binding.client_db_id AS client_db_id, client.client_secret_hash AS client_secret_hash, client.audience AS audience FROM application_client_bindings AS binding INNER JOIN clients AS client ON client.id = binding.client_db_id WHERE binding.application_id = {} AND binding.client_db_id = {} AND binding.protocol = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(client_db_id)
                .bind::<Text, _>("oidc")
                .get_result::<ApplicationOidcClientRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_application_client_binding_by_public_client_id(
        &self,
        client_id: &str,
    ) -> AppResult<Option<ApplicationClientBindingRecord>> {
        let client_id = client_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT bindings.application_id, bindings.client_db_id, bindings.protocol, bindings.authorization_profile_id, bindings.auth_domain_id, bindings.is_active, bindings.created_at, bindings.updated_at FROM application_client_bindings bindings INNER JOIN clients ON clients.id = bindings.client_db_id WHERE clients.client_id = {} AND bindings.is_active = 1",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(client_id)
                .get_result::<ApplicationClientBindingRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    /// Resolves the single application that owns an enrollment invitation.
    /// The mapping is intentionally separate from invitation metadata so a
    /// generic enterprise invitation cannot be mistaken for an app-scoped
    /// admission capability.
    pub async fn find_application_for_enrollment_code(
        &self,
        invitation_id: &str,
    ) -> AppResult<Option<ApplicationRecord>> {
        let invitation_id = invitation_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id IN (SELECT application_id FROM application_enrollment_codes WHERE invitation_id = {})",
                select_application_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(invitation_id)
                .get_result::<ApplicationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_application_client_ids(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<String>> {
        #[derive(diesel::QueryableByName)]
        struct ClientIdRow {
            #[diesel(sql_type = Text)]
            client_db_id: String,
        }

        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT client_db_id FROM application_client_bindings WHERE application_id = {} AND is_active = 1 ORDER BY created_at ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ClientIdRow>(&mut conn)
                .map(|rows| rows.into_iter().map(|row| row.client_db_id).collect())
                .map_err(AppError::from)
        })
    }

    /// Loads the client rows owned by an application in one bounded read.
    /// Enrollment-code creation needs the public client IDs and organization
    /// guard, so returning the rows here avoids one query per binding.
    pub async fn list_application_clients(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<ClientRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id IN (SELECT client_db_id FROM application_client_bindings WHERE application_id = {} AND is_active = 1) ORDER BY created_at ASC, id ASC",
                select_client_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// The invitation itself is the enrollment capability; this mapping gives
    /// it one tenant-owned application home for listing and revocation.
    pub async fn link_application_enrollment_code(
        &self,
        application_id: &str,
        invitation_id: &str,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let invitation_id = invitation_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO application_enrollment_codes (application_id, invitation_id, created_at) VALUES ({}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(invitation_id)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn list_application_enrollment_codes(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<InvitationRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT invitation_records.* FROM ({}) AS invitation_records INNER JOIN application_enrollment_codes ON application_enrollment_codes.invitation_id = invitation_records.id WHERE application_enrollment_codes.application_id = {} ORDER BY invitation_records.created_at DESC",
                select_invitation_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<InvitationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn application_enrollment_code_belongs_to(
        &self,
        application_id: &str,
        invitation_id: &str,
    ) -> AppResult<bool> {
        let application_id = application_id.to_string();
        let invitation_id = invitation_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM application_enrollment_codes WHERE application_id = {} AND invitation_id = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(invitation_id)
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count > 0)
                .map_err(AppError::from)
        })
    }

    pub async fn insert_application(
        &self,
        application: NewApplication,
    ) -> AppResult<ApplicationRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            insert_application_on_conn!(conn, kind, &id, &application, now)
        })
    }

    /// Creates an application and its management audit record atomically.
    /// The webhook is scheduled only after the transaction has committed.
    pub async fn insert_application_with_audit(
        &self,
        application: NewApplication,
        event: crate::audit::AuditEvent,
    ) -> AppResult<ApplicationRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let mut event = event;
        if event.target_id.is_none() {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        let (application, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(ApplicationRecord, AuditEventRecord), AppError, _>(|conn| {
                let application = insert_application_on_conn!(conn, kind, &id, &application, now,)?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((application, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(application)
    }

    /// Creates an application and its initial module in one aggregate
    /// transaction. The admin UI uses this for the first `protocols` module so
    /// a lost response or module write cannot leave a half-created website.
    pub async fn insert_application_with_module_with_audit(
        &self,
        application: NewApplication,
        module_key: &str,
        config_json: &str,
        is_enabled: bool,
        event: crate::audit::AuditEvent,
    ) -> AppResult<ApplicationRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let module_key = module_key.to_string();
        let config_json = config_json.to_string();
        let mut event = event;
        if event.target_id.is_none() {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        let (application, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(ApplicationRecord, AuditEventRecord), AppError, _>(|conn| {
                let application = insert_application_on_conn!(conn, kind, &id, &application, now)?;
                upsert_application_module_on_conn!(
                    conn,
                    kind,
                    &id,
                    &module_key,
                    &config_json,
                    is_enabled,
                    now,
                )?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((application, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(application)
    }

    pub async fn update_application(
        &self,
        id: &str,
        application: NewApplication,
    ) -> AppResult<ApplicationRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            update_application_on_conn!(conn, kind, &id, &application, now)
        })
    }

    /// Updates an application and its management audit record atomically.
    pub async fn update_application_with_audit(
        &self,
        id: &str,
        application: NewApplication,
        event: crate::audit::AuditEvent,
    ) -> AppResult<ApplicationRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        let webhook_db = self.clone();
        let (application, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(ApplicationRecord, AuditEventRecord), AppError, _>(|conn| {
                let application = update_application_on_conn!(conn, kind, &id, &application, now,)?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((application, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(application)
    }

    /// Updates an application, its module configuration, and management audit
    /// record atomically. Website-managed applications keep their canonical
    /// URL in the `protocols` module, so the two records must not drift.
    pub async fn update_application_with_module_with_audit(
        &self,
        id: &str,
        application: NewApplication,
        module_key: &str,
        config_json: &str,
        is_enabled: bool,
        event: crate::audit::AuditEvent,
    ) -> AppResult<ApplicationRecord> {
        let id = id.to_string();
        let module_key = module_key.to_string();
        let config_json = config_json.to_string();
        let now = util::now_ts();
        let webhook_db = self.clone();
        let (application, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(ApplicationRecord, AuditEventRecord), AppError, _>(|conn| {
                let application = update_application_on_conn!(conn, kind, &id, &application, now)?;
                upsert_application_module_on_conn!(
                    conn,
                    kind,
                    &id,
                    &module_key,
                    &config_json,
                    is_enabled,
                    now,
                )?;
                let audit_event = insert_audit_event_on_conn!(conn, kind, event)?;
                Ok((application, audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(application)
    }

    /// Deletes the complete application aggregate and its management audit
    /// event in one database transaction.
    ///
    /// `expected_organization_id` is deliberately checked on the same
    /// connection as every delete.  The handler may have loaded an
    /// application to authorize the request, but that read is not a
    /// sufficient ownership check for a destructive operation.
    pub async fn delete_application_with_expected_organization_and_audit(
        &self,
        id: &str,
        expected_organization_id: &str,
        event: crate::audit::AuditEvent,
    ) -> AppResult<()> {
        self.delete_application_aggregate(id, Some(expected_organization_id), Some(event))
            .await
    }

    /// Compatibility wrapper for internal callers that historically deleted
    /// an application without supplying an organization or audit event.
    /// New administrative code must use
    /// `delete_application_with_expected_organization_and_audit`.
    pub async fn delete_application(&self, id: &str) -> AppResult<()> {
        self.delete_application_aggregate(id, None, None).await
    }

    async fn delete_application_aggregate(
        &self,
        id: &str,
        expected_organization_id: Option<&str>,
        event: Option<crate::audit::AuditEvent>,
    ) -> AppResult<()> {
        #[derive(Debug, diesel::QueryableByName)]
        struct DetachedClientIdRow {
            #[diesel(sql_type = Text)]
            client_db_id: String,
        }
        #[derive(Debug, diesel::QueryableByName)]
        struct GroupIdRow {
            #[diesel(sql_type = Text)]
            group_id: String,
        }
        #[derive(Debug, diesel::QueryableByName)]
        struct ClientBindingCountRow {
            #[diesel(sql_type = Text)]
            client_db_id: String,
            #[diesel(sql_type = BigInt)]
            count: i64,
        }
        #[derive(Debug, diesel::QueryableByName)]
        struct OrganizationIdRow {
            #[diesel(sql_type = Text)]
            id: String,
        }
        #[derive(Debug, diesel::QueryableByName)]
        struct BillingActivityRow {
            #[diesel(sql_type = Integer)]
            has_activity: i32,
        }

        let id = id.to_string();
        let expected_organization_id = expected_organization_id.map(ToOwned::to_owned);
        let mut event = event;
        if let Some(event) = event.as_mut()
            && event.target_id.is_none()
        {
            event.target_id = Some(id.clone());
        }
        let webhook_db = self.clone();
        let audit_event = with_conn!(self, |conn, kind| {
            conn.transaction::<Option<AuditEventRecord>, AppError, _>(|conn| {
                // Serialize deletion against application-owned writers before
                // reading any child rows. The no-op UPDATE is portable across
                // SQLite, PostgreSQL and MySQL, and the organization predicate
                // keeps the destructive ownership check on the same lock.
                let lock_count = if let Some(expected_organization_id) =
                    expected_organization_id.as_deref()
                {
                    let lock_sql = format!(
                        "UPDATE applications SET updated_at = updated_at WHERE id = {} AND organization_id = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(lock_sql)
                        .bind::<Text, _>(&id)
                        .bind::<Text, _>(expected_organization_id)
                        .execute(conn)
                        .map_err(AppError::from)?
                } else {
                    let lock_sql = format!(
                        "UPDATE applications SET updated_at = updated_at WHERE id = {}",
                        ph(kind, 1)
                    );
                    sql_query(lock_sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?
                };
                if lock_count == 0 {
                    return Err(AppError::NotFound);
                }
                let application_sql = format!("{} WHERE id = {}", select_application_sql(), ph(kind, 1));
                let application = sql_query(application_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<ApplicationRecord>(conn)
                    .map_err(AppError::from)?;
                let application_organization_id = expected_organization_id
                    .clone()
                    .unwrap_or_else(|| application.organization_id.clone());

                // Monetary history is an immutable ledger, not disposable
                // application configuration. Refuse a hard delete once an
                // application wallet has participated in a transaction or
                // hold; otherwise deleting the application would orphan a
                // balance/entry with no ownership boundary. Empty wallet
                // accounts are removed below with the rest of the aggregate.
                let billing_activity_sql = format!(
                    "SELECT CASE WHEN EXISTS (SELECT 1 FROM wallet_transactions WHERE application_id = {p1} OR source_wallet_id IN (SELECT id FROM wallet_accounts WHERE application_id = {p2}) OR destination_wallet_id IN (SELECT id FROM wallet_accounts WHERE application_id = {p3})) OR EXISTS (SELECT 1 FROM wallet_holds WHERE application_id = {p4} OR wallet_id IN (SELECT id FROM wallet_accounts WHERE application_id = {p5})) OR EXISTS (SELECT 1 FROM wallet_entries WHERE wallet_id IN (SELECT id FROM wallet_accounts WHERE application_id = {p6})) THEN 1 ELSE 0 END AS has_activity",
                    p1 = ph(kind, 1),
                    p2 = ph(kind, 2),
                    p3 = ph(kind, 3),
                    p4 = ph(kind, 4),
                    p5 = ph(kind, 5),
                    p6 = ph(kind, 6),
                );
                let has_billing_activity = sql_query(billing_activity_sql)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(&id)
                    .get_result::<BillingActivityRow>(conn)
                    .map_err(AppError::from)?
                    .has_activity
                    != 0;
                if has_billing_activity {
                    return Err(AppError::BadRequest(
                        "application cannot be hard-deleted after billing activity; archive it instead"
                            .to_string(),
                    ));
                }

                // Capture every binding, including an inactive legacy row.
                // The rows are deleted below, and each surviving client must
                // either already have another owner or receive a fallback.
                let client_ids_sql = format!(
                    "SELECT client_db_id FROM application_client_bindings WHERE application_id = {} ORDER BY created_at ASC, client_db_id ASC",
                    ph(kind, 1)
                );
                let detached_client_ids = sql_query(client_ids_sql)
                    .bind::<Text, _>(&id)
                    .load::<DetachedClientIdRow>(conn)
                    .map_err(AppError::from)?
                    .into_iter()
                    .map(|row| row.client_db_id)
                    .collect::<Vec<_>>();
                let scim_group_ids_sql = format!(
                    "SELECT group_id FROM application_scim_groups WHERE application_id = {}",
                    ph(kind, 1)
                );
                let scim_group_ids = sql_query(scim_group_ids_sql)
                    .bind::<Text, _>(&id)
                    .load::<GroupIdRow>(conn)
                    .map_err(AppError::from)?
                    .into_iter()
                    .map(|row| row.group_id)
                    .collect::<BTreeSet<_>>();

                // Trial accounts are application-admission accounts. Revoke
                // their browser/session and pending authentication state
                // before revoking the enrollment itself. Normal registration
                // accounts remain global Signet accounts and are not deleted.
                let trial_users = format!(
                    "SELECT user_id FROM trial_enrollments WHERE invitation_id IN (SELECT invitation_id FROM application_enrollment_codes WHERE application_id = {})",
                    ph(kind, 1)
                );
                for table in ["session_credentials", "browser_context_accounts"] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE session_id IN (SELECT id FROM sessions WHERE user_id IN ({trial_users}))"
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                for (table, column) in [
                    ("authorization_codes", "user_id"),
                    ("oidc_login_grants", "user_id"),
                    ("refresh_tokens", "user_id"),
                    ("device_authorizations", "authorized_user_id"),
                    ("webauthn_challenges", "user_id"),
                    ("client_grants", "user_id"),
                ] {
                    let sql = format!("DELETE FROM {table} WHERE {column} IN ({trial_users})");
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!("DELETE FROM sessions WHERE user_id IN ({trial_users})");
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "UPDATE trial_enrollments SET revoked_at = {} WHERE invitation_id IN (SELECT invitation_id FROM application_enrollment_codes WHERE application_id = {}) AND revoked_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<BigInt, _>(util::now_ts())
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                // A client survives application deletion for compatibility,
                // so revoke all client-keyed authorization state as well.
                // This covers legacy rows whose nullable application_id was
                // never backfilled.
                let client_public_id_subquery = format!(
                    "SELECT clients.client_id FROM clients INNER JOIN application_client_bindings ON application_client_bindings.client_db_id = clients.id WHERE application_client_bindings.application_id = {}",
                    ph(kind, 1)
                );
                for (table, column) in [
                    ("client_assertion_jtis", "client_id"),
                    ("pushed_authorization_requests", "client_id"),
                    ("device_authorizations", "client_id"),
                    ("authorization_codes", "client_id"),
                    ("refresh_tokens", "client_id"),
                    ("client_grants", "client_id"),
                    ("oidc_login_grants", "client_id"),
                ] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE {column} IN ({client_public_id_subquery})"
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                for table in ["authorization_codes", "refresh_tokens"] {
                    let sql = format!("DELETE FROM {table} WHERE application_id = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                // Delete the enrollment capability and its redemption rows
                // together. Trial enrollment history is retained, but is
                // explicitly revoked above, so it cannot grant a session.
                let enrollment_invitation_subquery = format!(
                    "SELECT invitation_id FROM application_enrollment_codes WHERE application_id = {}",
                    ph(kind, 1)
                );
                for table in ["oidc_login_grants", "invitation_redemptions"] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE invitation_id IN ({enrollment_invitation_subquery})"
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!(
                    "DELETE FROM invitations WHERE id IN ({enrollment_invitation_subquery})"
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                // Remove profile-owned policy before the profile itself, then
                // remove the application-level authorization graph. Keeping
                // this list explicit makes a newly added policy table fail
                // review visibly instead of silently becoming an orphan.
                for table in [
                    "application_profile_permission_overrides",
                    "application_profile_user_roles",
                    "application_profile_group_roles",
                    "application_profile_organization_roles",
                    "application_permission_definitions",
                    "application_profile_roles",
                ] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE profile_id IN (SELECT id FROM application_authorization_profiles WHERE application_id = {})",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                // Authentication artifacts are deleted before their owning
                // domains/clients. These rows are all application state; the
                // generic client row itself is intentionally retained for the
                // compatibility fallback created before this transaction
                // commits.
                let sql = format!(
                    "DELETE FROM application_auth_contexts WHERE auth_domain_id IN (SELECT id FROM application_auth_domains WHERE application_id = {})",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "DELETE FROM application_jwt_client_secrets WHERE jwt_client_id IN (SELECT id FROM application_jwt_clients WHERE application_id = {})",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                // This table exists only on pre-binding deployments. New
                // databases intentionally omit it, so probe before deleting
                // to keep aggregate cleanup compatible with both schemas.
                let legacy_oidc_table_exists = match kind {
                    DatabaseKind::Sqlite => sql_query(
                        "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'application_oidc_clients'",
                    )
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                        > 0,
                    DatabaseKind::Postgres => sql_query(format!(
                        "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = {}",
                        ph(kind, 1)
                    ))
                    .bind::<Text, _>("application_oidc_clients")
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                        > 0,
                    DatabaseKind::Mysql => sql_query(format!(
                        "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = {}",
                        ph(kind, 1)
                    ))
                    .bind::<Text, _>("application_oidc_clients")
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                        > 0,
                };
                if legacy_oidc_table_exists {
                    let sql = format!(
                        "DELETE FROM application_oidc_clients WHERE application_id = {}",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                for table in [
                    "wallet_accounts",
                    "application_authorization_profiles",
                    "application_jwt_clients",
                    "application_jwt_codes",
                    "application_auth_domains",
                    "application_modules",
                    "application_authorization_migration_state",
                    "application_billing_settings",
                    "application_identity_bindings",
                    "application_saml_interactions",
                    "application_saml_replays",
                    "application_saml_sessions",
                    "application_cas_tickets",
                    "application_scim_tokens",
                    "application_scim_groups",
                    "application_members",
                    "application_enrollment_codes",
                    "application_discovery",
                    "directory_sync_runs",
                    "directory_sync_leases",
                    "directory_sync_checkpoints",
                    "directory_sync_memberships",
                    "directory_sync_groups",
                    "iap_applications",
                ] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE application_id = {}",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                // SCIM groups are global authorization subjects. Find all
                // groups that have no surviving reference in one set-based
                // query, then remove their membership edges in bounded
                // batches. The previous group × table count loop amplified
                // deletion cost linearly with both dimensions.
                let scim_group_ids = scim_group_ids.into_iter().collect::<Vec<_>>();
                let mut orphan_scim_group_ids = Vec::new();
                for chunk in scim_group_ids.chunks(400) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let placeholders = placeholders(kind, 1, chunk.len());
                    let orphan_sql = format!(
                        "SELECT id AS group_id FROM access_groups WHERE id IN ({placeholders}) AND NOT EXISTS (SELECT 1 FROM application_scim_groups WHERE group_id = access_groups.id) AND NOT EXISTS (SELECT 1 FROM application_profile_group_roles WHERE group_id = access_groups.id) AND NOT EXISTS (SELECT 1 FROM directory_sync_groups WHERE group_id = access_groups.id) AND NOT EXISTS (SELECT 1 FROM group_roles WHERE group_id = access_groups.id) AND NOT EXISTS (SELECT 1 FROM group_members WHERE group_id = access_groups.id)"
                    );
                    orphan_scim_group_ids.extend(
                        bind_text_list(conn, sql_query(orphan_sql), chunk)
                            .load::<GroupIdRow>(conn)
                            .map_err(AppError::from)?
                            .into_iter()
                            .map(|row| row.group_id),
                    );
                }
                for chunk in orphan_scim_group_ids.chunks(400) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let placeholders = placeholders(kind, 1, chunk.len());
                    for table in ["group_members", "group_roles"] {
                        let sql = format!("DELETE FROM {table} WHERE group_id IN ({placeholders})");
                        bind_text_list(conn, sql_query(sql), chunk)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                    let sql = format!(
                        "DELETE FROM access_groups WHERE id IN ({placeholders})"
                    );
                    bind_text_list(conn, sql_query(sql), chunk)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                // Idempotency claims are tenant-scoped records. Match both
                // keys so a malformed/legacy row cannot be removed merely by
                // reusing an application ID in another organization.
                let idempotency_sql = format!(
                    "DELETE FROM application_discovery_idempotency WHERE organization_id = {} AND application_id = {}",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(idempotency_sql)
                    .bind::<Text, _>(&application_organization_id)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let binding_sql = format!(
                    "DELETE FROM application_client_bindings WHERE application_id = {}",
                    ph(kind, 1)
                );
                sql_query(binding_sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                // The binding rows have now been detached. Hydrate all
                // surviving clients and their remaining ownership in bounded
                // batches, instead of issuing a client lookup and binding
                // count query for every edge below.
                let mut detached_clients = Vec::new();
                let mut active_detached_client_ids = BTreeSet::new();
                for chunk in detached_client_ids.chunks(400) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let placeholders = placeholders(kind, 1, chunk.len());
                    let client_sql = format!(
                        "{} WHERE id IN ({placeholders})",
                        select_client_sql()
                    );
                    detached_clients.extend(
                        bind_text_list(conn, sql_query(client_sql), chunk)
                            .load::<ClientRecord>(conn)
                            .map_err(AppError::from)?,
                    );
                    let active_binding_sql = format!(
                        "SELECT client_db_id, COUNT(*) AS count FROM application_client_bindings WHERE client_db_id IN ({placeholders}) AND is_active = 1 GROUP BY client_db_id"
                    );
                    for row in bind_text_list(conn, sql_query(active_binding_sql), chunk)
                        .load::<ClientBindingCountRow>(conn)
                        .map_err(AppError::from)?
                    {
                        if row.count > 0 {
                            active_detached_client_ids.insert(row.client_db_id);
                        }
                    }
                }
                let organization_ids = detached_clients
                    .iter()
                    .filter_map(|client| client.organization_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let mut valid_organization_ids = BTreeSet::new();
                for chunk in organization_ids.chunks(400) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let placeholders = placeholders(kind, 1, chunk.len());
                    let organization_sql = format!(
                        "SELECT id FROM organizations WHERE id IN ({placeholders})"
                    );
                    valid_organization_ids.extend(
                        bind_text_list(conn, sql_query(organization_sql), chunk)
                            .load::<OrganizationIdRow>(conn)
                            .map_err(AppError::from)?
                            .into_iter()
                            .map(|row| row.id),
                    );
                }

                let affected = if let Some(expected_organization_id) =
                    expected_organization_id.as_deref()
                {
                    let sql = format!(
                        "DELETE FROM applications WHERE id = {} AND organization_id = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .bind::<Text, _>(expected_organization_id)
                        .execute(conn)
                        .map_err(AppError::from)?
                } else {
                    let sql = format!("DELETE FROM applications WHERE id = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?
                };
                if affected == 0 {
                    return Err(AppError::NotFound);
                }

                // The old aggregate is gone only after every surviving
                // protocol client has received its locked compatibility
                // owner on this same connection. If any repair fails, the
                // whole deletion rolls back and no client is left unowned.
                for client in detached_clients {
                    if active_detached_client_ids.contains(&client.id) {
                        continue;
                    }
                    let organization_id = match client.organization_id.as_deref() {
                        Some(candidate) if valid_organization_ids.contains(candidate) => {
                            candidate.to_string()
                        }
                        _ => crate::organizations::SIGNET_ORGANIZATION_ID.to_string(),
                    };
                    if client.organization_id.as_deref() != Some(organization_id.as_str()) {
                        let update_client_sql = format!(
                            "UPDATE clients SET organization_id = {}, updated_at = {} WHERE id = {}",
                            ph(kind, 1),
                            ph(kind, 2),
                            ph(kind, 3)
                        );
                        sql_query(update_client_sql)
                            .bind::<Text, _>(&organization_id)
                            .bind::<BigInt, _>(util::now_ts())
                            .bind::<Text, _>(&client.id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                    insert_locked_compatibility_application_on_conn!(
                        conn,
                        kind,
                        &client,
                        &organization_id,
                        util::now_ts(),
                    )?;
                }

                let audit_event = event
                    .take()
                    .map(|event| insert_audit_event_on_conn!(conn, kind, event))
                    .transpose()?;
                Ok(audit_event)
            })
        })?;

        if let Some(audit_event) = audit_event {
            crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        }

        Ok(())
    }

    /// Links one protocol client to exactly one application and profile.
    /// Client configuration remains protocol-specific, while the application
    /// binding owns the authentication domain and authorization boundary.
    pub async fn link_client_to_application(
        &self,
        application_id: &str,
        client_db_id: &str,
        protocol: &str,
        authorization_profile_id: &str,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let client_db_id = client_db_id.to_string();
        let protocol = protocol.to_string();
        let authorization_profile_id = authorization_profile_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let application_lock_sql = format!(
                    "UPDATE applications SET updated_at = updated_at WHERE id = {}",
                    ph(kind, 1)
                );
                if sql_query(application_lock_sql)
                    .bind::<Text, _>(&application_id)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::NotFound);
                }
                if authorization_profile_id.is_empty() {
                    return Err(AppError::BadRequest(
                        "authorization profile is required".to_string(),
                    ));
                }
                // `default` is a compatibility profile key, not a physical
                // profile ID. The resolver intentionally looks it up by
                // (application_id, profile_key), and may fall back to the
                // legacy application-wide policy when older data has no
                // materialized default row.
                if authorization_profile_id != "default" {
                    // Non-default values are physical profile IDs.  Check
                    // ownership on the same transaction/connection as the
                    // binding write so a client can never reference another
                    // application's authorization policy.
                    let profile_count_sql = format!(
                        "SELECT COUNT(*) AS count FROM application_authorization_profiles WHERE id = {} AND application_id = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    if sql_query(profile_count_sql)
                        .bind::<Text, _>(&authorization_profile_id)
                        .bind::<Text, _>(&application_id)
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count
                        == 0
                    {
                        return Err(AppError::BadRequest(
                            "authorization profile must belong to the application".to_string(),
                        ));
                    }
                }
                let same_organization_sql = format!(
                    "SELECT COUNT(*) AS count FROM applications INNER JOIN clients ON clients.id = {} WHERE applications.id = {} AND clients.organization_id = applications.organization_id",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                if sql_query(same_organization_sql)
                    .bind::<Text, _>(&client_db_id)
                    .bind::<Text, _>(&application_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    return Err(AppError::BadRequest(
                        "OIDC client must belong to the application's organization".to_string(),
                    ));
                }
                let existing_binding_sql = format!(
                    "{} WHERE client_db_id = {}",
                    select_application_client_binding_sql(),
                    ph(kind, 1)
                );
                let existing_binding = sql_query(existing_binding_sql)
                    .bind::<Text, _>(&client_db_id)
                    .get_result::<ApplicationClientBindingRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;
                if let Some(existing_binding) = existing_binding.as_ref()
                    && existing_binding.application_id != application_id
                {
                    return Err(AppError::BadRequest(
                        "OIDC client already belongs to another application".to_string(),
                    ));
                }
                let auth_domain_id = format!("auth-domain:{application_id}");
                let auth_domain_count_sql = format!(
                    "SELECT COUNT(*) AS count FROM application_auth_domains WHERE application_id = {}",
                    ph(kind, 1)
                );
                if sql_query(auth_domain_count_sql)
                    .bind::<Text, _>(&application_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    == 0
                {
                    let auth_domain_sql = format!(
                        "INSERT INTO application_auth_domains (id, application_id, assurance_policy, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
                    );
                    sql_query(auth_domain_sql)
                        .bind::<Text, _>(&auth_domain_id)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>("default")
                        .bind::<Integer, _>(1)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                if existing_binding.is_some() {
                    let update_binding_sql = format!(
                        "UPDATE application_client_bindings SET protocol = {}, authorization_profile_id = {}, auth_domain_id = {}, is_active = {}, updated_at = {} WHERE application_id = {} AND client_db_id = {}",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7)
                    );
                    sql_query(update_binding_sql)
                        .bind::<Text, _>(&protocol)
                        .bind::<Text, _>(&authorization_profile_id)
                        .bind::<Text, _>(&auth_domain_id)
                        .bind::<Integer, _>(1)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(&client_db_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                } else {
                    let binding_sql = format!(
                        "INSERT INTO application_client_bindings (application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8)
                    );
                    sql_query(binding_sql)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(&client_db_id)
                        .bind::<Text, _>(&protocol)
                        .bind::<Text, _>(&authorization_profile_id)
                        .bind::<Text, _>(&auth_domain_id)
                        .bind::<Integer, _>(1)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                Ok(())
            })
        })
    }

    /// Detaches a client without leaving it ungoverned. The client immediately
    /// receives a locked fallback application.
    pub async fn unlink_client_from_application(&self, client_db_id: &str) -> AppResult<()> {
        let client_db_id = client_db_id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let client_sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
                let client = sql_query(client_sql)
                    .bind::<Text, _>(&client_db_id)
                    .get_result::<ClientRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?;
                let delete_sql = format!(
                    "DELETE FROM application_client_bindings WHERE client_db_id = {}",
                    ph(kind, 1)
                );
                sql_query(delete_sql)
                    .bind::<Text, _>(&client_db_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let Some(client) = client else {
                    return Ok(());
                };
                let active_binding_sql = format!(
                    "SELECT COUNT(*) AS count FROM application_client_bindings WHERE client_db_id = {} AND is_active = 1",
                    ph(kind, 1)
                );
                if sql_query(active_binding_sql)
                    .bind::<Text, _>(&client_db_id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count
                    > 0
                {
                    return Ok(());
                }
                let organization_id = if let Some(candidate) = client.organization_id.as_deref() {
                    let organization_sql = format!(
                        "SELECT COUNT(*) AS count FROM organizations WHERE id = {}",
                        ph(kind, 1)
                    );
                    if sql_query(organization_sql)
                        .bind::<Text, _>(candidate)
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count
                        > 0
                    {
                        candidate.to_string()
                    } else {
                        crate::organizations::SIGNET_ORGANIZATION_ID.to_string()
                    }
                } else {
                    crate::organizations::SIGNET_ORGANIZATION_ID.to_string()
                };
                if client.organization_id.as_deref() != Some(organization_id.as_str()) {
                    let update_client_sql = format!(
                        "UPDATE clients SET organization_id = {}, updated_at = {} WHERE id = {}",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3)
                    );
                    sql_query(update_client_sql)
                        .bind::<Text, _>(&organization_id)
                        .bind::<BigInt, _>(util::now_ts())
                        .bind::<Text, _>(&client_db_id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                insert_locked_compatibility_application_on_conn!(
                    conn,
                    kind,
                    &client,
                    &organization_id,
                    util::now_ts(),
                )?;
                Ok(())
            })
        })
    }

    /// Legacy compatibility reader. Application members are not a login
    /// roster; new runtime code must use organization membership and
    /// application entitlements instead.
    pub async fn list_application_members(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<ApplicationMemberRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} ORDER BY is_active DESC, created_at ASC",
                select_application_member_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ApplicationMemberRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Legacy compatibility reader; retained for migration/audit tooling only.
    pub async fn list_application_members_with_users(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<ApplicationMemberWithUserRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT application_members.application_id, application_members.user_id, application_members.role, application_members.is_active, application_members.created_at, application_members.updated_at, users.email, users.username, users.display_name, users.phone, users.email_verified_at, users.phone_verified_at FROM application_members INNER JOIN users ON users.id = application_members.user_id WHERE application_members.application_id = {} ORDER BY application_members.is_active DESC, users.email ASC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<ApplicationMemberWithUserRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Legacy compatibility writer for importing or repairing historical
    /// application_members rows. It is intentionally not used by any login,
    /// registration, or application-management runtime path.
    pub async fn replace_application_members(
        &self,
        application_id: &str,
        members: Vec<NewApplicationMember>,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let members = members
            .into_iter()
            .map(|member| (member.user_id.clone(), member))
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .collect::<Vec<_>>();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let app_sql = format!("{} WHERE id = {}", select_application_sql(), ph(kind, 1));
                let application = sql_query(app_sql)
                    .bind::<Text, _>(&application_id)
                    .get_result::<ApplicationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                const USER_VALIDATION_BATCH_SIZE: usize = 400;
                let requested_user_ids = members
                    .iter()
                    .map(|member| member.user_id.clone())
                    .collect::<Vec<_>>();
                let mut active_user_ids = BTreeSet::new();
                for user_id_batch in requested_user_ids.chunks(USER_VALIDATION_BATCH_SIZE) {
                    let placeholders = placeholders(kind, 1, user_id_batch.len());
                    let user_sql = format!(
                        "SELECT id FROM users WHERE id IN ({placeholders}) AND is_active = 1 AND archived_at IS NULL"
                    );
                    active_user_ids.extend(
                        bind_text_list(conn, sql_query(user_sql), user_id_batch)
                            .load::<StringIdRow>(conn)
                            .map_err(AppError::from)?
                            .into_iter()
                            .map(|user| user.id),
                    );
                }
                if let Some(missing_user_id) = requested_user_ids
                    .iter()
                    .find(|user_id| !active_user_ids.contains(*user_id))
                {
                    return Err(AppError::BadRequest(format!(
                        "active user does not exist: {missing_user_id}"
                    )));
                }
                let active_member_ids = members
                    .iter()
                    .filter(|member| member.is_active)
                    .map(|member| member.user_id.clone())
                    .collect::<BTreeSet<_>>();
                let blocked_member_ids = members
                    .iter()
                    .filter(|member| !member.is_active)
                    .map(|member| member.user_id.clone())
                    .collect::<BTreeSet<_>>();
                let binding_sql = format!(
                    "{} WHERE application_id = {}",
                    select_application_identity_binding_sql(),
                    ph(kind, 1)
                );
                let bound_user_ids = sql_query(binding_sql)
                    .bind::<Text, _>(&application_id)
                    .load::<ApplicationIdentityBindingRecord>(conn)
                    .map_err(AppError::from)?
                    .into_iter()
                    .map(|binding| binding.user_id)
                    .collect::<BTreeSet<_>>();
                let users_losing_access = match application.access_mode.as_str() {
                    crate::applications::ACCESS_ASSIGNED_ACCOUNTS => bound_user_ids
                        .difference(&active_member_ids)
                        .cloned()
                        .collect::<Vec<_>>(),
                    crate::applications::ACCESS_ORGANIZATION_MEMBERS => bound_user_ids
                        .intersection(&blocked_member_ids)
                        .cloned()
                        .collect::<Vec<_>>(),
                    crate::applications::ACCESS_ALL_SIGNET_USERS
                    | crate::applications::ACCESS_LEGACY_ALL_USERS => Vec::new(),
                    _ => {
                        return Err(AppError::Internal(
                            "application access mode is invalid".to_string(),
                        ));
                    }
                };
                // Replacing a roster must release leases only for accounts
                // that no longer have application access. Existing eligible
                // accounts keep their reservations throughout the update.
                for user_id in users_losing_access {
                    clear_application_identity_bindings_for_user_for_conn!(
                        conn,
                        kind,
                        &application_id,
                        &user_id
                    )?;
                }

                let delete_sql = format!(
                    "DELETE FROM application_members WHERE application_id = {}",
                    ph(kind, 1)
                );
                sql_query(delete_sql)
                    .bind::<Text, _>(&application_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                for member in members {
                    let insert_sql = format!(
                        "INSERT INTO application_members (application_id, user_id, role, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
                    );
                    sql_query(insert_sql)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(member.user_id)
                        .bind::<Text, _>(member.role)
                        .bind::<Integer, _>(i32::from(member.is_active))
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                Ok(())
            })
        })
    }

    pub async fn user_can_access_application(
        &self,
        application: &ApplicationRecord,
        user_id: &str,
    ) -> AppResult<bool> {
        Ok(self
            .users_can_access_application(application, &[user_id.to_string()])
            .await?
            .contains(user_id))
    }

    /// Resolves the account/application admission gate for a complete chooser
    /// page in one bounded query set.  Browser account selection commonly has
    /// several remembered accounts; doing the same two existence queries for
    /// every account turns that page into an avoidable O(N) round-trip fan-out.
    /// The final select/activate endpoint still re-checks one account
    /// transactionally, so this is only a read-model optimization.
    pub async fn users_can_access_application(
        &self,
        application: &ApplicationRecord,
        user_ids: &[String],
    ) -> AppResult<BTreeSet<String>> {
        const BATCH_SIZE: usize = 400;
        if application.is_active != 1 || user_ids.is_empty() {
            return Ok(BTreeSet::new());
        }
        let user_ids = user_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let organization_id = application.organization_id.clone();
        with_conn!(self, |conn, kind| {
            let organization_sql = format!(
                "SELECT COUNT(*) AS count FROM organizations WHERE id = {} AND is_active = 1",
                ph(kind, 1)
            );
            if sql_query(organization_sql)
                .bind::<Text, _>(&organization_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                == 0
            {
                return Ok(BTreeSet::new());
            }

            let mut accessible = BTreeSet::new();
            for chunk in user_ids.chunks(BATCH_SIZE) {
                if chunk.is_empty() {
                    continue;
                }
                let user_sql = format!(
                    "SELECT id FROM users WHERE id IN ({}) AND is_active = 1 AND archived_at IS NULL",
                    placeholders(kind, 1, chunk.len())
                );
                accessible.extend(
                    bind_text_list(&mut conn, sql_query(user_sql), chunk)
                        .load::<StringIdRow>(&mut conn)
                        .map_err(AppError::from)?
                        .into_iter()
                        .map(|row| row.id),
                );
            }
            // An application is a website integration, not a membership
            // roster. Once the global account and tenant are active, every
            // active Signet account is eligible to authenticate. Application
            // roles and directory mappings are evaluated after this gate.
            let _ = organization_id;
            Ok(accessible)
        })
    }

    /// Atomically replaces this user's application-scoped factor reservations.
    /// The primary key on `(application_id, factor_type, factor_digest)` is
    /// the final concurrent enforcement point, not the management UI.
    pub async fn replace_application_identity_bindings(
        &self,
        application_id: &str,
        user_id: &str,
        factors: Vec<(String, String)>,
    ) -> AppResult<()> {
        let application_id = application_id.to_string();
        let user_id = user_id.to_string();
        let factors = factors
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect::<Vec<_>>();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let delete_sql = format!(
                    "DELETE FROM application_identity_bindings WHERE application_id = {} AND user_id = {}",
                    ph(kind, 1), ph(kind, 2)
                );
                sql_query(delete_sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&user_id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                for (factor_type, factor_digest) in factors {
                    let insert_sql = format!(
                        "INSERT INTO application_identity_bindings (application_id, factor_type, factor_digest, user_id, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {})",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6)
                    );
                    sql_query(insert_sql)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(factor_type)
                        .bind::<Text, _>(factor_digest)
                        .bind::<Text, _>(&user_id)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(|err| AppError::BadRequest(format!(
                            "the verified identity factor is already used by another application account: {err}"
                        )))?;
                }
                Ok(())
            })
        })
    }

    pub async fn application_identity_factor_is_available(
        &self,
        application_id: &str,
        factor_type: &str,
        factor_digest: &str,
        user_id: &str,
    ) -> AppResult<bool> {
        let application_id = application_id.to_string();
        let factor_type = factor_type.to_string();
        let factor_digest = factor_digest.to_string();
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} AND factor_type = {} AND factor_digest = {}",
                select_application_identity_binding_sql(),
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(factor_type)
                .bind::<Text, _>(factor_digest)
                .get_result::<ApplicationIdentityBindingRecord>(&mut conn)
                .optional()
                .map(|binding| binding.is_none_or(|binding| binding.user_id == user_id))
                .map_err(AppError::from)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_profile_role_id_loads_each_key_once_including_missing_roles() {
        let mut cache = BTreeMap::new();
        let mut loads = 0;

        let first = cached_profile_role_id(&mut cache, "profile", "member", || {
            loads += 1;
            Ok(Some("role-id".to_string()))
        })
        .unwrap();
        let second = cached_profile_role_id(&mut cache, "profile", "member", || {
            loads += 1;
            Ok(Some("unexpected-role-id".to_string()))
        })
        .unwrap();
        assert_eq!(first.as_deref(), Some("role-id"));
        assert_eq!(second.as_deref(), Some("role-id"));
        assert_eq!(loads, 1);

        let missing = cached_profile_role_id(&mut cache, "profile", "missing", || {
            loads += 1;
            Ok(None)
        })
        .unwrap();
        let missing_again = cached_profile_role_id(&mut cache, "profile", "missing", || {
            loads += 1;
            Ok(Some("unexpected-role-id".to_string()))
        })
        .unwrap();
        assert!(missing.is_none());
        assert!(missing_again.is_none());
        assert_eq!(loads, 2);
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite_test_db() -> (Db, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-application-delete-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        let db = connect_sqlite(&DatabaseSettings {
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
    fn tenant(slug: &str) -> NewOrganization {
        NewOrganization {
            slug: slug.to_string(),
            name: format!("{slug} organization"),
            kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            allowed_email_domains: Vec::new(),
            is_active: true,
        }
    }

    #[cfg(feature = "sqlite")]
    fn application(organization_id: &str, slug: &str) -> NewApplication {
        NewApplication {
            organization_id: organization_id.to_string(),
            slug: slug.to_string(),
            name: format!("{slug} application"),
            description: None,
            access_mode: crate::applications::ACCESS_ALL_SIGNET_USERS.to_string(),
            registration_mode: crate::applications::REGISTRATION_INVITATION.to_string(),
            account_selection_mode: crate::applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
            unique_identity_factors: Vec::new(),
            is_active: true,
        }
    }

    #[cfg(feature = "sqlite")]
    fn application_enrollment_invitation(organization_id: &str) -> NewInvitation {
        NewInvitation {
            code_type: AuthorizationCodeType::Registration,
            login_code_level: LoginCodeLevel::AccountRecovery,
            allowed_client_ids: vec!["application-delete-client".to_string()],
            organization_id: Some(organization_id.to_string()),
            organization_role: Some(crate::organizations::ROLE_MEMBER.to_string()),
            description: Some("application delete test".to_string()),
            authorized_email: None,
            authorized_username: None,
            authorized_user_id: None,
            authorized_display_name: None,
            expires_at: Some(util::now_ts() + 300),
            max_uses: Some(1),
            is_active: true,
            created_by: None,
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_delete_rechecks_expected_organization_without_deleting() {
        let (db, path) = sqlite_test_db().await;
        let owner = db
            .insert_organization(tenant("application-delete-owner"))
            .await
            .unwrap();
        let wrong_owner = db
            .insert_organization(tenant("application-delete-wrong-owner"))
            .await
            .unwrap();
        let application = db
            .insert_application(application(&owner.id, "delete-organization-guard"))
            .await
            .unwrap();

        let result = db
            .delete_application_with_expected_organization_and_audit(
                &application.id,
                &wrong_owner.id,
                crate::audit::management_event(
                    "application-delete-test-actor",
                    "application.delete",
                    "application",
                    Some(application.id.clone()),
                    serde_json::json!({ "organization_id": wrong_owner.id }),
                ),
            )
            .await;
        assert!(matches!(result, Err(AppError::NotFound)));
        assert!(
            db.find_application_by_id(&application.id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            !db.list_audit_events(100)
                .await
                .unwrap()
                .into_iter()
                .any(|event| {
                    event.action == "application.delete"
                        && event.target_id.as_deref() == Some(application.id.as_str())
                })
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn application_delete_removes_enrollment_invitation_and_writes_audit() {
        let (db, path) = sqlite_test_db().await;
        let owner = db
            .insert_organization(tenant("application-delete-success"))
            .await
            .unwrap();
        let application = db
            .insert_application(application(&owner.id, "delete-success"))
            .await
            .unwrap();
        let (invitation, _) = db
            .insert_invitation(application_enrollment_invitation(&owner.id))
            .await
            .unwrap();
        db.link_application_enrollment_code(&application.id, &invitation.id)
            .await
            .unwrap();

        db.delete_application_with_expected_organization_and_audit(
            &application.id,
            &owner.id,
            crate::audit::management_event(
                "application-delete-test-actor",
                "application.delete",
                "application",
                Some(application.id.clone()),
                serde_json::json!({ "organization_id": owner.id }),
            ),
        )
        .await
        .unwrap();

        assert!(
            db.find_application_by_id(&application.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_application_enrollment_codes(&application.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.find_invitation_by_id(&invitation.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.list_audit_events(100)
                .await
                .unwrap()
                .into_iter()
                .any(|event| {
                    event.action == "application.delete"
                        && event.target_id.as_deref() == Some(application.id.as_str())
                })
        );

        drop(db);
        let _ = std::fs::remove_file(path);
    }
}
