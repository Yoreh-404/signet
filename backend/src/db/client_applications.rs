use super::*;

use super::{
    AppError, AppResult, ClientRecord, CountRow, Db, IapApplicationRecord, NewClient,
    NewIapApplication, normalize_permission_keys, ph, select_client_sql,
    select_iap_application_sql,
};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};

impl Db {
    pub async fn find_client_by_client_id(
        &self,
        client_id: &str,
    ) -> AppResult<Option<ClientRecord>> {
        let client_id = client_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE client_id = {}", select_client_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(client_id)
                .get_result::<ClientRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_client_by_id(&self, id: &str) -> AppResult<Option<ClientRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ClientRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_clients(&self) -> AppResult<Vec<ClientRecord>> {
        with_conn!(self, |conn, _kind| {
            let sql = format!("{} ORDER BY created_at DESC", select_client_sql());
            sql_query(sql)
                .load::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn count_clients(&self, active_only: bool) -> AppResult<i64> {
        with_conn!(self, |conn, _kind| {
            let sql = if active_only {
                "SELECT COUNT(*) AS count FROM clients WHERE is_active = 1"
            } else {
                "SELECT COUNT(*) AS count FROM clients"
            };
            sql_query(sql)
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count)
                .map_err(AppError::from)
        })
    }

    /// Tenant-scoped protocol connection listing for the management console.
    /// The unscoped variant remains available for protocol metadata and
    /// migration work, never for a tenant-facing API response.
    pub async fn list_clients_for_organization(
        &self,
        organization_id: &str,
    ) -> AppResult<Vec<ClientRecord>> {
        let organization_id = organization_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE organization_id = {} ORDER BY created_at DESC",
                select_client_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .load::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }
    pub async fn insert_client(&self, client: NewClient) -> AppResult<ClientRecord> {
        self.insert_client_internal(client).await
    }

    /// Creates an OIDC client inside an existing application. This is the
    /// application-first management path; it never manufactures a fallback
    /// application as a side effect.
    pub async fn insert_client_for_application(
        &self,
        application_id: &str,
        client: NewClient,
    ) -> AppResult<ClientRecord> {
        // Keep every application-owned OIDC write on the same aggregate
        // transaction as the physical profile, binding, and claim mappers.
        // The compatibility helper has no mapper input, so it intentionally
        // creates an empty mapper set rather than reopening the old
        // client-then-link sequence.
        self.create_application_oidc_client_graph(application_id, client, Vec::new())
            .await
    }

    async fn insert_client_internal(&self, client: NewClient) -> AppResult<ClientRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let redirect_uris = util::to_json(&client.redirect_uris)?;
        let post_logout_redirect_uris = util::to_json(&client.post_logout_redirect_uris)?;
        let scopes = util::to_json(&client.scopes)?;
        let audience = client.audience.trim().to_string();
        let grant_types = util::to_json(&client.grant_types)?;
        let response_types = util::to_json(&client.response_types)?;
        let authorization_details_types = util::to_json(&client.authorization_details_types)?;
        let service_account_permissions = util::to_json(&client.service_account_permissions)?;
        let created = with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO clients (id, client_id, client_secret_hash, client_name, logo_uri, organization_id, redirect_uris, post_logout_redirect_uris, scopes, audience, grant_types, response_types, token_endpoint_auth_method, require_pkce, require_mfa, require_pushed_authorization_requests, require_s256_pkce, require_confidential_client, require_dpop, require_account_selection, trust_email_verified, authorization_details_types, subject_type, sector_identifier_uri, jwks_uri, jwks, backchannel_logout_uri, backchannel_logout_session_required, frontchannel_logout_uri, frontchannel_logout_session_required, service_account_enabled, service_account_permissions, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 32),
                ph(kind, 33),
                ph(kind, 34),
                ph(kind, 35)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(client.client_id)
                .bind::<Nullable<Text>, _>(client.client_secret_hash)
                .bind::<Text, _>(client.client_name)
                .bind::<Text, _>(client.logo_uri)
                .bind::<Nullable<Text>, _>(client.organization_id)
                .bind::<Text, _>(redirect_uris)
                .bind::<Text, _>(post_logout_redirect_uris)
                .bind::<Text, _>(scopes)
                .bind::<Text, _>(audience)
                .bind::<Text, _>(grant_types)
                .bind::<Text, _>(response_types)
                .bind::<Text, _>(client.token_endpoint_auth_method)
                .bind::<Integer, _>(i32::from(client.require_pkce))
                .bind::<Integer, _>(i32::from(client.require_mfa))
                .bind::<Integer, _>(i32::from(client.require_pushed_authorization_requests))
                .bind::<Integer, _>(i32::from(client.require_s256_pkce))
                .bind::<Integer, _>(i32::from(client.require_confidential_client))
                .bind::<Integer, _>(i32::from(client.require_dpop))
                .bind::<Integer, _>(i32::from(client.require_account_selection))
                .bind::<Integer, _>(i32::from(client.trust_email_verified))
                .bind::<Text, _>(authorization_details_types)
                .bind::<Text, _>(client.subject_type)
                .bind::<Text, _>(client.sector_identifier_uri)
                .bind::<Text, _>(client.jwks_uri)
                .bind::<Text, _>(client.jwks)
                .bind::<Text, _>(client.backchannel_logout_uri)
                .bind::<Integer, _>(i32::from(client.backchannel_logout_session_required))
                .bind::<Text, _>(client.frontchannel_logout_uri)
                .bind::<Integer, _>(i32::from(client.frontchannel_logout_session_required))
                .bind::<Integer, _>(i32::from(client.service_account_enabled))
                .bind::<Text, _>(service_account_permissions)
                .bind::<Integer, _>(i32::from(client.is_active))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })?;
        self.ensure_application_for_client(&created).await?;
        self.find_client_by_id(&created.id)
            .await?
            .ok_or(AppError::NotFound)
    }

    pub async fn update_client(&self, id: &str, client: NewClient) -> AppResult<ClientRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        let redirect_uris = util::to_json(&client.redirect_uris)?;
        let post_logout_redirect_uris = util::to_json(&client.post_logout_redirect_uris)?;
        let scopes = util::to_json(&client.scopes)?;
        let audience = client.audience.trim().to_string();
        let grant_types = util::to_json(&client.grant_types)?;
        let response_types = util::to_json(&client.response_types)?;
        let authorization_details_types = util::to_json(&client.authorization_details_types)?;
        let service_account_permissions = util::to_json(&client.service_account_permissions)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE clients SET client_id = {}, client_secret_hash = {}, client_name = {}, logo_uri = {}, organization_id = {}, redirect_uris = {}, post_logout_redirect_uris = {}, scopes = {}, audience = {}, grant_types = {}, response_types = {}, token_endpoint_auth_method = {}, require_pkce = {}, require_mfa = {}, require_pushed_authorization_requests = {}, require_s256_pkce = {}, require_confidential_client = {}, require_dpop = {}, require_account_selection = {}, trust_email_verified = {}, authorization_details_types = {}, subject_type = {}, sector_identifier_uri = {}, jwks_uri = {}, jwks = {}, backchannel_logout_uri = {}, backchannel_logout_session_required = {}, frontchannel_logout_uri = {}, frontchannel_logout_session_required = {}, service_account_enabled = {}, service_account_permissions = {}, is_active = {}, updated_at = {} WHERE id = {}",
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
                ph(kind, 32),
                ph(kind, 33),
                ph(kind, 34)
            );
            sql_query(sql)
                .bind::<Text, _>(client.client_id)
                .bind::<Nullable<Text>, _>(client.client_secret_hash)
                .bind::<Text, _>(client.client_name)
                .bind::<Text, _>(client.logo_uri)
                .bind::<Nullable<Text>, _>(client.organization_id)
                .bind::<Text, _>(redirect_uris)
                .bind::<Text, _>(post_logout_redirect_uris)
                .bind::<Text, _>(scopes)
                .bind::<Text, _>(audience)
                .bind::<Text, _>(grant_types)
                .bind::<Text, _>(response_types)
                .bind::<Text, _>(client.token_endpoint_auth_method)
                .bind::<Integer, _>(i32::from(client.require_pkce))
                .bind::<Integer, _>(i32::from(client.require_mfa))
                .bind::<Integer, _>(i32::from(client.require_pushed_authorization_requests))
                .bind::<Integer, _>(i32::from(client.require_s256_pkce))
                .bind::<Integer, _>(i32::from(client.require_confidential_client))
                .bind::<Integer, _>(i32::from(client.require_dpop))
                .bind::<Integer, _>(i32::from(client.require_account_selection))
                .bind::<Integer, _>(i32::from(client.trust_email_verified))
                .bind::<Text, _>(authorization_details_types)
                .bind::<Text, _>(client.subject_type)
                .bind::<Text, _>(client.sector_identifier_uri)
                .bind::<Text, _>(client.jwks_uri)
                .bind::<Text, _>(client.jwks)
                .bind::<Text, _>(client.backchannel_logout_uri)
                .bind::<Integer, _>(i32::from(client.backchannel_logout_session_required))
                .bind::<Text, _>(client.frontchannel_logout_uri)
                .bind::<Integer, _>(i32::from(client.frontchannel_logout_session_required))
                .bind::<Integer, _>(i32::from(client.service_account_enabled))
                .bind::<Text, _>(service_account_permissions)
                .bind::<Integer, _>(i32::from(client.is_active))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let sql = format!("{} WHERE id = {}", select_client_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ClientRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_iap_applications(&self) -> AppResult<Vec<IapApplicationRecord>> {
        with_conn!(self, |conn, _kind| {
            let sql = format!(
                "{} ORDER BY is_active DESC, name ASC",
                select_iap_application_sql()
            );
            sql_query(sql)
                .load::<IapApplicationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_active_iap_applications(&self) -> AppResult<Vec<IapApplicationRecord>> {
        with_conn!(self, |conn, _kind| {
            let sql = format!(
                "{} WHERE is_active = 1 ORDER BY LENGTH(path_prefix) DESC, name ASC",
                select_iap_application_sql()
            );
            sql_query(sql)
                .load::<IapApplicationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_iap_applications_for_application(
        &self,
        application_id: &str,
    ) -> AppResult<Vec<IapApplicationRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {} ORDER BY is_active DESC, name ASC, path_prefix ASC",
                select_iap_application_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .load::<IapApplicationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_iap_application_by_id(
        &self,
        id: &str,
    ) -> AppResult<Option<IapApplicationRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id = {}",
                select_iap_application_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<IapApplicationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_iap_application(
        &self,
        app: NewIapApplication,
    ) -> AppResult<IapApplicationRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        if self
            .find_application_by_id(&app.application_id)
            .await?
            .is_none()
        {
            return Err(AppError::NotFound);
        }
        let roles = util::to_json(&dedupe_nonempty(app.required_organization_roles))?;
        let permissions = util::to_json(&normalize_permission_keys(app.required_permissions)?)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO iap_applications (id, application_id, slug, name, description, external_host, path_prefix, required_organization_id, required_organization_roles, required_permissions, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 13)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(app.application_id)
                .bind::<Text, _>(app.slug)
                .bind::<Text, _>(app.name)
                .bind::<Nullable<Text>, _>(app.description)
                .bind::<Text, _>(app.external_host)
                .bind::<Text, _>(app.path_prefix)
                .bind::<Nullable<Text>, _>(app.required_organization_id)
                .bind::<Text, _>(roles)
                .bind::<Text, _>(permissions)
                .bind::<Integer, _>(i32::from(app.is_active))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "{} WHERE id = {}",
                select_iap_application_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<IapApplicationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_iap_application(
        &self,
        id: &str,
        app: NewIapApplication,
    ) -> AppResult<IapApplicationRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        let roles = util::to_json(&dedupe_nonempty(app.required_organization_roles))?;
        let permissions = util::to_json(&normalize_permission_keys(app.required_permissions)?)?;
        with_conn!(self, |conn, kind| {
            let existing_sql = format!(
                "{} WHERE id = {}",
                select_iap_application_sql(),
                ph(kind, 1)
            );
            let existing = sql_query(existing_sql)
                .bind::<Text, _>(&id)
                .get_result::<IapApplicationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
                .ok_or(AppError::NotFound)?;
            if existing.application_id.as_deref() != Some(app.application_id.as_str()) {
                return Err(AppError::Forbidden);
            }
            let sql = format!(
                "UPDATE iap_applications SET slug = {}, name = {}, description = {}, external_host = {}, path_prefix = {}, required_organization_id = {}, required_organization_roles = {}, required_permissions = {}, is_active = {}, updated_at = {} WHERE id = {}",
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
                ph(kind, 11)
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(app.slug)
                .bind::<Text, _>(app.name)
                .bind::<Nullable<Text>, _>(app.description)
                .bind::<Text, _>(app.external_host)
                .bind::<Text, _>(app.path_prefix)
                .bind::<Nullable<Text>, _>(app.required_organization_id)
                .bind::<Text, _>(roles)
                .bind::<Text, _>(permissions)
                .bind::<Integer, _>(i32::from(app.is_active))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                return Err(AppError::NotFound);
            }
            let sql = format!(
                "{} WHERE id = {}",
                select_iap_application_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<IapApplicationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn delete_iap_application(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("DELETE FROM iap_applications WHERE id = {}", ph(kind, 1));
            let affected = sql_query(sql)
                .bind::<Text, _>(id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                Err(AppError::NotFound)
            } else {
                Ok(())
            }
        })
    }

    pub async fn delete_client(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                // These tables refer to the public OIDC client_id rather than
                // the internal clients.id. Clear them before the client record
                // disappears so no live credential or authorization state can
                // outlast a deleted client.
                for (table, column) in [
                    ("authorization_codes", "client_id"),
                    ("refresh_tokens", "client_id"),
                    ("client_grants", "client_id"),
                    ("device_authorizations", "client_id"),
                    ("pushed_authorization_requests", "client_id"),
                    ("oidc_login_grants", "client_id"),
                    ("client_assertion_jtis", "client_id"),
                ] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE {column} IN (SELECT client_id FROM clients WHERE id = {})",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                for table in ["client_registrations", "client_claim_mappers"] {
                    let sql = format!(
                        "DELETE FROM {table} WHERE client_db_id = {}",
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let binding_sql = format!(
                    "DELETE FROM application_client_bindings WHERE client_db_id = {}",
                    ph(kind, 1)
                );
                sql_query(binding_sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!("DELETE FROM clients WHERE id = {}", ph(kind, 1));
                let affected = sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::NotFound);
                }
                Ok(())
            })
        })
    }
}
