//! Persistence for external authentication providers and linked identities.

use super::{
    CountRow, Db, ExternalOidcProviderRecord, ExternalOidcStateRecord, LdapProviderRecord,
    LinkedIdentityRecord, NewExternalOidcProvider, NewLdapProvider, NewUser, OrganizationRecord,
    UserIdentityCandidate, UserRecord, UserRegistrationSource, bind_text_list, blocking,
    count_all_users_sql, count_user_identity_conflicts_sql, ensure_first_user_registration_state,
    insert_user_sql, ldap_provider_key, ph, placeholders, select_organization_sql, select_user_sql,
};
use crate::config::DatabaseKind;
use crate::error::{AppError, AppResult};
use crate::organizations::OrganizationEmailPolicy;
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};

pub(super) fn select_ldap_provider_sql() -> &'static str {
    "SELECT id, slug, display_name, organization_id, url, starttls, bind_dn, bind_password, base_dn, user_filter, user_id_attribute, email_attribute, username_attribute, display_name_attribute, phone_attribute, is_active, allow_login, allow_registration, created_at, updated_at FROM ldap_providers"
}

pub(super) fn count_linked_identity_sql(kind: DatabaseKind) -> String {
    format!(
        "SELECT COUNT(*) AS count FROM linked_identities WHERE provider_slug = {} AND external_subject = {}",
        ph(kind, 1),
        ph(kind, 2)
    )
}

fn select_external_oidc_provider_sql() -> &'static str {
    "SELECT id, slug, display_name, organization_id, issuer, client_id, client_secret, authorization_endpoint, token_endpoint, userinfo_endpoint, redirect_path, scopes, COALESCE(email_domains, '[]') AS email_domains, is_active, COALESCE(allow_login, 1) AS allow_login, allow_registration, created_at, updated_at FROM external_oidc_providers"
}

impl Db {
    pub async fn list_linked_identities(
        &self,
        user_id: &str,
    ) -> AppResult<Vec<LinkedIdentityRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, provider_slug, external_subject, external_email, created_at, updated_at FROM linked_identities WHERE user_id = {} ORDER BY created_at DESC",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .load::<LinkedIdentityRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_linked_identity(
        &self,
        provider_slug: &str,
        external_subject: &str,
    ) -> AppResult<Option<LinkedIdentityRecord>> {
        let provider_slug = provider_slug.to_string();
        let external_subject = external_subject.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT id, user_id, provider_slug, external_subject, external_email, created_at, updated_at FROM linked_identities WHERE provider_slug = {} AND external_subject = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(provider_slug)
                .bind::<Text, _>(external_subject)
                .get_result::<LinkedIdentityRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn insert_linked_identity(
        &self,
        user_id: &str,
        provider_slug: &str,
        external_subject: &str,
        external_email: Option<String>,
    ) -> AppResult<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let user_id = user_id.to_string();
        let provider_slug = provider_slug.to_string();
        let external_subject = external_subject.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO linked_identities (id, user_id, provider_slug, external_subject, external_email, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(provider_slug)
                .bind::<Text, _>(external_subject)
                .bind::<Nullable<Text>, _>(external_email)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn list_external_oidc_providers(&self) -> AppResult<Vec<ExternalOidcProviderRecord>> {
        with_conn!(self, |conn, _kind| {
            let sql = format!(
                "{} ORDER BY display_name ASC",
                select_external_oidc_provider_sql()
            );
            sql_query(sql)
                .load::<ExternalOidcProviderRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn list_external_oidc_providers_for_organization(
        &self,
        organization_id: &str,
    ) -> AppResult<Vec<ExternalOidcProviderRecord>> {
        let organization_id = organization_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE organization_id = {} ORDER BY display_name ASC",
                select_external_oidc_provider_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .load::<ExternalOidcProviderRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_external_oidc_provider(
        &self,
        slug: &str,
    ) -> AppResult<Option<ExternalOidcProviderRecord>> {
        let slug = slug.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE slug = {}",
                select_external_oidc_provider_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(slug)
                .get_result::<ExternalOidcProviderRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_external_oidc_provider_by_id(
        &self,
        id: &str,
    ) -> AppResult<Option<ExternalOidcProviderRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE id = {}",
                select_external_oidc_provider_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ExternalOidcProviderRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_external_oidc_providers_by_ids(
        &self,
        ids: &[String],
    ) -> AppResult<Vec<ExternalOidcProviderRecord>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids = ids.to_vec();
        with_conn!(self, |conn, kind| {
            let placeholders = placeholders(kind, 1, ids.len());
            let sql = format!(
                "{} WHERE id IN ({})",
                select_external_oidc_provider_sql(),
                placeholders,
            );
            bind_text_list(&mut conn, sql_query(sql), &ids)
                .load::<ExternalOidcProviderRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn insert_external_oidc_provider(
        &self,
        provider: NewExternalOidcProvider,
    ) -> AppResult<ExternalOidcProviderRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let scopes = util::to_json(&provider.scopes)?;
        let email_domains = util::to_json(&provider.email_domains)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO external_oidc_providers (id, slug, display_name, organization_id, issuer, client_id, client_secret, authorization_endpoint, token_endpoint, userinfo_endpoint, redirect_path, scopes, email_domains, is_active, allow_login, allow_registration, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 18)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(provider.slug)
                .bind::<Text, _>(provider.display_name)
                .bind::<Nullable<Text>, _>(provider.organization_id)
                .bind::<Text, _>(provider.issuer)
                .bind::<Text, _>(provider.client_id)
                .bind::<Text, _>(provider.client_secret)
                .bind::<Text, _>(provider.authorization_endpoint)
                .bind::<Text, _>(provider.token_endpoint)
                .bind::<Text, _>(provider.userinfo_endpoint)
                .bind::<Text, _>(provider.redirect_path)
                .bind::<Text, _>(scopes)
                .bind::<Text, _>(email_domains)
                .bind::<Integer, _>(i32::from(provider.is_active))
                .bind::<Integer, _>(i32::from(provider.allow_login))
                .bind::<Integer, _>(i32::from(provider.allow_registration))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!(
                "{} WHERE id = {}",
                select_external_oidc_provider_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<ExternalOidcProviderRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_external_oidc_provider(
        &self,
        id: &str,
        provider: NewExternalOidcProvider,
    ) -> AppResult<ExternalOidcProviderRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        let scopes = util::to_json(&provider.scopes)?;
        let email_domains = util::to_json(&provider.email_domains)?;
        with_conn!(self, |conn, kind| {
            conn.transaction::<ExternalOidcProviderRecord, AppError, _>(|conn| {
                let existing_sql = format!(
                    "{} WHERE id = {}",
                    select_external_oidc_provider_sql(),
                    ph(kind, 1)
                );
                let existing = sql_query(existing_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<ExternalOidcProviderRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                if existing.slug != provider.slug || existing.organization_id != provider.organization_id {
                    // A slug or ownership change creates a distinct trust
                    // boundary. Existing links must not silently transfer to
                    // the replacement configuration or enterprise.
                    for table in ["linked_identities", "external_oidc_states"] {
                        let sql = format!("DELETE FROM {table} WHERE provider_slug = {}", ph(kind, 1));
                        sql_query(sql)
                            .bind::<Text, _>(&existing.slug)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                }
                let sql = format!(
                    "UPDATE external_oidc_providers SET slug = {}, display_name = {}, organization_id = {}, issuer = {}, client_id = {}, client_secret = {}, authorization_endpoint = {}, token_endpoint = {}, userinfo_endpoint = {}, redirect_path = {}, scopes = {}, email_domains = {}, is_active = {}, allow_login = {}, allow_registration = {}, updated_at = {} WHERE id = {}",
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
                    ph(kind, 17)
                );
                sql_query(sql)
                    .bind::<Text, _>(provider.slug)
                    .bind::<Text, _>(provider.display_name)
                    .bind::<Nullable<Text>, _>(provider.organization_id)
                    .bind::<Text, _>(provider.issuer)
                    .bind::<Text, _>(provider.client_id)
                    .bind::<Text, _>(provider.client_secret)
                    .bind::<Text, _>(provider.authorization_endpoint)
                    .bind::<Text, _>(provider.token_endpoint)
                    .bind::<Text, _>(provider.userinfo_endpoint)
                    .bind::<Text, _>(provider.redirect_path)
                    .bind::<Text, _>(scopes)
                    .bind::<Text, _>(email_domains)
                    .bind::<Integer, _>(i32::from(provider.is_active))
                    .bind::<Integer, _>(i32::from(provider.allow_login))
                    .bind::<Integer, _>(i32::from(provider.allow_registration))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "{} WHERE id = {}",
                    select_external_oidc_provider_sql(),
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .get_result::<ExternalOidcProviderRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn delete_external_oidc_provider(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let provider_sql = format!(
                    "{} WHERE id = {}",
                    select_external_oidc_provider_sql(),
                    ph(kind, 1)
                );
                let provider = sql_query(provider_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<ExternalOidcProviderRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                // Provider slugs are reusable after deletion. Identity links
                // are therefore configuration-owned credentials, not durable
                // global identities: retaining them could bind a recreated
                // provider in another enterprise to a former member.
                for table in ["linked_identities", "external_oidc_states"] {
                    let sql = format!("DELETE FROM {table} WHERE provider_slug = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&provider.slug)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!(
                    "DELETE FROM external_oidc_providers WHERE id = {}",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                Ok(())
            })
        })
    }

    pub async fn list_ldap_providers(&self) -> AppResult<Vec<LdapProviderRecord>> {
        with_conn!(self, |conn, _kind| {
            sql_query(format!(
                "{} ORDER BY display_name ASC",
                select_ldap_provider_sql()
            ))
            .load::<LdapProviderRecord>(&mut conn)
            .map_err(AppError::from)
        })
    }

    pub async fn find_ldap_provider(&self, slug: &str) -> AppResult<Option<LdapProviderRecord>> {
        let slug = slug.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE slug = {}",
                select_ldap_provider_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(slug)
                .get_result::<LdapProviderRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_ldap_provider_by_id(
        &self,
        id: &str,
    ) -> AppResult<Option<LdapProviderRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_ldap_provider_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<LdapProviderRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_ldap_providers_by_ids(
        &self,
        ids: &[String],
    ) -> AppResult<Vec<LdapProviderRecord>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids = ids.to_vec();
        with_conn!(self, |conn, kind| {
            let placeholders = placeholders(kind, 1, ids.len());
            let sql = format!(
                "{} WHERE id IN ({})",
                select_ldap_provider_sql(),
                placeholders,
            );
            bind_text_list(&mut conn, sql_query(sql), &ids)
                .load::<LdapProviderRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn insert_ldap_provider(
        &self,
        provider: NewLdapProvider,
    ) -> AppResult<LdapProviderRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO ldap_providers (id, slug, display_name, organization_id, url, starttls, bind_dn, bind_password, base_dn, user_filter, user_id_attribute, email_attribute, username_attribute, display_name_attribute, phone_attribute, is_active, allow_login, allow_registration, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                ph(kind, 20)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(provider.slug)
                .bind::<Text, _>(provider.display_name)
                .bind::<Nullable<Text>, _>(provider.organization_id)
                .bind::<Text, _>(provider.url)
                .bind::<Integer, _>(i32::from(provider.starttls))
                .bind::<Text, _>(provider.bind_dn)
                .bind::<Text, _>(provider.bind_password.unwrap_or_default())
                .bind::<Text, _>(provider.base_dn)
                .bind::<Text, _>(provider.user_filter)
                .bind::<Text, _>(provider.user_id_attribute)
                .bind::<Text, _>(provider.email_attribute)
                .bind::<Text, _>(provider.username_attribute)
                .bind::<Text, _>(provider.display_name_attribute)
                .bind::<Text, _>(provider.phone_attribute)
                .bind::<Integer, _>(i32::from(provider.is_active))
                .bind::<Integer, _>(i32::from(provider.allow_login))
                .bind::<Integer, _>(i32::from(provider.allow_registration))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!("{} WHERE id = {}", select_ldap_provider_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<LdapProviderRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn update_ldap_provider(
        &self,
        id: &str,
        provider: NewLdapProvider,
    ) -> AppResult<LdapProviderRecord> {
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<LdapProviderRecord, AppError, _>(|conn| {
                let existing_sql =
                    format!("{} WHERE id = {}", select_ldap_provider_sql(), ph(kind, 1));
                let existing = sql_query(existing_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<LdapProviderRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                let trust_boundary_changed = existing.slug != provider.slug
                    || existing.organization_id != provider.organization_id;
                if trust_boundary_changed {
                    let provider_key = ldap_provider_key(&existing.slug);
                    let identity_sql = format!(
                        "DELETE FROM linked_identities WHERE provider_slug = {}",
                        ph(kind, 1)
                    );
                    sql_query(identity_sql)
                        .bind::<Text, _>(&provider_key)
                        .execute(conn)
                        .map_err(AppError::from)?;
                    // A worker holding the old provider configuration must
                    // fail closed rather than publish a snapshot under the
                    // new slug or organization.
                    for table in [
                        "directory_sync_leases",
                        "directory_sync_checkpoints",
                        "directory_sync_memberships",
                        "directory_sync_groups",
                        "directory_sync_runs",
                    ] {
                        let sql = format!(
                            "DELETE FROM {table} WHERE provider_id = {}",
                            ph(kind, 1)
                        );
                        sql_query(sql)
                            .bind::<Text, _>(&id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                }
                let bind_password = provider.bind_password.unwrap_or(existing.bind_password);
                let sql = format!(
                    "UPDATE ldap_providers SET slug = {}, display_name = {}, organization_id = {}, url = {}, starttls = {}, bind_dn = {}, bind_password = {}, base_dn = {}, user_filter = {}, user_id_attribute = {}, email_attribute = {}, username_attribute = {}, display_name_attribute = {}, phone_attribute = {}, is_active = {}, allow_login = {}, allow_registration = {}, updated_at = {} WHERE id = {}",
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
                    ph(kind, 19)
                );
                sql_query(sql)
                    .bind::<Text, _>(provider.slug)
                    .bind::<Text, _>(provider.display_name)
                    .bind::<Nullable<Text>, _>(provider.organization_id)
                    .bind::<Text, _>(provider.url)
                    .bind::<Integer, _>(i32::from(provider.starttls))
                    .bind::<Text, _>(provider.bind_dn)
                    .bind::<Text, _>(bind_password)
                    .bind::<Text, _>(provider.base_dn)
                    .bind::<Text, _>(provider.user_filter)
                    .bind::<Text, _>(provider.user_id_attribute)
                    .bind::<Text, _>(provider.email_attribute)
                    .bind::<Text, _>(provider.username_attribute)
                    .bind::<Text, _>(provider.display_name_attribute)
                    .bind::<Text, _>(provider.phone_attribute)
                    .bind::<Integer, _>(i32::from(provider.is_active))
                    .bind::<Integer, _>(i32::from(provider.allow_login))
                    .bind::<Integer, _>(i32::from(provider.allow_registration))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!("{} WHERE id = {}", select_ldap_provider_sql(), ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .get_result::<LdapProviderRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn delete_ldap_provider(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let provider_sql =
                    format!("{} WHERE id = {}", select_ldap_provider_sql(), ph(kind, 1));
                let provider = sql_query(provider_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<LdapProviderRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                let provider_key = ldap_provider_key(&provider.slug);
                let identity_sql = format!(
                    "DELETE FROM linked_identities WHERE provider_slug = {}",
                    ph(kind, 1)
                );
                sql_query(identity_sql)
                    .bind::<Text, _>(&provider_key)
                    .execute(conn)
                    .map_err(AppError::from)?;
                for table in [
                    "directory_sync_leases",
                    "directory_sync_checkpoints",
                    "directory_sync_memberships",
                    "directory_sync_groups",
                    "directory_sync_runs",
                ] {
                    let sql = format!("DELETE FROM {table} WHERE provider_id = {}", ph(kind, 1));
                    sql_query(sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!("DELETE FROM ldap_providers WHERE id = {}", ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                Ok(())
            })
        })
    }

    pub async fn insert_external_oidc_user(
        &self,
        user: NewUser,
        provider_slug: &str,
        external_subject: &str,
        external_email: Option<String>,
        organization_id: Option<String>,
        expected_first_user: bool,
    ) -> AppResult<UserRecord> {
        let user_id = uuid::Uuid::new_v4().to_string();
        let linked_identity_id = uuid::Uuid::new_v4().to_string();
        let provider_slug = provider_slug.to_string();
        let external_subject = external_subject.to_string();
        let organization_id = organization_id.map(|value| value.trim().to_string());
        let now = util::now_ts();
        let identity = UserIdentityCandidate::insert(&user);
        with_conn!(self, |conn, kind| {
            conn.transaction::<UserRecord, AppError, _>(|conn| {
                ensure_first_user_registration_still_first!(conn, expected_first_user)?;
                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "external OIDC email or username already belongs to an existing account"
                )?;

                let existing_identity_count = sql_query(count_linked_identity_sql(kind))
                    .bind::<Text, _>(&provider_slug)
                    .bind::<Text, _>(&external_subject)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count;
                if existing_identity_count > 0 {
                    return Err(AppError::BadRequest(
                        "external OIDC identity is already linked".to_string(),
                    ));
                }

                sql_query(insert_user_sql(kind, UserRegistrationSource::Local))
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&user.email)
                    .bind::<Text, _>(&user.username)
                    .bind::<Nullable<Text>, _>(user.display_name.clone())
                    .bind::<Nullable<Text>, _>(user.phone.clone())
                    .bind::<Text, _>(&user.password_hash)
                    .bind::<Nullable<BigInt>, _>(user.email_verified_at)
                    .bind::<Nullable<BigInt>, _>(user.phone_verified_at)
                    .bind::<Integer, _>(i32::from(user.is_admin))
                    .bind::<Integer, _>(i32::from(user.is_active))
                    .bind::<Nullable<BigInt>, _>(user.archived_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let linked_identity_sql = format!(
                    "INSERT INTO linked_identities (id, user_id, provider_slug, external_subject, external_email, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7)
                );
                sql_query(linked_identity_sql)
                    .bind::<Text, _>(linked_identity_id)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(provider_slug)
                    .bind::<Text, _>(external_subject)
                    .bind::<Nullable<Text>, _>(external_email)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                if let Some(organization_id) = organization_id.as_deref() {
                    let sql = format!("{} WHERE id = {}", select_organization_sql(), ph(kind, 1));
                    let organization = sql_query(sql)
                        .bind::<Text, _>(organization_id)
                        .get_result::<OrganizationRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?
                        .ok_or_else(|| {
                            AppError::BadRequest(
                            "external OIDC provider organization is missing".to_string(),
                            )
                        })?;
                    if !organization.allows_email(&user.email)? {
                        return Err(AppError::Forbidden);
                    }
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
                        .bind::<Text, _>(&user_id)
                        .bind::<Text, _>(crate::organizations::ROLE_MEMBER)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                let sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(user_id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn insert_external_oidc_state(
        &self,
        state: String,
        provider_slug: String,
        nonce: String,
        return_to: Option<String>,
        ttl_seconds: i64,
    ) -> AppResult<()> {
        let now = util::now_ts();
        let expires_at = now + ttl_seconds;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO external_oidc_states (state, provider_slug, nonce, return_to, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7)
            );
            sql_query(sql)
                .bind::<Text, _>(state)
                .bind::<Text, _>(provider_slug)
                .bind::<Text, _>(nonce)
                .bind::<Nullable<Text>, _>(return_to)
                .bind::<BigInt, _>(expires_at)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub async fn consume_external_oidc_state(
        &self,
        state_value: &str,
    ) -> AppResult<ExternalOidcStateRecord> {
        let state_value = state_value.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            // Claim the state with a compare-and-set update.  A plain
            // SELECT followed by UPDATE lets two concurrent callbacks both
            // observe an unconsumed row and both continue the login flow.
            let claim_sql = format!(
                "UPDATE external_oidc_states SET consumed_at = {} WHERE state = {} AND consumed_at IS NULL AND expires_at >= {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            let claimed = sql_query(claim_sql)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&state_value)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if claimed != 1 {
                return Err(AppError::BadRequest(
                    "OIDC state is invalid, expired, or already consumed".to_string(),
                ));
            }
            let sql = format!(
                "SELECT state, provider_slug, nonce, return_to, expires_at, consumed_at, created_at FROM external_oidc_states WHERE state = {}",
                ph(kind, 1)
            );
            let record = sql_query(sql)
                .bind::<Text, _>(&state_value)
                .get_result::<ExternalOidcStateRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
                .ok_or_else(|| AppError::BadRequest("OIDC state disappeared".to_string()))?;
            Ok(record)
        })
    }
}
