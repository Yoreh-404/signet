#[cfg(feature = "mysql")]
use super::migrate_mysql_phone_uniqueness;
#[cfg(feature = "postgres")]
use super::migrate_postgres_phone_uniqueness;
#[cfg(feature = "sqlite")]
use super::migrate_sqlite_phone_uniqueness;
use super::*;
use super::{
    ApplicationRecord, AuthorizationCodeType, BootstrapClient, ClientRecord, CountRow,
    DatabaseKind, Db, LoginCodeLevel, NewApplication, NewApplicationDiscovery, NewClient,
    NewExternalOidcProvider, NewLoginSettings, NewRegistrationSettings, NewRuntimeSettings,
    NewSecurityPolicy, NewUser, Settings, UserListScope, UserRegistrationSource,
    application_slug_base, application_slug_collision_candidate,
    authorization_code_registration_source_backfill_sql, blocking, connect_mysql, connect_postgres,
    connect_sqlite, default_openai_quick_link, is_ignorable_migration_error, migration_sql, ph,
};
use crate::error::{AppError, AppResult};
use diesel::{
    RunQueryDsl,
    connection::SimpleConnection,
    sql_query,
    sql_types::{BigInt, Text},
};
use std::time::Duration;
use tracing::warn;

pub(super) fn bootstrap_client_secret_hash(
    client: &BootstrapClient,
    existing: Option<&ClientRecord>,
) -> AppResult<Option<String>> {
    let auth_method = client.token_endpoint_auth_method.as_str();
    let existing_hash = existing.and_then(|record| record.client_secret_hash.as_deref());
    if !client.rotate_secret
        && let Some(existing_hash) = existing_hash
    {
        if matches!(
            auth_method,
            "none" | crate::client_assertion::PRIVATE_KEY_JWT
        ) || crate::client_assertion::stored_secret_supports_method(
            auth_method,
            Some(existing_hash),
        ) {
            return Ok(Some(existing_hash.to_string()));
        }
        return Err(AppError::Configuration(format!(
            "bootstrap client {} has an existing client_secret incompatible with {}, set rotate_secret=true to replace it",
            client.client_id, auth_method
        )));
    }
    if matches!(
        auth_method,
        "none" | crate::client_assertion::PRIVATE_KEY_JWT
    ) {
        return Ok(None);
    }

    let configured_secret = client
        .client_secret_env
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|env_name| {
            std::env::var(env_name).map_err(|err| {
                AppError::Configuration(format!(
                    "bootstrap client {} references unusable client_secret_env {env_name}: {err}",
                    client.client_id
                ))
            })
        })
        .transpose()?
        .or_else(|| (!client.client_secret.is_empty()).then(|| client.client_secret.clone()));
    let Some(configured_secret) = configured_secret.filter(|secret| !secret.is_empty()) else {
        return Err(AppError::Configuration(format!(
            "bootstrap client {} requires client_secret or client_secret_env",
            client.client_id
        )));
    };
    crate::client_assertion::store_client_secret(auth_method, &configured_secret)
}

impl Db {
    pub fn connect(settings: &Settings) -> AppResult<Self> {
        match settings.database.kind {
            DatabaseKind::Sqlite => connect_sqlite(&settings.database),
            DatabaseKind::Postgres => connect_postgres(&settings.database),
            DatabaseKind::Mysql => connect_mysql(&settings.database),
        }
    }

    /// Connect and verify the selected database while the shared database
    /// service may still be starting. The conductor intentionally leaves
    /// Compose services unordered, so a transient database error must not
    /// permanently terminate Signet during a normal bootstrap race.
    pub async fn connect_with_retry(settings: &Settings) -> AppResult<Self> {
        let mut retry_delay = Duration::from_secs(1);
        loop {
            match Self::connect(settings) {
                Ok(db) => match db.ping().await {
                    Ok(()) => return Ok(db),
                    Err(error) => {
                        warn!(
                            error = %error,
                            retry_in_seconds = retry_delay.as_secs(),
                            "Signet database is unavailable; retrying"
                        );
                    }
                },
                Err(error @ AppError::Configuration(_)) => return Err(error),
                Err(error) => {
                    warn!(
                        error = %error,
                        retry_in_seconds = retry_delay.as_secs(),
                        "Signet database pool could not be created; retrying"
                    );
                }
            }
            tokio::time::sleep(retry_delay).await;
            retry_delay = std::cmp::min(retry_delay + retry_delay, Duration::from_secs(30));
        }
    }

    pub async fn ping(&self) -> AppResult<()> {
        with_conn!(self, |conn, _kind| {
            conn.batch_execute("SELECT 1")
                .map_err(|err| AppError::Database(err.to_string()))
        })
    }

    /// Creates the complete Application/OIDC connection aggregate on one
    /// database connection.  The profile is materialized before the binding
    /// points at it, so a failed mapper, profile, or binding write rolls back
    /// the client as well.

    pub async fn migrate(&self) -> AppResult<()> {
        with_conn!(self, |conn, kind| {
            for statement in migration_sql(kind) {
                if let Err(err) = conn.batch_execute(statement) {
                    let message = err.to_string();
                    if !is_ignorable_migration_error(statement, &message) {
                        return Err(AppError::Database(message));
                    }
                }
            }
            Ok(())
        })?;
        self.remove_legacy_phone_uniqueness().await?;
        self.migrate_tenant_application_model().await?;
        with_conn!(self, |conn, kind| {
            // This data repair is deliberately outside the static migration
            // arrays: those arrays run on every startup and MySQL keeps them
            // schema-only. The statement is idempotent and only touches
            // legacy rows which still carry the default source.
            sql_query(authorization_code_registration_source_backfill_sql(kind))
                .bind::<Text, _>(UserRegistrationSource::AuthorizationCode.as_str())
                .bind::<Text, _>(UserRegistrationSource::Local.as_str())
                .bind::<Text, _>(AuthorizationCodeType::Registration.as_str())
                .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                .bind::<Text, _>(LoginCodeLevel::TrialEnrollment.as_str())
                .execute(&mut conn)
                .map_err(AppError::from)?;
            Ok(())
        })?;
        Ok(())
    }

    /// Older installations treated phone as an identity key. Phone is now a
    /// verification contact and may legitimately be shared across accounts.
    async fn remove_legacy_phone_uniqueness(&self) -> AppResult<()> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(pool) => {
                let pool = pool.clone();
                blocking(move || {
                    let mut conn = pool
                        .get()
                        .map_err(|err| AppError::Database(err.to_string()))?;
                    migrate_sqlite_phone_uniqueness(&mut conn)
                })
                .await
            }
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => {
                let pool = pool.clone();
                blocking(move || {
                    let mut conn = pool
                        .get()
                        .map_err(|err| AppError::Database(err.to_string()))?;
                    migrate_postgres_phone_uniqueness(&mut conn)
                })
                .await
            }
            #[cfg(feature = "mysql")]
            Self::Mysql(pool) => {
                let pool = pool.clone();
                blocking(move || {
                    let mut conn = pool
                        .get()
                        .map_err(|err| AppError::Database(err.to_string()))?;
                    migrate_mysql_phone_uniqueness(&mut conn)
                })
                .await
            }
        }
    }

    /// Creates the system tenant, adopts all old unowned protocol resources,
    /// and gives every historical OIDC client an application aggregate.  An
    /// application is a website integration: old member/assigned-account
    /// policies are normalized to the global Signet account boundary during
    /// startup so stale rows cannot continue to act as an authentication
    /// gate.
    async fn migrate_tenant_application_model(&self) -> AppResult<()> {
        let system_organization = self.system_organization().await?;
        let system_organization_id = system_organization.id.clone();
        let system_organization_id_for_update = system_organization_id.clone();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE clients SET organization_id = {} WHERE organization_id IS NULL OR organization_id = ''",
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(system_organization_id_for_update)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })?;

        for client in self.list_clients().await? {
            self.ensure_application_for_client(&client).await?;
        }
        self.migrate_application_binding_storage().await?;
        self.reconcile_application_client_binding_ownership()
            .await?;
        self.migrate_legacy_application_authorization().await?;
        self.migrate_iap_application_storage(&system_organization_id)
            .await?;
        self.normalize_application_login_boundary().await?;
        // Every application gets an explicit discovery ownership record. The
        // migration default is Signet-managed, so existing installations keep
        // their current behavior until an operator opts a website into the
        // website-managed mode through bootstrap or the admin API.
        for application in self.list_applications(None).await? {
            if self
                .find_application_discovery(&application.id)
                .await?
                .is_some()
            {
                continue;
            }
            let website_url = self
                .list_application_modules(&application.id)
                .await?
                .into_iter()
                .find(|module| module.module_key == "protocols")
                .and_then(|module| {
                    serde_json::from_str::<serde_json::Value>(&module.config_json)
                        .ok()
                        .and_then(|value| {
                            value
                                .get("website_url")
                                .and_then(serde_json::Value::as_str)
                                .map(str::trim)
                                .filter(|value| !value.is_empty())
                                .map(ToOwned::to_owned)
                        })
                })
                .unwrap_or_default();
            self.upsert_application_discovery(NewApplicationDiscovery {
                application_id: application.id,
                management_mode: crate::application_discovery::MANAGEMENT_MODE_SIGNET.to_string(),
                website_url,
                fetch_secret_ciphertext: String::new(),
                signing_public_jwks: String::new(),
                last_verified_revision: None,
                last_verified_version: None,
                last_verified_digest: None,
                last_verified_expires_at: None,
                sync_status: crate::application_discovery::SYNC_DISABLED.to_string(),
                last_fetched_at: None,
                last_success_at: None,
                last_error: None,
                snapshot_json: None,
                operator_disabled: false,
            })
            .await?;
        }
        Ok(())
    }

    async fn migrate_application_binding_storage(&self) -> AppResult<()> {
        with_conn!(self, |conn, kind| {
            let auth_domain_insert = match kind {
                DatabaseKind::Sqlite | DatabaseKind::Postgres => {
                    "INSERT INTO application_auth_domains (id, application_id, assurance_policy, is_active, created_at, updated_at) SELECT 'auth-domain:' || applications.id, applications.id, 'default', 1, applications.created_at, applications.updated_at FROM applications LEFT JOIN application_auth_domains ON application_auth_domains.application_id = applications.id WHERE application_auth_domains.application_id IS NULL"
                }
                DatabaseKind::Mysql => {
                    "INSERT IGNORE INTO application_auth_domains (id, application_id, assurance_policy, is_active, created_at, updated_at) SELECT CONCAT('auth-domain:', applications.id), applications.id, 'default', 1, applications.created_at, applications.updated_at FROM applications LEFT JOIN application_auth_domains ON application_auth_domains.application_id = applications.id WHERE application_auth_domains.application_id IS NULL"
                }
            };
            conn.batch_execute(auth_domain_insert)
                .map_err(AppError::from)?;
            let legacy_table_exists = match kind {
                DatabaseKind::Sqlite => sql_query(
                    "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'application_oidc_clients'",
                )
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                    > 0,
                DatabaseKind::Postgres => sql_query(format!(
                    "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = {}",
                    ph(kind, 1)
                ))
                .bind::<Text, _>("application_oidc_clients")
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                    > 0,
                DatabaseKind::Mysql => sql_query(format!(
                    "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = {}",
                    ph(kind, 1)
                ))
                .bind::<Text, _>("application_oidc_clients")
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                    > 0,
            };
            if !legacy_table_exists {
                let legacy_consent_table_exists = match kind {
                    DatabaseKind::Sqlite => sql_query(
                        "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'user_consents'",
                    )
                    .get_result::<CountRow>(&mut conn)
                    .map_err(AppError::from)?
                    .count
                        > 0,
                    DatabaseKind::Postgres => sql_query(format!(
                        "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = {}",
                        ph(kind, 1)
                    ))
                    .bind::<Text, _>("user_consents")
                    .get_result::<CountRow>(&mut conn)
                    .map_err(AppError::from)?
                    .count
                        > 0,
                    DatabaseKind::Mysql => sql_query(format!(
                        "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = {}",
                        ph(kind, 1)
                    ))
                    .bind::<Text, _>("user_consents")
                    .get_result::<CountRow>(&mut conn)
                    .map_err(AppError::from)?
                    .count
                        > 0,
                };
                if legacy_consent_table_exists {
                    let consent_migration = match kind {
                        DatabaseKind::Sqlite => {
                            "INSERT OR IGNORE INTO client_grants (user_id, client_id, authorization_profile_id, granted_scopes, granted_at, updated_at, revoked_at) SELECT user_id, client_id, 'default', granted_scopes, granted_at, updated_at, revoked_at FROM user_consents"
                        }
                        DatabaseKind::Postgres => {
                            "INSERT INTO client_grants (user_id, client_id, authorization_profile_id, granted_scopes, granted_at, updated_at, revoked_at) SELECT user_id, client_id, 'default', granted_scopes, granted_at, updated_at, revoked_at FROM user_consents ON CONFLICT DO NOTHING"
                        }
                        DatabaseKind::Mysql => {
                            "INSERT IGNORE INTO client_grants (user_id, client_id, authorization_profile_id, granted_scopes, granted_at, updated_at, revoked_at) SELECT user_id, client_id, 'default', granted_scopes, granted_at, updated_at, revoked_at FROM user_consents"
                        }
                    };
                    conn.batch_execute(consent_migration)
                        .map_err(AppError::from)?;
                }
                return Ok(());
            }
            let binding_insert = match kind {
                DatabaseKind::Sqlite | DatabaseKind::Postgres => {
                    "INSERT INTO application_client_bindings (application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at) SELECT links.application_id, links.client_db_id, 'oidc', 'default', 'auth-domain:' || links.application_id, clients.is_active, links.created_at, clients.updated_at FROM application_oidc_clients links INNER JOIN clients ON clients.id = links.client_db_id LEFT JOIN application_client_bindings bindings ON bindings.application_id = links.application_id AND bindings.client_db_id = links.client_db_id WHERE bindings.client_db_id IS NULL ON CONFLICT DO NOTHING"
                }
                DatabaseKind::Mysql => {
                    "INSERT IGNORE INTO application_client_bindings (application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at) SELECT links.application_id, links.client_db_id, 'oidc', 'default', CONCAT('auth-domain:', links.application_id), clients.is_active, links.created_at, clients.updated_at FROM application_oidc_clients links INNER JOIN clients ON clients.id = links.client_db_id LEFT JOIN application_client_bindings bindings ON bindings.application_id = links.application_id AND bindings.client_db_id = links.client_db_id WHERE bindings.client_db_id IS NULL"
                }
            };
            conn.batch_execute(binding_insert).map_err(AppError::from)?;
            let legacy_consent_table_exists = match kind {
                DatabaseKind::Sqlite => sql_query(
                    "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'table' AND name = 'user_consents'",
                )
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                    > 0,
                DatabaseKind::Postgres => sql_query(format!(
                    "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = {}",
                    ph(kind, 1)
                ))
                .bind::<Text, _>("user_consents")
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                    > 0,
                DatabaseKind::Mysql => sql_query(format!(
                    "SELECT COUNT(*) AS count FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = {}",
                    ph(kind, 1)
                ))
                .bind::<Text, _>("user_consents")
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                    > 0,
            };
            if legacy_consent_table_exists {
                let consent_migration = match kind {
                    DatabaseKind::Sqlite => {
                        "INSERT OR IGNORE INTO client_grants (user_id, client_id, authorization_profile_id, granted_scopes, granted_at, updated_at, revoked_at) SELECT user_id, client_id, 'default', granted_scopes, granted_at, updated_at, revoked_at FROM user_consents"
                    }
                    DatabaseKind::Postgres => {
                        "INSERT INTO client_grants (user_id, client_id, authorization_profile_id, granted_scopes, granted_at, updated_at, revoked_at) SELECT user_id, client_id, 'default', granted_scopes, granted_at, updated_at, revoked_at FROM user_consents ON CONFLICT DO NOTHING"
                    }
                    DatabaseKind::Mysql => {
                        "INSERT IGNORE INTO client_grants (user_id, client_id, authorization_profile_id, granted_scopes, granted_at, updated_at, revoked_at) SELECT user_id, client_id, 'default', granted_scopes, granted_at, updated_at, revoked_at FROM user_consents"
                    }
                };
                conn.batch_execute(consent_migration)
                    .map_err(AppError::from)?;
            }
            Ok(())
        })
    }

    /// Existing installations may have accumulated the old many-to-many
    /// client/application rows. Keep the earliest owner deterministically,
    /// remove later duplicates, and then enforce the one-application invariant
    /// at the database level for every supported engine.
    async fn reconcile_application_client_binding_ownership(&self) -> AppResult<()> {
        let mut owners = BTreeSet::new();
        for application in self.list_applications(None).await? {
            for binding in self
                .list_application_client_bindings(&application.id)
                .await?
            {
                if owners.insert(binding.client_db_id.clone()) {
                    continue;
                }
                let application_id = binding.application_id.clone();
                let client_db_id = binding.client_db_id.clone();
                with_conn!(self, |conn, kind| {
                    let sql = format!(
                        "DELETE FROM application_client_bindings WHERE application_id = {} AND client_db_id = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(&client_db_id)
                        .execute(&mut conn)
                        .map(|_| ())
                        .map_err(AppError::from)
                })?;
            }
        }

        with_conn!(self, |conn, kind| {
            match kind {
                DatabaseKind::Sqlite | DatabaseKind::Postgres => conn
                    .batch_execute(
                        "CREATE UNIQUE INDEX IF NOT EXISTS uq_application_client_bindings_client ON application_client_bindings(client_db_id)",
                    )
                    .map_err(AppError::from),
                DatabaseKind::Mysql => {
                    let exists = sql_query(
                        "SELECT COUNT(*) AS count FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'application_client_bindings' AND index_name = 'uq_application_client_bindings_client'",
                    )
                    .get_result::<CountRow>(&mut conn)
                    .map_err(AppError::from)?
                    .count
                        > 0;
                    if !exists {
                        conn.batch_execute(
                            "CREATE UNIQUE INDEX uq_application_client_bindings_client ON application_client_bindings(client_db_id)",
                        )
                        .map_err(AppError::from)?;
                    }
                    Ok(())
                }
            }
        })
    }

    async fn migrate_iap_application_storage(&self, system_organization_id: &str) -> AppResult<()> {
        for legacy in self.list_iap_applications().await? {
            if legacy.application_id.is_some() {
                continue;
            }
            let application_slug = self
                .next_legacy_application_slug(
                    system_organization_id,
                    &format!("iap-{}", legacy.slug),
                )
                .await?;
            let application = self
                .insert_application(NewApplication {
                    organization_id: system_organization_id.to_string(),
                    slug: application_slug,
                    name: legacy.name.clone(),
                    description: Some(format!(
                        "Application migrated from legacy IAP route {}.",
                        legacy.slug
                    )),
                    access_mode: crate::applications::ACCESS_ALL_SIGNET_USERS.to_string(),
                    registration_mode: crate::applications::REGISTRATION_DISABLED.to_string(),
                    account_selection_mode: crate::applications::ACCOUNT_SELECTION_OPTIONAL
                        .to_string(),
                    unique_identity_factors: Vec::new(),
                    is_active: legacy.is_active == 1,
                })
                .await?;
            let legacy_id = legacy.id.clone();
            let application_id = application.id.clone();
            with_conn!(self, |conn, kind| {
                let sql = format!(
                    "UPDATE iap_applications SET application_id = {} WHERE id = {} AND application_id IS NULL",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(sql)
                    .bind::<Text, _>(&application_id)
                    .bind::<Text, _>(&legacy_id)
                    .execute(&mut conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })?;
        }
        Ok(())
    }

    async fn normalize_application_login_boundary(&self) -> AppResult<()> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE applications SET access_mode = {}, registration_mode = {}, unique_identity_factors = {}, updated_at = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
            );
            sql_query(sql)
                .bind::<Text, _>(crate::applications::ACCESS_ALL_SIGNET_USERS)
                .bind::<Text, _>(crate::applications::REGISTRATION_DISABLED)
                .bind::<Text, _>("[]")
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    pub(crate) async fn ensure_application_for_client(
        &self,
        client: &ClientRecord,
    ) -> AppResult<()> {
        if self
            .find_application_for_client(&client.id)
            .await?
            .is_some()
        {
            return Ok(());
        }
        let system_organization = self.system_organization().await?;
        let organization_id = match client.organization_id.as_deref() {
            Some(id) if self.find_organization_by_id(id).await?.is_some() => id.to_string(),
            _ => {
                self.assign_client_to_organization(&client.id, &system_organization.id)
                    .await?;
                system_organization.id
            }
        };
        // A deployment bootstrap may create the website application before it
        // creates the first client. Reuse that stable application slug instead
        // of manufacturing a legacy `axon-2` aggregate, otherwise the signed
        // website manifest would be unable to attach its client without
        // taking ownership away from another application.
        if let Some(existing_application) = self
            .find_application_by_slug_in_organization(&organization_id, &client.client_id)
            .await?
        {
            let is_website_managed = self
                .find_application_discovery(&existing_application.id)
                .await?
                .is_some_and(|discovery| {
                    discovery.management_mode
                        == crate::application_discovery::MANAGEMENT_MODE_WEBSITE
                });
            if is_website_managed {
                return self
                    .link_client_to_application(
                        &existing_application.id,
                        &client.id,
                        "oidc",
                        "default",
                    )
                    .await;
            }
        }
        let slug = self
            .next_legacy_application_slug(&organization_id, &client.client_id)
            .await?;
        let application = self
            .insert_application(NewApplication {
                organization_id,
                slug,
                name: client.client_name.clone(),
                description: Some(format!(
                    "Website application migrated from OIDC client {}.",
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
                is_active: client.is_active == 1,
            })
            .await?;
        self.link_client_to_application(&application.id, &client.id, "oidc", "default")
            .await
    }

    /// Ensures the application aggregate created for a newly managed OIDC
    /// connection uses the same global-account login boundary as every other
    /// website application.
    pub async fn harden_new_client_application(
        &self,
        client_db_id: &str,
    ) -> AppResult<ApplicationRecord> {
        let client = self
            .find_client_by_id(client_db_id)
            .await?
            .ok_or(AppError::NotFound)?;
        let application = self
            .find_application_for_client(&client.id)
            .await?
            .ok_or_else(|| {
                AppError::Internal(
                    "new OIDC client does not have an application aggregate".to_string(),
                )
            })?;
        let organization_id = client.organization_id.as_deref().ok_or_else(|| {
            AppError::Internal("managed OIDC client is missing an organization".to_string())
        })?;
        if application.organization_id != organization_id {
            return Err(AppError::Internal(
                "OIDC client application belongs to a different organization".to_string(),
            ));
        }
        self.update_application(
            &application.id,
            NewApplication {
                organization_id: application.organization_id,
                slug: application.slug,
                name: application.name,
                description: Some(format!(
                    "Website application created for OIDC client {}.",
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
                // Application activation is independent from the connection's
                // protocol activation. A client created disabled can later be
                // enabled without leaving its application unexpectedly off.
                is_active: true,
            },
        )
        .await
    }

    async fn assign_client_to_organization(
        &self,
        client_db_id: &str,
        organization_id: &str,
    ) -> AppResult<()> {
        let client_db_id = client_db_id.to_string();
        let organization_id = organization_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE clients SET organization_id = {}, updated_at = {} WHERE id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(client_db_id)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    async fn next_legacy_application_slug(
        &self,
        organization_id: &str,
        client_id: &str,
    ) -> AppResult<String> {
        let base = application_slug_base(client_id);
        if self
            .find_application_by_slug_in_organization(organization_id, &base)
            .await?
            .is_none()
        {
            return Ok(base);
        }
        let candidate = application_slug_collision_candidate(&base, client_id);
        if self
            .find_application_by_slug_in_organization(organization_id, &candidate)
            .await?
            .is_none()
        {
            return Ok(candidate);
        }
        let mut prefix = base;
        prefix.truncate(31);
        let random_candidate = format!("{prefix}-{}", uuid::Uuid::new_v4().simple());
        if self
            .find_application_by_slug_in_organization(organization_id, &random_candidate)
            .await?
            .is_none()
        {
            return Ok(random_candidate);
        }
        Err(AppError::Internal(
            "could not allocate a unique application slug for migrated OIDC client".to_string(),
        ))
    }

    pub(crate) async fn ensure_bootstrap_client(
        &self,
        client: &BootstrapClient,
        system_organization_id: &str,
    ) -> AppResult<ClientRecord> {
        let existing = self.find_client_by_client_id(&client.client_id).await?;
        let permissions = crate::service_accounts::normalize_permissions(
            client.service_account_permissions.clone(),
        )?;
        let client_secret_hash = bootstrap_client_secret_hash(client, existing.as_ref())?;
        let organization_id = existing
            .as_ref()
            .and_then(|record| record.organization_id.clone())
            .or_else(|| Some(system_organization_id.to_string()));
        let desired = NewClient {
            client_id: client.client_id.clone(),
            client_secret_hash,
            client_name: client.client_name.clone(),
            logo_uri: client.logo_uri.clone(),
            organization_id,
            redirect_uris: client.redirect_uris.clone(),
            post_logout_redirect_uris: client.post_logout_redirect_uris.clone(),
            scopes: client.scopes.clone(),
            audience: client
                .audience
                .as_deref()
                .unwrap_or_default()
                .trim()
                .to_string(),
            grant_types: client.grant_types.clone(),
            response_types: client.response_types.clone(),
            token_endpoint_auth_method: client.token_endpoint_auth_method.clone(),
            require_pkce: client.require_pkce,
            require_mfa: false,
            require_pushed_authorization_requests: false,
            require_s256_pkce: false,
            require_confidential_client: client.require_confidential_client,
            require_dpop: false,
            require_account_selection: false,
            trust_email_verified: false,
            authorization_details_types: Vec::new(),
            subject_type: crate::subject::SUBJECT_TYPE_PUBLIC.to_string(),
            sector_identifier_uri: String::new(),
            jwks_uri: String::new(),
            jwks: String::new(),
            backchannel_logout_uri: String::new(),
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: String::new(),
            frontchannel_logout_session_required: false,
            service_account_enabled: client.service_account_enabled,
            service_account_permissions: permissions,
            is_active: true,
        };

        if let Some(existing) = existing {
            return self.update_client(&existing.id, desired).await;
        }

        match self.insert_client(desired.clone()).await {
            Ok(created) => Ok(created),
            Err(insert_error) => {
                // A second Signet process may have inserted the unique client_id
                // between the lookup and insert. Re-read it and apply the same
                // secret-preserving ensure rather than failing startup.
                let Some(existing) = self.find_client_by_client_id(&client.client_id).await? else {
                    return Err(insert_error);
                };
                let client_secret_hash = bootstrap_client_secret_hash(client, Some(&existing))?;
                self.update_client(
                    &existing.id,
                    NewClient {
                        client_secret_hash,
                        ..desired
                    },
                )
                .await
            }
        }
    }

    async fn ensure_bootstrap_application(
        &self,
        application: &BootstrapApplication,
        system_organization_id: &str,
        settings: &Settings,
    ) -> AppResult<ApplicationRecord> {
        let existing = self
            .find_application_by_slug_in_organization(
                system_organization_id,
                application.application_id.trim(),
            )
            .await?;
        let application_record = if let Some(existing) = existing {
            self.update_application(
                &existing.id,
                NewApplication {
                    organization_id: existing.organization_id.clone(),
                    slug: existing.slug.clone(),
                    name: application.name.trim().to_string(),
                    description: existing.description.clone(),
                    access_mode: crate::applications::ACCESS_ALL_SIGNET_USERS.to_string(),
                    registration_mode: crate::applications::REGISTRATION_DISABLED.to_string(),
                    account_selection_mode: existing.account_selection_mode.clone(),
                    unique_identity_factors: existing.unique_identity_factors()?,
                    is_active: application.is_active,
                },
            )
            .await?
        } else {
            self.insert_application(NewApplication {
                organization_id: system_organization_id.to_string(),
                slug: application.application_id.trim().to_string(),
                name: application.name.trim().to_string(),
                description: Some(
                    "Application registered by Signet deployment bootstrap.".to_string(),
                ),
                access_mode: crate::applications::ACCESS_ALL_SIGNET_USERS.to_string(),
                registration_mode: crate::applications::REGISTRATION_DISABLED.to_string(),
                account_selection_mode: crate::applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
                unique_identity_factors: Vec::new(),
                is_active: application.is_active,
            })
            .await?
        };
        let existing_discovery = self
            .find_application_discovery(&application_record.id)
            .await?;
        if let Some(existing_discovery) = existing_discovery.as_ref()
            && existing_discovery.management_mode != application.management_mode
            && existing_discovery.last_verified_revision.is_some()
        {
            return Err(AppError::Configuration(format!(
                "bootstrap application {} changes management_mode after a verified Discovery snapshot; switch it through the admin API",
                application.application_id
            )));
        }
        let fetch_secret_ciphertext = if application.fetch_secret.trim().is_empty() {
            existing_discovery
                .as_ref()
                .map(|value| value.fetch_secret_ciphertext.clone())
                .unwrap_or_default()
        } else {
            if settings.discovery.encryption_key.trim().is_empty() {
                return Err(AppError::Configuration(
                    "discovery encryption key is required to enroll a fetch secret".to_string(),
                ));
            }
            util::encrypt_discovery_secret(
                &settings.discovery.encryption_key,
                application.fetch_secret.trim(),
            )?
        };
        let signing_public_jwks = if application.signing_public_jwks.trim().is_empty() {
            existing_discovery
                .as_ref()
                .map(|value| value.signing_public_jwks.clone())
                .unwrap_or_default()
        } else {
            application.signing_public_jwks.trim().to_string()
        };
        let website_url = application
            .website_url
            .trim()
            .trim_end_matches('/')
            .to_string();
        let reset_snapshot = existing_discovery.as_ref().is_some_and(|value| {
            value.management_mode != application.management_mode
                || value.website_url != website_url
                || value.fetch_secret_ciphertext != fetch_secret_ciphertext
                || value.signing_public_jwks != signing_public_jwks
        });
        let sync_status = if application.management_mode
            == crate::application_discovery::MANAGEMENT_MODE_WEBSITE
        {
            if signing_public_jwks.is_empty() {
                crate::application_discovery::SYNC_UNCONFIGURED.to_string()
            } else if reset_snapshot {
                crate::application_discovery::SYNC_PENDING.to_string()
            } else {
                existing_discovery
                    .as_ref()
                    .map(|value| value.sync_status.clone())
                    .unwrap_or_else(|| crate::application_discovery::SYNC_PENDING.to_string())
            }
        } else {
            crate::application_discovery::SYNC_DISABLED.to_string()
        };
        self.upsert_application_discovery(NewApplicationDiscovery {
            application_id: application_record.id.clone(),
            management_mode: application.management_mode.clone(),
            website_url,
            fetch_secret_ciphertext,
            signing_public_jwks,
            last_verified_revision: existing_discovery
                .as_ref()
                .filter(|_| !reset_snapshot)
                .and_then(|value| value.last_verified_revision),
            last_verified_version: existing_discovery
                .as_ref()
                .filter(|_| !reset_snapshot)
                .and_then(|value| value.last_verified_version.clone()),
            last_verified_digest: existing_discovery
                .as_ref()
                .filter(|_| !reset_snapshot)
                .and_then(|value| value.last_verified_digest.clone()),
            last_verified_expires_at: existing_discovery
                .as_ref()
                .filter(|_| !reset_snapshot)
                .and_then(|value| value.last_verified_expires_at),
            sync_status,
            last_fetched_at: existing_discovery
                .as_ref()
                .and_then(|value| value.last_fetched_at),
            last_success_at: existing_discovery
                .as_ref()
                .filter(|_| !reset_snapshot)
                .and_then(|value| value.last_success_at),
            last_error: existing_discovery
                .as_ref()
                .filter(|_| !reset_snapshot)
                .and_then(|value| value.last_error.clone()),
            snapshot_json: existing_discovery
                .as_ref()
                .filter(|_| !reset_snapshot)
                .and_then(|value| value.snapshot_json.clone()),
            operator_disabled: existing_discovery.is_some_and(|value| value.operator_disabled == 1),
        })
        .await?;
        Ok(application_record)
    }

    pub async fn seed(&self, settings: &Settings) -> AppResult<()> {
        let admin = &settings.bootstrap.admin;
        if admin.create_on_startup && self.find_user_by_email(&admin.email).await?.is_none() {
            let password_hash = util::hash_password(&admin.password)?;
            self.insert_user(NewUser {
                email: admin.email.clone(),
                username: admin.username.clone(),
                display_name: Some(admin.display_name.clone()),
                phone: None,
                password_hash,
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: true,
                is_active: true,
                archived_at: None,
            })
            .await?;
        }

        self.upsert_registration_settings(NewRegistrationSettings {
            allow_password_registration: settings.registration.allow_password_registration,
            require_email_verification: settings.registration.require_email_verification,
            require_phone_verification: settings.registration.require_phone_verification,
            allow_external_oidc_registration: settings
                .registration
                .allow_external_oidc_registration,
            require_invitation: settings.registration.require_invitation,
            first_user_direct_admin: settings.registration.first_user_direct_admin,
            default_user_active: settings.registration.default_user_active,
        })
        .await?;

        self.ensure_security_policy(NewSecurityPolicy {
            password_min_length: settings.security.password_min_length as i32,
            password_require_uppercase: false,
            password_require_lowercase: false,
            password_require_digit: false,
            password_require_symbol: false,
            password_reject_user_info: true,
            login_lockout_enabled: true,
            max_failed_login_attempts: 5,
            failure_window_seconds: 900,
            lockout_seconds: 900,
            trusted_ip_cidrs: Vec::new(),
            require_mfa_outside_trusted_networks: false,
            allowed_ip_cidrs: Vec::new(),
            blocked_ip_cidrs: Vec::new(),
            allowed_email_domains: Vec::new(),
            blocked_email_domains: Vec::new(),
            captcha_enabled: false,
            captcha_after_failed_attempts: 3,
            captcha_ttl_seconds: 300,
        })
        .await?;

        self.ensure_runtime_settings(NewRuntimeSettings {
            public_base_url: settings.server.public_base_url.clone(),
            issuer: settings.oidc.issuer.clone(),
            trust_proxy_headers: settings.server.trust_proxy_headers,
        })
        .await?;

        self.ensure_login_settings(NewLoginSettings {
            brand_logo_url: String::new(),
            email_domains: Vec::new(),
            quick_links: vec![default_openai_quick_link()],
        })
        .await?;

        self.ensure_system_roles().await?;

        let system_organization = self.system_organization().await?;
        for user in self.list_users(UserListScope::All).await? {
            if user.is_admin == 1 && user.is_active == 1 && user.archived_at.is_none() {
                self.upsert_organization_member(
                    &system_organization.id,
                    &user.id,
                    crate::organizations::ROLE_OWNER,
                )
                .await?;
            }
        }

        for provider in &settings.external_oidc_providers {
            if self
                .find_external_oidc_provider(&provider.slug)
                .await?
                .is_none()
            {
                self.insert_external_oidc_provider(NewExternalOidcProvider {
                    slug: provider.slug.clone(),
                    display_name: provider.display_name.clone(),
                    organization_id: provider
                        .organization_id
                        .as_ref()
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    issuer: provider.issuer.clone(),
                    client_id: provider.client_id.clone(),
                    client_secret: provider.client_secret.clone(),
                    authorization_endpoint: provider.authorization_endpoint.clone(),
                    token_endpoint: provider.token_endpoint.clone(),
                    userinfo_endpoint: provider.userinfo_endpoint.clone(),
                    redirect_path: provider.redirect_path.clone(),
                    scopes: provider.scopes.clone(),
                    email_domains: crate::security_policy::normalize_email_domain_rules(
                        provider.email_domains.clone(),
                    )?,
                    is_active: provider.enabled,
                    allow_login: provider.allow_login,
                    allow_registration: provider.allow_registration,
                })
                .await?;
            }
        }

        for application in &settings.bootstrap.applications {
            self.ensure_bootstrap_application(application, &system_organization.id, settings)
                .await?;
        }

        for client in &settings.bootstrap.clients {
            self.ensure_bootstrap_client(client, &system_organization.id)
                .await?;
        }
        // Bootstrap clients are inserted after `migrate` has run. Give them
        // an application aggregate in the same startup rather than waiting
        // for a restart.
        self.migrate_tenant_application_model().await?;
        Ok(())
    }
}
