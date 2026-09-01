//! Persistence for application website discovery and reconciliation.

use super::applications::cached_profile_role_id;
use super::{
    APPLICATION_DISCOVERY_LEASE_TTL_SECONDS, AppError, AppResult,
    ApplicationAuthorizationProfileRecord, ApplicationClientBindingRecord,
    ApplicationDiscoveryIdempotencyClaim, ApplicationDiscoveryIdempotencyRecord,
    ApplicationDiscoveryJoinRecord, ApplicationDiscoveryLease, ApplicationDiscoveryMigrationRow,
    ApplicationDiscoveryRecord, ApplicationRecord, ClientRecord, CountRow, DatabaseKind, Db,
    NewApplicationDiscovery, WebsiteDiscoveryConnection, WebsiteDiscoveryProfileInput,
    bind_text_list, blocking, ph, placeholders, select_application_authorization_profile_sql,
    select_application_client_binding_sql, select_application_discovery_sql, select_client_sql,
};
use crate::application_discovery_contract::{MANAGEMENT_MODE_WEBSITE, SYNC_SYNCED};
use crate::util;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use diesel::{Connection, OptionalExtension, RunQueryDsl};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone)]
pub struct ApplicationDiscoveryManifest {
    pub revision: i64,
    pub version: String,
    pub digest: String,
    pub expires_at: i64,
    pub revoke_removed_clients: bool,
    pub clients: Vec<super::NewClient>,
    pub client_protocols: BTreeMap<String, String>,
    pub protocols: serde_json::Value,
    pub login_adapters: serde_json::Value,
    pub directory_sync: serde_json::Value,
    pub authorization: serde_json::Value,
    pub authorization_mappings: ApplicationDiscoveryAuthorizationMappings,
    pub profiles: BTreeMap<String, ApplicationDiscoveryProfile>,
    pub redacted_payload: serde_json::Value,
}

#[derive(Debug, Clone, Default)]
pub struct ApplicationDiscoveryAuthorizationMappings {
    pub group_mappings: Vec<ApplicationDiscoveryGroupMapping>,
    pub organization_role_mappings: Vec<ApplicationDiscoveryOrganizationRoleMapping>,
}

#[derive(Debug, Clone)]
pub struct ApplicationDiscoveryGroupMapping {
    pub group: String,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct ApplicationDiscoveryOrganizationRoleMapping {
    pub organization_role: String,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct ApplicationDiscoveryProfile {
    pub permissions: Vec<ApplicationDiscoveryPermission>,
    pub roles: Vec<ApplicationDiscoveryRole>,
}

#[derive(Debug, Clone)]
pub struct ApplicationDiscoveryPermission {
    pub key: String,
    pub label: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ApplicationDiscoveryRole {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub is_default: bool,
}

impl Db {
    pub(super) async fn list_applications_without_discovery(
        &self,
    ) -> AppResult<Vec<ApplicationDiscoveryMigrationRow>> {
        with_conn!(self, |conn, _kind| {
            sql_query(
                "SELECT applications.id AS application_id,
                        application_modules.config_json AS protocols_config_json
                 FROM applications
                 LEFT JOIN application_discovery
                   ON application_discovery.application_id = applications.id
                 LEFT JOIN application_modules
                   ON application_modules.application_id = applications.id
                  AND application_modules.module_key = 'protocols'
                 WHERE application_discovery.application_id IS NULL
                 ORDER BY applications.id ASC",
            )
            .load::<ApplicationDiscoveryMigrationRow>(&mut conn)
            .map_err(AppError::from)
        })
    }

    pub async fn find_application_discovery(
        &self,
        application_id: &str,
    ) -> AppResult<Option<ApplicationDiscoveryRecord>> {
        let application_id = application_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE application_id = {}",
                select_application_discovery_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(application_id)
                .get_result::<ApplicationDiscoveryRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_website_managed_discoveries(
        &self,
    ) -> AppResult<Vec<(ApplicationRecord, ApplicationDiscoveryRecord)>> {
        Ok(self
            .list_application_discoveries()
            .await?
            .into_iter()
            .filter(|(_, discovery)| discovery.management_mode == MANAGEMENT_MODE_WEBSITE)
            .collect())
    }

    pub async fn list_application_discoveries(
        &self,
    ) -> AppResult<Vec<(ApplicationRecord, ApplicationDiscoveryRecord)>> {
        let rows = with_conn!(self, |conn, _kind| {
            // The inner join intentionally preserves the old behavior for an
            // orphan discovery row: it is ignored rather than handed to the
            // reconciler as an application that no longer exists.  Unlike the
            // former per-row lookups, this is one query for the whole set.
            let sql = "SELECT applications.id AS id,
                              applications.organization_id AS organization_id,
                              applications.slug AS slug,
                              applications.name AS name,
                              applications.description AS description,
                              applications.access_mode AS access_mode,
                              applications.registration_mode AS registration_mode,
                              applications.account_selection_mode AS account_selection_mode,
                              COALESCE(applications.unique_identity_factors, '[]') AS unique_identity_factors,
                              applications.is_active AS is_active,
                              applications.created_at AS created_at,
                              applications.updated_at AS updated_at,
                              application_discovery.management_mode AS discovery_management_mode,
                              application_discovery.website_url AS discovery_website_url,
                              application_discovery.fetch_secret_ciphertext AS fetch_secret_ciphertext,
                              application_discovery.signing_public_jwks AS signing_public_jwks,
                              application_discovery.last_verified_revision AS last_verified_revision,
                              application_discovery.last_verified_version AS last_verified_version,
                              application_discovery.last_verified_digest AS last_verified_digest,
                              application_discovery.last_verified_expires_at AS last_verified_expires_at,
                              application_discovery.sync_status AS discovery_sync_status,
                              application_discovery.last_fetched_at AS last_fetched_at,
                              application_discovery.last_success_at AS last_success_at,
                              application_discovery.last_error AS discovery_last_error,
                              application_discovery.snapshot_json AS snapshot_json,
                              application_discovery.operator_disabled AS operator_disabled,
                              application_discovery.created_at AS discovery_created_at,
                              application_discovery.updated_at AS discovery_updated_at,
                              application_discovery.lease_owner AS discovery_lease_owner,
                              application_discovery.lease_expires_at AS discovery_lease_expires_at,
                              application_discovery.lease_generation AS discovery_lease_generation
                       FROM application_discovery
                       INNER JOIN applications
                         ON applications.id = application_discovery.application_id
                       ORDER BY applications.id ASC";
            sql_query(sql)
                .load::<ApplicationDiscoveryJoinRecord>(&mut conn)
                .map_err(AppError::from)
        })?;
        Ok(rows
            .into_iter()
            .map(|row| {
                let application_id = row.id.clone();
                (
                    ApplicationRecord {
                        id: row.id,
                        organization_id: row.organization_id,
                        slug: row.slug,
                        name: row.name,
                        description: row.description,
                        access_mode: row.access_mode,
                        registration_mode: row.registration_mode,
                        account_selection_mode: row.account_selection_mode,
                        unique_identity_factors: row.unique_identity_factors,
                        is_active: row.is_active,
                        created_at: row.created_at,
                        updated_at: row.updated_at,
                    },
                    ApplicationDiscoveryRecord {
                        application_id,
                        management_mode: row.discovery_management_mode,
                        website_url: row.discovery_website_url,
                        fetch_secret_ciphertext: row.fetch_secret_ciphertext,
                        signing_public_jwks: row.signing_public_jwks,
                        last_verified_revision: row.last_verified_revision,
                        last_verified_version: row.last_verified_version,
                        last_verified_digest: row.last_verified_digest,
                        last_verified_expires_at: row.last_verified_expires_at,
                        sync_status: row.discovery_sync_status,
                        last_fetched_at: row.last_fetched_at,
                        last_success_at: row.last_success_at,
                        last_error: row.discovery_last_error,
                        snapshot_json: row.snapshot_json,
                        operator_disabled: row.operator_disabled,
                        created_at: row.discovery_created_at,
                        updated_at: row.discovery_updated_at,
                        lease_owner: row.discovery_lease_owner,
                        lease_expires_at: row.discovery_lease_expires_at,
                        lease_generation: row.discovery_lease_generation,
                    },
                )
            })
            .collect())
    }

    pub async fn upsert_application_discovery(
        &self,
        discovery: NewApplicationDiscovery,
    ) -> AppResult<ApplicationDiscoveryRecord> {
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let existing = format!(
                "SELECT COUNT(*) AS count FROM application_discovery WHERE application_id = {}",
                ph(kind, 1)
            );
            let exists = sql_query(existing)
                .bind::<Text, _>(&discovery.application_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                > 0;
            if exists {
                let sql = format!(
                    "UPDATE application_discovery SET management_mode = {}, website_url = {}, fetch_secret_ciphertext = {}, signing_public_jwks = {}, last_verified_revision = {}, last_verified_version = {}, last_verified_digest = {}, last_verified_expires_at = {}, sync_status = {}, last_fetched_at = {}, last_success_at = {}, last_error = {}, snapshot_json = {}, operator_disabled = {}, updated_at = {} WHERE application_id = {}",
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
                    ph(kind, 16)
                );
                sql_query(sql)
                    .bind::<Text, _>(&discovery.management_mode)
                    .bind::<Text, _>(&discovery.website_url)
                    .bind::<Text, _>(&discovery.fetch_secret_ciphertext)
                    .bind::<Text, _>(&discovery.signing_public_jwks)
                    .bind::<Nullable<BigInt>, _>(discovery.last_verified_revision)
                    .bind::<Nullable<Text>, _>(&discovery.last_verified_version)
                    .bind::<Nullable<Text>, _>(&discovery.last_verified_digest)
                    .bind::<Nullable<BigInt>, _>(discovery.last_verified_expires_at)
                    .bind::<Text, _>(&discovery.sync_status)
                    .bind::<Nullable<BigInt>, _>(discovery.last_fetched_at)
                    .bind::<Nullable<BigInt>, _>(discovery.last_success_at)
                    .bind::<Nullable<Text>, _>(&discovery.last_error)
                    .bind::<Nullable<Text>, _>(&discovery.snapshot_json)
                    .bind::<Integer, _>(i32::from(discovery.operator_disabled))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&discovery.application_id)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            } else {
                let sql = format!(
                    "INSERT INTO application_discovery (application_id, management_mode, website_url, fetch_secret_ciphertext, signing_public_jwks, last_verified_revision, last_verified_version, last_verified_digest, last_verified_expires_at, sync_status, last_fetched_at, last_success_at, last_error, snapshot_json, operator_disabled, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
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
                    .bind::<Text, _>(&discovery.application_id)
                    .bind::<Text, _>(&discovery.management_mode)
                    .bind::<Text, _>(&discovery.website_url)
                    .bind::<Text, _>(&discovery.fetch_secret_ciphertext)
                    .bind::<Text, _>(&discovery.signing_public_jwks)
                    .bind::<Nullable<BigInt>, _>(discovery.last_verified_revision)
                    .bind::<Nullable<Text>, _>(&discovery.last_verified_version)
                    .bind::<Nullable<Text>, _>(&discovery.last_verified_digest)
                    .bind::<Nullable<BigInt>, _>(discovery.last_verified_expires_at)
                    .bind::<Text, _>(&discovery.sync_status)
                    .bind::<Nullable<BigInt>, _>(discovery.last_fetched_at)
                    .bind::<Nullable<BigInt>, _>(discovery.last_success_at)
                    .bind::<Nullable<Text>, _>(&discovery.last_error)
                    .bind::<Nullable<Text>, _>(&discovery.snapshot_json)
                    .bind::<Integer, _>(i32::from(discovery.operator_disabled))
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(&mut conn)
                    .map_err(AppError::from)?;
            }
            let sql = format!(
                "{} WHERE application_id = {}",
                select_application_discovery_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&discovery.application_id)
                .get_result::<ApplicationDiscoveryRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Claims a durable discovery lease. `None` means another process still
    /// owns a non-expired lease; a missing discovery row is reported as
    /// `NotFound` so callers cannot silently skip an application.
    pub async fn claim_application_discovery_lease(
        &self,
        application_id: &str,
        owner_token: &str,
    ) -> AppResult<Option<ApplicationDiscoveryLease>> {
        if owner_token.trim().is_empty() {
            return Err(AppError::BadRequest(
                "application discovery lease owner is required".to_string(),
            ));
        }
        let application_id = application_id.to_string();
        let owner_token = owner_token.to_string();
        let now = util::now_ts();
        let lease_expires_at = now + APPLICATION_DISCOVERY_LEASE_TTL_SECONDS;
        with_conn!(self, |conn, kind| {
            let exists_sql = format!(
                "SELECT COUNT(*) AS count FROM application_discovery WHERE application_id = {}",
                ph(kind, 1)
            );
            if sql_query(exists_sql)
                .bind::<Text, _>(&application_id)
                .get_result::<CountRow>(&mut conn)
                .map_err(AppError::from)?
                .count
                == 0
            {
                return Err(AppError::NotFound);
            }
            let claim_sql = format!(
                "UPDATE application_discovery SET lease_owner = {}, lease_expires_at = {}, lease_generation = COALESCE(lease_generation, 0) + 1, updated_at = {} WHERE application_id = {} AND (lease_owner IS NULL OR lease_expires_at IS NULL OR lease_expires_at <= {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
            );
            let claimed = sql_query(claim_sql)
                .bind::<Nullable<Text>, _>(Some(owner_token.clone()))
                .bind::<Nullable<BigInt>, _>(Some(lease_expires_at))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&application_id)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if claimed != 1 {
                return Ok(None);
            }

            #[derive(Debug, diesel::QueryableByName)]
            struct LeaseRow {
                #[diesel(sql_type = Nullable<Text>)]
                lease_owner: Option<String>,
                #[diesel(sql_type = Nullable<BigInt>)]
                lease_expires_at: Option<i64>,
                #[diesel(sql_type = BigInt)]
                lease_generation: i64,
            }
            let select_sql = format!(
                "SELECT lease_owner, lease_expires_at, lease_generation FROM application_discovery WHERE application_id = {}",
                ph(kind, 1)
            );
            let lease = sql_query(select_sql)
                .bind::<Text, _>(&application_id)
                .get_result::<LeaseRow>(&mut conn)
                .map_err(AppError::from)?;
            Ok(Some(ApplicationDiscoveryLease {
                application_id,
                owner_token: lease.lease_owner.unwrap_or(owner_token),
                lease_expires_at: lease.lease_expires_at.unwrap_or(lease_expires_at),
                lease_generation: lease.lease_generation,
            }))
        })
    }

    pub async fn renew_application_discovery_lease(
        &self,
        application_id: &str,
        owner_token: &str,
        lease_generation: i64,
    ) -> AppResult<bool> {
        let application_id = application_id.to_string();
        let owner_token = owner_token.to_string();
        let now = util::now_ts();
        let lease_expires_at = now + APPLICATION_DISCOVERY_LEASE_TTL_SECONDS;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_discovery SET lease_expires_at = {}, updated_at = {} WHERE application_id = {} AND lease_owner = {} AND lease_generation = {} AND lease_expires_at IS NOT NULL AND lease_expires_at >= {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
            );
            sql_query(sql)
                .bind::<Nullable<BigInt>, _>(Some(lease_expires_at))
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(owner_token)
                .bind::<BigInt, _>(lease_generation)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|affected| affected == 1)
                .map_err(AppError::from)
        })
    }

    pub async fn release_application_discovery_lease(
        &self,
        application_id: &str,
        owner_token: &str,
        lease_generation: i64,
    ) -> AppResult<bool> {
        let application_id = application_id.to_string();
        let owner_token = owner_token.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_discovery SET lease_owner = {}, lease_expires_at = {}, updated_at = {} WHERE application_id = {} AND lease_owner = {} AND lease_generation = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
            );
            sql_query(sql)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(util::now_ts())
                .bind::<Text, _>(application_id)
                .bind::<Text, _>(owner_token)
                .bind::<BigInt, _>(lease_generation)
                .execute(&mut conn)
                .map(|affected| affected == 1)
                .map_err(AppError::from)
        })
    }

    /// Publishes only a result that still owns the durable lease.  The
    /// existing contract reconciler is intentionally kept as the
    /// compatibility/non-leased entry point; the discovery module can switch
    /// to this method without changing its manifest model.
    pub async fn commit_application_discovery_if_owner(
        &self,
        application_id: &str,
        owner_token: &str,
        lease_generation: i64,
        manifest: ApplicationDiscoveryManifest,
    ) -> AppResult<ApplicationDiscoveryRecord> {
        self.apply_application_contract_with_lease(
            application_id,
            manifest,
            Some((owner_token.to_string(), lease_generation)),
        )
        .await
    }

    pub async fn mark_application_discovery_sync_error_if_owner(
        &self,
        application_id: &str,
        owner_token: &str,
        lease_generation: i64,
        sync_status: &str,
        last_error: Option<String>,
    ) -> AppResult<Option<ApplicationDiscoveryRecord>> {
        let application_id = application_id.to_string();
        let owner_token = owner_token.to_string();
        let sync_status = sync_status.to_string();
        let last_error = last_error.map(|value| value.chars().take(512).collect::<String>());
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_discovery SET sync_status = {}, last_fetched_at = {}, last_error = {}, updated_at = {} WHERE application_id = {} AND lease_owner = {} AND lease_generation = {} AND lease_expires_at IS NOT NULL AND lease_expires_at >= {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(&sync_status)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<Text>, _>(&last_error)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&application_id)
                .bind::<Text, _>(&owner_token)
                .bind::<BigInt, _>(lease_generation)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected != 1 {
                return Ok(None);
            }
            let select_sql = format!(
                "{} WHERE application_id = {}",
                select_application_discovery_sql(),
                ph(kind, 1)
            );
            sql_query(select_sql)
                .bind::<Text, _>(&application_id)
                .get_result::<ApplicationDiscoveryRecord>(&mut conn)
                .map(Some)
                .map_err(AppError::from)
        })
    }

    /// Claims one administrative auto-registration request. The claim is
    /// durable so retries and concurrent Signet processes share the same
    /// result instead of repeating the website challenge and provisioning
    /// sequence. Completed keys are retained for one day; an abandoned
    /// in-progress claim may be taken over after a bounded lease.
    pub async fn claim_application_discovery_idempotency(
        &self,
        organization_id: &str,
        idempotency_key: &str,
        request_hash: &str,
        origin: &str,
    ) -> AppResult<ApplicationDiscoveryIdempotencyClaim> {
        const COMPLETED_RETENTION_SECONDS: i64 = 24 * 60 * 60;
        const CLAIM_LEASE_SECONDS: i64 = 15 * 60;
        let organization_id = organization_id.to_string();
        let idempotency_key = idempotency_key.to_string();
        let request_hash = request_hash.to_string();
        let origin = origin.to_string();
        let now = util::now_ts();
        let claim_token = util::random_token(24);
        with_conn!(self, |conn, kind| {
            let cleanup_sql = format!(
                "DELETE FROM application_discovery_idempotency WHERE status <> {} AND updated_at <= {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(cleanup_sql)
                .bind::<Text, _>("in_progress")
                .bind::<BigInt, _>(now.saturating_sub(COMPLETED_RETENTION_SECONDS))
                .execute(&mut conn)
                .map_err(AppError::from)?;

            let insert_sql = match kind {
                DatabaseKind::Mysql => format!(
                    "INSERT IGNORE INTO application_discovery_idempotency (organization_id, idempotency_key, request_hash, origin, application_id, claim_token, status, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                ),
                _ => format!(
                    "INSERT INTO application_discovery_idempotency (organization_id, idempotency_key, request_hash, origin, application_id, claim_token, status, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}) ON CONFLICT (organization_id, idempotency_key) DO NOTHING",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                ),
            };
            let inserted = sql_query(insert_sql)
                .bind::<Text, _>(&organization_id)
                .bind::<Text, _>(&idempotency_key)
                .bind::<Text, _>(&request_hash)
                .bind::<Text, _>(&origin)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Text, _>(&claim_token)
                .bind::<Text, _>("in_progress")
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if inserted == 1 {
                return Ok(ApplicationDiscoveryIdempotencyClaim::Claimed { claim_token });
            }

            let select_sql = format!(
                "SELECT request_hash, origin, application_id, status, updated_at FROM application_discovery_idempotency WHERE organization_id = {} AND idempotency_key = {}",
                ph(kind, 1),
                ph(kind, 2)
            );
            let record = sql_query(select_sql)
                .bind::<Text, _>(&organization_id)
                .bind::<Text, _>(&idempotency_key)
                .get_result::<ApplicationDiscoveryIdempotencyRecord>(&mut conn)
                .map_err(AppError::from)?;
            if record.request_hash != request_hash || record.origin != origin {
                return Err(AppError::BadRequest(
                    "idempotency_key was already used for another discovery request".to_string(),
                ));
            }
            if record.status == "completed"
                && let Some(application_id) = record.application_id
            {
                return Ok(ApplicationDiscoveryIdempotencyClaim::Completed { application_id });
            }
            if record.status == "in_progress"
                && record.updated_at > now.saturating_sub(CLAIM_LEASE_SECONDS)
            {
                return Ok(ApplicationDiscoveryIdempotencyClaim::InProgress);
            }

            let update_sql = format!(
                "UPDATE application_discovery_idempotency SET application_id = {}, claim_token = {}, status = {}, updated_at = {} WHERE organization_id = {} AND idempotency_key = {} AND (status <> {} OR updated_at <= {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
            );
            let affected = sql_query(update_sql)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Text, _>(&claim_token)
                .bind::<Text, _>("in_progress")
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&organization_id)
                .bind::<Text, _>(&idempotency_key)
                .bind::<Text, _>("in_progress")
                .bind::<BigInt, _>(now.saturating_sub(CLAIM_LEASE_SECONDS))
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 1 {
                Ok(ApplicationDiscoveryIdempotencyClaim::Claimed { claim_token })
            } else {
                Ok(ApplicationDiscoveryIdempotencyClaim::InProgress)
            }
        })
    }

    pub async fn complete_application_discovery_idempotency(
        &self,
        organization_id: &str,
        idempotency_key: &str,
        claim_token: &str,
        application_id: &str,
    ) -> AppResult<()> {
        let organization_id = organization_id.to_string();
        let idempotency_key = idempotency_key.to_string();
        let claim_token = claim_token.to_string();
        let application_id = application_id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_discovery_idempotency SET application_id = {}, status = {}, updated_at = {} WHERE organization_id = {} AND idempotency_key = {} AND claim_token = {} AND status = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(&application_id)
                .bind::<Text, _>("completed")
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&organization_id)
                .bind::<Text, _>(&idempotency_key)
                .bind::<Text, _>(&claim_token)
                .bind::<Text, _>("in_progress")
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected != 1 {
                return Err(AppError::Database(
                    "application discovery idempotency claim is no longer active".to_string(),
                ));
            }
            Ok(())
        })
    }

    pub async fn fail_application_discovery_idempotency(
        &self,
        organization_id: &str,
        idempotency_key: &str,
        claim_token: &str,
    ) -> AppResult<()> {
        let organization_id = organization_id.to_string();
        let idempotency_key = idempotency_key.to_string();
        let claim_token = claim_token.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_discovery_idempotency SET application_id = {}, status = {}, updated_at = {} WHERE organization_id = {} AND idempotency_key = {} AND claim_token = {} AND status = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
            );
            sql_query(sql)
                .bind::<Nullable<Text>, _>(None::<String>)
                .bind::<Text, _>("failed")
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&organization_id)
                .bind::<Text, _>(&idempotency_key)
                .bind::<Text, _>(&claim_token)
                .bind::<Text, _>("in_progress")
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
    }

    /// Records a failed discovery attempt without touching the last verified
    /// snapshot.  Runtime authorization deliberately reads the verified
    /// revision/snapshot fields, so a transient website outage only changes
    /// operator-visible status and diagnostics.
    pub async fn mark_application_discovery_sync_error(
        &self,
        application_id: &str,
        sync_status: &str,
        last_error: Option<String>,
    ) -> AppResult<ApplicationDiscoveryRecord> {
        let application_id = application_id.to_string();
        let sync_status = sync_status.to_string();
        let last_error = last_error.map(|value| value.chars().take(512).collect::<String>());
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "UPDATE application_discovery SET sync_status = {}, last_fetched_at = {}, last_error = {}, updated_at = {} WHERE application_id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5)
            );
            let affected = sql_query(sql)
                .bind::<Text, _>(&sync_status)
                .bind::<BigInt, _>(now)
                .bind::<Nullable<Text>, _>(&last_error)
                .bind::<BigInt, _>(now)
                .bind::<Text, _>(&application_id)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            if affected == 0 {
                return Err(AppError::NotFound);
            }
            let sql = format!(
                "{} WHERE application_id = {}",
                select_application_discovery_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(&application_id)
                .get_result::<ApplicationDiscoveryRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    /// Applies one already verified website snapshot atomically. Network
    /// fetching and signature validation happen before this method; this
    /// transaction only reconciles the normalized result and the snapshot
    /// metadata. Client secrets are already hashed by the verifier.
    pub async fn apply_application_contract<M>(
        &self,
        application_id: &str,
        manifest: M,
    ) -> AppResult<ApplicationDiscoveryRecord>
    where
        M: Into<ApplicationDiscoveryManifest>,
    {
        self.apply_application_contract_with_lease(application_id, manifest.into(), None)
            .await
    }
    async fn apply_application_contract_with_lease(
        &self,
        application_id: &str,
        manifest: ApplicationDiscoveryManifest,
        lease: Option<(String, i64)>,
    ) -> AppResult<ApplicationDiscoveryRecord> {
        let application_id = application_id.to_string();
        let snapshot_json = util::to_json(&manifest.redacted_payload)?;
        let manifest = manifest.clone();
        let application_organization_id = self
            .find_application_by_id(&application_id)
            .await?
            .ok_or(AppError::NotFound)?
            .organization_id;
        with_conn!(self, |conn, kind| {
            conn.transaction::<ApplicationDiscoveryRecord, AppError, _>(|conn| {
                // Discovery role/profile reconciliation and manual role
                // writes share the application row as their serialization
                // point. This prevents two concurrent writers from both
                // materializing a default role in the same profile.
                let lock_sql = format!(
                    "UPDATE applications SET updated_at = updated_at WHERE id = {}",
                    ph(kind, 1)
                );
                if sql_query(lock_sql)
                    .bind::<Text, _>(&application_id)
                    .execute(conn)
                    .map_err(AppError::from)?
                    == 0
                {
                    return Err(AppError::NotFound);
                }
                let current_sql = format!(
                    "{} WHERE application_id = {}",
                    select_application_discovery_sql(),
                    ph(kind, 1)
                );
                let current = sql_query(current_sql)
                    .bind::<Text, _>(&application_id)
                    .get_result::<ApplicationDiscoveryRecord>(conn)
                    .map_err(AppError::from)?;
                if let Some((owner_token, lease_generation)) = lease.as_ref()
                    && (current.lease_owner.as_deref() != Some(owner_token.as_str())
                        || current.lease_generation != *lease_generation
                        || current.lease_expires_at.is_none_or(|expires_at| expires_at <= util::now_ts()))
                {
                    return Err(AppError::BadRequest(
                        "application discovery lease conflict".to_string(),
                    ));
                }
                if current.management_mode != MANAGEMENT_MODE_WEBSITE {
                    return Err(AppError::BadRequest(
                        "application is not website-managed".to_string(),
                    ));
                }
                if let Some(previous_revision) = current.last_verified_revision {
                    if manifest.revision < previous_revision {
                        return Err(AppError::BadRequest(
                            "application discovery revision moved backwards".to_string(),
                        ));
                    }
                    if manifest.revision == previous_revision {
                    if current.last_verified_digest.as_deref() == Some(manifest.digest.as_str()) {
                            // A verified website manifest is a short-lived
                            // JWS. Refresh its lease and clear a transient
                            // sync error even when the revision/content digest
                            // is unchanged; otherwise the persisted expiry
                            // would age out while periodic verification keeps
                            // succeeding.
                            let now = util::now_ts();
                            let refresh_sql = format!(
                                "UPDATE application_discovery SET last_verified_expires_at = {}, sync_status = {}, last_fetched_at = {}, last_success_at = {}, last_error = {}, snapshot_json = {}, updated_at = {} WHERE application_id = {}",
                                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8)
                            );
                            sql_query(refresh_sql)
                                .bind::<BigInt, _>(manifest.expires_at)
                                .bind::<Text, _>(SYNC_SYNCED)
                                .bind::<BigInt, _>(now)
                                .bind::<BigInt, _>(now)
                                .bind::<Nullable<Text>, _>(None::<String>)
                                .bind::<Nullable<Text>, _>(Some(snapshot_json.clone()))
                                .bind::<BigInt, _>(now)
                                .bind::<Text, _>(&application_id)
                                .execute(conn)
                                .map_err(AppError::from)?;
                            let result_sql = format!(
                                "{} WHERE application_id = {}",
                                select_application_discovery_sql(),
                                ph(kind, 1)
                            );
                            return sql_query(result_sql)
                                .bind::<Text, _>(&application_id)
                                .get_result::<ApplicationDiscoveryRecord>(conn)
                                .map_err(AppError::from);
                        }
                        return Err(AppError::BadRequest(
                            "application discovery revision was reused with different content".to_string(),
                        ));
                    }
                }

                let client_ids = manifest
                    .clients
                    .iter()
                    .map(|client| client.client_id.clone())
                    .collect::<HashSet<_>>();
                let mut client_db_ids = BTreeMap::new();
                let mut profile_db_ids = BTreeMap::new();
                for client in &manifest.clients {
                    let protocol = manifest
                        .client_protocols
                        .get(&client.client_id)
                        .ok_or_else(|| {
                            AppError::BadRequest(
                                "application contract is missing a client protocol".to_string(),
                            )
                        })?;
                    let existing_sql = format!(
                        "{} WHERE client_id = {}",
                        select_client_sql(),
                        ph(kind, 1)
                    );
                    let existing = sql_query(existing_sql)
                        .bind::<Text, _>(&client.client_id)
                        .get_result::<ClientRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?;
                    let client_db_id = if let Some(existing) = existing {
                        let owner_sql = format!(
                            "SELECT COUNT(*) AS count FROM application_client_bindings WHERE client_db_id = {} AND application_id <> {}",
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        let owned_elsewhere = sql_query(owner_sql)
                            .bind::<Text, _>(&existing.id)
                            .bind::<Text, _>(&application_id)
                            .get_result::<CountRow>(conn)
                            .map_err(AppError::from)?
                            .count
                            > 0;
                        if owned_elsewhere {
                            return Err(AppError::BadRequest(
                                "website-managed client belongs to another application".to_string(),
                            ));
                        }
                        if existing.organization_id.as_deref()
                            != Some(application_organization_id.as_str())
                        {
                            return Err(AppError::BadRequest(
                                "website-managed client belongs to another organization"
                                    .to_string(),
                            ));
                        }
                        conn.website_discovery_update_client(kind, &existing.id, client)?;
                        existing.id
                    } else {
                        conn.website_discovery_insert_client(kind, client)?
                    };
                    client_db_ids.insert(client.client_id.clone(), client_db_id.clone());
                    let link_count_sql = format!(
                        "SELECT COUNT(*) AS count FROM application_client_bindings WHERE application_id = {} AND client_db_id = {}",
                        ph(kind, 1), ph(kind, 2)
                    );
                    let linked = sql_query(link_count_sql)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(&client_db_id)
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count
                        > 0;
                    if !linked {
                        let link_sql = format!(
                            "INSERT INTO application_client_bindings (application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8)
                        );
                        sql_query(link_sql)
                            .bind::<Text, _>(&application_id)
                            .bind::<Text, _>(&client_db_id)
                            .bind::<Text, _>(protocol)
                            .bind::<Text, _>("default")
                            .bind::<Text, _>(&format!("auth-domain:{application_id}"))
                            .bind::<Integer, _>(1)
                            .bind::<BigInt, _>(util::now_ts())
                            .bind::<BigInt, _>(util::now_ts())
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                }
                let existing_clients_sql = format!(
                    "SELECT application_client_bindings.client_db_id, clients.client_id FROM application_client_bindings INNER JOIN clients ON clients.id = application_client_bindings.client_db_id WHERE application_client_bindings.application_id = {} AND application_client_bindings.is_active = 1",
                    ph(kind, 1)
                );
                #[derive(diesel::QueryableByName)]
                struct ClientBindingIdRow {
                    #[diesel(sql_type = Text)]
                    client_db_id: String,
                    #[diesel(sql_type = Text)]
                    client_id: String,
                }
                if manifest.revoke_removed_clients {
                    let removed_client_db_ids = sql_query(existing_clients_sql)
                        .bind::<Text, _>(&application_id)
                        .load::<ClientBindingIdRow>(conn)
                        .map_err(AppError::from)?
                        .into_iter()
                        .filter(|row| !client_ids.contains(&row.client_id))
                        .map(|row| row.client_db_id)
                        .collect::<Vec<_>>();
                    if !removed_client_db_ids.is_empty() {
                        let now = util::now_ts();
                        if matches!(kind, DatabaseKind::Postgres) {
                            let placeholders = placeholders(kind, 1, removed_client_db_ids.len());
                            let deactivate_sql = format!(
                                "UPDATE clients SET is_active = {}, updated_at = {} WHERE id IN ({placeholders})",
                                ph(kind, removed_client_db_ids.len() + 1),
                                ph(kind, removed_client_db_ids.len() + 2)
                            );
                            bind_text_list(conn, sql_query(deactivate_sql), &removed_client_db_ids)
                                .bind::<Integer, _>(0)
                                .bind::<BigInt, _>(now)
                                .execute(conn)
                                .map_err(AppError::from)?;
                        } else {
                            let placeholders = placeholders(kind, 1, removed_client_db_ids.len());
                            let deactivate_sql = format!(
                                "UPDATE clients SET is_active = ?, updated_at = ? WHERE id IN ({placeholders})"
                            );
                            let mut query = sql_query(deactivate_sql).into_boxed::<_>();
                            query = query
                                .bind::<Integer, _>(0)
                                .bind::<BigInt, _>(now);
                            for client_db_id in &removed_client_db_ids {
                                query = query.bind::<Text, _>(client_db_id.clone());
                            }
                            query.execute(conn).map_err(AppError::from)?;
                        }

                        let placeholders = placeholders(kind, 2, removed_client_db_ids.len());
                        let unlink_sql = format!(
                            "DELETE FROM application_client_bindings WHERE application_id = {} AND client_db_id IN ({placeholders})",
                            ph(kind, 1)
                        );
                        let mut query = sql_query(unlink_sql)
                            .into_boxed::<_>()
                            .bind::<Text, _>(&application_id);
                        for client_db_id in &removed_client_db_ids {
                            query = query.bind::<Text, _>(client_db_id.clone());
                        }
                        query.execute(conn).map_err(AppError::from)?;
                    }
                }

                conn.website_discovery_upsert_module(
                    kind,
                    &application_id,
                    "protocols",
                    &manifest.protocols,
                )?;
                conn.website_discovery_upsert_module(
                    kind,
                    &application_id,
                    "login_adapters",
                    &manifest.login_adapters,
                )?;
                conn.website_discovery_upsert_module(
                    kind,
                    &application_id,
                    "directory_sync",
                    &manifest.directory_sync,
                )?;
                conn.website_discovery_upsert_module(
                    kind,
                    &application_id,
                    "authorization",
                    &manifest.authorization,
                )?;

                // The website document is a complete snapshot. Remove
                // profile records that disappeared from the new revision,
                // together with their assignments and role/permission rows;
                // otherwise a later reuse of the same client_id could revive
                // stale website entitlements.
                let existing_profiles_sql = format!(
                    "{} WHERE application_id = {}",
                    select_application_authorization_profile_sql(),
                    ph(kind, 1)
                );
                let existing_profiles = sql_query(existing_profiles_sql)
                    .bind::<Text, _>(&application_id)
                    .load::<ApplicationAuthorizationProfileRecord>(conn)
                    .map_err(AppError::from)?;
                for existing_profile in existing_profiles {
                    if manifest.profiles.contains_key(&existing_profile.profile_key) {
                        continue;
                    }
                    for table in [
                        "application_profile_permission_overrides",
                        "application_profile_user_roles",
                        "application_profile_group_roles",
                        "application_profile_organization_roles",
                        "application_permission_definitions",
                        "application_profile_roles",
                    ] {
                        let delete_sql = format!(
                            "DELETE FROM {table} WHERE profile_id = {}",
                            ph(kind, 1)
                        );
                        sql_query(delete_sql)
                            .bind::<Text, _>(&existing_profile.id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                    let delete_profile_sql = format!(
                        "DELETE FROM application_authorization_profiles WHERE id = {}",
                        ph(kind, 1)
                    );
                    sql_query(delete_profile_sql)
                        .bind::<Text, _>(&existing_profile.id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                for (profile_key, profile) in &manifest.profiles {
                    let connection_id = client_db_ids.get(profile_key).cloned();
                    let connection_kind = if profile_key == "default" {
                        "application".to_string()
                    } else {
                        manifest
                            .client_protocols
                            .get(profile_key)
                            .cloned()
                            .ok_or_else(|| {
                                AppError::BadRequest(
                                    "application contract profile has no client protocol"
                                        .to_string(),
                                )
                            })?
                    };
                    let profile_id = conn.website_discovery_upsert_profile(
                        kind,
                        WebsiteDiscoveryProfileInput {
                            application_id: &application_id,
                            profile_key,
                            connection_id: connection_id.as_deref(),
                            connection_kind: &connection_kind,
                            version: &manifest.version,
                            digest: &manifest.digest,
                        },
                    )?;
                    profile_db_ids.insert(profile_key.clone(), profile_id.clone());
                    conn.website_discovery_replace_permissions(kind, &profile_id, profile)?;
                    conn.website_discovery_replace_roles(kind, &profile_id, profile)?;
                }

                // Every verified v3 client receives an explicit
                // application/profile binding in the runtime authority.
                let now = util::now_ts();
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
                for (client_id, client_db_id) in &client_db_ids {
                    let profile_id = profile_db_ids
                        .get(client_id)
                        .or_else(|| profile_db_ids.get("default"))
                        .map(String::as_str)
                        .unwrap_or("default");
                    let protocol = manifest
                        .client_protocols
                        .get(client_id)
                        .ok_or_else(|| {
                            AppError::BadRequest(
                                "application contract is missing a client protocol".to_string(),
                            )
                    })?;
                    let existing_binding_sql = format!(
                        "{} WHERE client_db_id = {}",
                        select_application_client_binding_sql(),
                        ph(kind, 1)
                    );
                    let existing_binding = sql_query(existing_binding_sql)
                        .bind::<Text, _>(client_db_id)
                        .get_result::<ApplicationClientBindingRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?;
                    if let Some(existing_binding) = existing_binding {
                        if existing_binding.application_id != application_id {
                            return Err(AppError::BadRequest(
                                "website-managed client belongs to another application"
                                    .to_string(),
                            ));
                        }
                        let update_binding_sql = format!(
                            "UPDATE application_client_bindings SET protocol = {}, authorization_profile_id = {}, auth_domain_id = {}, is_active = {}, updated_at = {} WHERE application_id = {} AND client_db_id = {}",
                            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7)
                        );
                        sql_query(update_binding_sql)
                            .bind::<Text, _>(protocol)
                            .bind::<Text, _>(profile_id)
                            .bind::<Text, _>(&auth_domain_id)
                            .bind::<Integer, _>(1)
                            .bind::<BigInt, _>(now)
                            .bind::<Text, _>(&application_id)
                            .bind::<Text, _>(client_db_id)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    } else {
                        let binding_sql = format!(
                            "INSERT INTO application_client_bindings (application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                            ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8)
                        );
                        sql_query(binding_sql)
                            .bind::<Text, _>(&application_id)
                            .bind::<Text, _>(client_db_id)
                            .bind::<Text, _>(protocol)
                            .bind::<Text, _>(profile_id)
                            .bind::<Text, _>(&auth_domain_id)
                            .bind::<Integer, _>(1)
                            .bind::<BigInt, _>(now)
                            .bind::<BigInt, _>(now)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }
                }

                if let Some(default_profile_id) = profile_db_ids.get("default") {
                    #[derive(Debug, diesel::QueryableByName)]
                    struct IdRow {
                        #[diesel(sql_type = Text)]
                        id: String,
                    }

                    // These mappings are website policy, so the complete set
                    // is replaced on every verified revision. User role
                    // assignments remain in the separate user-role table and
                    // are never present in the website manifest.
                    let profile_ids = profile_db_ids.values().cloned().collect::<Vec<_>>();
                    let mut profile_role_ids: BTreeMap<(String, String), Option<String>> = BTreeMap::new();
                    for profile_id in &profile_ids {
                        for table in [
                            "application_profile_group_roles",
                            "application_profile_organization_roles",
                        ] {
                            let delete_sql = format!(
                                "DELETE FROM {table} WHERE profile_id = {}",
                                ph(kind, 1)
                            );
                            sql_query(delete_sql)
                                .bind::<Text, _>(profile_id)
                                .execute(conn)
                                .map_err(AppError::from)?;
                        }
                    }
                    for mapping in &manifest.authorization_mappings.group_mappings {
                        let group_sql = format!(
                            "SELECT id FROM access_groups WHERE id = {} OR name = {}",
                            ph(kind, 1),
                            ph(kind, 2)
                        );
                        let group_id = sql_query(group_sql)
                            .bind::<Text, _>(&mapping.group)
                            .bind::<Text, _>(&mapping.group)
                            .get_result::<IdRow>(conn)
                            .optional()
                            .map_err(AppError::from)?
                            .ok_or_else(|| {
                                AppError::BadRequest(format!(
                                    "website authorization references unknown group: {}",
                                    mapping.group
                                ))
                        })?
                            .id;
                        for profile_id in &profile_ids {
                            let role_id = cached_profile_role_id(
                                &mut profile_role_ids,
                                profile_id,
                                &mapping.role,
                                || {
                                let role_sql = format!(
                                    "SELECT id FROM application_profile_roles WHERE profile_id = {} AND role_key = {} AND is_active = 1",
                                    ph(kind, 1),
                                    ph(kind, 2)
                                );
                                let role_id = sql_query(role_sql)
                                    .bind::<Text, _>(profile_id)
                                    .bind::<Text, _>(&mapping.role)
                                    .get_result::<IdRow>(conn)
                                    .optional()
                                    .map_err(AppError::from)?
                                    .map(|row| row.id);
                                Ok(role_id)
                            },
                            )?;
                            let Some(role_id) = role_id else {
                                if profile_id == default_profile_id {
                                    return Err(AppError::BadRequest(format!(
                                        "website authorization references unknown role: {}",
                                        mapping.role
                                    )));
                                }
                                continue;
                            };
                            let insert_sql = format!(
                                "INSERT INTO application_profile_group_roles (profile_id, group_id, role_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, 1, {}, {})",
                                ph(kind, 1),
                                ph(kind, 2),
                                ph(kind, 3),
                                ph(kind, 4),
                                ph(kind, 5)
                            );
                            let now = util::now_ts();
                            sql_query(insert_sql)
                                .bind::<Text, _>(profile_id)
                                .bind::<Text, _>(group_id.clone())
                                .bind::<Text, _>(role_id)
                                .bind::<BigInt, _>(now)
                                .bind::<BigInt, _>(now)
                                .execute(conn)
                                .map_err(AppError::from)?;
                        }
                    }
                    for mapping in &manifest.authorization_mappings.organization_role_mappings {
                        for profile_id in &profile_ids {
                            let role_id = cached_profile_role_id(
                                &mut profile_role_ids,
                                profile_id,
                                &mapping.role,
                                || {
                                let role_sql = format!(
                                    "SELECT id FROM application_profile_roles WHERE profile_id = {} AND role_key = {} AND is_active = 1",
                                    ph(kind, 1),
                                    ph(kind, 2)
                                );
                                let role_id = sql_query(role_sql)
                                    .bind::<Text, _>(profile_id)
                                    .bind::<Text, _>(&mapping.role)
                                    .get_result::<IdRow>(conn)
                                    .optional()
                                    .map_err(AppError::from)?
                                    .map(|row| row.id);
                                Ok(role_id)
                            },
                            )?;
                            let Some(role_id) = role_id else {
                                if profile_id == default_profile_id {
                                    return Err(AppError::BadRequest(format!(
                                        "website authorization references unknown role: {}",
                                        mapping.role
                                    )));
                                }
                                continue;
                            };
                            let insert_sql = format!(
                                "INSERT INTO application_profile_organization_roles (profile_id, organization_role, role_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, 1, {}, {})",
                                ph(kind, 1),
                                ph(kind, 2),
                                ph(kind, 3),
                                ph(kind, 4),
                                ph(kind, 5)
                            );
                            let now = util::now_ts();
                            sql_query(insert_sql)
                                .bind::<Text, _>(profile_id)
                                .bind::<Text, _>(&mapping.organization_role)
                                .bind::<Text, _>(role_id)
                                .bind::<BigInt, _>(now)
                                .bind::<BigInt, _>(now)
                                .execute(conn)
                                .map_err(AppError::from)?;
                        }
                    }
                }

                let now = util::now_ts();
                let affected = if let Some((owner_token, lease_generation)) = lease.as_ref() {
                    let update_sql = format!(
                        "UPDATE application_discovery SET last_verified_revision = {}, last_verified_version = {}, last_verified_digest = {}, last_verified_expires_at = {}, sync_status = {}, last_fetched_at = {}, last_success_at = {}, last_error = {}, snapshot_json = {}, updated_at = {}, lease_owner = {}, lease_expires_at = {} WHERE application_id = {} AND lease_owner = {} AND lease_generation = {} AND lease_expires_at IS NOT NULL AND lease_expires_at >= {}",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11), ph(kind, 12), ph(kind, 13), ph(kind, 14), ph(kind, 15), ph(kind, 16)
                    );
                    sql_query(update_sql)
                        .bind::<BigInt, _>(manifest.revision)
                        .bind::<Text, _>(&manifest.version)
                        .bind::<Text, _>(&manifest.digest)
                        .bind::<BigInt, _>(manifest.expires_at)
                        .bind::<Text, _>(SYNC_SYNCED)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<Nullable<Text>, _>(Some(snapshot_json))
                        .bind::<BigInt, _>(now)
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<Nullable<BigInt>, _>(None::<i64>)
                        .bind::<Text, _>(&application_id)
                        .bind::<Text, _>(owner_token)
                        .bind::<BigInt, _>(*lease_generation)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?
                } else {
                    let update_sql = format!(
                        "UPDATE application_discovery SET last_verified_revision = {}, last_verified_version = {}, last_verified_digest = {}, last_verified_expires_at = {}, sync_status = {}, last_fetched_at = {}, last_success_at = {}, last_error = {}, snapshot_json = {}, updated_at = {} WHERE application_id = {}",
                        ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5), ph(kind, 6), ph(kind, 7), ph(kind, 8), ph(kind, 9), ph(kind, 10), ph(kind, 11)
                    );
                    sql_query(update_sql)
                        .bind::<BigInt, _>(manifest.revision)
                        .bind::<Text, _>(&manifest.version)
                        .bind::<Text, _>(&manifest.digest)
                        .bind::<BigInt, _>(manifest.expires_at)
                        .bind::<Text, _>(SYNC_SYNCED)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<Nullable<Text>, _>(Some(snapshot_json))
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&application_id)
                        .execute(conn)
                        .map_err(AppError::from)?
                };
                if lease.is_some() && affected != 1 {
                    return Err(AppError::BadRequest(
                        "application discovery lease conflict".to_string(),
                    ));
                }
                let result_sql = format!(
                    "{} WHERE application_id = {}",
                    select_application_discovery_sql(),
                    ph(kind, 1)
                );
                sql_query(result_sql)
                    .bind::<Text, _>(&application_id)
                    .get_result::<ApplicationDiscoveryRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }
}
