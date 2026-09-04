use super::{
    AppError, AppResult, ApplicationDiscoveryJoinRecord, ApplicationDiscoveryMigrationRow,
    ApplicationDiscoveryRecord, ApplicationRecord, DatabaseKind, Db, blocking, ph,
    select_application_discovery_sql,
};
use crate::application_discovery_contract::MANAGEMENT_MODE_WEBSITE;
use diesel::sql_query;
use diesel::sql_types::Text;
use diesel::{OptionalExtension, RunQueryDsl};

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
}
