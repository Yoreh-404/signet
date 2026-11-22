//! Disconnected v2 persistence adapter. No runtime caller or schema auto-install.
//! A missing pre-approved reservation is a hard rejection, not a bootstrap.
use super::{
    AppError, AppResult, DatabaseKind, Db, blocking, ph, select_application_discovery_sql,
};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use diesel::{Connection, OptionalExtension, RunQueryDsl};
use crate::application_discovery::VerifiedAxonDeclaration;

pub(crate) struct AxonV2Enrollment {
    pub application_db_id: String,
    pub organization_id: String,
    pub application_slug: String,
    pub enrollment_id: String,
    pub website_origin: String,
    pub signer_pin: String,
}

#[derive(Debug, diesel::QueryableByName)]
pub(crate) struct AxonV2Reservation {
    #[diesel(sql_type = BigInt)]
    pub revision: i64,
    #[diesel(sql_type = BigInt)]
    pub generation: i64,
    #[diesel(sql_type = Text)]
    pub digest: String,
    #[diesel(sql_type = Integer)]
    pub withdrawn: i32,
}

#[derive(diesel::QueryableByName)]
struct LiveAxonV2Snapshot {
    #[diesel(sql_type = Text)]
    snapshot_json: String,
    #[diesel(sql_type = Text)]
    website_url: String,
    #[diesel(sql_type = Text)]
    signing_public_jwks: String,
}

#[allow(dead_code)] // Future guarded reconciliation caller.
impl Db {
    /// One consistent statement snapshot of the fenced authority and global user.
    pub(crate) async fn live_axon_v2_snapshot(
        &self,
        scope: AxonV2Enrollment,
        user_id: String,
        expected_revision: i64,
        expected_digest: String,
    ) -> AppResult<Option<serde_json::Value>> {
        with_conn!(self, |conn, kind| {
            let query = format!(
                "SELECT s.snapshot_json, d.website_url, d.signing_public_jwks
                 FROM axon_admin_authority_state s
                 JOIN applications a ON a.organization_id = s.organization_id AND a.slug = s.application_slug
                 JOIN application_discovery d ON d.application_id = a.id
                 JOIN users u ON u.id = {}
                 WHERE a.id = {} AND s.organization_id = {} AND s.application_slug = {}
                   AND s.enrollment_id = {} AND s.revision = {} AND s.digest = {}
                   AND s.withdrawn = 0 AND s.snapshot_json IS NOT NULL AND s.expires_at > {}
                   AND a.is_active = 1 AND d.operator_disabled = 0 AND d.management_mode = {}
                   AND u.is_admin = 1 AND u.is_active = 1 AND u.archived_at IS NULL",
                ph(kind,1), ph(kind,2), ph(kind,3), ph(kind,4), ph(kind,5),
                ph(kind,6), ph(kind,7), ph(kind,8), ph(kind,9),
            );
            let found = sql_query(query).bind::<Text, _>(&user_id)
                .bind::<Text, _>(&scope.application_db_id)
                .bind::<Text, _>(&scope.organization_id)
                .bind::<Text, _>(&scope.application_slug)
                .bind::<Text, _>(&scope.enrollment_id)
                .bind::<BigInt, _>(expected_revision)
                .bind::<Text, _>(&expected_digest)
                .bind::<BigInt, _>(crate::util::now_ts())
                .bind::<Text, _>(crate::application_discovery::MANAGEMENT_MODE_WEBSITE)
                .get_result::<LiveAxonV2Snapshot>(&mut conn).optional().map_err(AppError::from)?;
            let Some(row) = found else { return Ok(None); };
            if crate::application_discovery::website_origin(&row.website_url).ok().as_deref()
                != Some(scope.website_origin.as_str())
                || crate::application_discovery::axon_signer_pin(&row.signing_public_jwks).as_deref()
                    != Some(scope.signer_pin.as_str())
            {
                return Ok(None);
            }
            serde_json::from_str(&row.snapshot_json).map(Some)
                .map_err(|_| AppError::Internal("invalid stored Axon declaration snapshot".into()))
        })
    }

    /// Atomically stage a verified higher-revision declaration and snapshot.
    /// Expected generation comes from the durable store, never the statement.
    /// Operator disable/reapproval are separate controls, not parameters here.
    /// This never updates general v1 reconciliation or activates issuance.
    pub(crate) async fn reserve_axon_v2_revision(
        &self,
        scope: AxonV2Enrollment,
        expected_generation: i64,
        verified: VerifiedAxonDeclaration,
    ) -> AppResult<AxonV2Reservation> {
        let manifest = verified.manifest();
        let digest = manifest.digest.as_bytes();
        if scope.enrollment_id.is_empty() || expected_generation <= 0 || manifest.revision <= 0
            || verified.organization_id() != scope.organization_id
            || verified.website_origin() != scope.website_origin
            || manifest.application_id != scope.application_slug
            || manifest.redacted_payload["_signet_axon_verified_signer"].as_str()
                != Some(scope.signer_pin.as_str())
            || digest.len() != 43
            || !digest.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(AppError::Forbidden);
        }
        let revision = manifest.revision;
        let digest = manifest.digest.clone();
        let expires = manifest.expires_at;
        let withdrawal = verified.is_withdrawal();
        let snapshot = if withdrawal { None } else {
            Some(serde_json::to_string(&manifest.redacted_payload)
                .map_err(|_| AppError::Internal("cannot serialize Axon declaration snapshot".into()))?)
        };
        with_conn!(self, |conn, kind| {
            conn.transaction::<AxonV2Reservation, AppError, _>(|conn| {
                // Same lock order as incumbent discovery updates.
                let lock = format!(
                    "UPDATE applications SET updated_at = updated_at WHERE id = {} AND organization_id = {} AND slug = {} AND is_active = 1",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3),
                );
                if sql_query(lock).bind::<Text, _>(&scope.application_db_id)
                    .bind::<Text, _>(&scope.organization_id).bind::<Text, _>(&scope.application_slug)
                    .execute(conn).map_err(AppError::from)? != 1
                {
                    return Err(AppError::Forbidden);
                }
                let query = format!("{} WHERE application_id = {}",
                    select_application_discovery_sql(), ph(kind, 1));
                let row = sql_query(query).bind::<Text, _>(&scope.application_db_id)
                    .get_result::<super::ApplicationDiscoveryRecord>(conn)
                    .optional().map_err(AppError::from)?.ok_or(AppError::Forbidden)?;
                if row.operator_disabled != 0
                    || row.management_mode != crate::application_discovery::MANAGEMENT_MODE_WEBSITE
                    || crate::application_discovery::website_origin(&row.website_url).ok().as_deref()
                       != Some(scope.website_origin.as_str())
                    || crate::application_discovery::axon_signer_pin(&row.signing_public_jwks).as_deref()
                       != Some(scope.signer_pin.as_str())
                {
                    return Err(AppError::Forbidden);
                }

                if expires <= crate::util::now_ts() {
                    return Err(AppError::Forbidden);
                }
                let change_sql = format!(
                    "UPDATE axon_admin_authority_state SET revision = {}, digest = {}, generation = generation + 1, snapshot_json = {}, expires_at = {}, withdrawn = {}
                     WHERE organization_id = {} AND application_slug = {} AND enrollment_id = {}
                       AND generation = {} AND revision < {} AND withdrawn = 0",
                    ph(kind,1), ph(kind,2), ph(kind,3), ph(kind,4), ph(kind,5),
                    ph(kind,6), ph(kind,7), ph(kind,8), ph(kind,9), ph(kind,10),
                );
                if sql_query(change_sql).bind::<BigInt, _>(revision)
                    .bind::<Text, _>(&digest).bind::<Nullable<Text>, _>(snapshot.as_deref())
                    .bind::<Nullable<BigInt>, _>((!withdrawal).then_some(expires))
                    .bind::<Integer, _>(i32::from(withdrawal))
                    .bind::<Text, _>(&scope.organization_id).bind::<Text, _>(&scope.application_slug)
                    .bind::<Text, _>(&scope.enrollment_id).bind::<BigInt, _>(expected_generation)
                    .bind::<BigInt, _>(revision).execute(conn).map_err(AppError::from)? != 1
                {
                    return Err(AppError::Forbidden);
                }
                let read = format!(
                    "SELECT revision, digest, generation, withdrawn FROM axon_admin_authority_state WHERE organization_id = {} AND application_slug = {} AND enrollment_id = {}",
                    ph(kind, 1), ph(kind, 2), ph(kind, 3),
                );
                sql_query(read).bind::<Text, _>(&scope.organization_id)
                    .bind::<Text, _>(&scope.application_slug).bind::<Text, _>(&scope.enrollment_id)
                    .get_result(conn).map_err(AppError::from)
            })
        })
    }

    /// Dedicated, authorized local control. Not callable from normal discovery
    /// sync. Invalidates staged state without inventing a signed wire revision.
    pub(crate) async fn disable_axon_v2_reservation(
        &self,
        scope: AxonV2Enrollment,
        expected_generation: i64,
    ) -> AppResult<()> {
        if scope.enrollment_id.is_empty() || expected_generation <= 0 {
            return Err(AppError::Forbidden);
        }
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let lock = format!(
                    "UPDATE applications SET updated_at = updated_at WHERE id = {} AND organization_id = {} AND slug = {}",
                    ph(kind,1), ph(kind,2), ph(kind,3),
                );
                if sql_query(lock).bind::<Text, _>(&scope.application_db_id)
                    .bind::<Text, _>(&scope.organization_id).bind::<Text, _>(&scope.application_slug)
                    .execute(conn).map_err(AppError::from)? != 1
                {
                    return Err(AppError::Forbidden);
                }
                let update = format!(
                    "UPDATE axon_admin_authority_state SET withdrawn = 1, generation = generation + 1,
                     snapshot_json = NULL, expires_at = NULL
                     WHERE organization_id = {} AND application_slug = {} AND enrollment_id = {}
                       AND generation = {} AND withdrawn = 0",
                    ph(kind,1), ph(kind,2), ph(kind,3), ph(kind,4),
                );
                if sql_query(update).bind::<Text, _>(&scope.organization_id)
                    .bind::<Text, _>(&scope.application_slug).bind::<Text, _>(&scope.enrollment_id)
                    .bind::<BigInt, _>(expected_generation).execute(conn).map_err(AppError::from)? != 1
                {
                    return Err(AppError::Forbidden);
                }
                Ok(())
            })
        })
    }
}
