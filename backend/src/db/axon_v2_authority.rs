//! Disconnected v2 persistence adapter. No runtime caller or schema auto-install.
//! A missing pre-approved reservation is a hard rejection, not a bootstrap.
use super::{
    AppError, AppResult, DatabaseKind, Db, blocking, ph, select_application_discovery_sql,
};
use diesel::sql_query;
use diesel::sql_types::{BigInt, Integer, Text};
use diesel::{Connection, OptionalExtension, RunQueryDsl};

pub(crate) struct AxonV2Enrollment {
    pub application_db_id: String,
    pub organization_id: String,
    pub application_slug: String,
    pub enrollment_id: String,
    pub website_origin: String,
    pub signer_pin: String,
}

pub(crate) struct AxonV2Advance {
    pub expected_generation: i64,
    pub revision: i64,
    pub digest: String,
    pub withdrawal: bool,
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

#[allow(dead_code)] // Future guarded reconciliation caller.
impl Db {
    /// Atomically accept a verified higher-revision declaration or withdrawal.
    /// Expected generation comes from the durable store, never the statement.
    /// Operator disable/reapproval are separate controls, not parameters here.
    /// Prior to activation, combine this transaction with snapshot reconciliation.
    pub(crate) async fn reserve_axon_v2_revision(
        &self,
        scope: AxonV2Enrollment,
        change: AxonV2Advance,
    ) -> AppResult<AxonV2Reservation> {
        let digest = change.digest.as_bytes();
        if scope.enrollment_id.is_empty() || change.expected_generation <= 0 || change.revision <= 0
            || digest.len() != 43
            || !digest.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(AppError::Forbidden);
        }
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

                let change_sql = format!(
                    "UPDATE axon_admin_authority_state SET revision = {}, digest = {}, generation = generation + 1, withdrawn = {}
                     WHERE organization_id = {} AND application_slug = {} AND enrollment_id = {}
                       AND generation = {} AND revision < {} AND withdrawn = 0",
                    ph(kind,1), ph(kind,2), ph(kind,3), ph(kind,4), ph(kind,5),
                    ph(kind,6), ph(kind,7), ph(kind,8),
                );
                if sql_query(change_sql).bind::<BigInt, _>(change.revision)
                    .bind::<Text, _>(&change.digest).bind::<Integer, _>(i32::from(change.withdrawal))
                    .bind::<Text, _>(&scope.organization_id).bind::<Text, _>(&scope.application_slug)
                    .bind::<Text, _>(&scope.enrollment_id).bind::<BigInt, _>(change.expected_generation)
                    .bind::<BigInt, _>(change.revision).execute(conn).map_err(AppError::from)? != 1
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
}
