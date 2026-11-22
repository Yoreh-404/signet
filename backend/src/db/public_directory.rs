//! Read-only, opt-in public project directory.
//!
//! The existing organization is the workspace security boundary.  Short names
//! are unique only within that workspace; different organizations may use the
//! same short name without acquiring a global name monopoly.

use super::{AppError, AppResult, Db, DatabaseKind, blocking, ph};
use diesel::RunQueryDsl;
use diesel::sql_query;
use diesel::sql_types::{Nullable, Text};

#[derive(Debug, diesel::QueryableByName)]
pub(crate) struct PublicDirectoryCandidate {
    #[diesel(sql_type = Text)]
    pub workspace: String,
    #[diesel(sql_type = Text)]
    pub workspace_name: String,
    #[diesel(sql_type = Text)]
    pub short_name: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Text)]
    pub directory_config_json: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub discovery_management_mode: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    pub website_snapshot_json: Option<String>,
}

impl Db {
    /// Only modules explicitly opted into listing are candidates. Verified
    /// website-managed applications disappear when their discovery snapshot
    /// expires or an operator disables discovery. SQL uses bound parameters
    /// for both tenant and short name, never interpolated names.
    pub(crate) async fn public_directory_candidates(
        &self,
        short_name: Option<&str>,
        workspace: Option<&str>,
    ) -> AppResult<Vec<PublicDirectoryCandidate>> {
        let short_name = short_name.unwrap_or_default().to_owned();
        let workspace = workspace.unwrap_or_default().to_owned();
        let now = crate::util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT o.slug AS workspace, o.name AS workspace_name,
                        a.slug AS short_name, a.name AS name,
                        a.description AS description,
                        m.config_json AS directory_config_json,
                        d.management_mode AS discovery_management_mode,
                        d.snapshot_json AS website_snapshot_json
                 FROM applications a
                 JOIN organizations o ON o.id = a.organization_id
                 JOIN application_modules m ON m.application_id = a.id
                   AND m.module_key = 'directory' AND m.is_enabled = 1
                 LEFT JOIN application_discovery d ON d.application_id = a.id
                 WHERE a.is_active = 1 AND o.is_active = 1
                   AND m.config_json LIKE '%\"listed\":true%'
                   AND ({} = '' OR a.slug = {})
                   AND ({} = '' OR o.slug = {})
                   AND (d.application_id IS NULL OR d.management_mode != 'website_managed'
                     OR (d.operator_disabled = 0
                       AND d.last_verified_revision IS NOT NULL
                       AND d.snapshot_json IS NOT NULL
                       AND (d.last_verified_expires_at IS NULL OR d.last_verified_expires_at > {})))
                 ORDER BY o.slug ASC, a.slug ASC LIMIT 101",
                ph(kind, 1), ph(kind, 2), ph(kind, 3), ph(kind, 4), ph(kind, 5),
            );
            sql_query(sql)
                .bind::<Text, _>(short_name.clone())
                .bind::<Text, _>(short_name)
                .bind::<Text, _>(workspace.clone())
                .bind::<Text, _>(workspace)
                .bind::<diesel::sql_types::BigInt, _>(now)
                .load::<PublicDirectoryCandidate>(&mut conn)
                .map_err(AppError::from)
        })
    }
}
