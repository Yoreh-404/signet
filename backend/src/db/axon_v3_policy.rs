//! Inert Signet-owned V3 registration. No OAuth path reads this table.
#![allow(dead_code)]

use super::{AppError, AppResult, DatabaseKind, Db, blocking, ph};
use crate::application_discovery::axon_v3_acceptance::VerifiedPolicy;
use diesel::{RunQueryDsl, sql_query, sql_types::{BigInt, Text}};

pub(super) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS axon_v3_staged_application_policy (
    application_db_id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL,
    enrollment_id VARCHAR(255) NOT NULL,
    client_db_id VARCHAR(255) NOT NULL,
    revision BIGINT NOT NULL,
    generation BIGINT NOT NULL,
    policy_sha256 VARCHAR(71) NOT NULL,
    policy_json TEXT NOT NULL
)";

impl Db {
    /// A verified declaration is input to staging, not a grant. Only the
    /// existing active, exact client/application registration can be staged.
    pub(crate) async fn stage_axon_v3_policy(&self, approved: VerifiedPolicy) -> AppResult<()> {
        if crate::dcr::is_website_client_id(&approved.policy().client_id) {
            return Err(AppError::Forbidden);
        }
        with_conn!(self, |conn, kind| {
            if matches!(kind, DatabaseKind::Mysql) {
                return Err(AppError::Forbidden);
            }
            let policy = approved.policy();
            let sql = format!(
                "INSERT INTO axon_v3_staged_application_policy
                  (application_db_id, organization_id, enrollment_id, client_db_id,
                   revision, generation, policy_sha256, policy_json)
                 SELECT a.id, o.id, {}, c.id, {}, {}, {}, {}
                 FROM applications a
                 JOIN organizations o ON o.id = a.organization_id AND o.is_active = 1
                 JOIN application_client_bindings b ON b.application_id = a.id
                   AND b.is_active = 1 AND b.protocol = 'oauth2_oidc'
                 JOIN clients c ON c.id = b.client_db_id AND c.organization_id = o.id
                   AND c.is_active = 1 AND c.require_pkce = 1 AND c.require_s256_pkce = 1
                 WHERE a.is_active = 1 AND o.id = {} AND a.slug = {}
                   AND c.client_id = {} AND c.audience = {}
                 ON CONFLICT(application_db_id) DO UPDATE SET
                   revision = excluded.revision, generation = excluded.generation,
                   policy_sha256 = excluded.policy_sha256, policy_json = excluded.policy_json
                 WHERE axon_v3_staged_application_policy.organization_id = excluded.organization_id
                   AND axon_v3_staged_application_policy.enrollment_id = excluded.enrollment_id
                   AND axon_v3_staged_application_policy.client_db_id = excluded.client_db_id
                   AND ((excluded.revision > axon_v3_staged_application_policy.revision
                         AND excluded.generation > axon_v3_staged_application_policy.generation)
                     OR (excluded.revision = axon_v3_staged_application_policy.revision
                         AND excluded.generation = axon_v3_staged_application_policy.generation
                         AND excluded.policy_sha256 = axon_v3_staged_application_policy.policy_sha256))",
                ph(kind,1), ph(kind,2), ph(kind,3), ph(kind,4), ph(kind,5),
                ph(kind,6), ph(kind,7), ph(kind,8), ph(kind,9),
            );
            let changed = sql_query(sql)
                .bind::<Text,_>(&policy.enrollment_id)
                .bind::<BigInt,_>(policy.revision)
                .bind::<BigInt,_>(policy.generation)
                .bind::<Text,_>(approved.sha256())
                .bind::<Text,_>(approved.bytes())
                .bind::<Text,_>(&policy.organization_id)
                .bind::<Text,_>(&policy.application_id)
                .bind::<Text,_>(&policy.client_id)
                .bind::<Text,_>(&policy.audience)
                .execute(&mut conn).map_err(AppError::from)?;
            if changed != 1 { return Err(AppError::Forbidden); }
            Ok(())
        })
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::application_discovery::axon_v3_acceptance::tests::{HEADER, policy, verify_case};
    use diesel::connection::SimpleConnection;
    use serde_json::json;

    #[tokio::test]
    async fn axon_v3_staging_uses_registered_binding_and_never_replaces_with_stale_bytes() {
        let (db, path) = super::super::tests::sqlite_test_db().await;
        let Db::Sqlite(pool) = &db else { unreachable!() };
        let registration = "
            INSERT INTO organizations (id,slug,name,is_active,created_at,updated_at)
              VALUES ('example-org','example-org','Example',1,0,0);
            INSERT INTO applications (id,organization_id,slug,name,access_mode,registration_mode,account_selection_mode,is_active,created_at,updated_at)
              VALUES ('app-db','example-org','axon','Axon','public','open','default',1,0,0);
            INSERT INTO clients (id,client_id,client_name,organization_id,redirect_uris,post_logout_redirect_uris,scopes,audience,
                grant_types,response_types,token_endpoint_auth_method,require_pkce,require_s256_pkce,is_active,created_at,updated_at)
              VALUES ('client-db','bound-client','Axon','example-org','[]','[]','[\"openid\"]','https://axon.example/admin',
                '[\"authorization_code\"]','[\"code\"]','none',1,1,1,0,0);
            INSERT INTO application_client_bindings
              (application_id,client_db_id,protocol,auth_domain_id,is_active,created_at,updated_at)
              VALUES ('app-db','client-db','oauth2_oidc','auth-domain',1,0,0);";
        let put = |r: i64, g: i64, whitespace: bool| {
            let mut p = policy();
            p["revision"] = json!(r);
            p["generation"] = json!(g);
            let bytes = if whitespace { format!("{p}\n") } else { p.to_string() };
            verify_case(&bytes, |claims| {
                claims["revision"] = json!(r);
                claims["generation"] = json!(g);
            }, 9, HEADER, (r, g, false), 1100).unwrap()
        };
        assert!(db.stage_axon_v3_policy(put(4, 7, false)).await.is_err());
        pool.get().unwrap().batch_execute(registration).unwrap();
        db.stage_axon_v3_policy(put(4, 7, false)).await.unwrap();
        db.stage_axon_v3_policy(put(4, 7, false)).await.unwrap();
        assert!(db.stage_axon_v3_policy(put(4, 7, true)).await.is_err());
        assert!(db.stage_axon_v3_policy(put(5, 7, false)).await.is_err());
        db.stage_axon_v3_policy(put(5, 8, false)).await.unwrap();
        assert!(db.stage_axon_v3_policy(put(4, 7, false)).await.is_err());
        pool.get().unwrap().batch_execute("UPDATE clients SET is_active=0 WHERE id='client-db'").unwrap();
        assert!(db.stage_axon_v3_policy(put(6, 9, false)).await.is_err());
        drop(db);
        std::fs::remove_file(path).unwrap();
    }
}
