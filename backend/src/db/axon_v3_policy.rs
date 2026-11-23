//! Inert Signet-owned V3 registration. No OAuth path reads this table.
#![allow(dead_code)]

use super::{AppError, AppResult, DatabaseKind, Db, blocking, ph};
use crate::application_discovery::axon_v3_acceptance::VerifiedPolicy;
use crate::application_discovery::axon_v3_restore::RestoreInterlock;
use diesel::{OptionalExtension, RunQueryDsl, sql_query, sql_types::{BigInt, Text}};
use serde_json::{Value, json};

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

pub(super) const ACTIVE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS axon_v3_application_activation (
    application_db_id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL,
    enrollment_id VARCHAR(255) NOT NULL,
    client_db_id VARCHAR(255) NOT NULL,
    revision BIGINT NOT NULL,
    generation BIGINT NOT NULL,
    policy_sha256 VARCHAR(71) NOT NULL,
    policy_json TEXT NOT NULL,
    withdrawn INTEGER NOT NULL
)";

/// Derived exclusively from authenticated resource introspection and its
/// configured exact confidential verifier binding, never request JSON.
pub(crate) struct CheckedScope {
    pub organization_id: String,
    pub enrollment_id: String,
    pub application_id: String,
    pub issuer: String,
    pub client_id: String,
    pub verifier_client_id: String,
    pub audience: String,
    pub origin: String,
    pub subject: String,
}

#[derive(diesel::QueryableByName)]
struct ActivePolicy {
    #[diesel(sql_type = Text)]
    policy_json: String,
    #[diesel(sql_type = Text)]
    policy_sha256: String,
    #[diesel(sql_type = BigInt)]
    revision: i64,
    #[diesel(sql_type = BigInt)]
    generation: i64,
}

impl Db {
    /// Deliberate foreground activation, never called by discovery or OAuth.
    pub(crate) async fn activate_axon_v3_policy(
        &self, enrolled: crate::config::AxonAdminV3Enrollment, expected_sha256: String,
        interlock: &RestoreInterlock,
    ) -> AppResult<()> {
        let Some(initial) = interlock.reconciled() else { return Err(AppError::Forbidden); };
        with_conn!(self, |conn, kind| {
            if matches!(kind, DatabaseKind::Mysql) { return Err(AppError::Forbidden); }
            let sql = format!(
                "INSERT INTO axon_v3_application_activation (
                   application_db_id, organization_id, enrollment_id, client_db_id,
                   revision, generation, policy_sha256, policy_json, withdrawn)
                 SELECT p.application_db_id, p.organization_id, p.enrollment_id, p.client_db_id,
                   p.revision, p.generation, p.policy_sha256, p.policy_json, 0
                 FROM axon_v3_staged_application_policy p
                 JOIN applications a ON a.id = p.application_db_id AND a.is_active = 1 AND a.organization_id = p.organization_id
                 JOIN organizations o ON o.id = p.organization_id AND o.is_active = 1
                 JOIN clients c ON c.id = p.client_db_id AND c.is_active = 1 AND c.organization_id = o.id
                 JOIN application_client_bindings b ON b.application_id = a.id
                   AND b.client_db_id = c.id AND b.is_active = 1 AND b.protocol = 'oauth2_oidc'
                 JOIN clients v ON v.organization_id = o.id AND v.audience = c.audience
                   AND v.is_active = 1 AND v.token_endpoint_auth_method <> 'none'
                 WHERE p.organization_id = {} AND p.enrollment_id = {} AND a.slug = {}
                   AND c.client_id = {} AND v.client_id = {} AND c.audience = {} AND p.policy_sha256 = {}
                   AND c.require_pkce = 1 AND c.require_s256_pkce = 1
                   AND NOT EXISTS (SELECT 1 FROM application_discovery d
                     WHERE d.application_id = a.id AND d.management_mode = 'website_managed')
                 ON CONFLICT(application_db_id) DO UPDATE SET
                   revision = excluded.revision, generation = excluded.generation,
                   policy_sha256 = excluded.policy_sha256, policy_json = excluded.policy_json, withdrawn = 0
                 WHERE axon_v3_application_activation.organization_id = excluded.organization_id
                   AND axon_v3_application_activation.enrollment_id = excluded.enrollment_id
                   AND axon_v3_application_activation.client_db_id = excluded.client_db_id
                   AND ((excluded.revision > axon_v3_application_activation.revision
                         AND excluded.generation > axon_v3_application_activation.generation)
                     OR (excluded.revision = axon_v3_application_activation.revision
                         AND excluded.generation = axon_v3_application_activation.generation
                         AND excluded.policy_sha256 = axon_v3_application_activation.policy_sha256
                         AND axon_v3_application_activation.withdrawn = 0))",
                ph(kind,1), ph(kind,2), ph(kind,3), ph(kind,4), ph(kind,5), ph(kind,6), ph(kind,7),
            );
            let changed = sql_query(sql)
                .bind::<Text,_>(&enrolled.organization_id).bind::<Text,_>(&enrolled.enrollment_id)
                .bind::<Text,_>(&enrolled.application_id).bind::<Text,_>(&enrolled.client_id)
                .bind::<Text,_>(&enrolled.introspection_client_id).bind::<Text,_>(&enrolled.audience)
                .bind::<Text,_>(&expected_sha256).execute(&mut conn).map_err(AppError::from)?;
            if changed != 1 { return Err(AppError::Forbidden); }
            Ok(())
        })?;
        if interlock.reconciled().as_ref() != Some(&initial) { return Err(AppError::Forbidden); }
        Ok(())
    }

    pub(crate) async fn withdraw_axon_v3_policy(
        &self, enrolled: crate::config::AxonAdminV3Enrollment, expected_sha256: String,
    ) -> AppResult<()> {
        with_conn!(self, |conn, kind| {
            if matches!(kind, DatabaseKind::Mysql) { return Err(AppError::Forbidden); }
            let sql = format!(
                "UPDATE axon_v3_application_activation SET withdrawn = 1
                 WHERE organization_id = {} AND enrollment_id = {} AND policy_sha256 = {}
                   AND application_db_id IN (SELECT id FROM applications WHERE organization_id = {} AND slug = {})",
                ph(kind,1), ph(kind,2), ph(kind,3), ph(kind,4), ph(kind,5),
            );
            let changed = sql_query(sql)
                .bind::<Text,_>(&enrolled.organization_id).bind::<Text,_>(&enrolled.enrollment_id)
                .bind::<Text,_>(&expected_sha256).bind::<Text,_>(&enrolled.organization_id)
                .bind::<Text,_>(&enrolled.application_id).execute(&mut conn).map_err(AppError::from)?;
            if changed != 1 { return Err(AppError::Forbidden); }
            Ok(())
        })
    }

    pub(crate) async fn read_active_axon_v3_policy(
        &self, scope: CheckedScope, interlock: &RestoreInterlock,
    ) -> AppResult<Option<Value>> {
        let Some(initial) = interlock.reconciled() else { return Ok(None); };
        if scope.client_id == scope.verifier_client_id
            || crate::dcr::is_website_client_id(&scope.client_id)
            || crate::dcr::is_website_client_id(&scope.verifier_client_id)
        { return Ok(None); }
        let row = with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT p.policy_json, p.policy_sha256, p.revision, p.generation
                 FROM axon_v3_application_activation p
                 JOIN applications a ON a.id = p.application_db_id AND a.is_active = 1
                 JOIN organizations o ON o.id = p.organization_id AND o.id = a.organization_id AND o.is_active = 1
                 JOIN users u ON u.is_active = 1 AND u.is_admin = 1 AND u.archived_at IS NULL
                 JOIN application_client_bindings b ON b.application_id = a.id AND b.client_db_id = p.client_db_id
                   AND b.is_active = 1 AND b.protocol IN ('oauth2_oidc', 'oidc')
                 JOIN clients c ON c.id = p.client_db_id AND c.organization_id = o.id
                   AND c.is_active = 1 AND c.require_pkce = 1 AND c.require_s256_pkce = 1
                 JOIN clients v ON v.organization_id = o.id AND v.audience = c.audience
                   AND v.is_active = 1 AND v.token_endpoint_auth_method <> 'none'
                 WHERE p.withdrawn = 0 AND p.organization_id = {} AND p.enrollment_id = {} AND a.slug = {}
                   AND c.client_id = {} AND v.client_id = {} AND c.audience = {} AND u.id = {}
                   AND NOT EXISTS (SELECT 1 FROM application_discovery d
                     WHERE d.application_id = a.id AND d.management_mode = 'website_managed')",
                ph(kind,1), ph(kind,2), ph(kind,3), ph(kind,4), ph(kind,5), ph(kind,6), ph(kind,7),
            );
            let row = sql_query(sql)
                .bind::<Text,_>(&scope.organization_id).bind::<Text,_>(&scope.enrollment_id)
                .bind::<Text,_>(&scope.application_id).bind::<Text,_>(&scope.client_id)
                .bind::<Text,_>(&scope.verifier_client_id).bind::<Text,_>(&scope.audience)
                .bind::<Text,_>(&scope.subject)
                .get_result::<ActivePolicy>(&mut conn).optional().map_err(AppError::from)?;
            let Some(row) = row else { return Ok::<_, AppError>(None); };
            let Some(policy) = crate::application_discovery::axon_v3_acceptance::read_stored_policy(
                row.policy_json.as_bytes(), &row.policy_sha256,
            ) else { return Ok(None); };
            if policy.issuer != scope.issuer || policy.origin != scope.origin
                || policy.organization_id != scope.organization_id || policy.enrollment_id != scope.enrollment_id
                || policy.application_id != scope.application_id || policy.client_id != scope.client_id
                || policy.audience != scope.audience || policy.revision != row.revision
                || policy.generation != row.generation
            { return Ok(None); }
            Ok(Some(json!({
                "format":"axon.signet.application-admin.live.v3",
                "policy_sha256":row.policy_sha256, "organization_id":policy.organization_id,
                "enrollment_id":policy.enrollment_id, "application_id":policy.application_id,
                "issuer":policy.issuer, "client_id":policy.client_id, "audience":policy.audience,
                "origin":policy.origin, "subject":scope.subject,
                "revision":row.revision, "generation":row.generation, "permissions":policy.permissions,
            })))
        })?;
        Ok(if interlock.reconciled().as_ref() == Some(&initial) { row } else { None })
    }

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
                   AND b.is_active = 1 AND b.protocol IN ('oauth2_oidc', 'oidc')
                 JOIN clients c ON c.id = b.client_db_id AND c.organization_id = o.id
                   AND c.is_active = 1 AND c.require_pkce = 1 AND c.require_s256_pkce = 1
                 WHERE a.is_active = 1 AND o.id = {} AND a.slug = {}
                   AND c.client_id = {} AND c.audience = {}
                   AND NOT EXISTS (SELECT 1 FROM application_discovery d
                     WHERE d.application_id = a.id AND d.management_mode = 'website_managed')
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
        #[cfg(target_os = "linux")]
        check_restore_read_side(&db, &path).await;
        assert!(db.stage_axon_v3_policy(put(4, 7, true)).await.is_err());
        assert!(db.stage_axon_v3_policy(put(5, 7, false)).await.is_err());
        db.stage_axon_v3_policy(put(5, 8, false)).await.unwrap();
        assert!(db.stage_axon_v3_policy(put(4, 7, false)).await.is_err());
        pool.get().unwrap().batch_execute("UPDATE clients SET is_active=0 WHERE id='client-db'").unwrap();
        assert!(db.stage_axon_v3_policy(put(6, 9, false)).await.is_err());
        drop(db);
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(target_os = "linux")]
    async fn check_restore_read_side(db: &Db, db_path: &std::path::Path) {
        use std::{fs, os::unix::fs::PermissionsExt};
        use crate::application_discovery::{run_axon_v3_operator_command, axon_v3_acceptance::tests::sign};
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_dalek::SigningKey;
        use sha2::{Digest, Sha256};
        let Db::Sqlite(pool) = db else { unreachable!() };
        let dir = db_path.with_extension("restore");
        fs::create_dir(&dir).unwrap();
        let marker = dir.join("current.json");
        let update = |data: &str| {
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
            let tmp = dir.join("new.json");
            fs::write(&tmp, data).unwrap();
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o400)).unwrap();
            fs::rename(&tmp, &marker).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        };
        let interlock = RestoreInterlock::new(marker.clone(), rustix::process::geteuid().as_raw());
        let scope = || CheckedScope {
            organization_id: "example-org".into(), enrollment_id: "enrollment".into(),
            application_id: "axon".into(), issuer: "https://signet.example".into(),
            client_id: "bound-client".into(), verifier_client_id: "confidential-verifier".into(),
            audience: "https://axon.example/admin".into(), origin: "https://axon.example".into(),
            subject: "fixture-admin".into(),
        };
        let read = || db.read_active_axon_v3_policy(scope(), &interlock);
        assert!(read().await.unwrap().is_none());
        update(r#"{"format":"signet-privileged-restore/v1","state":"reconciled","operation_id":"ac84cfd6-f2d8-46f3-8fd1-986c43afd131"}"#);
        let ready = fs::read_to_string(&marker).unwrap();
        pool.get().unwrap().batch_execute("
            INSERT INTO clients (id,client_id,client_name,organization_id,redirect_uris,post_logout_redirect_uris,scopes,audience,
              grant_types,response_types,token_endpoint_auth_method,require_pkce,require_s256_pkce,is_active,created_at,updated_at)
              VALUES ('verifier-db','confidential-verifier','Resource','example-org','[]','[]','[]','https://axon.example/admin',
                       '[]','[]','client_secret_basic',0,0,1,0,0);
            INSERT INTO users (id,email,username,password_hash,is_admin,is_active,created_at,updated_at)
              VALUES ('fixture-admin','fixture@example.invalid','fixture-admin','not-a-credential',1,1,0,0);").unwrap();
        assert!(read().await.unwrap().is_none(), "staged row cannot grant");
        let mut settings: crate::Settings = toml::from_str(include_str!("../../../config/default.toml")).unwrap();
        settings.discovery.axon_admin_v3 = Some(crate::config::AxonAdminV3Enrollment {
            organization_id: "example-org".into(), enrollment_id: "enrollment".into(),
            application_id: "axon".into(), issuer: "https://signet.example".into(),
            client_id: "bound-client".into(), introspection_client_id: "confidential-verifier".into(),
            audience: "https://axon.example/admin".into(), origin: "https://axon.example".into(),
            restore_marker_path: marker.clone(), restore_marker_owner_uid: rustix::process::geteuid().as_raw(),
        });
        let public = SigningKey::from_bytes(&[9; 32]).verifying_key();
        settings.discovery.axon_admin_trust = Some(crate::config::AxonAdminTrust {
            organization_id: "example-org".into(), application_id: "axon".into(),
            client_id: "bound-client".into(), audience: "https://axon.example/admin".into(),
            origin: "https://axon.example".into(), signing_public_jwks: json!({"keys":[{
                "kty":"OKP","crv":"Ed25519","kid":"approval","x":URL_SAFE_NO_PAD.encode(public.as_bytes()),
            }]}).to_string(),
        });
        let raw = policy().to_string();
        let digest = format!("sha256:{:x}", Sha256::digest(&raw));
        let now = crate::util::now_ts();
        let approval = sign(&json!({"format":"axon.signet.application-admin.acceptance.v3",
            "policy_sha256":digest,"revision":4,"generation":7,"aud":"https://signet.example",
            "iat":now,"exp":now+900}).to_string(), 9, HEADER);
        let policy_file = db_path.with_extension("policy.json");
        let approval_file = db_path.with_extension("approval.jws");
        fs::write(&policy_file, raw).unwrap();
        fs::write(&approval_file, approval).unwrap();
        let activate = vec!["activate".to_owned(), policy_file.to_str().unwrap().to_owned(),
            approval_file.to_str().unwrap().to_owned(), digest.clone()];
        run_axon_v3_operator_command(&settings, db, &activate).await.unwrap();
        let proof = read().await.unwrap().unwrap();
        assert_eq!(proof["format"], "axon.signet.application-admin.live.v3");
        assert_eq!(proof["subject"], "fixture-admin");
        assert_eq!(proof["revision"], 4);
        assert!(proof.get("exp").is_none());
        let mut foreign = scope();
        foreign.origin = "https://other.example".into();
        assert!(db.read_active_axon_v3_policy(foreign, &interlock).await.unwrap().is_none());
        update(r#"{"format":"signet-privileged-restore/v1","state":"held","operation_id":"df63e995-c3c1-487f-9aa9-468c13431322"}"#);
        assert!(read().await.unwrap().is_none(), "old DB row cannot defeat a restore hold");
        update(r#"{"format":"signet-privileged-restore/v1","state":"reconciled"}"#);
        assert!(read().await.unwrap().is_none(), "incomplete reconciliation must deny");
        pool.get().unwrap().batch_execute("UPDATE users SET is_admin=0 WHERE id='fixture-admin'").unwrap();
        update(&ready);
        assert!(read().await.unwrap().is_none(), "current demotion wins on reopen");
        pool.get().unwrap().batch_execute("UPDATE users SET is_admin=1 WHERE id='fixture-admin'").unwrap();
        run_axon_v3_operator_command(&settings, db, &["withdraw".into(), digest]).await.unwrap();
        assert!(read().await.unwrap().is_none(), "withdrawn activation cannot grant");
        assert!(run_axon_v3_operator_command(&settings, db, &activate).await.is_err(),
            "the same signed policy cannot reopen a withdrawn revision");
        fs::remove_file(policy_file).unwrap();
        fs::remove_file(approval_file).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
