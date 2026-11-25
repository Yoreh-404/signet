//! Optional incumbent ledger. Installing empty tables does not
//! establish enrollment, accept a receipt, or grant access.
#![allow(dead_code)]

use crate::application_discovery::axon_v3_restore::{Reconciliation, RestoreInterlock};

pub(crate) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS axon_v3_incumbent_activation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    profile TEXT NOT NULL CHECK (profile = 'incumbent_v1'),
    application_db_id TEXT NOT NULL,
    client_db_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    signer_pin TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    generation BIGINT NOT NULL CHECK (generation > 0),
    withdrawn INTEGER NOT NULL CHECK (withdrawn IN (0, 1)),
    accepted_jws TEXT,
    verified_at BIGINT
)";

/// Installed only with the dormant SQLite incumbent ledger. No code or
/// session bearer is stored: both lookups use their public/hash identities.
pub(crate) const CODE_PROVENANCE_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS axon_v3_incumbent_code_provenance (
    code_sha256 TEXT PRIMARY KEY NOT NULL,
    user_sha256 TEXT NOT NULL,
    session_public_id TEXT NOT NULL,
    application_db_id TEXT NOT NULL,
    client_db_id TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    signer_pin TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    generation BIGINT NOT NULL CHECK (generation > 0),
    code_expires_at BIGINT NOT NULL
)";
/// Opt-in SQLite purpose index. No JWT, raw identity, or extra lifetime.
pub(crate) const ACCESS_PROOF_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS axon_v3_incumbent_access_proof (
    jti TEXT PRIMARY KEY NOT NULL,
    user_sha256 TEXT NOT NULL,
    session_public_id TEXT NOT NULL,
    application_db_id TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    client_db_id TEXT NOT NULL,
    enrollment_id TEXT NOT NULL,
    signer_key_sha256 TEXT NOT NULL,
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    revision BIGINT NOT NULL,
    generation BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
)";

#[cfg(all(feature = "sqlite", feature = "axon-incumbent-storage"))]
pub(super) fn install_schema(conn: &mut diesel::SqliteConnection) -> diesel::QueryResult<()> {
    use diesel::connection::SimpleConnection;

    conn.immediate_transaction(|conn| {
        for ddl in [SCHEMA, CODE_PROVENANCE_SCHEMA, ACCESS_PROOF_SCHEMA] {
            conn.batch_execute(ddl)?;
        }
        Ok(())
    })
}

/// Current row identity for future exact compare-and-set; this is not a grant.
#[derive(Clone, Copy)]
pub(crate) struct Version<'a> {
    pub(crate) digest: &'a str,
    pub(crate) revision: i64,
    pub(crate) generation: i64,
}

/// Keep the original operator gate alive across one prospective transaction.
/// This is not an approval to activate, or a standalone restore guarantee.
pub(crate) struct RestoreSnapshot<'a> {
    interlock: &'a RestoreInterlock,
    initial: Reconciliation,
}

impl<'a> RestoreSnapshot<'a> {
    pub(crate) fn capture(interlock: &'a RestoreInterlock) -> Option<Self> {
        Some(Self { interlock, initial: interlock.reconciled()? })
    }

    pub(crate) fn unchanged(&self) -> bool {
        self.interlock.reconciled().as_ref() == Some(&self.initial)
    }
}

// Private storage primitive: callers do not exist outside the fixture.
// Accepting a value here alone must never be treated as authorization.
#[cfg(all(feature = "sqlite", feature = "axon-incumbent-storage"))]
pub(crate) mod sqlite {
    use super::{RestoreInterlock, RestoreSnapshot, Version};
    use crate::application_discovery::{
        axon_v3_acceptance::VerifiedPolicy,
        incumbent_preflight::{IncumbentPin, approved_enrolled_signer},
    };
    use crate::db::SessionRecord;
    use diesel::{Connection, QueryResult, RunQueryDsl, SqliteConnection, result::Error,
        sql_query, sql_types::{BigInt, Text}};
    use diesel::OptionalExtension;

    /// Transaction-owned browser predicate; the caller supplies the
    /// server-derived hash and exact authenticated session, never HTTP data.
    /// Returns the current session for ordinary assurance derivation, not
    /// permission to admit a code. Keep the record internal to the caller.
    pub(crate) fn current_incumbent_browser_on_conn(
        conn: &mut SqliteConnection, credential_id: &str, session_id: &str,
        user_id: &str, now: i64,
    ) -> QueryResult<Option<SessionRecord>> {
        // Match session_from_cookie: prefer a current credential mapping,
        // then allow the original direct session ID. Check the exact resolved
        // session even if another session belongs to the same account.
        sql_query("SELECT s.id, s.user_id, s.csrf_token, s.ip_address, s.user_agent,
            s.login_method, s.expires_at, s.created_at
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.id = COALESCE((
                SELECT mapped.id FROM session_credentials sc
                JOIN sessions mapped ON mapped.id = sc.session_id
                WHERE sc.credential_id = ? AND sc.expires_at >= ? AND mapped.expires_at >= ?
            ), ?) AND s.id = ? AND u.id = ?
            AND s.expires_at > ? AND u.is_admin = 1 AND u.is_active = 1 AND u.archived_at IS NULL
            AND COALESCE(s.login_method, '') <> 'authorization_code'
            AND NOT EXISTS (SELECT 1 FROM trial_enrollments t WHERE t.user_id = u.id)")
            .bind::<Text, _>(credential_id).bind::<BigInt, _>(now).bind::<BigInt, _>(now)
            .bind::<Text, _>(credential_id).bind::<Text, _>(session_id).bind::<Text, _>(user_id)
            .bind::<BigInt, _>(now).get_result::<SessionRecord>(conn).optional()
            .map(|row| row.filter(|session| session.id == session_id))
    }

    type BackendConn = SqliteConnection;

    fn registry_select(sql: &'static str) -> &'static str { sql }
    fn registry_write_transaction<T>(
        conn: &mut BackendConn, f: impl FnOnce(&mut BackendConn) -> QueryResult<T>,
    ) -> QueryResult<T> { conn.immediate_transaction(f) }
    fn registry_read_transaction<T>(
        conn: &mut BackendConn, f: impl FnOnce(&mut BackendConn) -> QueryResult<T>,
    ) -> QueryResult<T> { conn.transaction(f) }

    include!("axon_v3_incumbent_registry.rs");

    /// Persist the exact admitted purpose beside the ordinary code in the
    /// same transaction. The original code and session ID stay out of the ledger.
    pub(crate) fn bind_code_provenance_on_conn(
        conn: &mut SqliteConnection,
        row: &crate::db::NewAuthorizationCode,
        pin: &IncumbentPin<'_>,
        approved: &VerifiedPolicy,
        now: i64,
    ) -> QueryResult<()> {
        let policy = approved.policy();
        let sid = row.session_id.as_deref().ok_or(Error::RollbackTransaction)?;
        if row.application_id.as_deref() != Some(pin.application_db_id)
            || row.client_id != policy.client_id
        {
            return Err(Error::RollbackTransaction);
        }
        // Bound retention to the existing code expiry; no extra clock or job.
        sql_query("DELETE FROM axon_v3_incumbent_code_provenance WHERE code_expires_at < ?")
            .bind::<BigInt,_>(now).execute(conn)?;
        sql_query("INSERT INTO axon_v3_incumbent_code_provenance
            (code_sha256,user_sha256,session_public_id,application_db_id,client_db_id,
             enrollment_id,signer_pin,policy_sha256,revision,generation,code_expires_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)")
            .bind::<Text,_>(crate::util::sha256_base64url(&row.code))
            .bind::<Text,_>(crate::util::sha256_base64url(&row.user_id)).bind::<Text,_>(sid)
            .bind::<Text,_>(pin.application_db_id).bind::<Text,_>(pin.client_db_id)
            .bind::<Text,_>(&policy.enrollment_id).bind::<Text,_>(pin.signer_pin)
            .bind::<Text,_>(approved.sha256()).bind::<BigInt,_>(policy.revision)
            .bind::<BigInt,_>(policy.generation).bind::<BigInt,_>(row.expires_at)
            .execute(conn).map(|_| ())
    }

    /// Immutable committed exchange evidence. This is neither a token nor a
    /// promise that authority stays live after the consuming transaction.
    /// It holds no authorization code, cookie, raw session ID or CSRF value.
    pub(crate) struct CommittedIncumbentCode<'a> {
        approved: &'a VerifiedPolicy,
        user_id: String,
        public_sid: String,
        scope: String,
        application_db_id: String,
        client_db_id: String,
        profile_id: String,
        auth_context_id: String,
        auth_time: i64,
        code_assurance: crate::assurance::AuthenticationAssurance,
        session_assurance: crate::assurance::AuthenticationAssurance,
    }

    impl<'a> CommittedIncumbentCode<'a> {
        fn from_current_exchange(
            row: crate::db::AuthorizationCodeRecord,
            session: SessionRecord,
            pin: &IncumbentPin<'_>,
            approved: &'a VerifiedPolicy,
        ) -> crate::error::AppResult<Self> {
            use crate::{assurance::SessionAuthenticationAssurance, error::AppError};
            if row.scope != "openid"
                || row.resource.as_deref() != Some(approved.policy().audience.as_str())
                || row.user_id != session.user_id
                || row.session_id.as_deref() != Some(crate::util::session_public_id(&session.id).as_str())
                || row.auth_time != session.created_at
            {
                return Err(AppError::Forbidden);
            }
            let session_assurance = session.authentication_assurance();
            Ok(Self {
                approved,
                user_id: row.user_id,
                public_sid: row.session_id.ok_or(AppError::Forbidden)?,
                scope: row.scope,
                application_db_id: row.application_id.ok_or(AppError::Forbidden)?,
                client_db_id: pin.client_db_id.to_owned(),
                profile_id: row.authorization_profile_id.ok_or(AppError::Forbidden)?,
                auth_context_id: row.auth_context_id.ok_or(AppError::Forbidden)?,
                auth_time: row.auth_time,
                code_assurance: crate::assurance::AuthenticationAssurance {
                    acr: row.acr,
                    amr: crate::util::from_json(&row.amr)?,
                },
                session_assurance,
            })
        }

        pub(crate) fn approved_policy(&self) -> &VerifiedPolicy { self.approved }
        pub(crate) fn user_id(&self) -> &str { &self.user_id }
        pub(crate) fn public_sid(&self) -> &str { &self.public_sid }
        pub(crate) fn scope(&self) -> &str { &self.scope }
        pub(crate) fn application_db_id(&self) -> &str { &self.application_db_id }
        pub(crate) fn client_db_id(&self) -> &str { &self.client_db_id }
        pub(crate) fn profile_id(&self) -> &str { &self.profile_id }
        pub(crate) fn auth_context_id(&self) -> &str { &self.auth_context_id }
        pub(crate) fn auth_time(&self) -> i64 { self.auth_time }
        pub(crate) fn code_assurance(&self) -> &crate::assurance::AuthenticationAssurance { &self.code_assurance }
        pub(crate) fn session_assurance(&self) -> &crate::assurance::AuthenticationAssurance { &self.session_assurance }
    }

    fn current_exchange_session_on_conn(
        conn: &mut SqliteConnection,
        row: &crate::db::AuthorizationCodeRecord,
        pin: &IncumbentPin<'_>,
        approved: &VerifiedPolicy,
        now: i64,
    ) -> QueryResult<Option<SessionRecord>> {
        #[derive(diesel::QueryableByName)]
        struct Identity {
            #[diesel(sql_type = Text)]
            id: String,
        }

        let policy = approved.policy();
        let Some(sid) = row.session_id.as_deref() else { return Ok(None); };
        if row.application_id.as_deref() != Some(pin.application_db_id)
            || row.client_id != policy.client_id
        {
            return Ok(None);
        }
        let key = crate::util::sha256_base64url(&row.code);
        let marker = sql_query("SELECT code_sha256 AS id FROM axon_v3_incumbent_code_provenance
            WHERE code_sha256=? AND user_sha256=? AND session_public_id=? AND application_db_id=?
              AND client_db_id=? AND enrollment_id=? AND signer_pin=? AND policy_sha256=?
              AND revision=? AND generation=? AND code_expires_at=?")
            .bind::<Text,_>(&key).bind::<Text,_>(crate::util::sha256_base64url(&row.user_id))
            .bind::<Text,_>(sid)
            .bind::<Text,_>(pin.application_db_id).bind::<Text,_>(pin.client_db_id)
            .bind::<Text,_>(&policy.enrollment_id).bind::<Text,_>(pin.signer_pin)
            .bind::<Text,_>(approved.sha256()).bind::<BigInt,_>(policy.revision)
            .bind::<BigInt,_>(policy.generation).bind::<BigInt,_>(row.expires_at)
            .get_result::<Identity>(conn).optional()?;
        if !marker.is_some_and(|marker| marker.id == key) {
            return Ok(None);
        }
        // The confidential exchange does not receive the browser cookie. Use
        // the exact existing public SID and only current sessions of this user.
        current_admin_session_by_public_sid_on_conn(conn, &row.user_id, sid, now)
    }

    fn current_admin_session_by_public_sid_on_conn(
        conn: &mut SqliteConnection, user_id: &str, sid: &str, now: i64,
    ) -> QueryResult<Option<SessionRecord>> {
        let sessions = sql_query("SELECT s.id, s.user_id, s.csrf_token, s.ip_address, s.user_agent,
            s.login_method, s.expires_at, s.created_at FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE u.id=? AND s.expires_at>? AND u.is_admin=1 AND u.is_active=1
              AND u.archived_at IS NULL AND COALESCE(s.login_method,'')<>'authorization_code'
              AND NOT EXISTS (SELECT 1 FROM trial_enrollments t WHERE t.user_id=u.id)")
            .bind::<Text,_>(user_id).bind::<BigInt,_>(now).load::<SessionRecord>(conn)?;
        Ok(sessions.into_iter().find(|session| crate::util::session_public_id(&session.id) == sid))
    }

    /// Bind only an access token actually signed by the normal signer inside
    /// this exact issuance transaction. There is no bearer in the index.
    pub(crate) fn bind_access_proof_on_conn(
        conn: &mut SqliteConnection,
        evidence: &CommittedIncumbentCode<'_>,
        claims: &crate::jwt::TokenClaims,
    ) -> QueryResult<()> {
        let approved = evidence.approved_policy();
        let signed = approved.policy();
        let jti = claims.jti.as_deref().filter(|value| !value.is_empty())
            .ok_or(Error::RollbackTransaction)?;
        if claims.iss != signed.issuer || claims.aud != signed.audience
            || claims.client_id != signed.client_id || claims.scope != evidence.scope()
            || claims.sub != evidence.user_id() || claims.sid.as_deref() != Some(evidence.public_sid())
            || claims.application_id.as_deref() != Some(evidence.application_db_id())
            || claims.authorization_profile_id.as_deref() != Some(evidence.profile_id())
            || claims.exp <= claims.iat
        {
            return Err(Error::RollbackTransaction);
        }
        sql_query("DELETE FROM axon_v3_incumbent_access_proof WHERE expires_at<=?")
            .bind::<BigInt,_>(claims.iat).execute(conn)?;
        sql_query("INSERT INTO axon_v3_incumbent_access_proof
            (jti,user_sha256,session_public_id,application_db_id,profile_id,client_db_id,
             enrollment_id,signer_key_sha256,issuer,audience,policy_sha256,revision,generation,expires_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind::<Text,_>(jti).bind::<Text,_>(crate::util::sha256_base64url(&claims.sub))
            .bind::<Text,_>(evidence.public_sid()).bind::<Text,_>(evidence.application_db_id())
            .bind::<Text,_>(evidence.profile_id()).bind::<Text,_>(evidence.client_db_id())
            .bind::<Text,_>(&signed.enrollment_id).bind::<Text,_>(approved.signer_key_sha256()).bind::<Text,_>(&claims.iss).bind::<Text,_>(&claims.aud)
            .bind::<Text,_>(approved.sha256()).bind::<BigInt,_>(signed.revision)
            .bind::<BigInt,_>(signed.generation).bind::<BigInt,_>(claims.exp)
            .execute(conn).map(|_| ())
    }

    // This predicate accepts only claims verified by the existing JWT manager.
    // The outer reader must authenticate the configured confidential verifier.
    pub(crate) fn read_live_access_proof_on_conn(
        conn: &mut SqliteConnection,
        gate: &RestoreInterlock,
        pin: &IncumbentPin<'_>,
        approved: &VerifiedPolicy,
        claims: &crate::jwt::TokenClaims,
        now: i64,
    ) -> crate::error::AppResult<bool> {
        #[derive(diesel::QueryableByName)]
        struct Proof {
            #[diesel(sql_type = Text)] jti: String,
        }
        let signed = approved.policy();
        let (Some(jti), Some(sid), Some(profile)) = (claims.jti.as_deref(), claims.sid.as_deref(),
            claims.authorization_profile_id.as_deref()) else { return Ok(false); };
        if jti.is_empty() || claims.iss != signed.issuer || claims.aud != signed.audience
            || claims.client_id != signed.client_id || claims.scope != "openid"
            || claims.application_id.as_deref() != Some(pin.application_db_id)
            || claims.exp <= now || claims.iat > now || claims.iat <= 0
            || !exact_active_policy(conn, gate, pin, approved)?
        {
            return Ok(false);
        }
        let proof = sql_query("SELECT jti FROM axon_v3_incumbent_access_proof
            WHERE jti=? AND user_sha256=? AND session_public_id=? AND application_db_id=?
              AND profile_id=? AND client_db_id=? AND enrollment_id=? AND signer_key_sha256=? AND issuer=?
              AND audience=? AND policy_sha256=? AND revision=? AND generation=? AND expires_at=?")
            .bind::<Text,_>(jti).bind::<Text,_>(crate::util::sha256_base64url(&claims.sub))
            .bind::<Text,_>(sid).bind::<Text,_>(pin.application_db_id).bind::<Text,_>(profile)
            .bind::<Text,_>(pin.client_db_id).bind::<Text,_>(&signed.enrollment_id).bind::<Text,_>(approved.signer_key_sha256())
            .bind::<Text,_>(&claims.iss).bind::<Text,_>(&claims.aud).bind::<Text,_>(approved.sha256())
            .bind::<BigInt,_>(signed.revision).bind::<BigInt,_>(signed.generation).bind::<BigInt,_>(claims.exp)
            .get_result::<Proof>(conn).optional()?;
        if !proof.is_some_and(|row| row.jti == jti)
            || current_admin_session_by_public_sid_on_conn(conn, &claims.sub, sid, now)?.is_none()
        {
            return Ok(false);
        }
        let graph = crate::db::load_sqlite_oidc_policy_snapshot_on_conn(conn, pin.client_db_id, &claims.sub)?;
        // Incumbent policy freshness is the live exact ledger/restore/registry
        // check above, not the generic website metadata's deadline.
        Ok(graph.has_client_application_boundary(pin.client_db_id)
            && graph.has_profile_application_boundary()
            && graph.protocol_enabled
            && graph.application.as_ref().is_some_and(|row| row.id == pin.application_db_id)
            && graph.binding.as_ref().is_some_and(|row| row.authorization_profile_id == profile)
            && graph.profile.as_ref().is_some_and(|row| row.id == profile))
    }

    /// Consume only a code admitted for the active exact incumbent policy.
    /// This is not mounted and does not grant or issue any token.
    pub(crate) fn consume_incumbent_code<'a, T>(
        conn: &mut SqliteConnection,
        gate: &RestoreInterlock,
        pin: &IncumbentPin<'_>,
        approved: &'a VerifiedPolicy,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        code_verifier: &str,
        complete: impl FnOnce(&mut SqliteConnection, &CommittedIncumbentCode<'a>) -> crate::error::AppResult<T>,
    ) -> crate::error::AppResult<(CommittedIncumbentCode<'a>, T)> {
        use crate::error::AppError;
        conn.immediate_transaction::<_, AppError, _>(|conn| {
            let snapshot = RestoreSnapshot::capture(gate).ok_or(AppError::Forbidden)?;
            if !exact_active_policy(conn, gate, pin, approved)? {
                return Err(AppError::Forbidden);
            }
            let now = crate::util::now_ts();
            let row = super::super::authorization_codes::consume_sqlite_authorization_code_for_client_on_conn(
                conn, code, client_id, Some(redirect_uri), Some(code_verifier), true, true, now,
            )?;
            let session = current_exchange_session_on_conn(conn, &row, pin, approved, now)?
                .ok_or(AppError::Forbidden)?;
            let cleared = sql_query("DELETE FROM axon_v3_incumbent_code_provenance WHERE code_sha256=?")
                .bind::<Text,_>(crate::util::sha256_base64url(&row.code)).execute(conn)?;
            let proof = CommittedIncumbentCode::from_current_exchange(row, session, pin, approved)?;
            let result = complete(conn, &proof)?;
            if cleared != 1 || !snapshot.unchanged() {
                return Err(AppError::Forbidden);
            }
            Ok((proof, result))
        })
    }

}

#[cfg(all(feature = "postgres", feature = "axon-incumbent-storage"))]
pub(crate) mod postgres {
    use super::{RestoreInterlock, RestoreSnapshot, Version};
    use crate::application_discovery::{
        axon_v3_acceptance::VerifiedPolicy,
        incumbent_preflight::{IncumbentPin, approved_enrolled_signer},
    };
    use diesel::{Connection, OptionalExtension, PgConnection, QueryResult, RunQueryDsl,
        result::Error, sql_query, sql_types::{BigInt, Text}};

    type BackendConn = PgConnection;

    // Prevent the exact application's binding, signer or client changing
    // between registry resolution and the end of its activation transaction.
    fn registry_select(sql: &str) -> String { format!("{sql} FOR SHARE OF a,o,d,b,c") }
    fn registry_write_transaction<T>(
        conn: &mut BackendConn, f: impl FnOnce(&mut BackendConn) -> QueryResult<T>,
    ) -> QueryResult<T> { conn.build_transaction().serializable().run(f) }
    fn registry_read_transaction<T>(
        conn: &mut BackendConn, f: impl FnOnce(&mut BackendConn) -> QueryResult<T>,
    ) -> QueryResult<T> { conn.build_transaction().repeatable_read().run(f) }

    include!("axon_v3_incumbent_registry.rs");
}
