use super::*;
use crate::application_discovery::axon_v3_restart;
use serde_json::{json, Value};

macro_rules! on_conn {
    ($pool:expr, $restore:path, $provider:path, $state:ident, $adapter:ident,
     $conn:ident, $mat:ident, $action:expr) => {{
        use $provider as $adapter;
        let settings = &$state.settings.discovery;
        let (Some(floor), Some(enrolled), Some(trust)) = (
            settings.axon_admin_incumbent_floor.as_ref(), settings.axon_admin_v3.as_ref(),
            settings.axon_admin_trust.as_ref(),
        ) else { return Ok::<_, AppError>(None); };
        let mut pooled = $pool.get()?;
        let $conn = &mut *pooled;
        let Some($mat) = $restore($conn, floor, enrolled, trust, util::now_ts())? else {
            return Ok::<_, AppError>(None);
        };
        let value = $action?;
        Ok(if $mat.still_current(floor, enrolled.restore_marker_owner_uid) { Some(value) } else { None })
    }};
}

// No pool, floor, identity or trust material is taken from the HTTP request.
macro_rules! dispatch {
    ($state:ident, |$adapter:ident, $conn:ident, $mat:ident| $action:expr) => {{
        let $state = $state.clone();
        tokio::task::spawn_blocking(move || match &$state.db {
            #[cfg(feature = "postgres")]
            crate::db::Db::Postgres(pool) => on_conn!(pool, axon_v3_restart::restore_postgres_material,
                super::postgres_incumbent, $state, $adapter, $conn, $mat, $action),
            #[cfg(feature = "sqlite")]
            crate::db::Db::Sqlite(pool) => on_conn!(pool, axon_v3_restart::restore_sqlite_material,
                super::sqlite_incumbent, $state, $adapter, $conn, $mat, $action),
            #[allow(unreachable_patterns)]
            _ => Ok(None),
        }).await.map_err(|error| AppError::Internal(error.to_string()))?
    }};
}

pub(super) async fn introspect(
    state: &AppState, verifier_id: &str, issuer: &str, token: &str, subject: &str,
) -> AppResult<Option<Value>> {
    let (verifier_id, issuer, token, subject) = (
        verifier_id.to_owned(), issuer.to_owned(), token.to_owned(), subject.to_owned(),
    );
    let value = dispatch!(state, |provider, conn, material| {
        let pin = material.pin();
        if !provider::verify_incumbent_access_proof(conn, &state, &verifier_id, &issuer,
            &pin, &material.policy, &token)?
        {
            Ok::<_, AppError>(None)
        } else {
            let p = material.policy.policy();
            Ok(Some(json!({
                "format":"axon.signet.application-admin.live.v3", "policy_sha256":material.policy.sha256(),
                "organization_id":p.organization_id, "enrollment_id":p.enrollment_id,
                "application_id":p.application_id, "issuer":p.issuer, "client_id":p.client_id,
                "audience":p.audience, "origin":p.origin, "subject":subject,
                "revision":p.revision, "generation":p.generation, "permissions":p.permissions,
            })))
        }
    })?;
    Ok(value.flatten())
}

pub(super) async fn admit(
    context: &AuthorizationHttpContext<'_>, user: &UserRecord, session: &SessionRecord,
    client: &ClientRecord, req: &ResolvedAuthorizeRequest,
) -> AppResult<Option<String>> {
    let state = context.state;
    let settings = &state.settings.discovery;
    let Some(enrolled) = settings.axon_admin_v3.as_ref() else { return Ok(None); };
    if settings.axon_admin_incumbent_floor.is_none() || user.is_admin != 1
        || client.client_id != enrolled.client_id || req.resource.as_deref() != Some(&enrolled.audience)
        || req.scope.as_deref() != Some("openid")
    {
        return Ok(None);
    }
    let jar = CookieJar::from_headers(context.headers);
    let credential = jar.get(&state.settings.security.cookie_name)
        .and_then(|cookie| util::session_id_from_cookie(cookie.value())).ok_or(AppError::Forbidden)?;
    let issuer = state.effective_issuer(context.headers).await?;
    let ip = state.request_ip(context.headers, context.remote_addr).await?;
    let ip = ip.map(|ip| ip.to_string());
    let (req, user, session_id) = (req.clone(), user.clone(), session.id.clone());
    dispatch!(state, |provider, conn, material| {
        let enrolled = state.settings.discovery.axon_admin_v3.as_ref().ok_or(AppError::Forbidden)?;
        let gate = crate::application_discovery::axon_v3_restore::RestoreInterlock::new(
            enrolled.restore_marker_path.clone(), enrolled.restore_marker_owner_uid);
        let pin = material.pin();
        provider::store_incumbent_authorization_code(conn, IncumbentAuthorizationInput {
            state: &state, resolved: &req, issuer: &issuer, ip: ip.as_deref(), credential: &credential,
            session_id: &session_id, user: &user, pin: &pin, approved: &material.policy, gate: &gate,
        }, #[cfg(test)] &|_| Ok(()), #[cfg(test)] &|_| Ok(()))
    })
}

pub(super) async fn exchange(
    state: &AppState, client: &ClientRecord, issuer: String, code: String, redirect: String,
    verifier: Option<String>, resource: Option<String>, details: Option<String>,
    dpop: Option<crate::dpop::DpopBinding>,
) -> AppResult<Option<oidc_token::TokenResponse>> {
    let Some(enrolled) = state.settings.discovery.axon_admin_v3.as_ref() else { return Ok(None); };
    if client.client_id != enrolled.client_id || issuer != enrolled.issuer
        || client.organization_id.as_deref() != Some(&enrolled.organization_id)
    { return Ok(None); }
    let Some(verifier) = verifier else { return Ok(None); };
    let client_id = client.client_id.clone();
    dispatch!(state, |provider, conn, material| {
        let enrolled = state.settings.discovery.axon_admin_v3.as_ref().ok_or(AppError::Forbidden)?;
        let gate = crate::application_discovery::axon_v3_restore::RestoreInterlock::new(
            enrolled.restore_marker_path.clone(), enrolled.restore_marker_owner_uid);
        provider::exchange_incumbent_tokens(conn, &state, &issuer, &gate, &material.pin(),
            &material.policy, &code, &client_id, &redirect, &verifier, resource, details, dpop.as_ref())
            .map(|(_, response)| response)
    })
}
