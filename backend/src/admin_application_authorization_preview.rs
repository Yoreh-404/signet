use super::{
    admin_application_authorization_scope::{
        application_authorization_user, managed_authorization_profile,
    },
    admin_application_scope::managed_application,
};
use crate::{
    AppState, authorization,
    error::{AppError, AppResult},
};
use axum::{
    Json,
    extract::{Path, State},
};
use axum_extra::extract::cookie::CookieJar;

fn entitlements_value(
    entitlements: authorization::ApplicationEntitlements,
) -> AppResult<serde_json::Value> {
    let claims = entitlements.claims.clone();
    let mut value = serde_json::to_value(entitlements).map_err(|error| {
        AppError::Internal(format!("failed to serialize entitlements: {error}"))
    })?;
    if let serde_json::Value::Object(object) = &mut value {
        for (key, claim) in claims {
            object.entry(key).or_insert(claim);
        }
    }
    Ok(value)
}

fn access_decision(
    snapshot: &authorization::AuthorizationPolicySnapshot,
    application_id: &str,
) -> AppResult<authorization::ApplicationAccessDecision> {
    if snapshot.client_id.is_some()
        || snapshot
            .application
            .as_ref()
            .is_none_or(|application| application.id != application_id)
    {
        return Err(AppError::Forbidden);
    }
    let application = snapshot.application.as_ref().ok_or(AppError::Forbidden)?;
    let policy_version = crate::util::sha256_base64url(&format!(
        "signet:application-policy:v2:{}:{}:{}",
        application.id,
        application.updated_at,
        serde_json::to_string(&snapshot.authorization_config).unwrap_or_default()
    ));
    let allowed = application.is_active == 1
        && snapshot.application_runtime_active
        && snapshot.organization_active
        && snapshot.user_active;
    Ok(authorization::ApplicationAccessDecision {
        allowed,
        reason: if allowed {
            "active_account"
        } else {
            "inactive_account_or_tenant"
        },
        policy_version,
    })
}

pub(super) async fn profile(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, user_id)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (_, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let user = application_authorization_user(&state, &application, &user_id).await?;
    let snapshot = state
        .db
        .load_profile_policy_snapshot(&application.id, &profile.id, &user.id)
        .await?;
    let decision = access_decision(&snapshot, &application.id)?;
    let entitlements = if decision.allowed {
        Some(entitlements_value(
            authorization::resolve_entitlements_from_snapshot(&snapshot, &user)?,
        )?)
    } else {
        None
    };
    Ok(Json(
        serde_json::json!({ "decision": decision, "entitlements": entitlements }),
    ))
}

pub(super) async fn application(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, user_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (_, application) = managed_application(&state, &jar, &id).await?;
    let user = application_authorization_user(&state, &application, &user_id).await?;
    let snapshot = state
        .db
        .load_application_policy_snapshot(&application.id, &user.id)
        .await?;
    let decision = access_decision(&snapshot, &application.id)?;
    let entitlements = if decision.allowed {
        Some(entitlements_value(
            authorization::resolve_entitlements_from_snapshot(&snapshot, &user)?,
        )?)
    } else {
        None
    };
    Ok(Json(
        serde_json::json!({ "decision": decision, "entitlements": entitlements }),
    ))
}
