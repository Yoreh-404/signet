use super::{application_authorization_user, managed_application, managed_authorization_profile};
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

pub(super) async fn profile(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, profile_id, user_id)): Path<(String, String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let (_, application, profile) =
        managed_authorization_profile(&state, &jar, &id, &profile_id).await?;
    let user = application_authorization_user(&state, &application, &user_id).await?;
    let decision = authorization::check_login_access(&state, &application, &user.id).await?;
    let entitlements = if decision.allowed {
        Some(entitlements_value(
            authorization::resolve_entitlements_for_profile(&state, &application, &profile, &user)
                .await?,
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
    let decision = authorization::check_login_access(&state, &application, &user.id).await?;
    let entitlements = if decision.allowed {
        Some(entitlements_value(
            authorization::resolve_entitlements(&state, &application, &user).await?,
        )?)
    } else {
        None
    };
    Ok(Json(
        serde_json::json!({ "decision": decision, "entitlements": entitlements }),
    ))
}
