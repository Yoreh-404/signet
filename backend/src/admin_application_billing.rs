use super::{
    AppResult, AppState, CookieJar, Json, NewApplicationBillingSettings, Path, State,
    admin_application_scope::managed_application, audit, billing, util,
};
use crate::audit::AuditSink;

pub(super) async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<billing::ApplicationBillingSettingsResponse>> {
    let (_current, _application) = managed_application(&state, &jar, &id).await?;
    let settings = state.db.ensure_application_billing_settings(&id).await?;
    Ok(Json(billing::application_billing_settings_response(
        settings,
    )?))
}

pub(super) async fn update(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<billing::ApplicationBillingSettingsInput>,
) -> AppResult<Json<billing::ApplicationBillingSettingsResponse>> {
    let (current, application) = managed_application(&state, &jar, &id).await?;
    let (accept_signet_balance, wallet_mode, supported_currencies) =
        billing::normalize_application_billing_input(&state.settings, payload)?;
    let settings = state
        .db
        .upsert_application_billing_settings(NewApplicationBillingSettings {
            application_id: id.clone(),
            accept_signet_balance,
            wallet_mode,
            supported_currencies,
        })
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "application.billing_settings.update",
            "application",
            Some(id),
            serde_json::json!({
                "organization_id": application.organization_id,
                "accept_signet_balance": settings.accept_signet_balance == 1,
                "wallet_mode": settings.wallet_mode,
                "supported_currencies": util::from_json::<Vec<String>>(&settings.supported_currencies)?,
            }),
        ))
        .await?;
    Ok(Json(billing::application_billing_settings_response(
        settings,
    )?))
}
