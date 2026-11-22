use crate::{
    AppState,
    config::{PeerMember, PeerNamespace},
    dcr::authenticate_active_registration,
    error::{AppError, AppResult},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, header::CACHE_CONTROL},
    response::IntoResponse,
};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize)]
struct PeerDirectory<'a> {
    peers: Vec<&'a PeerMember>,
}

fn member_namespace<'a>(
    namespaces: &'a [PeerNamespace],
    namespace_id: &str,
    client_id: &str,
) -> AppResult<&'a PeerNamespace> {
    namespaces
        .iter()
        .find(|ns| ns.id == namespace_id && ns.members.iter().any(|m| m.client_id == client_id))
        .ok_or(AppError::NotFound)
}

pub(crate) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((client_id, namespace_id)): Path<(String, String)>,
) -> AppResult<impl IntoResponse> {
    let caller = authenticate_active_registration(&state, &headers, &client_id).await?;
    let namespace = member_namespace(
        &state.settings.discovery.namespaces,
        &namespace_id,
        &client_id,
    )?;
    let ids: Vec<_> = namespace
        .members
        .iter()
        .map(|m| m.client_id.clone())
        .collect();
    let mut active = HashMap::new();
    for client in state.db.registered_peers(&ids).await? {
        let Some(member) = namespace
            .members
            .iter()
            .find(|m| m.client_id == client.client_id)
        else {
            continue;
        };
        let callbacks: Vec<String> = crate::util::from_json(&client.redirect_uris)?;
        if !callbacks.is_empty()
            && callbacks.iter().all(|uri| {
                url::Url::parse(uri).is_ok_and(|url| {
                    url.scheme() == "https" && url.origin().ascii_serialization() == member.origin
                })
            })
            && state
                .db
                .load_client_runtime_snapshot(&client.id, Some("oauth2_oidc"))
                .await?
                .is_interactive_client_runtime_active()
        {
            active.insert(client.client_id, client.id);
        }
    }
    if active.get(&client_id) != Some(&caller) {
        return Err(AppError::NotFound);
    }
    let peers = namespace
        .members
        .iter()
        .filter(|m| active.contains_key(&m.client_id) && m.client_id != client_id)
        .collect();
    Ok(([(CACHE_CONTROL, "no-store")], Json(PeerDirectory { peers })).into_response())
}
