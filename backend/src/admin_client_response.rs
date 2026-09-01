use super::admin_management_scope::current_organization_client_manager;
use crate::{
    AppState,
    db::{ClientRecord, PublicClient, PublicClientClaimMapper},
    error::AppResult,
};
use axum::{Json, extract::State};
use axum_extra::extract::cookie::CookieJar;

pub(crate) async fn list_clients(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<PublicClient>>> {
    let (_, organization) = current_organization_client_manager(&state, &jar, false).await?;
    let clients = state
        .db
        .list_clients_for_organization(&organization.id)
        .await?;
    let client_ids = clients
        .iter()
        .map(|client| client.id.clone())
        .collect::<Vec<_>>();
    let mut mappers_by_client = state
        .db
        .list_client_claim_mappers_by_client_ids(&client_ids)
        .await?;
    let clients = clients
        .into_iter()
        .map(|client| {
            let claim_mappers = mappers_by_client
                .remove(&client.id)
                .unwrap_or_default()
                .into_iter()
                .map(|mapper| mapper.public())
                .collect();
            public_client_from_context(
                &client,
                Some((&organization.slug, &organization.name)),
                claim_mappers,
            )
        })
        .collect::<AppResult<Vec<_>>>()?;
    Ok(Json(clients))
}

pub(crate) fn public_client_from_context(
    client: &ClientRecord,
    organization: Option<(&str, &str)>,
    claim_mappers: Vec<PublicClientClaimMapper>,
) -> AppResult<PublicClient> {
    let mut public = client.clone().public()?;
    if let Some((slug, name)) = organization {
        public.organization_slug = Some(slug.to_string());
        public.organization_name = Some(name.to_string());
    }
    public.claim_mappers = claim_mappers;
    Ok(public)
}

pub(crate) async fn public_client_with_claim_mappers(
    state: &AppState,
    client: ClientRecord,
) -> AppResult<PublicClient> {
    let mappers = state
        .db
        .list_client_claim_mappers(&client.id)
        .await?
        .into_iter()
        .map(|mapper| mapper.public())
        .collect::<Vec<PublicClientClaimMapper>>();
    let organization = if let Some(organization_id) = client.organization_id.as_deref() {
        state.db.find_organization_by_id(organization_id).await?
    } else {
        None
    };
    public_client_from_context(
        &client,
        organization
            .as_ref()
            .map(|organization| (organization.slug.as_str(), organization.name.as_str())),
        mappers,
    )
}
