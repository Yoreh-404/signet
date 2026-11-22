//! Public, opt-in Signet project discovery.
//!
//! A workspace is the existing organization ownership boundary. A short name
//! is unique *within* that workspace, not across all tenants. This route never
//! returns OAuth clients, registration settings, module secrets, or disabled
//! website-managed discovery entries.

use crate::{AppState, applications, db::public_directory::PublicDirectoryCandidate, error::{AppError, AppResult}, organizations};
use axum::{Json, Router, extract::{Path, Query, State}, routing::get};
use serde::{Deserialize, Serialize};

const MAX_RESULTS: usize = 50;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/directory/resolve", get(resolve))
        .route("/api/directory/shared-authentication", get(shared_authentication))
        .route("/api/directory/workspaces/{workspace}/projects", get(workspace_projects))
        .route("/api/directory/workspaces/{workspace}/projects/{short_name}", get(workspace_project))
}

#[derive(Debug, Serialize)]
struct PublicAuthenticationProvider {
    id: String,
    slug: String,
    name: String,
}

/// Platform-owned connectors are reusable across websites. Only public
/// identifying metadata is exposed here; credentials, internal endpoints,
/// secret references, and tenant-owned connectors are never returned.
async fn shared_authentication(
    State(state): State<AppState>,
) -> AppResult<Json<Vec<PublicAuthenticationProvider>>> {
    let result = state.db.list_external_oidc_providers().await?
        .into_iter()
        .filter(|provider| provider.organization_id.is_none()
            && provider.is_active == 1 && provider.allow_login == 1)
        .take(100)
        .map(|provider| PublicAuthenticationProvider {
            id: provider.id,
            slug: provider.slug,
            name: provider.display_name,
        })
        .collect::<Vec<_>>();
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveQuery {
    name: String,
    workspace: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct PublicProject {
    workspace: String,
    workspace_name: String,
    short_name: String,
    name: String,
    description: Option<String>,
    website_url: String,
}

#[derive(Debug, Serialize)]
struct DirectoryResponse {
    matches: Vec<PublicProject>,
    ambiguous: bool,
    truncated: bool,
}

fn published_project(row: PublicDirectoryCandidate) -> Option<PublicProject> {
    let config: serde_json::Value = serde_json::from_str(&row.directory_config_json).ok()?;
    let config = applications::normalize_module_config("directory", config).ok()?;
    if config.get("listed").and_then(serde_json::Value::as_bool) != Some(true) {
        return None;
    }
    let mut website_url = config.get("website_url")?.as_str()?.to_owned();
    if row.discovery_management_mode.as_deref()
        == Some(crate::application_discovery::MANAGEMENT_MODE_WEBSITE)
    {
        // A workspace operator cannot publish a private website or
        // substitute an unrelated URL: the verified website snapshot is the
        // authoritative source of its directory metadata.
        let site_snapshot: serde_json::Value = serde_json::from_str(
            row.website_snapshot_json.as_deref()?
        ).ok()?;
        let signed = applications::normalize_module_config(
            "directory", site_snapshot.pointer("/modules/directory")?.clone()
        ).ok()?;
        if signed.get("listed").and_then(serde_json::Value::as_bool) != Some(true) {
            return None;
        }
        website_url = signed.get("website_url")?.as_str()?.to_owned();
    }
    Some(PublicProject {
        workspace: row.workspace,
        workspace_name: row.workspace_name,
        short_name: row.short_name,
        name: row.name,
        description: row.description,
        website_url,
    })
}

async fn search(
    state: &AppState,
    name: Option<&str>,
    workspace: Option<&str>,
) -> AppResult<DirectoryResponse> {
    let candidates = state.db.public_directory_candidates(name, workspace).await?;
    let mut matches = candidates.into_iter().filter_map(published_project).collect::<Vec<_>>();
    let truncated = matches.len() > MAX_RESULTS;
    matches.truncate(MAX_RESULTS);
    Ok(DirectoryResponse {
        ambiguous: matches.len() > 1,
        truncated,
        matches,
    })
}

async fn resolve(
    State(state): State<AppState>,
    Query(query): Query<ResolveQuery>,
) -> AppResult<Json<DirectoryResponse>> {
    let name = applications::normalize_application_slug(&query.name)?;
    let workspace = query.workspace.map(|value| organizations::normalize_slug(&value)).transpose()?;
    Ok(Json(search(&state, Some(&name), workspace.as_deref()).await?))
}

async fn workspace_projects(
    State(state): State<AppState>,
    Path(workspace): Path<String>,
) -> AppResult<Json<DirectoryResponse>> {
    let workspace = organizations::normalize_slug(&workspace)?;
    Ok(Json(search(&state, None, Some(&workspace)).await?))
}

async fn workspace_project(
    State(state): State<AppState>,
    Path((workspace, short_name)): Path<(String, String)>,
) -> AppResult<Json<PublicProject>> {
    let workspace = organizations::normalize_slug(&workspace)?;
    let short_name = applications::normalize_application_slug(&short_name)?;
    search(&state, Some(&short_name), Some(&workspace))
        .await?
        .matches
        .into_iter()
        .next()
        .map(Json)
        .ok_or(AppError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(workspace: &str, listed: bool, website_url: &str) -> PublicDirectoryCandidate {
        PublicDirectoryCandidate {
            workspace: workspace.into(),
            workspace_name: format!("{workspace} Workspace"),
            short_name: "axon".into(),
            name: "Axon".into(),
            description: None,
            directory_config_json: serde_json::json!({
                "listed": listed,
                "website_url": website_url,
            }).to_string(),
            discovery_management_mode: None,
            website_snapshot_json: None,
        }
    }

    #[test]
    fn the_same_short_name_is_allowed_in_separate_workspaces() {
        let first = published_project(candidate("team-a", true, "https://a.example.org")).unwrap();
        let second = published_project(candidate("team-b", true, "https://b.example.org")).unwrap();
        assert_eq!(first.short_name, second.short_name);
        assert_ne!(first.workspace, second.workspace);
        assert_ne!(first.website_url, second.website_url);
    }

    #[test]
    fn private_or_invalid_directory_entries_are_never_disclosed() {
        assert!(published_project(candidate("private", false, "https://private.example.org")).is_none());
        assert!(published_project(candidate("evil", true, "http://insecure.example.org")).is_none());
        assert!(published_project(candidate("evil", true, "https://user:pass@evil.example.org")).is_none());
    }

    #[test]
    fn website_managed_project_cannot_be_listed_without_site_consent() {
        let mut project = candidate("team-a", true, "https://operator.example.org");
        project.discovery_management_mode = Some("website_managed".into());
        assert!(published_project(project).is_none());
        let mut project = candidate("team-a", true, "https://operator.example.org");
        project.discovery_management_mode = Some("website_managed".into());
        project.website_snapshot_json = Some(serde_json::json!({
            "modules": {
                "directory": {"listed": true, "website_url": "https://site.example.org"}
            }
        }).to_string());
        let listed = published_project(project).unwrap();
        assert_eq!(listed.website_url, "https://site.example.org");
    }
}
