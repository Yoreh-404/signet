use super::{LoginSettingsRecord, OrganizationMemberInput, QuickLink};
use crate::{access::Permission, error::AppResult, util};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub(super) fn merge_missing_quick_links(
    existing: &LoginSettingsRecord,
    defaults: &[QuickLink],
) -> AppResult<Option<String>> {
    let mut links = util::from_json::<Vec<QuickLink>>(&existing.quick_links)?;
    let mut ids = links
        .iter()
        .map(|link| link.id.clone())
        .collect::<HashSet<_>>();
    let mut urls = links
        .iter()
        .map(|link| link.url.clone())
        .collect::<HashSet<_>>();
    let mut changed = false;
    for default in defaults {
        if ids.contains(&default.id) || urls.contains(&default.url) {
            continue;
        }
        ids.insert(default.id.clone());
        urls.insert(default.url.clone());
        links.push(default.clone());
        changed = true;
    }
    changed.then(|| util::to_json(&links)).transpose()
}

pub(super) fn dedupe_nonempty(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn dedupe_organization_members(
    members: Vec<OrganizationMemberInput>,
) -> Vec<OrganizationMemberInput> {
    members
        .into_iter()
        .map(|member| OrganizationMemberInput {
            user_id: member.user_id.trim().to_string(),
            role: member.role.trim().to_string(),
        })
        .filter(|member| !member.user_id.is_empty() && !member.role.is_empty())
        .map(|member| (member.user_id.clone(), member))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

pub(super) fn normalize_permission_keys(values: Vec<String>) -> AppResult<Vec<String>> {
    let mut keys = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        keys.insert(Permission::try_from(trimmed)?.as_str().to_string());
    }
    Ok(keys.into_iter().collect())
}

pub(super) fn normalize_application_entitlement_keys(
    values: Vec<String>,
) -> AppResult<Vec<String>> {
    let mut keys = BTreeSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if value.len() > 256
            || value
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace())
            || value.split(':').any(str::is_empty)
        {
            return Err(crate::error::AppError::BadRequest(
                "application permission key is invalid".to_string(),
            ));
        }
        keys.insert(value.to_string());
    }
    Ok(keys.into_iter().collect())
}

pub(super) fn application_slug_base(client_id: &str) -> String {
    let normalized = client_id.trim().to_ascii_lowercase();
    let mut base = String::with_capacity(normalized.len());
    let mut previous_was_separator = false;
    for character in normalized.chars() {
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            base.push(character);
            previous_was_separator = false;
        } else if !previous_was_separator {
            base.push('-');
            previous_was_separator = true;
        }
    }
    let mut base = base.trim_matches('-').to_string();
    if base.len() < 2 {
        base = format!(
            "app-{}",
            util::sha256_base64url(client_id)
                .chars()
                .take(10)
                .collect::<String>()
        );
    }
    base.truncate(54);
    if client_id.trim() != base {
        return application_slug_collision_candidate(&base, client_id);
    }
    base
}

pub(super) fn application_slug_collision_candidate(base_slug: &str, client_id: &str) -> String {
    let suffix = util::sha256_base64url(client_id)
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(10)
        .collect::<String>();
    let mut prefix = base_slug.to_string();
    prefix.truncate(52);
    format!("{prefix}-{suffix}")
}
