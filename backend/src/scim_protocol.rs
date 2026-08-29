use crate::{
    db::{GroupRecord, ScimGroupMemberRecord, UserRecord},
    util,
};
use axum::http::{HeaderMap, header};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::ScimError;

pub(super) const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub(super) const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub(super) const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScimUser {
    pub(super) schemas: Vec<&'static str>,
    pub(super) id: String,
    pub(super) user_name: String,
    pub(super) active: bool,
    pub(super) name: ScimName,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) display_name: Option<String>,
    pub(super) emails: Vec<ScimEmail>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) phone_numbers: Vec<ScimPhone>,
    pub(super) meta: ScimMeta,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScimName {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) formatted: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ScimEmail {
    pub(super) value: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub(super) kind: Option<String>,
    pub(super) primary: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ScimPhone {
    pub(super) value: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub(super) kind: Option<String>,
    pub(super) primary: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ListResponse<T> {
    pub(super) schemas: Vec<&'static str>,
    pub(super) total_results: usize,
    pub(super) start_index: usize,
    pub(super) items_per_page: usize,
    #[serde(rename = "Resources")]
    pub(super) resources: Vec<T>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScimMeta {
    pub(super) resource_type: &'static str,
    pub(super) created: String,
    pub(super) last_modified: String,
    pub(super) location: String,
    pub(super) version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScimGroup {
    schemas: Vec<&'static str>,
    id: String,
    display_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    members: Vec<ScimMember>,
    meta: ScimMeta,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(super) struct ScimMember {
    pub(super) value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) display: Option<String>,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub(super) ref_: Option<String>,
}

pub(super) trait ScimUserMapper {
    fn to_scim_user(&self, base_url: &str) -> ScimUser;
}

impl ScimUserMapper for UserRecord {
    fn to_scim_user(&self, base_url: &str) -> ScimUser {
        ScimUser {
            schemas: vec![USER_SCHEMA],
            id: self.id.clone(),
            user_name: self.username.clone(),
            active: self.is_active == 1 && self.archived_at.is_none(),
            name: ScimName {
                formatted: self.display_name.clone(),
            },
            display_name: self.display_name.clone(),
            emails: vec![ScimEmail {
                value: self.email.clone(),
                kind: Some("work".to_string()),
                primary: true,
            }],
            phone_numbers: self
                .phone
                .clone()
                .map(|phone| {
                    vec![ScimPhone {
                        value: phone,
                        kind: Some("work".to_string()),
                        primary: true,
                    }]
                })
                .unwrap_or_default(),
            meta: ScimMeta {
                resource_type: "User",
                created: iso_ts(self.created_at),
                last_modified: iso_ts(self.updated_at),
                location: format!("{base_url}/scim/v2/Users/{}", self.id),
                version: self.scim_concurrency_version(),
            },
        }
    }
}

pub(super) fn group_members_from_users(
    group_id: &str,
    users: Vec<UserRecord>,
) -> Vec<ScimGroupMemberRecord> {
    users
        .into_iter()
        .map(|user| ScimGroupMemberRecord {
            group_id: group_id.to_string(),
            user_id: user.id,
            username: user.username,
            display_name: user.display_name,
        })
        .collect()
}

pub(super) fn group_to_scim_with_members(
    base_url: &str,
    group: &GroupRecord,
    members: Vec<ScimGroupMemberRecord>,
) -> ScimGroup {
    let location = format!("{base_url}/scim/v2/Groups/{}", group.id);
    let members = members
        .into_iter()
        .map(|member| ScimMember {
            ref_: Some(format!("{base_url}/scim/v2/Users/{}", member.user_id)),
            display: member.display_name.or(Some(member.username)),
            value: member.user_id,
        })
        .collect();
    ScimGroup {
        schemas: vec![GROUP_SCHEMA],
        id: group.id.clone(),
        display_name: group.name.clone(),
        members,
        meta: ScimMeta {
            resource_type: "Group",
            created: iso_ts(group.created_at),
            last_modified: iso_ts(group.updated_at),
            location,
            version: group.version.to_string(),
        },
    }
}

pub(super) fn iso_ts(value: i64) -> String {
    DateTime::<Utc>::from_timestamp(value, 0)
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
        .to_rfc3339()
}

pub(super) fn member_ids(members: Vec<ScimMember>) -> Vec<String> {
    members
        .into_iter()
        .map(|member| member.value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

pub(super) fn generated_scim_password() -> String {
    format!("Scim-{}9!", util::random_token(24))
}

pub(super) fn normalize_path(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .split('[')
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase()
}

pub(super) fn etag_for_serializable<T: Serialize>(value: &T) -> String {
    let body = serde_json::to_vec(value).unwrap_or_default();
    format!(
        "\"{}\"",
        util::sha256_base64url(&String::from_utf8_lossy(&body))
    )
}

pub(super) fn ensure_if_match(headers: &HeaderMap, current_etag: &str) -> Result<(), ScimError> {
    let Some(raw) = headers.get(header::IF_MATCH) else {
        return Ok(());
    };
    let value = raw
        .to_str()
        .map_err(|_| ScimError::bad_request("invalidValue", "If-Match is not valid ASCII"))?;
    if value
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate == current_etag)
    {
        Ok(())
    } else {
        Err(ScimError::conflict(
            "the SCIM resource changed; refetch it and retry with its current ETag",
        ))
    }
}
