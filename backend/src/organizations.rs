use crate::{
    db::OrganizationRecord,
    error::{AppError, AppResult},
    security_policy, util,
};
use serde::{Deserialize, Serialize};

pub const ROLE_OWNER: &str = "owner";
pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_MEMBER: &str = "member";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRole {
    Owner,
    Admin,
    Member,
}

impl OrganizationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            OrganizationRole::Owner => ROLE_OWNER,
            OrganizationRole::Admin => ROLE_ADMIN,
            OrganizationRole::Member => ROLE_MEMBER,
        }
    }
}

impl TryFrom<&str> for OrganizationRole {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.trim().to_ascii_lowercase().as_str() {
            ROLE_OWNER => Ok(OrganizationRole::Owner),
            ROLE_ADMIN => Ok(OrganizationRole::Admin),
            ROLE_MEMBER => Ok(OrganizationRole::Member),
            other => Err(AppError::BadRequest(format!(
                "unknown organization role: {other}"
            ))),
        }
    }
}

pub fn normalize_slug(value: &str) -> AppResult<String> {
    let slug = value.trim().to_ascii_lowercase();
    if slug.len() < 2 || slug.len() > 64 {
        return Err(AppError::BadRequest(
            "organization slug must be 2-64 characters".to_string(),
        ));
    }
    let valid = slug
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        && slug
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && slug
            .chars()
            .last()
            .is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit());
    if !valid || slug.contains("--") {
        return Err(AppError::BadRequest(
            "organization slug must contain lowercase letters, digits, and single hyphens"
                .to_string(),
        ));
    }
    Ok(slug)
}

pub fn normalize_name(value: &str) -> AppResult<String> {
    let name = value.trim().to_string();
    if name.is_empty() || name.len() > 160 {
        return Err(AppError::BadRequest(
            "organization name must be 1-160 characters".to_string(),
        ));
    }
    Ok(name)
}

pub fn normalize_role(value: &str) -> AppResult<String> {
    OrganizationRole::try_from(value).map(|role| role.as_str().to_string())
}

pub trait OrganizationEmailPolicy {
    fn allowed_email_domains(&self) -> AppResult<Vec<String>>;

    fn allows_email(&self, email: &str) -> AppResult<bool> {
        let domains = self.allowed_email_domains()?;
        Ok(domains.is_empty()
            || security_policy::domain_matches_any(
                security_policy::email_domain(email).as_deref(),
                &domains,
            ))
    }
}

impl OrganizationEmailPolicy for OrganizationRecord {
    fn allowed_email_domains(&self) -> AppResult<Vec<String>> {
        security_policy::normalize_email_domain_rules(
            util::from_json::<Vec<String>>(&self.allowed_email_domains).map_err(|err| {
                AppError::BadRequest(format!(
                    "organization email domain rules are invalid: {err}"
                ))
            })?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn organization_record(domains: Vec<&str>) -> OrganizationRecord {
        OrganizationRecord {
            id: "org-id".to_string(),
            slug: "corp".to_string(),
            name: "Corp".to_string(),
            description: None,
            allowed_email_domains: util::to_json(
                &domains.into_iter().map(str::to_string).collect::<Vec<_>>(),
            )
            .unwrap(),
            is_active: 1,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn slug_requires_dns_like_safe_value() {
        assert_eq!(normalize_slug(" Acme-01 ").unwrap(), "acme-01");
        assert!(normalize_slug("-acme").is_err());
        assert!(normalize_slug("acme--inc").is_err());
        assert!(normalize_slug("a").is_err());
    }

    #[test]
    fn roles_are_normalized() {
        assert_eq!(normalize_role("Owner").unwrap(), ROLE_OWNER);
        assert_eq!(normalize_role("admin").unwrap(), ROLE_ADMIN);
        assert!(normalize_role("root").is_err());
    }

    #[test]
    fn email_policy_matches_parent_domains() {
        let organization = organization_record(vec!["example.com"]);

        assert!(organization.allows_email("alice@team.example.com").unwrap());
        assert!(!organization.allows_email("alice@other.test").unwrap());
    }

    #[test]
    fn empty_email_policy_allows_any_domain() {
        let organization = organization_record(Vec::new());

        assert!(organization.allows_email("alice@other.test").unwrap());
    }
}
