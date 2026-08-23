use crate::db::ClientGrantRecord;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy)]
pub struct OidcConsentPolicy {
    skip_consent: bool,
}

impl OidcConsentPolicy {
    pub fn new(skip_consent: bool) -> Self {
        Self { skip_consent }
    }

    pub fn requires_prompt(
        self,
        existing: Option<&ClientGrantRecord>,
        requested_scopes: &[String],
    ) -> bool {
        if self.skip_consent {
            return false;
        }
        !existing
            .filter(|record| record.revoked_at.is_none())
            .is_some_and(|record| grants_all(&record.granted_scopes, requested_scopes))
    }
}

pub fn merged_granted_scopes(
    existing: Option<&ClientGrantRecord>,
    requested_scopes: &[String],
) -> String {
    let mut scopes = BTreeSet::new();
    if let Some(record) = existing.filter(|record| record.revoked_at.is_none()) {
        scopes.extend(scope_set(&record.granted_scopes));
    }
    scopes.extend(requested_scopes.iter().map(String::as_str));
    scopes.into_iter().collect::<Vec<_>>().join(" ")
}

pub fn canonical_scopes(scopes: &[String]) -> String {
    scopes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(" ")
}

fn grants_all(granted_scopes: &str, requested_scopes: &[String]) -> bool {
    let granted = scope_set(granted_scopes);
    requested_scopes
        .iter()
        .all(|scope| granted.contains(scope.as_str()))
}

fn scope_set(scopes: &str) -> BTreeSet<&str> {
    scopes
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consent(scopes: &str) -> ClientGrantRecord {
        ClientGrantRecord {
            user_id: "user".to_string(),
            client_id: "client".to_string(),
            granted_scopes: scopes.to_string(),
            granted_at: 1,
            updated_at: 1,
            revoked_at: None,
        }
    }

    #[test]
    fn policy_skips_when_disabled() {
        let requested = vec!["openid".to_string(), "email".to_string()];
        assert!(!OidcConsentPolicy::new(true).requires_prompt(None, &requested));
    }

    #[test]
    fn policy_prompts_for_new_scope() {
        let requested = vec!["openid".to_string(), "email".to_string()];
        assert!(
            OidcConsentPolicy::new(false).requires_prompt(Some(&consent("openid")), &requested)
        );
        assert!(
            !OidcConsentPolicy::new(false)
                .requires_prompt(Some(&consent("openid email profile")), &requested)
        );
    }

    #[test]
    fn merge_grants_union() {
        let requested = vec!["email".to_string(), "profile".to_string()];
        assert_eq!(
            merged_granted_scopes(Some(&consent("openid email")), &requested),
            "email openid profile"
        );
    }
}
