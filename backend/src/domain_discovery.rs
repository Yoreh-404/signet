use crate::{
    db::ExternalOidcProviderRecord,
    error::{AppError, AppResult},
    security_policy, util,
};
use std::collections::HashMap;

pub trait EmailDomainRoutable {
    fn email_domain_rules(&self) -> AppResult<Vec<String>>;
}

impl EmailDomainRoutable for ExternalOidcProviderRecord {
    fn email_domain_rules(&self) -> AppResult<Vec<String>> {
        normalized_email_domain_rules(&self.email_domains)
    }
}

#[derive(Debug)]
pub struct EmailDomainRoute<'a, P> {
    pub provider: &'a P,
    pub matched_domain: String,
}

pub fn normalized_email_domain_rules(value: &str) -> AppResult<Vec<String>> {
    security_policy::normalize_email_domain_rules(util::from_json::<Vec<String>>(value).map_err(
        |err| AppError::BadRequest(format!("provider email domains are invalid: {err}")),
    )?)
}

pub fn best_matching_rule<'a>(subject: &str, rules: &'a [String]) -> Option<&'a str> {
    let domain = security_policy::email_domain(subject)?;
    rules
        .iter()
        .filter(|rule| {
            security_policy::domain_matches_any(Some(&domain), std::slice::from_ref(rule))
        })
        .max_by_key(|rule| rule.len())
        .map(String::as_str)
}

pub fn find_provider_for_subject<'a, P: EmailDomainRoutable>(
    providers: &'a [P],
    subject: &str,
) -> AppResult<Option<EmailDomainRoute<'a, P>>> {
    let Some(domain) = security_policy::email_domain(subject) else {
        return Ok(None);
    };
    let mut provider_by_rule = HashMap::<String, usize>::new();
    for (provider_index, provider) in providers.iter().enumerate() {
        let rules = provider.email_domain_rules()?;
        for rule in rules {
            provider_by_rule.entry(rule).or_insert(provider_index);
        }
    }

    for (start, _) in domain.char_indices() {
        if start != 0 && domain.as_bytes()[start - 1] != b'.' {
            continue;
        }
        let candidate = &domain[start..];
        let Some(&provider_index) = provider_by_rule.get(candidate) else {
            continue;
        };
        return Ok(Some(EmailDomainRoute {
            provider: &providers[provider_index],
            matched_domain: candidate.to_string(),
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Provider {
        domains: String,
    }

    impl EmailDomainRoutable for Provider {
        fn email_domain_rules(&self) -> AppResult<Vec<String>> {
            normalized_email_domain_rules(&self.domains)
        }
    }

    #[test]
    fn finds_most_specific_provider_for_email_domain() {
        let providers = vec![
            Provider {
                domains: util::to_json(&vec!["example.com".to_string()]).unwrap(),
            },
            Provider {
                domains: util::to_json(&vec!["team.example.com".to_string()]).unwrap(),
            },
        ];

        let route = find_provider_for_subject(&providers, "alice@team.example.com")
            .unwrap()
            .unwrap();

        assert_eq!(route.matched_domain, "team.example.com");
    }

    #[test]
    fn parent_domain_matches_subdomain() {
        let rules =
            security_policy::normalize_email_domain_rules(vec!["example.com".to_string()]).unwrap();

        assert_eq!(
            best_matching_rule("alice@dev.example.com", &rules),
            Some("example.com")
        );
    }

    #[test]
    fn invalid_subject_does_not_match() {
        let rules =
            security_policy::normalize_email_domain_rules(vec!["example.com".to_string()]).unwrap();

        assert_eq!(best_matching_rule("not-an-email", &rules), None);
    }
}
