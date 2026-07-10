use crate::{
    AppState,
    db::{LdapProviderRecord, NewUser, UserRecord},
    error::{AppError, AppResult},
    util,
};
use ldap3::{LdapConnAsync, LdapConnSettings, ResultEntry, Scope, SearchEntry, ldap_escape};
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct DirectoryProfile {
    pub provider_key: String,
    pub subject: String,
    pub email: String,
    pub username: String,
    pub display_name: Option<String>,
    pub phone: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DirectoryLogin {
    pub user: UserRecord,
    pub provider_key: String,
}

#[allow(async_fn_in_trait)]
pub trait DirectoryAuthenticator {
    async fn authenticate(
        &self,
        provider: &LdapProviderRecord,
        login: &str,
        password: &str,
    ) -> AppResult<Option<DirectoryProfile>>;
}

#[derive(Debug, Clone, Copy)]
pub struct LdapDirectoryAuthenticator;

impl DirectoryAuthenticator for LdapDirectoryAuthenticator {
    async fn authenticate(
        &self,
        provider: &LdapProviderRecord,
        login: &str,
        password: &str,
    ) -> AppResult<Option<DirectoryProfile>> {
        if password.is_empty() {
            return Ok(None);
        }
        let mut settings = LdapConnSettings::new();
        if provider.starttls == 1 {
            settings = settings.set_starttls(true);
        }
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &provider.url)
            .await
            .map_err(directory_error)?;
        ldap3::drive!(conn);
        if !provider.bind_dn.trim().is_empty() {
            ldap.simple_bind(&provider.bind_dn, &provider.bind_password)
                .await
                .map_err(directory_error)?
                .success()
                .map_err(directory_error)?;
        }
        let filter = user_filter(provider, login);
        let attrs = provider_attrs(provider);
        let (entries, _result) = ldap
            .search(&provider.base_dn, Scope::Subtree, &filter, attrs)
            .await
            .map_err(directory_error)?
            .success()
            .map_err(directory_error)?;
        let Some(entry) = single_search_entry(entries)? else {
            let _ = ldap.unbind().await;
            return Ok(None);
        };
        let dn = entry.dn.clone();
        let profile = profile_from_entry(provider, entry)?;
        let bind_result = ldap.simple_bind(&dn, password).await;
        let _ = ldap.unbind().await;
        match bind_result {
            Ok(result) => {
                if result.success().is_ok() {
                    Ok(Some(profile))
                } else {
                    Ok(None)
                }
            }
            Err(err) => {
                tracing::warn!(provider = %provider.slug, error = %err, "LDAP user bind failed");
                Ok(None)
            }
        }
    }
}

pub async fn authenticate_with_configured_directories(
    state: &AppState,
    login: &str,
    password: &str,
) -> AppResult<Option<DirectoryLogin>> {
    authenticate_with_directories(state, login, password, &LdapDirectoryAuthenticator).await
}

pub async fn authenticate_with_directories<A: DirectoryAuthenticator>(
    state: &AppState,
    login: &str,
    password: &str,
    authenticator: &A,
) -> AppResult<Option<DirectoryLogin>> {
    for provider in state.db.list_ldap_providers().await? {
        if provider.is_active != 1 || provider.allow_login != 1 {
            continue;
        }
        let profile = match authenticator.authenticate(&provider, login, password).await {
            Ok(Some(profile)) => profile,
            Ok(None) => continue,
            Err(err) => {
                tracing::warn!(provider = %provider.slug, error = %err, "LDAP provider authentication failed");
                continue;
            }
        };
        return resolve_directory_user(state, &provider, profile)
            .await
            .map(Some);
    }
    Ok(None)
}

async fn resolve_directory_user(
    state: &AppState,
    provider: &LdapProviderRecord,
    profile: DirectoryProfile,
) -> AppResult<DirectoryLogin> {
    let existing_identity = state
        .db
        .find_linked_identity(&profile.provider_key, &profile.subject)
        .await?;
    let registration = state.db.registration_settings().await?.public();
    let first_user = state.db.user_count().await? == 0;
    let user = if let Some(identity) = existing_identity {
        state
            .db
            .find_user_by_id(&identity.user_id)
            .await?
            .ok_or(AppError::Unauthorized)?
    } else {
        if !can_create_directory_user(
            first_user,
            registration.allow_external_oidc_registration,
            provider.allow_registration == 1,
        ) {
            return Err(AppError::Forbidden);
        }
        let email = crate::security_policy::normalize_login_subject(&profile.email);
        if state.db.find_user_by_email(&email).await?.is_some() {
            return Err(AppError::Forbidden);
        }
        state
            .db
            .insert_external_oidc_user(
                NewUser {
                    email: email.clone(),
                    username: unique_directory_username(&profile.username, &profile.subject),
                    display_name: profile.display_name,
                    phone: profile.phone,
                    password_hash: util::hash_password(&util::random_token(32))?,
                    email_verified_at: Some(util::now_ts()),
                    phone_verified_at: None,
                    is_admin: crate::db::registered_user_is_admin(first_user),
                    is_active: registration.default_user_active || first_user,
                    archived_at: None,
                },
                &profile.provider_key,
                &profile.subject,
                Some(email),
                None,
                first_user,
            )
            .await?
    };
    if user.is_active != 1 || user.archived_at.is_some() {
        return Err(AppError::Unauthorized);
    }
    Ok(DirectoryLogin {
        user,
        provider_key: provider.provider_key(),
    })
}

fn user_filter(provider: &LdapProviderRecord, login: &str) -> String {
    provider
        .user_filter
        .replace("{login}", ldap_escape(login).as_ref())
}

fn provider_attrs(provider: &LdapProviderRecord) -> Vec<String> {
    let mut attrs = BTreeSet::new();
    for attr in [
        provider.user_id_attribute.as_str(),
        provider.email_attribute.as_str(),
        provider.username_attribute.as_str(),
        provider.display_name_attribute.as_str(),
        provider.phone_attribute.as_str(),
    ] {
        let attr = attr.trim();
        if !attr.is_empty() && !attr.eq_ignore_ascii_case("dn") {
            attrs.insert(attr.to_string());
        }
    }
    attrs.into_iter().collect()
}

fn single_search_entry(entries: Vec<ResultEntry>) -> AppResult<Option<SearchEntry>> {
    let mut entries = entries.into_iter().map(SearchEntry::construct);
    let Some(entry) = entries.next() else {
        return Ok(None);
    };
    if entries.next().is_some() {
        return Err(AppError::Unauthorized);
    }
    Ok(Some(entry))
}

fn profile_from_entry(
    provider: &LdapProviderRecord,
    entry: SearchEntry,
) -> AppResult<DirectoryProfile> {
    let subject =
        attr_or_dn(&entry, &provider.user_id_attribute).ok_or_else(|| AppError::Unauthorized)?;
    let email = attr(&entry, &provider.email_attribute).ok_or_else(|| AppError::Unauthorized)?;
    let username = attr(&entry, &provider.username_attribute)
        .or_else(|| email.split('@').next().map(ToOwned::to_owned))
        .unwrap_or_else(|| "directory-user".to_string());
    Ok(DirectoryProfile {
        provider_key: provider.provider_key(),
        subject,
        email,
        username,
        display_name: attr(&entry, &provider.display_name_attribute),
        phone: attr(&entry, &provider.phone_attribute),
    })
}

fn attr_or_dn(entry: &SearchEntry, name: &str) -> Option<String> {
    if name.trim().eq_ignore_ascii_case("dn") {
        Some(entry.dn.clone())
    } else {
        attr(entry, name)
    }
}

fn attr(entry: &SearchEntry, name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    entry
        .attrs
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, values)| values.first())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn can_create_directory_user(
    first_user: bool,
    global_allows_external_registration: bool,
    provider_allows_registration: bool,
) -> bool {
    provider_allows_registration && (first_user || global_allows_external_registration)
}

fn unique_directory_username(username: &str, subject: &str) -> String {
    let base = username
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .collect::<String>();
    let base = if base.is_empty() {
        "directory-user".to_string()
    } else {
        base
    };
    format!(
        "{}-{}",
        base,
        util::sha256_base64url(subject)
            .chars()
            .take(8)
            .collect::<String>()
    )
}

fn directory_error(err: ldap3::LdapError) -> AppError {
    AppError::Internal(format!("LDAP operation failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn provider() -> LdapProviderRecord {
        LdapProviderRecord {
            id: "id".to_string(),
            slug: "corp".to_string(),
            display_name: "Corp LDAP".to_string(),
            url: "ldap://ldap.example.com".to_string(),
            starttls: 1,
            bind_dn: "cn=reader,dc=example,dc=com".to_string(),
            bind_password: "secret".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            user_filter: "(&(objectClass=person)(|(mail={login})(uid={login})))".to_string(),
            user_id_attribute: "dn".to_string(),
            email_attribute: "mail".to_string(),
            username_attribute: "uid".to_string(),
            display_name_attribute: "cn".to_string(),
            phone_attribute: "telephoneNumber".to_string(),
            is_active: 1,
            allow_login: 1,
            allow_registration: 1,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn filter_escapes_login_literal() {
        let provider = provider();
        let filter = user_filter(&provider, "a*)(uid=*)");
        assert!(filter.contains(r"a\2a\29\28uid=\2a\29"));
    }

    #[test]
    fn attrs_are_deduplicated_and_skip_dn() {
        let mut provider = provider();
        provider.username_attribute = "mail".to_string();
        let attrs = provider_attrs(&provider);
        assert_eq!(attrs, vec!["cn", "mail", "telephoneNumber"]);
    }

    #[test]
    fn profile_uses_dn_subject_and_case_insensitive_attrs() {
        let provider = provider();
        let entry = SearchEntry {
            dn: "uid=alice,dc=example,dc=com".to_string(),
            attrs: HashMap::from([
                ("MAIL".to_string(), vec!["alice@example.com".to_string()]),
                ("uid".to_string(), vec!["alice".to_string()]),
                ("cn".to_string(), vec!["Alice".to_string()]),
            ]),
            bin_attrs: HashMap::new(),
        };
        let profile = profile_from_entry(&provider, entry).unwrap();

        assert_eq!(profile.provider_key, "ldap:corp");
        assert_eq!(profile.subject, "uid=alice,dc=example,dc=com");
        assert_eq!(profile.email, "alice@example.com");
        assert_eq!(profile.username, "alice");
        assert_eq!(profile.display_name.as_deref(), Some("Alice"));
    }

    #[test]
    fn directory_registration_requires_global_or_first_user_and_provider_switch() {
        assert!(can_create_directory_user(true, false, true));
        assert!(can_create_directory_user(false, true, true));
        assert!(!can_create_directory_user(false, false, true));
        assert!(!can_create_directory_user(true, true, false));
    }
}
