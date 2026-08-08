use crate::{
    db::{ClientRecord, UserRecord},
    error::{AppError, AppResult},
    util,
};
use url::Url;

pub const SUBJECT_TYPE_PUBLIC: &str = "public";
pub const SUBJECT_TYPE_PAIRWISE: &str = "pairwise";

pub struct SubjectContext<'a> {
    pub issuer: &'a str,
    pub user: &'a UserRecord,
    pub client: &'a ClientRecord,
}

pub trait SubjectIdentifier {
    fn subject(&self, context: &SubjectContext<'_>) -> AppResult<String>;
}

pub struct PublicSubjectIdentifier;

impl SubjectIdentifier for PublicSubjectIdentifier {
    fn subject(&self, context: &SubjectContext<'_>) -> AppResult<String> {
        Ok(context.user.id.clone())
    }
}

pub struct PairwiseSubjectIdentifier;

impl SubjectIdentifier for PairwiseSubjectIdentifier {
    fn subject(&self, context: &SubjectContext<'_>) -> AppResult<String> {
        let sector = sector_identifier(context.client)?;
        Ok(util::sha256_base64url(&format!(
            "pairwise|{}|{}|{}",
            context.issuer.trim_end_matches('/'),
            sector,
            context.user.id
        )))
    }
}

pub fn subject_for_client(
    issuer: &str,
    user: &UserRecord,
    client: &ClientRecord,
) -> AppResult<String> {
    let context = SubjectContext {
        issuer,
        user,
        client,
    };
    match client.subject_type.as_str() {
        SUBJECT_TYPE_PUBLIC => PublicSubjectIdentifier.subject(&context),
        SUBJECT_TYPE_PAIRWISE => PairwiseSubjectIdentifier.subject(&context),
        other => Err(AppError::BadRequest(format!(
            "unsupported subject_type: {other}"
        ))),
    }
}

pub fn validate_subject_config(subject_type: &str, sector_identifier_uri: &str) -> AppResult<()> {
    match subject_type {
        SUBJECT_TYPE_PUBLIC | SUBJECT_TYPE_PAIRWISE => {}
        other => {
            return Err(AppError::BadRequest(format!(
                "unsupported subject_type: {other}"
            )));
        }
    }
    if !sector_identifier_uri.trim().is_empty() {
        Url::parse(sector_identifier_uri)
            .map_err(|err| AppError::BadRequest(format!("invalid sector_identifier_uri: {err}")))?;
    }
    Ok(())
}

fn sector_identifier(client: &ClientRecord) -> AppResult<String> {
    if !client.sector_identifier_uri.trim().is_empty() {
        let url = Url::parse(&client.sector_identifier_uri)
            .map_err(|err| AppError::BadRequest(format!("invalid sector_identifier_uri: {err}")))?;
        return sector_from_url(&url);
    }
    let redirect_uris = client.redirect_uris()?;
    if let Some(first) = redirect_uris.first() {
        let url = Url::parse(first)
            .map_err(|err| AppError::BadRequest(format!("invalid redirect_uri: {err}")))?;
        return sector_from_url(&url);
    }
    Ok(client.client_id.clone())
}

fn sector_from_url(url: &Url) -> AppResult<String> {
    url.host_str()
        .map(|host| host.to_ascii_lowercase())
        .ok_or_else(|| AppError::BadRequest("sector URI must include a host".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(subject_type: &str, sector_identifier_uri: &str) -> ClientRecord {
        ClientRecord {
            id: "client-db-id".to_string(),
            client_id: "demo-web".to_string(),
            client_secret_hash: None,
            client_name: "Demo".to_string(),
            logo_uri: String::new(),
            organization_id: None,
            redirect_uris: serde_json::json!(["https://app.example/callback"]).to_string(),
            post_logout_redirect_uris: "[]".to_string(),
            scopes: "[]".to_string(),
            audience: String::new(),
            grant_types: "[]".to_string(),
            response_types: "[]".to_string(),
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: 1,
            require_mfa: 0,
            require_pushed_authorization_requests: 0,
            require_s256_pkce: 0,
            require_confidential_client: 0,
            require_dpop: 0,
            require_account_selection: 0,
            trust_email_verified: 0,
            authorization_details_types: "[]".to_string(),
            subject_type: subject_type.to_string(),
            sector_identifier_uri: sector_identifier_uri.to_string(),
            jwks_uri: String::new(),
            jwks: String::new(),
            backchannel_logout_uri: String::new(),
            backchannel_logout_session_required: 0,
            frontchannel_logout_uri: String::new(),
            frontchannel_logout_session_required: 0,
            service_account_enabled: 0,
            service_account_permissions: "[]".to_string(),
            is_active: 1,
            created_at: 1,
            updated_at: 1,
        }
    }

    fn user(id: &str) -> UserRecord {
        UserRecord {
            id: id.to_string(),
            email: "a@example.com".to_string(),
            username: "alice".to_string(),
            display_name: None,
            phone: None,
            password_hash: "hash".to_string(),
            email_verified_at: None,
            phone_verified_at: None,
            is_admin: 0,
            is_active: 1,
            archived_at: None,
            registration_source: "local".to_string(),
            last_login_at: None,
            last_login_ip: None,
            last_oidc_client_id: None,
            last_login_method: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn public_subject_is_user_id() {
        let subject = subject_for_client(
            "https://issuer.example",
            &user("user-1"),
            &client("public", ""),
        )
        .unwrap();
        assert_eq!(subject, "user-1");
    }

    #[test]
    fn pairwise_subject_is_stable_and_sector_scoped() {
        let user = user("user-1");
        let first =
            subject_for_client("https://issuer.example", &user, &client("pairwise", "")).unwrap();
        let second =
            subject_for_client("https://issuer.example", &user, &client("pairwise", "")).unwrap();
        let other_sector = subject_for_client(
            "https://issuer.example",
            &user,
            &client("pairwise", "https://sector.example/ids.json"),
        )
        .unwrap();
        assert_eq!(first, second);
        assert_ne!(first, other_sector);
    }
}
