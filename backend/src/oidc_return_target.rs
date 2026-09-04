use super::oidc_request::AuthorizeRequest;
#[cfg(test)]
use super::oidc_request::ResolvedAuthorizeRequest;
use crate::{error::AppError, util::url_decode};

pub(crate) fn absolute(base_url: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!(
            "{}{}",
            base_url.trim_end_matches('/'),
            if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{path}")
            }
        )
    }
}

pub(crate) fn frontend_login_url(
    return_to: &str,
    login_hint: Option<&str>,
    force_login: bool,
) -> String {
    crate::redirects::frontend_login_url(return_to, login_hint, force_login)
}

#[cfg(test)]
pub(crate) fn resolved_query_to_pairs(
    request: &ResolvedAuthorizeRequest,
    strip_login_prompt: bool,
) -> Vec<(&'static str, String)> {
    let mut pairs = Vec::new();
    pairs.push(("response_type", request.response_type.clone()));
    pairs.push(("client_id", request.client_id.clone()));
    pairs.push(("redirect_uri", request.redirect_uri.clone()));
    if let Some(value) = &request.scope {
        pairs.push(("scope", value.clone()));
    }
    if let Some(value) = &request.resource {
        pairs.push(("resource", value.clone()));
    }
    if let Some(value) = &request.authorization_details {
        pairs.push(("authorization_details", value.clone()));
    }
    if let Some(value) = &request.login_hint {
        pairs.push(("login_hint", value.clone()));
    }
    let prompt = if strip_login_prompt {
        super::oidc_browser_interaction::prompt_without_login(request.prompt.as_deref())
    } else {
        request.prompt.clone()
    };
    if let Some(value) = prompt {
        pairs.push(("prompt", value));
    }
    if let Some(value) = request.max_age {
        pairs.push(("max_age", value.to_string()));
    }
    if let Some(value) = &request.acr_values {
        pairs.push(("acr_values", value.clone()));
    }
    if let Some(value) = &request.claims
        && let Ok(encoded) = value.to_authorization_parameter()
    {
        pairs.push(("claims", encoded));
    }
    if let Some(value) = &request.state {
        pairs.push(("state", value.clone()));
    }
    if let Some(value) = &request.nonce {
        pairs.push(("nonce", value.clone()));
    }
    if let Some(value) = &request.code_challenge {
        pairs.push(("code_challenge", value.clone()));
    }
    if let Some(value) = &request.code_challenge_method {
        pairs.push(("code_challenge_method", value.clone()));
    }
    if let Some(value) = &request.response_mode {
        pairs.push(("response_mode", value.clone()));
    }
    pairs
}

#[cfg(test)]
pub(crate) fn authorize_return_to_resolved_for_login(
    request: &ResolvedAuthorizeRequest,
    strip_login_prompt: bool,
) -> String {
    format!(
        "/oauth2/authorize?{}",
        serde_urlencode(&resolved_query_to_pairs(request, strip_login_prompt))
    )
}

#[cfg(test)]
pub(crate) fn serde_urlencode(pairs: &[(&'static str, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

pub(crate) fn authorize_request_from_return_to(
    return_to: &str,
) -> crate::error::AppResult<Option<AuthorizeRequest>> {
    let return_to = decode_authorize_return_to(return_to);
    let Some(query) = return_to.strip_prefix("/oauth2/authorize?") else {
        return Ok(None);
    };
    serde_urlencoded::from_str(query)
        .map(Some)
        .map_err(|err| AppError::BadRequest(format!("invalid OIDC return target: {err}")))
}

pub(crate) fn decode_authorize_return_to(return_to: &str) -> String {
    let return_to = return_to.trim();
    if return_to.starts_with("/oauth2/authorize?") {
        return_to.to_string()
    } else {
        url_decode(return_to)
    }
}

pub(crate) fn strict_interaction_request_from_return_to(return_to: Option<&str>) -> Option<String> {
    let return_to = decode_authorize_return_to(return_to?.trim());
    if return_to.contains('#') {
        return None;
    }
    let query = return_to.strip_prefix("/oauth2/authorize?")?;
    let pairs = url::form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
    if pairs.len() != 1 || pairs[0].0 != "interaction_request" {
        return None;
    }
    let interaction_request = pairs[0].1.trim();
    (!interaction_request.is_empty()).then(|| interaction_request.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_encoded_authorize_return_target() {
        assert_eq!(
            decode_authorize_return_to(
                "%2Foauth2%2Fauthorize%3Fclient_id%3Dclient-a%26state%3Dstate"
            ),
            "/oauth2/authorize?client_id=client-a&state=state"
        );
    }

    #[test]
    fn parses_only_authorize_return_targets() {
        let request =
            authorize_request_from_return_to("/oauth2/authorize?client_id=client-a&state=state")
                .unwrap()
                .unwrap();
        assert_eq!(request.client_id.as_deref(), Some("client-a"));
        assert_eq!(request.state.as_deref(), Some("state"));
        assert!(
            authorize_request_from_return_to("/login?return_to=authorize")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn strict_interaction_target_rejects_fragments_and_duplicates() {
        assert_eq!(
            strict_interaction_request_from_return_to(Some(
                "/oauth2/authorize?interaction_request=one",
            )),
            Some("one".to_string())
        );
        for return_to in [
            Some("/oauth2/authorize?interaction_request=one#fragment"),
            Some("/oauth2/authorize?interaction_request=one&interaction_request=two"),
            Some("/oauth2/authorize?client_id=client-a"),
            None,
        ] {
            assert_eq!(strict_interaction_request_from_return_to(return_to), None);
        }
    }

    #[test]
    fn absolute_preserves_absolute_urls_and_normalizes_paths() {
        assert_eq!(
            absolute("https://example.com/", "/oauth2/token"),
            "https://example.com/oauth2/token"
        );
        assert_eq!(
            absolute("https://example.com", "oauth2/token"),
            "https://example.com/oauth2/token"
        );
        assert_eq!(
            absolute("https://example.com/", "https://other.example/callback"),
            "https://other.example/callback"
        );
    }

    #[test]
    fn url_encoding_preserves_pair_order_and_duplicate_keys() {
        assert_eq!(
            serde_urlencode(&[
                ("prompt", "select_account".to_string()),
                ("scope", "openid profile".to_string()),
                ("scope", "email".to_string()),
            ]),
            "prompt=select_account&scope=openid+profile&scope=email"
        );
    }

    #[test]
    fn resolved_login_return_removes_only_login_prompt_value() {
        let request = ResolvedAuthorizeRequest::from_query(
            serde_urlencoded::from_str(
                "response_type=code&client_id=client-a&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=openid&login_hint=alice%40example.com&prompt=login+select_account+consent&state=state",
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            authorize_return_to_resolved_for_login(&request, true),
            "/oauth2/authorize?response_type=code&client_id=client-a&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=openid&login_hint=alice%40example.com&prompt=select_account+consent&state=state"
        );
    }
}
