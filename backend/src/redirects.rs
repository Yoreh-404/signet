pub fn local_return_to(value: Option<&str>) -> String {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return "/".to_string();
    };
    if is_local_return_to(value) {
        value.to_string()
    } else {
        "/".to_string()
    }
}

pub fn optional_local_return_to(value: Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(|value| local_return_to(Some(value)))
        .filter(|value| value != "/")
}

pub fn frontend_login_url(return_to: &str, login_hint: Option<&str>, force_login: bool) -> String {
    let return_to = local_return_to(Some(return_to));
    let mut pairs = vec![("auth", "login".to_string()), ("return_to", return_to)];
    if let Some(value) = login_hint.map(str::trim).filter(|value| !value.is_empty()) {
        pairs.push(("login_hint", value.to_string()));
    }
    if force_login {
        pairs.push(("force_login", "1".to_string()));
    }
    format!("/?{}", serde_urlencode(&pairs))
}

pub fn frontend_account_selection_url(return_to: &str, login_hint: Option<&str>) -> String {
    let return_to = local_return_to(Some(return_to));
    let mut pairs = vec![
        ("auth", "select_account".to_string()),
        ("return_to", return_to),
    ];
    if let Some(value) = login_hint.map(str::trim).filter(|value| !value.is_empty()) {
        pairs.push(("login_hint", value.to_string()));
    }
    format!("/?{}", serde_urlencode(&pairs))
}

pub fn frontend_auth_error_url(return_to: Option<&str>, message: &str) -> String {
    let return_to = local_return_to(return_to);
    let pairs = vec![
        ("auth", "login".to_string()),
        ("return_to", return_to),
        ("auth_error", message.trim().to_string()),
    ];
    format!("/?{}", serde_urlencode(&pairs))
}

pub fn frontend_auth_error_code_url(return_to: Option<&str>, code: &str, detail: &str) -> String {
    let return_to = local_return_to(return_to);
    let mut pairs = vec![
        ("auth", "login".to_string()),
        ("return_to", return_to),
        ("auth_error_code", code.trim().to_string()),
    ];
    if !detail.trim().is_empty() {
        pairs.push(("auth_error_detail", detail.trim().to_string()));
    }
    format!("/?{}", serde_urlencode(&pairs))
}

fn is_local_return_to(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn serde_urlencode(pairs: &[(&str, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in pairs {
        serializer.append_pair(key, value);
    }
    serializer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_same_site_paths() {
        assert_eq!(local_return_to(Some("/")), "/");
        assert_eq!(
            local_return_to(Some("/oauth2/authorize?client_id=demo&scope=openid")),
            "/oauth2/authorize?client_id=demo&scope=openid"
        );
        assert_eq!(local_return_to(Some("/#/admin/users")), "/#/admin/users");
    }

    #[test]
    fn rejects_external_or_ambiguous_targets() {
        assert_eq!(local_return_to(Some("https://example.com")), "/");
        assert_eq!(local_return_to(Some("//example.com/path")), "/");
        assert_eq!(local_return_to(Some("\\\\example.com\\path")), "/");
        assert_eq!(local_return_to(Some("/\\example.com")), "/");
        assert_eq!(local_return_to(Some("admin/users")), "/");
        assert_eq!(
            local_return_to(Some("/admin\r\nLocation: https://example.com")),
            "/"
        );
        assert_eq!(local_return_to(Some("   ")), "/");
        assert_eq!(local_return_to(None), "/");
    }

    #[test]
    fn optional_form_drops_default_root() {
        assert_eq!(
            optional_local_return_to(Some("/admin".to_string())),
            Some("/admin".to_string())
        );
        assert_eq!(
            optional_local_return_to(Some("https://example.com".to_string())),
            None
        );
        assert_eq!(optional_local_return_to(Some("/".to_string())), None);
        assert_eq!(optional_local_return_to(None), None);
    }

    #[test]
    fn frontend_login_url_preserves_local_target_and_hint() {
        let url = frontend_login_url(
            "/oauth2/authorize?client_id=client-a&login_hint=alice%40example.com",
            Some("alice@example.com"),
            true,
        );
        assert_eq!(
            url,
            "/?auth=login&return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Dclient-a%26login_hint%3Dalice%2540example.com&login_hint=alice%40example.com&force_login=1"
        );
    }

    #[test]
    fn frontend_login_url_rejects_external_target() {
        assert_eq!(
            frontend_login_url("https://evil.example", None, false),
            "/?auth=login&return_to=%2F"
        );
    }

    #[test]
    fn account_selection_url_preserves_only_a_local_target_and_hint() {
        assert_eq!(
            frontend_account_selection_url(
                "/oauth2/authorize?interaction_request=opaque",
                Some("alice@example.com")
            ),
            "/?auth=select_account&return_to=%2Foauth2%2Fauthorize%3Finteraction_request%3Dopaque&login_hint=alice%40example.com"
        );
        assert_eq!(
            frontend_account_selection_url("https://evil.example", None),
            "/?auth=select_account&return_to=%2F"
        );
    }

    #[test]
    fn frontend_auth_error_url_keeps_local_return_target() {
        assert_eq!(
            frontend_auth_error_url(Some("/oauth2/authorize?client_id=demo"), "access denied"),
            "/?auth=login&return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Ddemo&auth_error=access+denied"
        );
        assert_eq!(
            frontend_auth_error_url(Some("https://evil.example"), "bad"),
            "/?auth=login&return_to=%2F&auth_error=bad"
        );
    }

    #[test]
    fn frontend_auth_error_code_url_preserves_machine_readable_error() {
        assert_eq!(
            frontend_auth_error_code_url(
                Some("/oauth2/authorize?client_id=demo"),
                "company_email_required",
                "example.com"
            ),
            "/?auth=login&return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Ddemo&auth_error_code=company_email_required&auth_error_detail=example.com"
        );
    }
}
