use crate::{error::AppResult, util};
use serde_json::Value;
use std::net::IpAddr;
use url::Host;

const REGISTRATION_PROOF_EXTENSION: &str = "registration_proof";

pub(super) fn validate_host(host: Option<Host<&str>>) -> AppResult<()> {
    let Some(host) = host else {
        return Err(crate::error::AppError::BadRequest(
            "website URL must include a host".to_string(),
        ));
    };
    let host_name = host.to_string();
    if host_name.eq_ignore_ascii_case("localhost")
        || host_name.ends_with(".localhost")
        || host_name.ends_with(".local")
    {
        return Err(crate::error::AppError::BadRequest(
            "website URL cannot target a local hostname".to_string(),
        ));
    }
    let ip = match host {
        Host::Ipv4(value) => IpAddr::V4(value),
        Host::Ipv6(value) => IpAddr::V6(value),
        Host::Domain(_) => return Ok(()),
    };
    if is_forbidden_ip(ip) {
        return Err(crate::error::AppError::BadRequest(
            "website URL cannot target a private network address".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => {
            value.is_loopback()
                || value.is_private()
                || value.is_link_local()
                || value.is_unspecified()
                || value.is_multicast()
                || value.is_broadcast()
        }
        IpAddr::V6(value) => {
            value.is_loopback()
                || value.is_unspecified()
                || value.is_multicast()
                || (value.segments()[0] & 0xfe00) == 0xfc00
                || (value.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

pub(super) fn manifest_content_digest(payload: &[u8]) -> AppResult<String> {
    let mut value = serde_json::from_slice::<Value>(payload).map_err(|_| {
        crate::error::AppError::BadRequest("application discovery schema is invalid".to_string())
    })?;
    let object = value.as_object_mut().ok_or_else(|| {
        crate::error::AppError::BadRequest("application discovery schema is invalid".to_string())
    })?;
    object.remove("iat");
    object.remove("exp");
    if let Some(extensions) = object.get_mut("extensions").and_then(Value::as_object_mut) {
        extensions.remove(REGISTRATION_PROOF_EXTENSION);
    }
    let canonical = serde_json::to_string(&value).map_err(|_| {
        crate::error::AppError::Internal(
            "failed to encode application discovery digest".to_string(),
        )
    })?;
    Ok(util::sha256_base64url(&canonical))
}

pub(super) fn audience_contains(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

pub(super) fn normalize_permission_key(value: &str) -> AppResult<String> {
    let value = visible_text(value, 256, "permission key")?;
    if value.split(':').any(str::is_empty) {
        return Err(crate::error::AppError::BadRequest(
            "permission key is invalid".to_string(),
        ));
    }
    Ok(value)
}

pub(super) fn normalize_string_list(
    values: &[String],
    max_length: usize,
    field: &str,
) -> AppResult<Vec<String>> {
    let mut normalized = std::collections::BTreeSet::new();
    for value in values {
        normalized.insert(visible_text(value, max_length, field)?);
    }
    Ok(normalized.into_iter().collect())
}

pub(super) fn normalize_url_list(values: &[String], field: &str) -> AppResult<Vec<String>> {
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let value = visible_text(value, 2048, field)?;
        let parsed = url::Url::parse(&value)
            .map_err(|_| crate::error::AppError::BadRequest(format!("{field} is invalid")))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(crate::error::AppError::BadRequest(format!(
                "{field} is invalid"
            )));
        }
        result.push(value);
    }
    Ok(result)
}

pub(super) fn normalize_display_text(
    value: &str,
    max_length: usize,
    field: &str,
) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > max_length || value.chars().any(|ch| ch.is_control()) {
        return Err(crate::error::AppError::BadRequest(format!(
            "{field} is invalid"
        )));
    }
    Ok(value.to_string())
}

pub(super) fn visible_text(value: &str, max_length: usize, field: &str) -> AppResult<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > max_length
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(crate::error::AppError::BadRequest(format!(
            "{field} is invalid"
        )));
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_local_and_private_targets() {
        assert!(validate_host(Some(Host::Domain("localhost"))).is_err());
        assert!(is_forbidden_ip("127.0.0.1".parse().unwrap()));
        assert!(is_forbidden_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_forbidden_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn normalizes_lists_deterministically() {
        let values = vec![
            " beta ".to_string(),
            "alpha".to_string(),
            "beta".to_string(),
        ];
        assert_eq!(
            normalize_string_list(&values, 32, "scope").unwrap(),
            ["alpha", "beta"]
        );
        assert!(normalize_permission_key("scope:").is_err());
        assert_eq!(
            normalize_display_text("  Display  ", 32, "name").unwrap(),
            "Display"
        );
    }

    #[test]
    fn validates_audience_and_urls() {
        assert!(audience_contains(&json!("client"), "client"));
        assert!(audience_contains(&json!(["other", "client"]), "client"));
        assert!(!audience_contains(&json!(42), "client"));
        assert!(
            normalize_url_list(&["https://example.com/callback".to_string()], "redirect").is_ok()
        );
        assert!(normalize_url_list(&["javascript:alert(1)".to_string()], "redirect").is_err());
    }

    #[test]
    fn digest_ignores_volatile_and_registration_proof_fields() {
        let first =
            br#"{"aud":"client","iat":1,"exp":2,"extensions":{"registration_proof":"one"}}"#;
        let second =
            br#"{"aud":"client","iat":9,"exp":10,"extensions":{"registration_proof":"two"}}"#;
        assert_eq!(
            manifest_content_digest(first).unwrap(),
            manifest_content_digest(second).unwrap()
        );
    }
}
