use crate::error::{AppError, AppResult};
use url::Url;

pub(crate) fn validate_safe_http_endpoint(value: &str, label: &str) -> AppResult<()> {
    parse_safe_http_endpoint(value, label).map(|_| ())
}

pub(crate) fn parse_safe_http_endpoint(value: &str, label: &str) -> AppResult<Url> {
    let url = Url::parse(value).map_err(|_| invalid_endpoint(label))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || (url.scheme() == "http" && !loopback)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid_endpoint(label));
    }
    Ok(url)
}

fn invalid_endpoint(label: &str) -> AppError {
    AppError::BadRequest(format!("{label} is invalid"))
}

#[cfg(test)]
mod tests {
    use super::validate_safe_http_endpoint;

    #[test]
    fn accepts_https_and_loopback_http() {
        assert!(validate_safe_http_endpoint("https://app.example/callback", "endpoint").is_ok());
        assert!(validate_safe_http_endpoint("http://localhost:3000/callback", "endpoint").is_ok());
    }

    #[test]
    fn rejects_unsafe_http_endpoints() {
        for value in [
            "http://app.example/callback",
            "https://user:password@app.example/callback",
            "https://app.example/callback#fragment",
            "/callback",
        ] {
            assert!(
                validate_safe_http_endpoint(value, "endpoint").is_err(),
                "{value}"
            );
        }
    }
}
