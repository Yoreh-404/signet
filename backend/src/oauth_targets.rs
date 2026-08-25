//! Shared validation for OAuth resource and audience target parameters.
//!
//! Authorization, token issuance, device flow, and token exchange all carry
//! the same target vocabulary.  The protocol handlers own their error
//! mapping, while this module owns the URI/character invariants so the
//! security boundary cannot drift between endpoints.

use std::fmt;
use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResourceValidationError {
    Empty,
    Whitespace,
    InvalidUrl(String),
    Fragment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AudienceValidationError;

impl fmt::Display for ResourceValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("value is empty"),
            Self::Whitespace => formatter.write_str("value contains whitespace"),
            Self::InvalidUrl(error) => formatter.write_str(error),
            Self::Fragment => formatter.write_str("value contains a fragment"),
        }
    }
}

pub(crate) fn normalize_resource(
    value: Option<&str>,
) -> Result<Option<String>, ResourceValidationError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    normalize_resource_value(value).map(Some)
}

pub(crate) fn normalize_resource_value(value: &str) -> Result<String, ResourceValidationError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ResourceValidationError::Empty);
    }
    if value.chars().any(char::is_whitespace) {
        return Err(ResourceValidationError::Whitespace);
    }
    let parsed = Url::parse(value)
        .map_err(|error| ResourceValidationError::InvalidUrl(error.to_string()))?;
    if parsed.fragment().is_some() {
        return Err(ResourceValidationError::Fragment);
    }
    Ok(value.to_string())
}

pub(crate) fn normalize_audience(value: &str) -> Result<String, AudienceValidationError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_whitespace) {
        return Err(AudienceValidationError);
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        AudienceValidationError, ResourceValidationError, normalize_audience, normalize_resource,
    };

    #[test]
    fn resource_validation_is_shared_and_strict() {
        assert_eq!(
            normalize_resource(Some(" https://api.example/resource ")).unwrap(),
            Some("https://api.example/resource".to_string())
        );
        assert!(matches!(
            normalize_resource(Some("/relative")),
            Err(ResourceValidationError::InvalidUrl(_))
        ));
        assert!(matches!(
            normalize_resource(Some("https://api.example/#fragment")),
            Err(ResourceValidationError::Fragment)
        ));
        assert_eq!(normalize_resource(Some("  ")).unwrap(), None);
    }

    #[test]
    fn audience_validation_rejects_empty_and_whitespace_values() {
        assert_eq!(
            normalize_audience(" https://api.example ").unwrap(),
            "https://api.example"
        );
        assert_eq!(normalize_audience(""), Err(AudienceValidationError));
        assert_eq!(
            normalize_audience("api example"),
            Err(AudienceValidationError)
        );
    }
}
