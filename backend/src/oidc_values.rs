use crate::{
    db::ClientRecord,
    error::{AppError, AppResult},
    oauth_targets::{self, AudienceValidationError, ResourceValidationError},
};

pub(crate) fn normalize_resource(resource: Option<&str>) -> AppResult<Option<String>> {
    oauth_targets::normalize_resource(resource).map_err(|error| match error {
        ResourceValidationError::Empty => {
            AppError::Oidc("invalid resource parameter: value is empty".to_string())
        }
        ResourceValidationError::Whitespace => {
            AppError::Oidc("invalid resource parameter: value contains whitespace".to_string())
        }
        ResourceValidationError::InvalidUrl(error) => {
            AppError::Oidc(format!("invalid resource parameter: {error}"))
        }
        ResourceValidationError::Fragment => {
            AppError::Oidc("resource parameter must not include a fragment".to_string())
        }
    })
}

pub(super) fn resolve_client_credentials_audience(
    client: &ClientRecord,
    requested_resource: Option<String>,
    requested_audience: Option<&str>,
) -> AppResult<Option<String>> {
    let requested_audience = requested_audience
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(normalize_audience)
        .transpose()?;
    if let (Some(resource), Some(audience)) = (&requested_resource, &requested_audience)
        && resource != audience
    {
        return Err(AppError::Oidc(
            "resource and audience identify different targets".to_string(),
        ));
    }
    let configured =
        (!client.audience.trim().is_empty()).then(|| client.audience.trim().to_string());
    let requested = requested_resource.or(requested_audience);
    if let (Some(expected), Some(requested)) = (&configured, &requested)
        && expected != requested
    {
        return Err(AppError::Oidc(
            "resource parameter does not match configured client audience".to_string(),
        ));
    }
    Ok(requested.or(configured))
}

fn normalize_audience(audience: &str) -> AppResult<String> {
    oauth_targets::normalize_audience(audience)
        .map_err(|AudienceValidationError| AppError::Oidc("invalid audience parameter".to_string()))
}

pub(super) fn merge_token_resource(
    issued: Option<String>,
    requested: Option<String>,
) -> AppResult<Option<String>> {
    let requested = normalize_resource(requested.as_deref())?;
    match (issued, requested) {
        (Some(issued), Some(requested)) if issued != requested => Err(AppError::Oidc(
            "resource parameter does not match authorization request".to_string(),
        )),
        (Some(issued), _) => Ok(Some(issued)),
        (None, requested) => Ok(requested),
    }
}
