use super::normalize_resource;
use crate::{
    assurance,
    client_policy::AuthorizationRequestSource,
    error::{AppError, AppResult},
    oidc_claims::RequestedClaims,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub(super) struct AuthorizeRequest {
    pub(super) interaction_request: Option<String>,
    pub(super) request: Option<String>,
    pub(super) request_uri: Option<String>,
    pub(super) response_type: Option<String>,
    pub(super) client_id: Option<String>,
    pub(super) redirect_uri: Option<String>,
    pub(super) scope: Option<String>,
    pub(super) resource: Option<String>,
    pub(super) authorization_details: Option<String>,
    pub(super) login_hint: Option<String>,
    pub(super) prompt: Option<String>,
    pub(super) max_age: Option<String>,
    pub(super) acr_values: Option<String>,
    pub(super) claims: Option<String>,
    pub(super) state: Option<String>,
    pub(super) nonce: Option<String>,
    pub(super) code_challenge: Option<String>,
    pub(super) code_challenge_method: Option<String>,
    pub(super) response_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ConsentForm {
    pub(super) _csrf: Option<String>,
    pub(super) action: String,
    pub(super) remember: Option<String>,
    pub(super) response_type: String,
    pub(super) client_id: String,
    pub(super) redirect_uri: String,
    pub(super) scope: String,
    pub(super) resource: Option<String>,
    pub(super) authorization_details: Option<String>,
    pub(super) login_hint: Option<String>,
    pub(super) prompt: Option<String>,
    pub(super) max_age: Option<String>,
    pub(super) interaction_request: Option<String>,
    pub(super) request_uri: Option<String>,
    pub(super) acr_values: Option<String>,
    pub(super) claims: Option<String>,
    pub(super) state: Option<String>,
    pub(super) nonce: Option<String>,
    pub(super) code_challenge: Option<String>,
    pub(super) code_challenge_method: Option<String>,
    pub(super) response_mode: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PromptBehavior {
    pub(super) force_consent: bool,
    pub(super) force_login: bool,
    pub(super) select_account: bool,
    pub(super) none: bool,
}

pub(super) fn required_query_value(value: Option<String>, field: &str) -> AppResult<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Oidc(format!("{field} is required")))
}

pub(super) fn optional_form_value(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn parse_max_age(value: Option<&str>) -> AppResult<Option<i64>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let max_age = value
        .parse::<i64>()
        .map_err(|_| AppError::Oidc("max_age must be a non-negative integer".to_string()))?;
    validate_max_age(max_age).map(Some)
}

pub(crate) fn validate_max_age(max_age: i64) -> AppResult<i64> {
    if max_age < 0 {
        return Err(AppError::Oidc(
            "max_age must be a non-negative integer".to_string(),
        ));
    }
    Ok(max_age)
}

pub(crate) fn normalize_acr_values_param(value: Option<&str>) -> AppResult<Option<String>> {
    let values = assurance::parse_acr_values(value)?;
    Ok((!values.is_empty()).then(|| values.join(" ")))
}

pub(super) fn prompt_behavior(prompt: Option<&str>) -> AppResult<PromptBehavior> {
    let values = prompt
        .unwrap_or_default()
        .split_whitespace()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let mut behavior = PromptBehavior {
        force_consent: false,
        force_login: false,
        select_account: false,
        none: false,
    };
    if values.is_empty() {
        return Ok(behavior);
    }
    for value in &values {
        match *value {
            "consent" => behavior.force_consent = true,
            "login" => behavior.force_login = true,
            "select_account" => behavior.select_account = true,
            "none" => behavior.none = true,
            other => return Err(AppError::Oidc(format!("unsupported prompt: {other}"))),
        }
    }
    if behavior.none && values.len() > 1 {
        return Err(AppError::Oidc(
            "prompt=none cannot be combined with other prompt values".to_string(),
        ));
    }
    Ok(behavior)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ResolvedAuthorizeRequest {
    #[serde(default)]
    pub(crate) source: AuthorizationRequestSource,
    pub(crate) response_type: String,
    pub(crate) client_id: String,
    pub(crate) redirect_uri: String,
    pub(crate) scope: Option<String>,
    pub(crate) resource: Option<String>,
    pub(crate) authorization_details: Option<String>,
    pub(crate) login_hint: Option<String>,
    pub(crate) prompt: Option<String>,
    pub(crate) max_age: Option<i64>,
    pub(crate) acr_values: Option<String>,
    pub(crate) claims: Option<RequestedClaims>,
    pub(crate) state: Option<String>,
    pub(crate) nonce: Option<String>,
    pub(crate) code_challenge: Option<String>,
    pub(crate) code_challenge_method: Option<String>,
    pub(crate) response_mode: Option<String>,
    #[serde(default)]
    pub(crate) account_selection_prompted: bool,
    #[serde(default)]
    pub(crate) account_selection_required: bool,
    #[serde(default)]
    pub(crate) reauthentication_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) selected_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) selected_user_id: Option<String>,
}

impl ResolvedAuthorizeRequest {
    pub(super) fn from_query(query: AuthorizeRequest) -> AppResult<Self> {
        Ok(Self {
            source: AuthorizationRequestSource::Query,
            response_type: super::required_query_value(query.response_type, "response_type")?,
            client_id: super::required_query_value(query.client_id, "client_id")?,
            redirect_uri: super::required_query_value(query.redirect_uri, "redirect_uri")?,
            scope: query.scope,
            resource: normalize_resource(query.resource.as_deref())?,
            authorization_details: super::optional_form_value(query.authorization_details),
            login_hint: super::optional_form_value(query.login_hint),
            prompt: query.prompt,
            max_age: super::parse_max_age(query.max_age.as_deref())?,
            acr_values: super::normalize_acr_values_param(query.acr_values.as_deref())?,
            claims: RequestedClaims::from_authorization_parameter(query.claims.as_deref())?,
            state: query.state,
            nonce: query.nonce,
            code_challenge: query.code_challenge,
            code_challenge_method: query.code_challenge_method,
            response_mode: query.response_mode,
            account_selection_prompted: false,
            account_selection_required: false,
            reauthentication_required: false,
            selected_session_id: None,
            selected_user_id: None,
        })
    }

    pub(super) fn prompt_behavior(&self) -> AppResult<PromptBehavior> {
        super::prompt_behavior(self.prompt.as_deref())
    }

    pub(super) fn requested_assurance(&self) -> AppResult<assurance::RequestedAssurance> {
        self.claims
            .as_ref()
            .map(|claims| claims.requested_assurance(self.acr_values.as_deref()))
            .unwrap_or_else(|| {
                assurance::RequestedAssurance::new(
                    self.acr_values.as_deref(),
                    Vec::new(),
                    Vec::new(),
                )
            })
    }
}

impl ConsentForm {
    pub(super) fn resolved_request(&self) -> AppResult<ResolvedAuthorizeRequest> {
        ResolvedAuthorizeRequest::from_query(AuthorizeRequest {
            interaction_request: None,
            request: None,
            request_uri: None,
            response_type: Some(self.response_type.clone()),
            client_id: Some(self.client_id.clone()),
            redirect_uri: Some(self.redirect_uri.clone()),
            scope: Some(self.scope.clone()),
            resource: self.resource.clone(),
            authorization_details: self.authorization_details.clone(),
            login_hint: self.login_hint.clone(),
            prompt: super::optional_form_value(self.prompt.clone()),
            max_age: self.max_age.clone(),
            acr_values: self.acr_values.clone(),
            claims: self.claims.clone(),
            state: super::optional_form_value(self.state.clone()),
            nonce: super::optional_form_value(self.nonce.clone()),
            code_challenge: super::optional_form_value(self.code_challenge.clone()),
            code_challenge_method: super::optional_form_value(self.code_challenge_method.clone()),
            response_mode: super::optional_form_value(self.response_mode.clone()),
        })
    }
}
