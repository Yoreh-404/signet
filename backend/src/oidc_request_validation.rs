use super::oidc_request::ResolvedAuthorizeRequest;
use crate::{
    error::{AppError, AppResult},
    pkce::is_valid_code_challenge,
};

pub(super) fn validate_authorization_request_parameters(
    request: &ResolvedAuthorizeRequest,
) -> AppResult<()> {
    if request.selected_session_id.is_some() && request.selected_user_id.is_none() {
        return Err(AppError::Oidc(
            "selected_session_id requires selected_user_id".to_string(),
        ));
    }
    if request.reauthentication_required && request.selected_session_id.is_some() {
        return Err(AppError::Oidc(
            "reauthentication cannot retain a selected session".to_string(),
        ));
    }
    if request.account_selection_required && request.account_selection_prompted {
        return Err(AppError::Oidc(
            "account selection cannot be both required and completed".to_string(),
        ));
    }
    for (field, value, max_length) in [
        ("state", request.state.as_deref(), 4096usize),
        ("nonce", request.nonce.as_deref(), 512usize),
        ("login_hint", request.login_hint.as_deref(), 512usize),
        (
            "code_challenge",
            request.code_challenge.as_deref(),
            128usize,
        ),
    ] {
        if value.is_some_and(|value| {
            value.is_empty()
                || value.len() > max_length
                || value.bytes().any(|byte| byte.is_ascii_control())
        }) {
            return Err(AppError::Oidc(format!("{field} is invalid")));
        }
    }
    if request
        .code_challenge
        .as_deref()
        .is_some_and(|challenge| !is_valid_code_challenge(challenge))
    {
        return Err(AppError::Oidc("code_challenge is invalid".to_string()));
    }
    if request
        .code_challenge_method
        .as_deref()
        .is_some_and(|method| {
            !matches!(method, "plain" | "S256") || request.code_challenge.is_none()
        })
    {
        return Err(AppError::Oidc(
            "code_challenge_method is invalid".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::oidc_request::ResolvedAuthorizeRequest;
    use super::validate_authorization_request_parameters;
    use crate::client_policy::AuthorizationRequestSource;

    fn request() -> ResolvedAuthorizeRequest {
        ResolvedAuthorizeRequest {
            source: AuthorizationRequestSource::Query,
            response_type: "code".to_string(),
            client_id: "client-a".to_string(),
            redirect_uri: "https://app.example/callback".to_string(),
            scope: None,
            resource: None,
            authorization_details: None,
            login_hint: None,
            prompt: None,
            max_age: None,
            acr_values: None,
            claims: None,
            state: Some("state".to_string()),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            response_mode: None,
            account_selection_prompted: false,
            account_selection_required: false,
            reauthentication_required: false,
            selected_session_id: None,
            selected_user_id: None,
        }
    }

    #[test]
    fn preserves_shape_validation_errors() {
        let mut request = request();
        request.state = Some("bad\nstate".to_string());

        assert_eq!(
            validate_authorization_request_parameters(&request)
                .unwrap_err()
                .to_string(),
            "oidc error: state is invalid"
        );
    }

    #[test]
    fn validates_pkce_challenge_before_method() {
        let mut request = request();
        request.code_challenge = Some("too-short".to_string());
        request.code_challenge_method = Some("invalid".to_string());

        assert_eq!(
            validate_authorization_request_parameters(&request)
                .unwrap_err()
                .to_string(),
            "oidc error: code_challenge is invalid"
        );
    }

    #[test]
    fn rejects_inconsistent_interaction_state() {
        let mut session_without_user = request();
        session_without_user.selected_session_id = Some("session-a".to_string());
        assert!(validate_authorization_request_parameters(&session_without_user).is_err());

        let mut reauthentication_with_session = request();
        reauthentication_with_session.reauthentication_required = true;
        reauthentication_with_session.selected_session_id = Some("session-a".to_string());
        reauthentication_with_session.selected_user_id = Some("user-a".to_string());
        assert!(validate_authorization_request_parameters(&reauthentication_with_session).is_err());

        let mut completed_selection_still_required = request();
        completed_selection_still_required.account_selection_required = true;
        completed_selection_still_required.account_selection_prompted = true;
        assert!(
            validate_authorization_request_parameters(&completed_selection_still_required).is_err()
        );
    }
}
