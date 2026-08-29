use super::ResolvedAuthorizeRequest;

pub(super) fn return_to_request(
    request: &ResolvedAuthorizeRequest,
    strip_login_prompt: bool,
) -> ResolvedAuthorizeRequest {
    let mut request = request.clone();
    if strip_login_prompt {
        request.prompt = prompt_without_login(request.prompt.as_deref());
    }
    request
}

pub(super) fn reauthentication_request(
    request: &ResolvedAuthorizeRequest,
) -> ResolvedAuthorizeRequest {
    let mut request = request.clone();
    request.reauthentication_required = true;
    request.selected_session_id = None;
    request
}

pub(super) fn account_selection_prompted_request(
    request: &ResolvedAuthorizeRequest,
) -> ResolvedAuthorizeRequest {
    let mut request = request.clone();
    request.account_selection_prompted = false;
    request.account_selection_required = true;
    request.reauthentication_required = false;
    request.selected_session_id = None;
    request.selected_user_id = None;
    request
}

pub(super) fn prompt_without_login(prompt: Option<&str>) -> Option<String> {
    let prompt = prompt?
        .split_whitespace()
        .filter(|value| *value != "login")
        .collect::<Vec<_>>()
        .join(" ");
    (!prompt.is_empty()).then_some(prompt)
}
