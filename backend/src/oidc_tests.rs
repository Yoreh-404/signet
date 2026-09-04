use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use std::{collections::HashMap, path::PathBuf, sync::Mutex};
use tower::ServiceExt;

struct StubInteractionStore {
    request_uri: String,
    stored: Mutex<Vec<ResolvedAuthorizeRequest>>,
}

impl StubInteractionStore {
    fn new(request_uri: &str) -> Self {
        Self {
            request_uri: request_uri.to_string(),
            stored: Mutex::new(Vec::new()),
        }
    }
}

impl AuthorizationInteractionRequestStore for StubInteractionStore {
    async fn store_interaction_request(
        &self,
        client_id: &str,
        request: &ResolvedAuthorizeRequest,
    ) -> AppResult<String> {
        assert_eq!(client_id, request.client_id);
        self.stored.lock().unwrap().push(request.clone());
        Ok(self.request_uri.clone())
    }
}

fn redirect_url(response: &Response) -> Url {
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("redirect must include Location")
        .to_str()
        .unwrap();
    Url::parse("http://sso.test/")
        .unwrap()
        .join(location)
        .unwrap()
}

fn query_value(url: &Url, name: &str) -> String {
    url.query_pairs()
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
        .unwrap_or_else(|| panic!("redirect query must include {name}"))
}

#[test]
fn prompt_none_is_exclusive() {
    assert!(prompt_behavior(Some("none")).unwrap().none);
    assert!(prompt_behavior(Some("none consent")).is_err());
    assert!(prompt_behavior(Some("none login")).is_err());
}

#[test]
fn account_selection_client_preserves_non_interactive_prompt_none() {
    let request = test_authorize_request(Some("none"), None);
    let strict_client = test_client();
    assert!(
        prompt_behavior_for_client(&strict_client, &request)
            .unwrap()
            .none
    );

    let mut interactive_client = test_client();
    interactive_client.require_account_selection = 1;
    let behavior = prompt_behavior_for_client(&interactive_client, &request).unwrap();
    assert!(behavior.none);
    assert!(!behavior.force_login);
    assert!(!behavior.force_consent);
}

#[test]
fn authorization_request_parameters_are_bounded_and_pkce_is_well_formed() {
    let mut client = test_client();
    client.require_pkce = 1;
    let mut request = test_authorize_request(None, None);
    request.code_challenge = Some("a".repeat(43));
    request.code_challenge_method = Some("S256".to_string());
    assert!(validate_authorize_request_for_client(&client, &request).is_ok());

    request.state = Some("x".repeat(4097));
    assert!(validate_authorize_request_for_client(&client, &request).is_err());
    request.state = Some("line\nfeed".to_string());
    assert!(validate_authorize_request_for_client(&client, &request).is_err());

    request.state = Some("safe-state".to_string());
    request.code_challenge = Some("a".repeat(42));
    assert!(validate_authorize_request_for_client(&client, &request).is_err());
    request.code_challenge = Some("a".repeat(43));
    request.code_challenge_method = Some("plain-ish".to_string());
    assert!(validate_authorize_request_for_client(&client, &request).is_err());
    request.code_challenge_method = None;
    assert!(validate_authorize_request_for_client(&client, &request).is_ok());
    client.require_s256_pkce = 1;
    assert!(validate_authorize_request_for_client(&client, &request).is_err());
}

#[test]
fn prompt_consent_forces_consent() {
    let behavior = prompt_behavior(Some("consent")).unwrap();
    assert!(behavior.force_consent);
    assert!(!behavior.none);
}

#[test]
fn prompt_login_forces_reauthentication() {
    let behavior = prompt_behavior(Some("login consent")).unwrap();
    assert!(behavior.force_login);
    assert!(behavior.force_consent);
    assert!(!behavior.none);
}

#[test]
fn prompt_select_account_forces_account_selection() {
    let behavior = prompt_behavior(Some("select_account consent")).unwrap();
    assert!(behavior.select_account);
    assert!(!behavior.force_login);
    assert!(behavior.force_consent);
    assert!(!behavior.none);
}

#[test]
fn max_age_parses_non_negative_seconds() {
    assert_eq!(parse_max_age(None).unwrap(), None);
    assert_eq!(parse_max_age(Some("")).unwrap(), None);
    assert_eq!(parse_max_age(Some("0")).unwrap(), Some(0));
    assert_eq!(parse_max_age(Some("300")).unwrap(), Some(300));
    assert!(parse_max_age(Some("-1")).is_err());
    assert!(parse_max_age(Some("soon")).is_err());
}

#[test]
fn session_freshness_respects_prompt_login_and_max_age() {
    let session = test_session(100);
    assert!(session.needs_reauthentication(
        PromptBehavior {
            force_consent: false,
            force_login: false,
            select_account: false,
            none: false,
        },
        Some(0),
        100
    ));
    assert!(session.needs_reauthentication(
        PromptBehavior {
            force_consent: false,
            force_login: true,
            select_account: false,
            none: false,
        },
        None,
        100
    ));
    assert!(!session.needs_reauthentication(
        PromptBehavior {
            force_consent: false,
            force_login: false,
            select_account: false,
            none: false,
        },
        Some(30),
        130
    ));
    assert!(session.needs_reauthentication(
        PromptBehavior {
            force_consent: false,
            force_login: false,
            select_account: false,
            none: false,
        },
        Some(30),
        131
    ));
}

#[test]
fn reauthentication_return_to_removes_login_prompt() {
    let mut request = test_authorize_request(Some("login select_account consent"), Some(300));
    request.acr_values = Some(assurance::ACR_MFA.to_string());
    request.login_hint = Some("alice@example.com".to_string());
    request.claims = RequestedClaims::from_authorization_parameter(Some(
        r#"{"id_token":{"amr":{"essential":true,"values":["otp"]}}}"#,
    ))
    .unwrap();
    let return_to = authorize_return_to_resolved_for_login(&request, true);
    assert!(return_to.starts_with("/oauth2/authorize?"));
    let query = return_to.trim_start_matches("/oauth2/authorize?");
    let parsed = serde_urlencoded::from_str::<HashMap<String, String>>(query).unwrap();
    assert_eq!(
        parsed.get("prompt").map(String::as_str),
        Some("select_account consent")
    );
    assert_eq!(parsed.get("max_age").map(String::as_str), Some("300"));
    assert_eq!(
        parsed.get("acr_values").map(String::as_str),
        Some(assurance::ACR_MFA)
    );
    assert!(
        parsed
            .get("claims")
            .is_some_and(|value| value.contains(r#""amr""#))
    );
    assert_eq!(
        parsed.get("login_hint").map(String::as_str),
        Some("alice@example.com")
    );
}

#[test]
fn frontend_login_url_prefills_hint_and_local_return_target() {
    let url = frontend_login_url(
        "/oauth2/authorize?client_id=client-a&login_hint=alice%40example.com",
        Some("alice@example.com"),
        false,
    );
    let query = url.trim_start_matches("/?");
    let parsed = serde_urlencoded::from_str::<HashMap<String, String>>(query).unwrap();
    assert_eq!(parsed.get("auth").map(String::as_str), Some("login"));
    assert_eq!(
        parsed.get("return_to").map(String::as_str),
        Some("/oauth2/authorize?client_id=client-a&login_hint=alice%40example.com")
    );
    assert_eq!(
        parsed.get("login_hint").map(String::as_str),
        Some("alice@example.com")
    );
}

#[test]
fn frontend_login_url_can_force_interactive_login() {
    let url = frontend_login_url("/oauth2/authorize?client_id=client-a", None, true);
    let query = url.trim_start_matches("/?");
    let parsed = serde_urlencoded::from_str::<HashMap<String, String>>(query).unwrap();
    assert_eq!(parsed.get("force_login").map(String::as_str), Some("1"));
}

#[test]
fn universal_login_context_accepts_only_one_opaque_interaction_handle() {
    assert_eq!(
        strict_interaction_request_from_return_to(Some(
            "/oauth2/authorize?interaction_request=urn%3Agpt-sso%3Abrowser-interaction%3Asecret"
        ))
        .as_deref(),
        Some("urn:gpt-sso:browser-interaction:secret")
    );
    for invalid in [
        "/oauth2/authorize?client_id=client-a&response_type=code",
        "/oauth2/authorize?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Apar",
        "/oauth2/authorize?interaction_request=one&client_id=client-a",
        "/oauth2/authorize?interaction_request=one&interaction_request=two",
        "/oauth2/authorize?interaction_request=one#fragment",
        "https://evil.example/oauth2/authorize?interaction_request=one",
    ] {
        assert_eq!(
            strict_interaction_request_from_return_to(Some(invalid)),
            None
        );
    }
}

#[test]
fn account_selection_entry_request_cannot_mark_selection_complete() {
    let request = test_authorize_request(Some("login select_account consent"), None);
    let prompted = account_selection_prompted_request(&request);
    assert!(!prompted.account_selection_prompted);
    assert!(prompted.account_selection_required);
    assert!(!prompted.reauthentication_required);
    assert_eq!(
        prompted.prompt.as_deref(),
        Some("login select_account consent")
    );
}

#[test]
fn public_authorize_query_cannot_forge_internal_account_state() {
    let query = serde_urlencoded::from_str::<AuthorizeRequest>(
            "response_type=code&client_id=demo-web&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&account_selection_prompted=true&account_selection_required=true&reauthentication_required=true&selected_session_id=forged-session&selected_user_id=forged-user",
        )
        .unwrap();
    let request = ResolvedAuthorizeRequest::from_query(query).unwrap();

    assert!(!request.account_selection_prompted);
    assert!(!request.account_selection_required);
    assert!(!request.reauthentication_required);
    assert_eq!(request.selected_session_id, None);
    assert_eq!(request.selected_user_id, None);
}

#[test]
fn reauthentication_request_remains_incomplete_until_login_proves_a_session() {
    let mut request = test_authorize_request(Some("login select_account"), Some(0));
    request.selected_user_id = Some("user-id".to_string());
    request.selected_session_id = Some("old-session".to_string());

    let pending = reauthentication_request(&request);

    assert!(pending.reauthentication_required);
    assert_eq!(pending.selected_user_id.as_deref(), Some("user-id"));
    assert_eq!(pending.selected_session_id, None);
    assert!(reauthentication_pending(&pending));
}

#[tokio::test]
async fn interaction_return_to_uses_short_request_uri() {
    let store = StubInteractionStore::new("urn:ietf:params:oauth:request_uri:stored-request");
    let mut request = test_authorize_request(Some("login consent"), None);
    request.state = Some("state-value-that-should-stay-server-side".repeat(8));
    request.nonce = Some("nonce-value-that-should-stay-server-side".repeat(8));

    let return_to = authorize_return_to_for_interaction(&store, &request, true)
        .await
        .unwrap();

    assert!(return_to.starts_with("/oauth2/authorize?"));
    assert!(!return_to.contains("client_id="));
    assert!(!return_to.contains("state-value"));
    assert!(!return_to.contains("nonce-value"));
    let query = return_to.trim_start_matches("/oauth2/authorize?");
    let parsed = serde_urlencoded::from_str::<HashMap<String, String>>(query).unwrap();
    assert_eq!(
        parsed.get("interaction_request").map(String::as_str),
        Some("urn:ietf:params:oauth:request_uri:stored-request")
    );

    let stored = store.stored.lock().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].prompt.as_deref(), Some("consent"));
    assert_eq!(stored[0].state, request.state);
    assert_eq!(stored[0].nonce, request.nonce);
}

#[tokio::test]
async fn login_context_uses_direct_authorization_return_to() {
    let (state, path) = test_app_state().await;
    let return_to = format!(
        "/oauth2/authorize?{}",
        serde_urlencode(&[
            ("response_type", "code".to_string()),
            ("client_id", "demo-web".to_string()),
            ("redirect_uri", "http://localhost:3000/callback".to_string(),),
            ("scope", "openid profile".to_string()),
            ("acr_values", assurance::ACR_MFA.to_string()),
        ])
    );

    let context =
        authorization_login_context_from_return_to(&state, &HeaderMap::new(), Some(&return_to))
            .await
            .unwrap();

    assert_eq!(
        context
            .client
            .as_ref()
            .map(|client| client.client_id.as_str()),
        Some("demo-web")
    );
    assert!(context.request_requires_mfa);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn login_context_peeks_interaction_request_without_consuming_it() {
    let (state, path) = test_app_state().await;
    let mut request = test_authorize_request(None, None);
    request.client_id = "demo-web".to_string();
    request.redirect_uri = "http://localhost:3000/callback".to_string();
    request.scope = Some("openid profile".to_string());
    request.acr_values = Some(assurance::ACR_MFA.to_string());
    let request_uri =
        crate::par::store_interaction_authorization_request(&state, &request.client_id, &request)
            .await
            .unwrap();
    let return_to = format!(
        "/oauth2/authorize?interaction_request={}",
        url_encode(&request_uri)
    );

    let context =
        authorization_login_context_from_return_to(&state, &HeaderMap::new(), Some(&return_to))
            .await
            .unwrap();

    assert_eq!(
        context
            .client
            .as_ref()
            .map(|client| client.client_id.as_str()),
        Some("demo-web")
    );
    assert!(context.request_requires_mfa);
    let consumed = crate::par::consume_interaction_request(&state, &request_uri)
        .await
        .unwrap();
    assert_eq!(consumed.client_id, "demo-web");
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn browser_account_context_exposes_the_verified_client_logo_uri() {
    let (state, path) = test_app_state().await;
    let client = insert_test_oidc_client(
        &state,
        "branded-client",
        "http://localhost:4100/callback",
        "https://assets.example.com/branded-client.svg",
    )
    .await;
    let mut request = test_authorize_request(None, None);
    request.client_id = client.client_id;
    request.redirect_uri = "http://localhost:4100/callback".to_string();
    let request_uri =
        crate::par::store_interaction_authorization_request(&state, &request.client_id, &request)
            .await
            .unwrap();
    let return_to = format!(
        "/oauth2/authorize?interaction_request={}",
        url_encode(&request_uri)
    );

    let context = browser_account_interaction_context(&state, &return_to)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(context.client_name, "branded-client");
    assert_eq!(
        context.client_logo_uri.as_deref(),
        Some("https://assets.example.com/branded-client.svg")
    );

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[test]
fn authorize_request_derives_assurance_from_acr_and_claims() {
    let mut request = test_authorize_request(None, None);
    request.acr_values = Some(assurance::ACR_PASSWORD.to_string());
    request.claims = RequestedClaims::from_authorization_parameter(Some(&format!(
            r#"{{"id_token":{{"acr":{{"essential":true,"values":["{}"]}},"amr":{{"essential":true,"values":["otp"]}}}}}}"#,
            assurance::ACR_MFA
        )))
        .unwrap();

    let requested = request.requested_assurance().unwrap();
    assert_eq!(
        requested.acr_values,
        vec![assurance::ACR_PASSWORD.to_string()]
    );
    assert_eq!(
        requested.essential_acr_values,
        vec![assurance::ACR_MFA.to_string()]
    );
    assert_eq!(requested.essential_amr_values, vec!["otp".to_string()]);
}

#[test]
fn post_logout_redirect_appends_state() {
    let redirect =
        post_logout_redirect_url("http://localhost:3000/logout?done=1", Some("abc 123")).unwrap();
    assert_eq!(
        redirect.as_str(),
        "http://localhost:3000/logout?done=1&state=abc+123"
    );
    assert!(post_logout_redirect_url("not a url", Some("state")).is_none());
}

#[tokio::test]
async fn invalid_consent_csrf_does_not_consume_interaction_request() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "consent-csrf").await;
    let (session, cookie_value) = state
        .db
        .insert_session(&user.id, 600, crate::db::SessionMetadata::default())
        .await
        .unwrap();
    let jar = CookieJar::new().add(auth::session_cookie(&state, cookie_value, 600));

    let page = consent_page(
        &state,
        &jar,
        &test_authorize_request(None, None),
        &test_client(),
        &user,
        true,
        &["openid".to_string()],
    )
    .await
    .unwrap();
    assert!(
        page.0
            .contains(&format!(r#"name="_csrf" value="{}""#, session.csrf_token))
    );
    let temporary_page = consent_page(
        &state,
        &jar,
        &test_authorize_request(None, None),
        &test_client(),
        &user,
        false,
        &["openid".to_string()],
    )
    .await
    .unwrap();
    assert!(!temporary_page.0.contains("name=\"remember\""));
    assert!(
        temporary_page
            .0
            .contains("restricted authorization-code session cannot remember")
    );

    let mut request = test_authorize_request(None, None);
    request.client_id = "demo-web".to_string();
    request.redirect_uri = "http://localhost:3000/callback".to_string();
    let request_uri =
        crate::par::store_interaction_authorization_request(&state, &request.client_id, &request)
            .await
            .unwrap();
    let result = authorize_consent(
        State(state.clone()),
        jar,
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12345".parse().unwrap()),
        Form(ConsentForm {
            _csrf: Some("wrong-token".to_string()),
            action: "approve".to_string(),
            remember: None,
            response_type: "code".to_string(),
            client_id: "demo-web".to_string(),
            redirect_uri: "http://localhost:3000/callback".to_string(),
            scope: "openid".to_string(),
            resource: None,
            authorization_details: None,
            login_hint: None,
            prompt: None,
            max_age: None,
            interaction_request: Some(request_uri.clone()),
            request_uri: None,
            acr_values: None,
            claims: None,
            state: None,
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            response_mode: None,
        }),
    )
    .await;
    assert!(matches!(result, Err(AppError::Forbidden)));
    let consumed = crate::par::consume_interaction_request(&state, &request_uri)
        .await
        .unwrap();
    assert_eq!(consumed.client_id, "demo-web");

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn logout_hint_must_match_subject_and_public_session_id() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "logout-hint").await;
    let (session, _cookie_value) = state
        .db
        .insert_session(&user.id, 600, crate::db::SessionMetadata::default())
        .await
        .unwrap();
    let current = auth::CurrentUser {
        user: user.clone(),
        session_id: session.id.clone(),
        session_kind: auth::AccountSessionKind::Standard,
    };
    let client = state
        .db
        .find_client_by_client_id("demo-web")
        .await
        .unwrap()
        .unwrap();
    let headers = HeaderMap::new();
    let issuer = state.effective_issuer(&headers).await.unwrap();
    let subject_identifier = subject::subject_for_client(&issuer, &user, &client).unwrap();
    let sign_hint = |subject_identifier: &str, sid: Option<&str>| {
        let mut extra_claims = serde_json::Map::new();
        if let Some(sid) = sid {
            extra_claims.insert(
                "sid".to_string(),
                serde_json::Value::String(sid.to_string()),
            );
        }
        state
            .jwt
            .sign_id_token_with_subject_and_claims(
                &issuer,
                TokenSubject {
                    user: &user,
                    client_id: &client.client_id,
                    audience: None,
                    scope: "openid",
                    nonce: None,
                    auth_time: Some(session.created_at),
                },
                subject_identifier,
                600,
                extra_claims,
            )
            .unwrap()
    };
    let request_for = |id_token_hint: String| LogoutRequest {
        _csrf: None,
        id_token_hint: Some(id_token_hint),
        logout_hint: None,
        client_id: Some(client.client_id.clone()),
        post_logout_redirect_uri: None,
        state: None,
        ui_locales: None,
    };

    let public_sid = util::session_public_id(&session.id);
    assert!(
        logout_hint_authorizes_current_session(
            &state,
            &headers,
            &current,
            &request_for(sign_hint(&subject_identifier, Some(&public_sid))),
        )
        .await
        .unwrap()
    );
    assert!(
        logout_hint_authorizes_current_session(
            &state,
            &headers,
            &current,
            &request_for(sign_hint(&subject_identifier, None)),
        )
        .await
        .unwrap()
    );
    assert!(
        !logout_hint_authorizes_current_session(
            &state,
            &headers,
            &current,
            &request_for(sign_hint(&subject_identifier, Some("sid.wrong"))),
        )
        .await
        .unwrap()
    );
    assert!(
        !logout_hint_authorizes_current_session(
            &state,
            &headers,
            &current,
            &request_for(sign_hint("different-subject", Some(&public_sid))),
        )
        .await
        .unwrap()
    );
    assert!(
        !logout_hint_authorizes_current_session(
            &state,
            &headers,
            &current,
            &request_for("not-a-token".to_string()),
        )
        .await
        .unwrap()
    );

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn untrusted_logout_get_requires_confirmation_without_deleting_session() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "logout-confirmation").await;
    let (session, cookie_value) = state
        .db
        .insert_session(&user.id, 600, crate::db::SessionMetadata::default())
        .await
        .unwrap();
    let jar = CookieJar::new().add(auth::session_cookie(&state, cookie_value, 600));
    let response = logout_get(
        State(state.clone()),
        jar.clone(),
        HeaderMap::new(),
        Query(LogoutRequest {
            _csrf: None,
            id_token_hint: Some("not-a-token".to_string()),
            logout_hint: None,
            client_id: Some("demo-web".to_string()),
            post_logout_redirect_uri: Some("http://localhost:3000/".to_string()),
            state: Some("opaque-state".to_string()),
            ui_locales: None,
        }),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert!(state.db.find_session(&session.id).await.unwrap().is_some());

    let client_only_response = logout_get(
        State(state.clone()),
        jar.clone(),
        HeaderMap::new(),
        Query(LogoutRequest {
            _csrf: None,
            id_token_hint: None,
            logout_hint: None,
            client_id: Some("demo-web".to_string()),
            post_logout_redirect_uri: Some("http://localhost:3000/".to_string()),
            state: Some("opaque-state".to_string()),
            ui_locales: None,
        }),
    )
    .await
    .unwrap();
    assert_eq!(client_only_response.status(), StatusCode::OK);
    assert!(state.db.find_session(&session.id).await.unwrap().is_some());

    let result = logout_post(
        State(state.clone()),
        jar,
        HeaderMap::new(),
        Form(LogoutRequest {
            _csrf: None,
            id_token_hint: Some("not-a-token".to_string()),
            logout_hint: None,
            client_id: Some("demo-web".to_string()),
            post_logout_redirect_uri: Some("http://localhost:3000/".to_string()),
            state: Some("opaque-state".to_string()),
            ui_locales: None,
        }),
    )
    .await;
    assert!(matches!(result, Err(AppError::Forbidden)));
    assert!(state.db.find_session(&session.id).await.unwrap().is_some());

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn account_switch_authorize_get_preserves_existing_session() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "account-switch").await;
    let (session, cookie_value) = state
        .db
        .insert_session(&user.id, 600, crate::db::SessionMetadata::default())
        .await
        .unwrap();
    let jar = CookieJar::new().add(auth::session_cookie(&state, cookie_value, 600));
    let response = authorize(
        State(state.clone()),
        jar,
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12345".parse().unwrap()),
        Query(AuthorizeRequest {
            interaction_request: None,
            request: None,
            request_uri: None,
            response_type: Some("code".to_string()),
            client_id: Some("demo-web".to_string()),
            redirect_uri: Some("http://localhost:3000/callback".to_string()),
            scope: Some("openid profile".to_string()),
            resource: None,
            authorization_details: None,
            login_hint: Some("someone-else@example.com".to_string()),
            prompt: None,
            max_age: None,
            acr_values: None,
            claims: None,
            state: Some("opaque-state".to_string()),
            nonce: Some("opaque-nonce".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            response_mode: None,
        }),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(state.db.find_session(&session.id).await.unwrap().is_some());

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn remembered_account_without_primary_cookie_opens_incomplete_account_chooser() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "remembered-account").await;
    let full_jar = auth::issue_session(
        &state,
        CookieJar::new(),
        &HeaderMap::new(),
        None,
        &user,
        "password",
    )
    .await
    .unwrap();
    let current = auth::require_current_user(&state, &full_jar).await.unwrap();
    let context_cookie = full_jar
        .get(&auth::browser_context_cookie_name(&state))
        .unwrap()
        .clone();
    let context_only_jar = CookieJar::new().add(context_cookie);

    let response = authorize(
        State(state.clone()),
        context_only_jar.clone(),
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12345".parse().unwrap()),
        Query(test_authorize_query(None, None)),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = redirect_url(&response);
    assert_eq!(query_value(&location, "auth"), "select_account");
    let return_to = query_value(&location, "return_to");
    let interaction_request = strict_interaction_request_from_return_to(Some(&return_to)).unwrap();
    let stored = crate::par::peek_interaction_request(&state, &interaction_request)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.account_selection_required);
    assert!(!stored.account_selection_prompted);
    assert!(!stored.reauthentication_required);
    assert_eq!(stored.selected_session_id, None);
    assert_eq!(stored.selected_user_id, None);
    assert!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|value| !value
                .to_str()
                .unwrap()
                .starts_with(&format!("{}=", state.settings.security.cookie_name)))
    );
    assert!(
        state
            .db
            .find_session(&current.session_id)
            .await
            .unwrap()
            .is_some()
    );

    let prompt_none_response = authorize(
        State(state.clone()),
        context_only_jar,
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12346".parse().unwrap()),
        Query(test_authorize_query(Some("none"), None)),
    )
    .await
    .unwrap();
    let prompt_none_location = redirect_url(&prompt_none_response);
    assert_eq!(
        query_value(&prompt_none_location, "error"),
        "login_required"
    );
    assert!(
        prompt_none_location
            .query_pairs()
            .all(|(key, value)| key != "auth" || value != "select_account")
    );

    let explicit_selection_response = authorize(
        State(state.clone()),
        CookieJar::new(),
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12347".parse().unwrap()),
        Query(test_authorize_query(Some("select_account"), None)),
    )
    .await
    .unwrap();
    assert_eq!(
        query_value(&redirect_url(&explicit_selection_response), "auth"),
        "select_account"
    );

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn login_prompt_continuation_requires_one_time_session_proof() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "login-proof").await;
    let (_session, cookie_value) = state
        .db
        .insert_session(
            &user.id,
            600,
            crate::db::SessionMetadata {
                login_method: Some("password".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let initial = authorize(
        State(state.clone()),
        CookieJar::new(),
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12345".parse().unwrap()),
        Query(test_authorize_query(Some("login"), None)),
    )
    .await
    .unwrap();
    let initial_location = redirect_url(&initial);
    assert_eq!(query_value(&initial_location, "auth"), "login");
    assert!(!query_value(&initial_location, "account_flow").is_empty());
    let return_to = query_value(&initial_location, "return_to");
    let interaction_request = strict_interaction_request_from_return_to(Some(&return_to)).unwrap();
    let pending = crate::par::peek_interaction_request(&state, &interaction_request)
        .await
        .unwrap()
        .unwrap();
    assert!(pending.reauthentication_required);
    assert_eq!(pending.selected_session_id, None);

    let existing_session_jar = CookieJar::new().add(auth::session_cookie(
        &state,
        cookie_value,
        state.settings.security.session_ttl_seconds,
    ));
    let bypass_attempt = authorize(
        State(state.clone()),
        existing_session_jar,
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12346".parse().unwrap()),
        Query(interaction_authorize_query(&interaction_request)),
    )
    .await
    .unwrap();
    let bypass_location = redirect_url(&bypass_attempt);
    assert_eq!(query_value(&bypass_location, "auth"), "login");
    assert!(!query_value(&bypass_location, "account_flow").is_empty());
    assert_ne!(bypass_location.host_str(), Some("localhost"));

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn selected_account_reauthentication_binds_new_session_and_satisfies_max_age() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "selected-reauth").await;
    let jar = auth::issue_session(
        &state,
        CookieJar::new(),
        &HeaderMap::new(),
        None,
        &user,
        "password",
    )
    .await
    .unwrap();
    let original = auth::require_current_user(&state, &jar).await.unwrap();
    let context_id = auth::browser_context_id_from_jar(&state, &jar).unwrap();

    let mut request = test_authorize_request(Some("login select_account"), Some(300));
    request.client_id = "demo-web".to_string();
    request.redirect_uri = "http://localhost:3000/callback".to_string();
    let selection_request = account_selection_prompted_request(&request);
    let selection_handle = crate::par::store_interaction_authorization_request(
        &state,
        &selection_request.client_id,
        &selection_request,
    )
    .await
    .unwrap();
    let selection_return_to = format!(
        "/oauth2/authorize?interaction_request={}",
        url_encode(&selection_handle)
    );
    let continuation =
        complete_browser_account_selection(&state, &selection_return_to, &original.session_id)
            .await
            .unwrap();
    assert!(continuation.reauthentication_required);
    let continuation_handle =
        strict_interaction_request_from_return_to(Some(&continuation.continue_to)).unwrap();
    let pending = crate::par::peek_interaction_request(&state, &continuation_handle)
        .await
        .unwrap()
        .unwrap();
    assert!(pending.account_selection_prompted);
    assert!(!pending.account_selection_required);
    assert!(pending.reauthentication_required);
    assert_eq!(pending.selected_user_id.as_deref(), Some(user.id.as_str()));
    assert_eq!(pending.selected_session_id, None);
    assert_eq!(pending.prompt.as_deref(), Some("login"));
    assert_eq!(pending.max_age, Some(300));

    let account_flow = format!("alf1.{}", util::random_token(24));
    state
        .db
        .insert_account_login_flow(
            &util::token_hash(&account_flow),
            &context_id,
            &continuation.continue_to,
            Some(&user.id),
            600,
        )
        .await
        .unwrap();
    let reauthenticated_jar = auth::issue_session_with_login_event(
        &state,
        jar,
        &HeaderMap::new(),
        None,
        &user,
        "password",
        auth::LoginEventContext {
            account_flow: Some(account_flow),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let reauthenticated = auth::require_current_user(&state, &reauthenticated_jar)
        .await
        .unwrap();
    assert_ne!(reauthenticated.session_id, original.session_id);
    assert!(
        state
            .db
            .find_session(&original.session_id)
            .await
            .unwrap()
            .is_none()
    );
    let completed = crate::par::peek_interaction_request(&state, &continuation_handle)
        .await
        .unwrap()
        .unwrap();
    assert!(!completed.reauthentication_required);
    assert_eq!(
        completed.selected_session_id.as_deref(),
        Some(reauthenticated.session_id.as_str())
    );
    assert_eq!(
        completed.selected_user_id.as_deref(),
        Some(user.id.as_str())
    );
    assert_eq!(completed.prompt.as_deref(), Some("login"));
    assert_eq!(completed.max_age, Some(300));
    let session = state
        .db
        .find_session(&reauthenticated.session_id)
        .await
        .unwrap()
        .unwrap();
    assert!(session_binding_satisfies_reauthentication(
        &completed, &session
    ));

    let response = authorize(
        State(state.clone()),
        reauthenticated_jar,
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12347".parse().unwrap()),
        Query(interaction_authorize_query(&continuation_handle)),
    )
    .await
    .unwrap();
    if response.status() == StatusCode::SEE_OTHER {
        let location = redirect_url(&response);
        assert_ne!(
            location
                .query_pairs()
                .find(|(key, _)| key == "auth")
                .map(|(_, value)| value.into_owned())
                .as_deref(),
            Some("login")
        );
        assert_ne!(
            location
                .query_pairs()
                .find(|(key, _)| key == "auth")
                .map(|(_, value)| value.into_owned())
                .as_deref(),
            Some("select_account")
        );
    } else {
        assert_eq!(response.status(), StatusCode::OK);
    }

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn max_age_zero_selected_account_always_requires_bound_reauthentication() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "max-age-zero-selection").await;
    let jar = auth::issue_session(
        &state,
        CookieJar::new(),
        &HeaderMap::new(),
        None,
        &user,
        "password",
    )
    .await
    .unwrap();
    let current = auth::require_current_user(&state, &jar).await.unwrap();
    let mut request = test_authorize_request(Some("select_account"), Some(0));
    request.client_id = "demo-web".to_string();
    request.redirect_uri = "http://localhost:3000/callback".to_string();
    let request = account_selection_prompted_request(&request);
    let selection_handle =
        crate::par::store_interaction_authorization_request(&state, &request.client_id, &request)
            .await
            .unwrap();
    let selection_return_to = format!(
        "/oauth2/authorize?interaction_request={}",
        url_encode(&selection_handle)
    );

    let continuation =
        complete_browser_account_selection(&state, &selection_return_to, &current.session_id)
            .await
            .unwrap();
    assert!(continuation.reauthentication_required);
    let continuation_handle =
        strict_interaction_request_from_return_to(Some(&continuation.continue_to)).unwrap();
    let pending = crate::par::peek_interaction_request(&state, &continuation_handle)
        .await
        .unwrap()
        .unwrap();
    assert!(pending.reauthentication_required);
    assert_eq!(pending.max_age, Some(0));
    assert_eq!(pending.selected_user_id.as_deref(), Some(user.id.as_str()));
    assert_eq!(pending.selected_session_id, None);

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn expired_selected_session_is_rejected_without_consuming_selection() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "expired-selection").await;
    let (expired_session, _) = state
        .db
        .insert_session(
            &user.id,
            -1,
            crate::db::SessionMetadata {
                login_method: Some("password".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let mut request = test_authorize_request(Some("select_account"), None);
    request.client_id = "demo-web".to_string();
    request.redirect_uri = "http://localhost:3000/callback".to_string();
    let request = account_selection_prompted_request(&request);
    let interaction_request =
        crate::par::store_interaction_authorization_request(&state, &request.client_id, &request)
            .await
            .unwrap();
    let return_to = format!(
        "/oauth2/authorize?interaction_request={}",
        url_encode(&interaction_request)
    );

    assert!(
        complete_browser_account_selection(&state, &return_to, &expired_session.id)
            .await
            .is_err()
    );
    assert!(
        crate::par::peek_interaction_request(&state, &interaction_request)
            .await
            .unwrap()
            .is_some()
    );

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn completed_account_binding_cannot_be_reselected_from_another_context_or_cookie() {
    let (state, path) = test_app_state().await;
    let alice = insert_refresh_test_user(&state, "binding-alice").await;
    let bob = insert_refresh_test_user(&state, "binding-bob").await;
    let alice_jar = auth::issue_session(
        &state,
        CookieJar::new(),
        &HeaderMap::new(),
        None,
        &alice,
        "password",
    )
    .await
    .unwrap();
    let alice_current = auth::require_current_user(&state, &alice_jar)
        .await
        .unwrap();
    let bob_jar = auth::issue_session(
        &state,
        CookieJar::new(),
        &HeaderMap::new(),
        None,
        &bob,
        "password",
    )
    .await
    .unwrap();
    let bob_current = auth::require_current_user(&state, &bob_jar).await.unwrap();
    let bob_context_cookie = bob_jar
        .get(&auth::browser_context_cookie_name(&state))
        .unwrap()
        .clone();

    let wrong_cookie_handle =
        completed_selection_interaction(&state, &alice_current.session_id).await;
    let wrong_cookie_response = authorize(
        State(state.clone()),
        bob_jar.clone(),
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12345".parse().unwrap()),
        Query(interaction_authorize_query(&wrong_cookie_handle)),
    )
    .await
    .unwrap();
    let wrong_cookie_location = redirect_url(&wrong_cookie_response);
    assert_eq!(query_value(&wrong_cookie_location, "auth"), "login");
    assert!(
        wrong_cookie_location
            .query_pairs()
            .all(|(key, value)| key != "auth" || value != "select_account")
    );
    let account_flow = query_value(&wrong_cookie_location, "account_flow");
    assert!(
        auth::issue_session_with_login_event(
            &state,
            bob_jar,
            &HeaderMap::new(),
            None,
            &bob,
            "password",
            auth::LoginEventContext {
                account_flow: Some(account_flow),
                ..Default::default()
            },
        )
        .await
        .is_err()
    );
    assert!(
        state
            .db
            .find_session(&bob_current.session_id)
            .await
            .unwrap()
            .is_some()
    );

    let cross_context_handle =
        completed_selection_interaction(&state, &alice_current.session_id).await;
    let context_only_jar = CookieJar::new().add(bob_context_cookie);
    let cross_context_response = authorize(
        State(state.clone()),
        context_only_jar,
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12346".parse().unwrap()),
        Query(interaction_authorize_query(&cross_context_handle)),
    )
    .await
    .unwrap();
    let cross_context_location = redirect_url(&cross_context_response);
    assert_eq!(query_value(&cross_context_location, "auth"), "login");
    assert!(
        cross_context_location
            .query_pairs()
            .all(|(key, value)| key != "auth" || value != "select_account")
    );
    let pending_return_to = query_value(&cross_context_location, "return_to");
    let pending_handle =
        strict_interaction_request_from_return_to(Some(&pending_return_to)).unwrap();
    let pending = crate::par::peek_interaction_request(&state, &pending_handle)
        .await
        .unwrap()
        .unwrap();
    assert!(pending.reauthentication_required);
    assert_eq!(pending.selected_user_id.as_deref(), Some(alice.id.as_str()));
    assert_eq!(pending.selected_session_id, None);

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn temporary_authorization_code_session_allows_oidc_but_rejects_offline_access() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "temporary-oidc").await;
    let jar = auth::issue_session_with_login_event(
        &state,
        CookieJar::new(),
        &HeaderMap::new(),
        None,
        &user,
        "authorization_code",
        auth::LoginEventContext {
            session_ttl_seconds: Some(120),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let response = authorize(
        State(state.clone()),
        jar.clone(),
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12345".parse().unwrap()),
        Query(test_authorize_query(None, None)),
    )
    .await
    .unwrap();
    if response.status() == StatusCode::SEE_OTHER {
        let location = redirect_url(&response);
        assert!(
            location
                .query_pairs()
                .all(|(key, value)| { key != "error" || value != "access_denied" })
        );
    } else {
        assert_eq!(response.status(), StatusCode::OK);
    }

    let mut offline_query = test_authorize_query(None, None);
    offline_query.scope = Some("openid offline_access".to_string());
    let offline_response = authorize(
        State(state.clone()),
        jar,
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12346".parse().unwrap()),
        Query(offline_query),
    )
    .await
    .unwrap();
    assert_eq!(
        query_value(&redirect_url(&offline_response), "error"),
        "invalid_scope"
    );

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn trial_enrollment_session_only_authorizes_its_immutable_client_allowlist() {
    let (state, path) = test_app_state().await;
    let organization = state
        .db
        .insert_organization(crate::db::NewOrganization {
            slug: "trial-oidc".to_string(),
            name: "Trial OIDC".to_string(),
            kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            allowed_email_domains: vec!["example.com".to_string()],
            is_active: true,
        })
        .await
        .unwrap();
    let blocked_client = insert_test_oidc_client(
        &state,
        "trial-blocked",
        "http://localhost:4100/callback",
        "",
    )
    .await;
    let (invitation, code) = state
        .db
        .insert_invitation(crate::db::NewInvitation {
            code_type: crate::db::AuthorizationCodeType::Login,
            login_code_level: crate::db::LoginCodeLevel::TrialEnrollment,
            allowed_client_ids: vec!["demo-web".to_string()],
            organization_id: Some(organization.id.clone()),
            organization_role: Some(crate::organizations::ROLE_MEMBER.to_string()),
            description: None,
            authorized_email: None,
            authorized_username: None,
            authorized_user_id: None,
            authorized_display_name: None,
            expires_at: Some(util::now_ts() + 600),
            max_uses: Some(1),
            is_active: true,
            created_by: None,
        })
        .await
        .unwrap();
    let enrollment = state
        .db
        .redeem_trial_enrollment_code_for_new_user(
            &code,
            crate::db::NewTrialEnrollmentUser {
                email: "trial-oidc@example.com".to_string(),
                username: "trial-oidc".to_string(),
                display_name: None,
                password_hash: "test-hash".to_string(),
            },
        )
        .await
        .unwrap();
    let jar = auth::issue_session_with_login_event(
        &state,
        CookieJar::new(),
        &HeaderMap::new(),
        None,
        &enrollment.user,
        "trial_enrollment",
        auth::LoginEventContext {
            session_ttl_seconds: Some(300),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let allowed_response = authorize(
        State(state.clone()),
        jar.clone(),
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12345".parse().unwrap()),
        Query(test_authorize_query(None, None)),
    )
    .await
    .unwrap();
    if allowed_response.status().is_redirection() {
        assert!(
            redirect_url(&allowed_response)
                .query_pairs()
                .all(|(key, value)| key != "error" || value != "access_denied")
        );
    } else {
        assert_ne!(allowed_response.status(), StatusCode::FORBIDDEN);
    }

    let mut blocked_query = test_authorize_query(None, None);
    blocked_query.client_id = Some(blocked_client.client_id.clone());
    blocked_query.redirect_uri = Some("http://localhost:4100/callback".to_string());
    let blocked_response = authorize(
        State(state.clone()),
        jar.clone(),
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12346".parse().unwrap()),
        Query(blocked_query),
    )
    .await
    .unwrap();
    assert_eq!(
        query_value(&redirect_url(&blocked_response), "error"),
        "access_denied"
    );

    let mut offline_query = test_authorize_query(None, None);
    offline_query.scope = Some("openid offline_access".to_string());
    let offline_response = authorize(
        State(state.clone()),
        jar.clone(),
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12347".parse().unwrap()),
        Query(offline_query),
    )
    .await
    .unwrap();
    assert_eq!(
        query_value(&redirect_url(&offline_response), "error"),
        "invalid_scope"
    );

    state
        .db
        .update_invitation(crate::db::InvitationUpdate {
            id: &invitation.id,
            description: None,
            authorized_email: None,
            authorized_username: None,
            authorized_display_name: None,
            expires_at: Some(util::now_ts() + 600),
            max_uses: Some(1),
            is_active: false,
        })
        .await
        .unwrap();
    assert!(
        auth::current_user_from_cookie(&state, &jar)
            .await
            .unwrap()
            .is_none()
    );

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn admin_universal_grant_precedes_primary_session_and_has_one_winner() {
    let (state, path) = test_app_state().await;
    let primary_user = insert_refresh_test_user(&state, "universal-primary").await;
    let target_user = insert_refresh_test_user(&state, "universal-target").await;
    let (primary_session, primary_cookie) = state
        .db
        .insert_session(&primary_user.id, 600, crate::db::SessionMetadata::default())
        .await
        .unwrap();

    let mut request = test_authorize_request(None, None);
    request.client_id = "demo-web".to_string();
    request.redirect_uri = "http://localhost:3000/callback".to_string();
    request.scope = Some("openid profile".to_string());
    let interaction_request =
        crate::par::store_interaction_authorization_request(&state, &request.client_id, &request)
            .await
            .unwrap();
    let (_invitation, raw_code) = state
        .db
        .insert_invitation(crate::db::NewInvitation {
            code_type: crate::db::AuthorizationCodeType::Login,
            login_code_level: crate::db::LoginCodeLevel::AdminUniversal,
            allowed_client_ids: vec!["demo-web".to_string()],
            organization_id: None,
            organization_role: None,
            description: Some("test universal code".to_string()),
            authorized_email: None,
            authorized_username: None,
            authorized_user_id: None,
            authorized_display_name: None,
            expires_at: Some(util::now_ts() + 600),
            max_uses: Some(1),
            is_active: true,
            created_by: None,
        })
        .await
        .unwrap();
    let (credential_hash, credential_value) = new_oidc_login_grant_credentials();
    let interaction_request_hash = util::token_hash(&interaction_request);
    let redemption = state
        .db
        .redeem_admin_login_code_for_oidc_grant(crate::db::AdminLoginCodeRedemptionInput {
            code: &raw_code,
            user_id: &target_user.id,
            email: &target_user.email,
            trusted_client_id: "demo-web",
            interaction_request_hash: &interaction_request_hash,
            credential_hash: &credential_hash,
            ttl_seconds: OIDC_LOGIN_GRANT_TTL_SECONDS,
        })
        .await
        .unwrap();
    assert_eq!(redemption.user.id, target_user.id);

    let jar = CookieJar::new()
        .add(auth::session_cookie(&state, primary_cookie, 600))
        .add(oidc_login_grant_cookie(&state, credential_value));
    let query = AuthorizeRequest {
        interaction_request: Some(interaction_request),
        request: None,
        request_uri: None,
        response_type: None,
        client_id: None,
        redirect_uri: None,
        scope: None,
        resource: None,
        authorization_details: None,
        login_hint: None,
        prompt: None,
        max_age: None,
        acr_values: None,
        claims: None,
        state: None,
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
        response_mode: None,
    };
    let first = authorize(
        State(state.clone()),
        jar.clone(),
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12345".parse().unwrap()),
        Query(query.clone()),
    );
    let second = authorize(
        State(state.clone()),
        jar,
        HeaderMap::new(),
        ConnectInfo("127.0.0.1:12346".parse().unwrap()),
        Query(query),
    );
    let (first, second) = tokio::join!(first, second);

    let mut location = None;
    let mut failures = 0;
    for result in [first, second] {
        match result {
            Ok(response) if response.status() == StatusCode::SEE_OTHER => {
                assert!(location.is_none(), "only one authorization may succeed");
                location = Some(
                    response
                        .headers()
                        .get(header::LOCATION)
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string(),
                );
            }
            Err(_) => failures += 1,
            Ok(response) => panic!("unexpected authorization status: {}", response.status()),
        }
    }
    assert_eq!(failures, 1);
    let location = Url::parse(location.as_deref().expect("one redirect should succeed")).unwrap();
    let code = location
        .query_pairs()
        .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
        .expect("authorization redirect should contain a code");
    let authorization_code = state.db.consume_authorization_code(&code).await.unwrap();
    assert_eq!(authorization_code.user_id, target_user.id);
    assert_eq!(authorization_code.client_id, "demo-web");
    assert_eq!(authorization_code.session_id, None);
    assert_eq!(authorization_code.acr, assurance::ACR_PASSWORD);
    assert_eq!(
        util::from_json::<Vec<String>>(&authorization_code.amr).unwrap(),
        vec!["authorization_code".to_string()]
    );
    assert!(
        state
            .db
            .find_session(&primary_session.id)
            .await
            .unwrap()
            .is_some(),
        "universal login must preserve the primary browser session"
    );

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[test]
fn resource_parameter_must_be_absolute_without_fragment() {
    assert_eq!(
        normalize_resource(Some("https://api.example/resource")).unwrap(),
        Some("https://api.example/resource".to_string())
    );
    assert!(normalize_resource(Some("/relative")).is_err());
    assert!(normalize_resource(Some("https://api.example/#frag")).is_err());
}

#[test]
fn client_credentials_use_and_enforce_configured_audience() {
    let mut client = test_client();
    client.audience = "https://memory.example/api".to_string();

    assert_eq!(
        resolve_client_credentials_audience(&client, None, None).unwrap(),
        Some("https://memory.example/api".to_string())
    );
    assert_eq!(
        resolve_client_credentials_audience(
            &client,
            Some("https://other.example/api".to_string()),
            None,
        )
        .unwrap_err()
        .to_string(),
        "oidc error: resource parameter does not match configured client audience"
    );
    assert_eq!(
        resolve_client_credentials_audience(
            &client,
            Some("https://memory.example/api".to_string()),
            None,
        )
        .unwrap(),
        Some("https://memory.example/api".to_string())
    );
}

#[test]
fn token_resource_cannot_change_issued_resource() {
    assert_eq!(
        merge_token_resource(
            Some("https://api.example/one".to_string()),
            Some("https://api.example/one".to_string())
        )
        .unwrap(),
        Some("https://api.example/one".to_string())
    );
    assert!(
        merge_token_resource(
            Some("https://api.example/one".to_string()),
            Some("https://api.example/two".to_string())
        )
        .is_err()
    );
}

#[test]
fn authorization_code_tokens_preserve_login_code_provenance() {
    assert_eq!(
        authorization_code_login_level(Some("sid.recovery"), &["temporary".to_string()]),
        Some(LoginCodeLevel::AccountRecovery)
    );
    assert_eq!(
        authorization_code_login_level(None, &["authorization_code".to_string()]),
        Some(LoginCodeLevel::AdminUniversal)
    );
    assert_eq!(
        authorization_code_login_level(Some("sid.trial"), &["trial_enrollment".to_string()]),
        Some(LoginCodeLevel::TrialEnrollment)
    );
    assert_eq!(
        authorization_code_login_level(Some("sid.normal"), &["pwd".to_string()]),
        None
    );
}

#[tokio::test]
async fn login_code_tokens_are_marked_and_never_receive_refresh_tokens() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "login-code-token").await;
    let client = state
        .db
        .find_client_by_client_id("demo-web")
        .await
        .unwrap()
        .unwrap();
    let issuer = state.settings.oidc.issuer.clone();

    for (suffix, session_id, amr, expected_level) in [
        (
            "recovery",
            Some("sid.recovery".to_string()),
            vec!["temporary".to_string()],
            "account_recovery",
        ),
        (
            "universal",
            None,
            vec!["authorization_code".to_string()],
            "admin_universal",
        ),
        (
            "trial",
            Some("sid.trial".to_string()),
            vec!["trial_enrollment".to_string()],
            "trial_enrollment",
        ),
    ] {
        let code = format!("login-code-token-{suffix}");
        state
            .db
            .insert_authorization_code(NewAuthorizationCode {
                code: code.clone(),
                client_id: client.client_id.clone(),
                user_id: user.id.clone(),
                application_id: None,
                authorization_profile_id: None,
                auth_context_id: None,
                session_id,
                redirect_uri: "http://localhost:3000/callback".to_string(),
                // This inconsistent defense-in-depth fixture proves that
                // login-code provenance suppresses refresh issuance even
                // if an old/stale authorization record contains offline.
                scope: "openid offline_access".to_string(),
                resource: None,
                authorization_details: None,
                nonce: Some(format!("nonce-{suffix}")),
                code_challenge: None,
                code_challenge_method: None,
                auth_time: util::now_ts(),
                acr: assurance::ACR_PASSWORD.to_string(),
                amr,
                expires_at: util::now_ts() + 300,
            })
            .await
            .unwrap();

        let Json(response) = token_from_authorization_code(
            state.clone(),
            client.clone(),
            test_authorization_code_token_request(&code),
            issuer.clone(),
            None,
        )
        .await
        .unwrap();
        assert!(response.refresh_token.is_none());
        let access_claims = state
            .jwt
            .verify_access_token_with_issuers(&response.access_token, &[issuer.as_str()])
            .unwrap();
        assert_eq!(
            access_claims.gpt_sso_login_code_level.as_deref(),
            Some(expected_level)
        );
        let id_token = response
            .id_token
            .expect("authorization code returns ID token");
        let id_claims = state
            .jwt
            .verify_id_token_hint_with_issuers(&id_token, &[issuer.as_str()])
            .unwrap();
        assert_eq!(
            id_claims.gpt_sso_login_code_level.as_deref(),
            Some(expected_level)
        );
    }

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn concurrent_refresh_grant_has_one_winner_and_returns_invalid_grant() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "race").await;
    let refresh_token = "concurrent-refresh-token";
    state
        .db
        .insert_refresh_token(
            "demo-web".to_string(),
            RefreshTokenInput {
                token_hash: util::token_hash(refresh_token),
                user_id: user.id,
                scope: "profile".to_string(),
                resource: None,
                authorization_details: None,
                dpop_jkt: None,
                auth_context_id: None,
                expires_at: util::now_ts() + 600,
            },
        )
        .await
        .unwrap();

    let client = test_refresh_client(&state).await;
    let issuer = state.settings.oidc.issuer.clone();
    let (first, second) = tokio::join!(
        token_from_refresh_token(
            state.clone(),
            client.clone(),
            test_refresh_request(refresh_token),
            issuer.clone(),
            None,
        ),
        token_from_refresh_token(
            state.clone(),
            client,
            test_refresh_request(refresh_token),
            issuer,
            None,
        )
    );

    let mut replacement_token = None;
    let mut invalid_grants = 0;
    for result in [first, second] {
        match result {
            Ok(Json(response)) => {
                assert!(replacement_token.is_none());
                replacement_token = response.refresh_token;
            }
            Err(AppError::OAuth { error, status, .. }) => {
                assert_eq!(error, "invalid_grant");
                assert_eq!(status, StatusCode::BAD_REQUEST);
                invalid_grants += 1;
            }
            Err(other) => panic!("unexpected refresh error: {other:?}"),
        }
    }
    assert_eq!(invalid_grants, 1);
    let replacement_token = replacement_token.expect("one rotation should succeed");
    assert!(
        state
            .db
            .find_refresh_token(&util::token_hash(&replacement_token))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        state
            .db
            .find_refresh_token(&util::token_hash(refresh_token))
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn failed_dpop_and_resource_validation_do_not_consume_refresh_token() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "validation").await;
    let refresh_token = "validation-refresh-token";
    let refresh_hash = util::token_hash(refresh_token);
    state
        .db
        .insert_refresh_token(
            "demo-web".to_string(),
            RefreshTokenInput {
                token_hash: refresh_hash.clone(),
                user_id: user.id,
                scope: "profile".to_string(),
                resource: Some("https://api.example/one".to_string()),
                authorization_details: None,
                dpop_jkt: Some("expected-jkt".to_string()),
                auth_context_id: None,
                expires_at: util::now_ts() + 600,
            },
        )
        .await
        .unwrap();

    let client = test_refresh_client(&state).await;
    let issuer = state.settings.oidc.issuer.clone();
    let dpop_error = token_from_refresh_token(
        state.clone(),
        client.clone(),
        test_refresh_request(refresh_token),
        issuer.clone(),
        Some(DpopBinding {
            jkt: "wrong-jkt".to_string(),
        }),
    )
    .await
    .expect_err("mismatched DPoP key should fail");
    assert!(matches!(
        dpop_error,
        AppError::OAuth { error, .. } if error == "invalid_dpop_proof"
    ));
    assert!(
        state
            .db
            .find_refresh_token(&refresh_hash)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );

    let mut invalid_resource_request = test_refresh_request(refresh_token);
    invalid_resource_request.resource = Some("https://api.example/two".to_string());
    assert!(
        token_from_refresh_token(
            state.clone(),
            client.clone(),
            invalid_resource_request,
            issuer.clone(),
            Some(DpopBinding {
                jkt: "expected-jkt".to_string(),
            }),
        )
        .await
        .is_err()
    );
    assert!(
        state
            .db
            .find_refresh_token(&refresh_hash)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );

    let mut valid_request = test_refresh_request(refresh_token);
    valid_request.resource = Some("https://api.example/one".to_string());
    let response = token_from_refresh_token(
        state.clone(),
        client,
        valid_request,
        issuer,
        Some(DpopBinding {
            jkt: "expected-jkt".to_string(),
        }),
    )
    .await
    .unwrap();
    assert!(response.0.refresh_token.is_some());

    drop(state);
    let _ = std::fs::remove_file(path);
}

#[test]
fn client_policy_requires_pushed_authorization_requests() {
    let mut client = test_client();
    client.require_pushed_authorization_requests = 1;
    let mut request = test_authorize_request(None, None);

    assert!(validate_authorize_request_for_client(&client, &request).is_err());
    request.source = AuthorizationRequestSource::PushedAuthorizationRequest;
    assert!(validate_authorize_request_for_client(&client, &request).is_ok());
}

#[test]
fn client_policy_requires_s256_pkce() {
    let mut client = test_client();
    client.require_pkce = 1;
    client.require_s256_pkce = 1;
    let mut request = test_authorize_request(None, None);
    request.code_challenge = Some("c".repeat(43));
    request.code_challenge_method = Some("plain".to_string());

    assert!(validate_authorize_request_for_client(&client, &request).is_err());
    request.code_challenge_method = Some("S256".to_string());
    assert!(validate_authorize_request_for_client(&client, &request).is_ok());
}

#[test]
fn authorization_details_require_allowed_client_types() {
    let mut request = test_authorize_request(None, None);
    request.authorization_details =
        Some(r#"[{"type":"resource_access","actions":["read"]}]"#.to_string());
    let mut client = test_client();

    assert!(validate_authorize_request_for_client(&client, &request).is_err());
    client.authorization_details_types = serde_json::json!(["resource_access"]).to_string();
    assert!(validate_authorize_request_for_client(&client, &request).is_ok());
}

fn test_session(created_at: i64) -> SessionRecord {
    SessionRecord {
        id: "session-id".to_string(),
        user_id: "user-id".to_string(),
        csrf_token: "csrf".to_string(),
        ip_address: None,
        user_agent: None,
        login_method: Some("password".to_string()),
        expires_at: created_at + 3600,
        created_at,
    }
}

fn test_authorize_request(prompt: Option<&str>, max_age: Option<i64>) -> ResolvedAuthorizeRequest {
    ResolvedAuthorizeRequest {
        source: AuthorizationRequestSource::Query,
        response_type: "code".to_string(),
        client_id: "client-a".to_string(),
        redirect_uri: "https://app.example/callback".to_string(),
        scope: Some("openid profile".to_string()),
        resource: None,
        authorization_details: None,
        login_hint: None,
        prompt: prompt.map(str::to_string),
        max_age,
        acr_values: None,
        claims: None,
        state: Some("state-a".to_string()),
        nonce: Some("nonce-a".to_string()),
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

fn test_authorize_query(prompt: Option<&str>, max_age: Option<i64>) -> AuthorizeRequest {
    AuthorizeRequest {
        interaction_request: None,
        request: None,
        request_uri: None,
        response_type: Some("code".to_string()),
        client_id: Some("demo-web".to_string()),
        redirect_uri: Some("http://localhost:3000/callback".to_string()),
        scope: Some("openid profile".to_string()),
        resource: None,
        authorization_details: None,
        login_hint: None,
        prompt: prompt.map(str::to_string),
        max_age: max_age.map(|value| value.to_string()),
        acr_values: None,
        claims: None,
        state: Some("opaque-state".to_string()),
        nonce: Some("opaque-nonce".to_string()),
        code_challenge: None,
        code_challenge_method: None,
        response_mode: None,
    }
}

fn interaction_authorize_query(interaction_request: &str) -> AuthorizeRequest {
    let mut query = test_authorize_query(None, None);
    query.interaction_request = Some(interaction_request.to_string());
    query.response_type = None;
    query.client_id = None;
    query.redirect_uri = None;
    query.scope = None;
    query.state = None;
    query.nonce = None;
    query
}

async fn completed_selection_interaction(state: &AppState, session_id: &str) -> String {
    let mut request = test_authorize_request(Some("select_account"), None);
    request.client_id = "demo-web".to_string();
    request.redirect_uri = "http://localhost:3000/callback".to_string();
    let request = account_selection_prompted_request(&request);
    let selection_handle =
        crate::par::store_interaction_authorization_request(state, &request.client_id, &request)
            .await
            .unwrap();
    let selection_return_to = format!(
        "/oauth2/authorize?interaction_request={}",
        url_encode(&selection_handle)
    );
    let continuation = complete_browser_account_selection(state, &selection_return_to, session_id)
        .await
        .unwrap();
    strict_interaction_request_from_return_to(Some(&continuation.continue_to)).unwrap()
}

fn test_refresh_request(refresh_token: &str) -> TokenRequest {
    TokenRequest {
        grant_type: "refresh_token".to_string(),
        code: None,
        device_code: None,
        redirect_uri: None,
        client_auth: ClientAuthForm {
            client_id: Some("demo-web".to_string()),
            ..Default::default()
        },
        code_verifier: None,
        refresh_token: Some(refresh_token.to_string()),
        scope: None,
        resource: None,
        authorization_details: None,
        subject_token: None,
        subject_token_type: None,
        requested_token_type: None,
        audience: None,
        actor_token: None,
    }
}

fn test_authorization_code_token_request(code: &str) -> TokenRequest {
    TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: Some(code.to_string()),
        device_code: None,
        redirect_uri: Some("http://localhost:3000/callback".to_string()),
        client_auth: ClientAuthForm {
            client_id: Some("demo-web".to_string()),
            ..Default::default()
        },
        code_verifier: None,
        refresh_token: None,
        scope: None,
        resource: None,
        authorization_details: None,
        subject_token: None,
        subject_token_type: None,
        requested_token_type: None,
        audience: None,
        actor_token: None,
    }
}

async fn test_refresh_client(state: &AppState) -> ClientRecord {
    state
        .db
        .find_client_by_client_id("demo-web")
        .await
        .unwrap()
        .expect("test bootstrap client")
}

#[cfg(feature = "sqlite")]
async fn oidc_http_body_json(response: Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn oidc_http_flow_exposes_application_entitlements_and_rechecks_access() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "application-http").await;
    let (_session, cookie_value) = state
        .db
        .insert_session(&user.id, 600, crate::db::SessionMetadata::default())
        .await
        .unwrap();
    let cookie = format!("{}={cookie_value}", state.settings.security.cookie_name);
    let app = routes().with_state(state.clone());

    let discovery = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(discovery.status(), StatusCode::OK);
    let discovery_body = oidc_http_body_json(discovery).await;
    assert_eq!(
        discovery_body["authorization_endpoint"],
        "http://localhost:8080/oauth2/authorize"
    );
    assert_eq!(
        discovery_body["token_endpoint"],
        "http://localhost:8080/oauth2/token"
    );
    assert_eq!(
        discovery_body["jwks_uri"],
        "http://localhost:8080/oauth2/jwks"
    );

    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("response_type", "code")
        .append_pair("client_id", "demo-web")
        .append_pair("redirect_uri", "http://localhost:3000/callback")
        .append_pair("scope", "openid profile email")
        .append_pair("state", "oidc-state")
        .append_pair("nonce", "oidc-nonce");
    let mut authorize_request = Request::builder()
        .uri(format!("/oauth2/authorize?{}", query.finish()))
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    authorize_request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43000))));
    let authorize_response = app.clone().oneshot(authorize_request).await.unwrap();
    assert_eq!(authorize_response.status(), StatusCode::SEE_OTHER);
    let redirect = redirect_url(&authorize_response);
    assert_eq!(redirect.path(), "/callback");
    assert_eq!(query_value(&redirect, "state"), "oidc-state");
    let code = query_value(&redirect, "code");

    let form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "http://localhost:3000/callback"),
    ])
    .unwrap();
    let basic = STANDARD.encode("demo-web:demo-secret-change-me");
    let wrong_redirect_form = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", "http://localhost:3000/wrong-callback"),
    ])
    .unwrap();
    let wrong_redirect = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header(header::AUTHORIZATION, format!("Basic {basic}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(wrong_redirect_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_redirect.status(), StatusCode::BAD_REQUEST);

    let token_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oauth2/token")
                .header(header::AUTHORIZATION, format!("Basic {basic}"))
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(token_response.status(), StatusCode::OK);
    let token_body = oidc_http_body_json(token_response).await;
    let access_token = token_body["access_token"].as_str().unwrap();
    let claims = state.jwt.verify_access_token(access_token).unwrap();
    assert_eq!(claims.sub, user.id);
    assert_eq!(claims.client_id, "demo-web");
    assert_eq!(claims.nonce, None);

    let userinfo = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth2/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(userinfo.status(), StatusCode::OK);
    let userinfo_body = oidc_http_body_json(userinfo).await;
    assert_eq!(userinfo_body["email"], user.email);

    let application = state
        .db
        .find_application_for_client(
            &state
                .db
                .find_client_by_client_id("demo-web")
                .await
                .unwrap()
                .unwrap()
                .id,
        )
        .await
        .unwrap()
        .unwrap();
    state
        .db
        .update_application(
            &application.id,
            crate::db::NewApplication {
                organization_id: application.organization_id.clone(),
                slug: application.slug.clone(),
                name: application.name.clone(),
                description: application.description.clone(),
                access_mode: applications::ACCESS_ALL_SIGNET_USERS.to_string(),
                registration_mode: applications::REGISTRATION_DISABLED.to_string(),
                account_selection_mode: application.account_selection_mode.clone(),
                unique_identity_factors: application.unique_identity_factors().unwrap(),
                is_active: false,
            },
        )
        .await
        .unwrap();
    let revoked = app
        .oneshot(
            Request::builder()
                .uri("/oauth2/userinfo")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::FORBIDDEN);

    let _ = std::fs::remove_file(path);
}

async fn insert_refresh_test_user(state: &AppState, suffix: &str) -> UserRecord {
    state
        .db
        .insert_user(crate::db::NewUser {
            email: format!("refresh-{suffix}@example.com"),
            username: format!("refresh-{suffix}"),
            display_name: None,
            phone: None,
            password_hash: "test-hash".to_string(),
            email_verified_at: Some(util::now_ts()),
            phone_verified_at: None,
            is_admin: false,
            is_active: true,
            archived_at: None,
        })
        .await
        .unwrap()
}

async fn insert_test_oidc_client(
    state: &AppState,
    client_id: &str,
    redirect_uri: &str,
    logo_uri: &str,
) -> ClientRecord {
    state
        .db
        .insert_client(crate::db::NewClient {
            client_id: client_id.to_string(),
            client_secret_hash: None,
            client_name: client_id.to_string(),
            logo_uri: logo_uri.to_string(),
            organization_id: None,
            redirect_uris: vec![redirect_uri.to_string()],
            post_logout_redirect_uris: Vec::new(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "offline_access".to_string(),
            ],
            audience: String::new(),
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: false,
            require_mfa: false,
            require_pushed_authorization_requests: false,
            require_s256_pkce: false,
            require_confidential_client: false,
            require_dpop: false,
            require_account_selection: false,
            trust_email_verified: false,
            authorization_details_types: Vec::new(),
            subject_type: subject::SUBJECT_TYPE_PUBLIC.to_string(),
            sector_identifier_uri: String::new(),
            jwks_uri: String::new(),
            jwks: String::new(),
            backchannel_logout_uri: String::new(),
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: String::new(),
            frontchannel_logout_session_required: false,
            service_account_enabled: false,
            service_account_permissions: Vec::new(),
            is_active: true,
        })
        .await
        .unwrap()
}

async fn test_app_state() -> (AppState, PathBuf) {
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../config/default.toml");
    let raw = std::fs::read_to_string(config_path).unwrap();
    let mut settings: crate::Settings = toml::from_str(&raw).unwrap();
    // The production profile now requires explicit consent before a
    // delegated scope is granted. These fixture-based HTTP tests exercise
    // the post-login protocol path and historically assume the browser
    // consent page is skipped; consent-specific behavior is covered by
    // dedicated tests below.
    settings.oidc.skip_consent = true;
    let path = std::env::temp_dir().join(format!(
        "gpt-sso-oidc-test-{}.sqlite3",
        uuid::Uuid::new_v4()
    ));
    settings.database.kind = crate::config::DatabaseKind::Sqlite;
    settings.database.url = path.to_string_lossy().to_string();
    settings.database.run_migrations = true;
    settings.bootstrap.admin.create_on_startup = false;
    // Keep the production profile free of authentication clients while
    // preserving the historical OIDC HTTP fixture used by this module.
    // This client exists only in the per-test database and is still
    // reconciled through the normal bootstrap path, including its
    // application boundary.
    settings
        .bootstrap
        .clients
        .push(crate::config::BootstrapClient {
            client_id: "demo-web".to_string(),
            client_name: "Demo Web App".to_string(),
            logo_uri: String::new(),
            client_secret: "demo-secret-change-me".to_string(),
            client_secret_env: None,
            redirect_uris: vec![
                "http://localhost:3000/callback".to_string(),
                "http://localhost:5173/callback".to_string(),
            ],
            post_logout_redirect_uris: vec!["http://localhost:3000/".to_string()],
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "offline_access".to_string(),
            ],
            grant_types: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
            ],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            require_pkce: false,
            require_confidential_client: false,
            service_account_enabled: false,
            service_account_permissions: Vec::new(),
            audience: None,
            rotate_secret: false,
        });
    let db = crate::db::Db::connect(&settings).unwrap();
    db.migrate().await.unwrap();
    db.seed(&settings).await.unwrap();
    let jwt = crate::jwt::JwtManager::new(&settings).unwrap();
    (AppState { settings, db, jwt }, path)
}

fn test_client() -> ClientRecord {
    ClientRecord {
        id: "client-db-id".to_string(),
        client_id: "client-a".to_string(),
        client_secret_hash: None,
        client_name: "Client A".to_string(),
        logo_uri: String::new(),
        organization_id: None,
        redirect_uris: serde_json::json!(["https://app.example/callback"]).to_string(),
        post_logout_redirect_uris: "[]".to_string(),
        scopes: serde_json::json!(["openid", "profile"]).to_string(),
        audience: String::new(),
        grant_types: serde_json::json!(["authorization_code"]).to_string(),
        response_types: serde_json::json!(["code"]).to_string(),
        token_endpoint_auth_method: "none".to_string(),
        require_pkce: 0,
        require_mfa: 0,
        require_pushed_authorization_requests: 0,
        require_s256_pkce: 0,
        require_confidential_client: 0,
        require_dpop: 0,
        require_account_selection: 0,
        trust_email_verified: 0,
        authorization_details_types: "[]".to_string(),
        subject_type: subject::SUBJECT_TYPE_PUBLIC.to_string(),
        sector_identifier_uri: String::new(),
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

#[test]
fn service_introspection_uses_machine_policy_without_interactive_oidc() {
    let mut client = test_client();
    client.service_account_enabled = 1;
    client.grant_types = serde_json::json!(["client_credentials"]).to_string();

    assert!(service_client_endpoint_request(
        &client,
        "/oauth2/introspect"
    ));
    assert!(!service_client_endpoint_request(&client, "/oauth2/revoke"));

    client.service_account_enabled = 0;
    assert!(!service_client_endpoint_request(
        &client,
        "/oauth2/introspect"
    ));
}

#[test]
fn service_account_introspection_rechecks_current_client_lifecycle() {
    let mut client = test_client();
    client.service_account_enabled = 1;
    client.grant_types = serde_json::json!(["client_credentials"]).to_string();
    let claims = crate::jwt::TokenClaims {
        iss: "https://issuer.example".to_string(),
        sub: "service-account:client-a".to_string(),
        aud: "client-a".to_string(),
        exp: 2,
        iat: 1,
        jti: Some("jti-1".to_string()),
        token_use: "access_token".to_string(),
        client_id: "client-a".to_string(),
        application_id: None,
        authorization_profile_id: None,
        scope: String::new(),
        email: String::new(),
        email_verified: false,
        name: None,
        preferred_username: "client-a".to_string(),
        nonce: None,
        auth_time: None,
        sid: None,
        cnf: None,
        authorization_details: None,
        act: None,
        grant_id: None,
        gpt_sso_login_code_level: None,
    };
    assert!(service_account_claim_is_live(&client, &claims));
    let mut legacy_claims = claims.clone();
    legacy_claims.sub = client.client_id.clone();
    legacy_claims.email.clear();
    assert!(service_account_claim_is_live(&client, &legacy_claims));
    client.service_account_enabled = 0;
    assert!(!service_account_claim_is_live(&client, &claims));
    assert!(!service_account_claim_is_live(&client, &legacy_claims));
}

#[test]
fn machine_token_detection_does_not_skip_user_runtime_checks() {
    let mut claims = crate::jwt::TokenClaims {
        iss: "https://issuer.example".to_string(),
        sub: "client-a".to_string(),
        aud: "client-a".to_string(),
        exp: 2,
        iat: 1,
        jti: None,
        token_use: "access_token".to_string(),
        client_id: "client-a".to_string(),
        application_id: None,
        authorization_profile_id: None,
        scope: String::new(),
        email: "user@example.com".to_string(),
        email_verified: true,
        name: Some("User".to_string()),
        preferred_username: "client-a".to_string(),
        nonce: None,
        auth_time: None,
        sid: None,
        cnf: None,
        authorization_details: None,
        act: None,
        grant_id: None,
        gpt_sso_login_code_level: None,
    };
    assert!(!is_machine_token_claims(&claims));
    claims.email.clear();
    assert!(is_machine_token_claims(&claims));
}
