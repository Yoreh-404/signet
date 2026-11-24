use super::*;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use std::{collections::HashMap, path::PathBuf, sync::Mutex};
use tower::ServiceExt;

#[tokio::test]
async fn reserved_authority_never_projects_from_stored_mappers() {
    use crate::claim_mapper::{AXON_ADMIN_AUTHORITY_CLAIM, ClaimContext, ClaimOutputTarget, mapped_claims};
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "mapper").await;
    let client = test_client();
    let mapper = |name: &str| crate::db::ClientClaimMapperRecord {
        id: name.to_owned(),
        client_db_id: client.id.clone(),
        claim_name: name.to_owned(),
        source: "static".into(),
        source_value: "true".into(),
        value_type: "bool".into(),
        include_in_id_token: 1,
        include_in_access_token: 1,
        include_in_userinfo: 1,
        is_active: 1,
        sort_order: 0,
        created_at: 0,
        updated_at: 0,
    };
    let records = [mapper(AXON_ADMIN_AUTHORITY_CLAIM), mapper("axon_admin"), mapper("x-team")];
    let context = ClaimContext { user: &user, client: &client, scope: "openid" };
    for target in [ClaimOutputTarget::AccessToken, ClaimOutputTarget::IdToken, ClaimOutputTarget::UserInfo] {
        let output = mapped_claims(&records, &context, target).unwrap();
        assert!(!output.contains_key(AXON_ADMIN_AUTHORITY_CLAIM));
        assert_eq!(output["axon_admin"], serde_json::json!(true));
        assert_eq!(output["x-team"], serde_json::json!(true));
    }
    let _ = std::fs::remove_file(path);
}

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

#[tokio::test]
async fn one_signet_browser_session_authenticates_distinct_website_origins() {
    let (state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "cross-domain-sso").await;
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
    let signet_cookie = jar.get(&state.settings.security.cookie_name).unwrap();
    assert!(
        signet_cookie.domain().is_none(),
        "central Signet cookie must remain host-only"
    );
    assert_eq!(signet_cookie.same_site(), Some(SameSite::Lax));
    for (index, origin) in ["https://site-a.example", "https://site-b.other"]
        .iter()
        .enumerate()
    {
        let client_id = format!("sso-client-{index}");
        let redirect_uri = format!("{origin}/auth/callback");
        insert_test_oidc_client(&state, &client_id, &redirect_uri, "").await;
        let request: AuthorizeRequest = serde_urlencoded::from_str(&serde_urlencode(&[
            ("response_type", "code".to_string()),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri.clone()),
            ("scope", "openid profile".to_string()),
        ]))
        .unwrap();
        let response = authorize(
            State(state.clone()),
            jar.clone(),
            HeaderMap::new(),
            ConnectInfo("127.0.0.1:12345".parse().unwrap()),
            Query(request),
        )
        .await
        .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "a valid central login should not redirect to a password form"
        );
        assert!(redirect_url(&response).as_str().starts_with(&redirect_uri));
    }
    drop(state);
    let _ = std::fs::remove_file(path);
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

#[cfg(all(feature = "sqlite", target_os = "linux"))]
#[tokio::test]
async fn axon_v3_incumbent_preflight_never_changes_existing_website_oauth_eligibility() {
    use crate::application_discovery::axon_v3_acceptance::{
        TrustedFloor, TrustedRegistration, tests::{HEADER, sign}, verify_acceptance,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use diesel::{RunQueryDsl, sql_query, sql_types::Text};
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    let (mut state, path) = test_app_state_with_issuer(Some("https://signet.example")).await;
    let fixture = insert_refresh_test_user(&state, "incumbent-preflight").await;
    let client = test_refresh_client(&state).await;
    let binding = state.db.find_application_client_binding_by_public_client_id(&client.client_id)
        .await.unwrap().unwrap();
    let app = state.db.find_application_by_id(&binding.application_id).await.unwrap().unwrap();
    let origin = "https://axon.example";
    let effective_issuer = state.effective_issuer(&HeaderMap::new()).await.unwrap();
    assert_eq!(effective_issuer, "https://signet.example");
    let issuer = effective_issuer.as_str();
    assert!(state.accepted_issuers(&HeaderMap::new()).await.unwrap().contains(&effective_issuer));
    let audience = "https://axon.example/admin";
    let verifier = insert_test_oidc_client(
        &state, "incumbent-website-verifier", "https://verifier.example/callback", "",
    ).await;
    let verifier_secret = "synthetic-incumbent-website-verifier";
    state.settings.discovery.axon_admin_v3 = Some(crate::config::AxonAdminV3Enrollment {
        organization_id: app.organization_id.clone(),
        enrollment_id: "explicit-incumbent-test".into(),
        application_id: app.slug.clone(),
        issuer: issuer.to_owned(),
        client_id: client.client_id.clone(),
        introspection_client_id: verifier.client_id.clone(),
        audience: audience.into(),
        origin: origin.into(),
        restore_marker_path: path.with_extension("incumbent-private").join("restore/current.json"),
        restore_marker_owner_uid: rustix::process::geteuid().as_raw(),
    });
    let callback = format!("{origin}/admin/api/auth/signet/callback");
    let now = util::now_ts();
    let public = SigningKey::from_bytes(&[9; 32]).verifying_key();
    let approved_jwks = json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"approval",
        "x":URL_SAFE_NO_PAD.encode(public.as_bytes())}]}).to_string();
    state.db.upsert_application_discovery(crate::db::NewApplicationDiscovery {
        application_id: app.id.clone(), management_mode: crate::application_discovery::MANAGEMENT_MODE_WEBSITE.into(),
        website_url: origin.into(), fetch_secret_ciphertext: String::new(), signing_public_jwks: approved_jwks.clone(),
        last_verified_revision: Some(3), last_verified_version: Some("fixture".into()),
        last_verified_digest: Some("prior-verified-metadata-fixture".into()), last_verified_expires_at: Some(now+600),
        sync_status: crate::application_discovery_contract::SYNC_STATUS_SYNCED.into(), last_error: None,
        last_fetched_at: Some(now-301), last_success_at: Some(now-301), operator_disabled: false,
        snapshot_json: Some(json!({"modules":{"axon_admin_mapping":{"permissions":["admin:session:read"]}}}).to_string()),
    }).await.unwrap();

    let crate::db::Db::Sqlite(pool) = &state.db else { unreachable!() };
    {
        let mut conn = pool.get().unwrap();
        sql_query("UPDATE clients SET organization_id=?, audience=?,
            token_endpoint_auth_method='client_secret_basic', client_secret_hash=? WHERE id=?")
            .bind::<Text,_>(&app.organization_id).bind::<Text,_>(audience)
            .bind::<Text,_>(util::hash_password(verifier_secret).unwrap())
            .bind::<Text,_>(&verifier.id).execute(&mut conn).unwrap();
        sql_query("UPDATE users SET is_admin=1 WHERE id=?").bind::<Text,_>(&fixture.id).execute(&mut conn).unwrap();
        sql_query("DELETE FROM organization_members WHERE user_id=?").bind::<Text,_>(&fixture.id).execute(&mut conn).unwrap();
        sql_query("UPDATE clients SET organization_id=?,audience=?,redirect_uris=?,scopes='[\"openid\"]',
            grant_types='[\"authorization_code\"]',token_endpoint_auth_method='none',
            require_pkce=1,require_s256_pkce=1 WHERE id=?")
            .bind::<Text,_>(&app.organization_id).bind::<Text,_>(audience)
            .bind::<Text,_>(json!([callback]).to_string()).bind::<Text,_>(&client.id).execute(&mut conn).unwrap();
    }
    let jar = auth::issue_session_with_login_event(&state, CookieJar::new(), &HeaderMap::new(),
        None, &fixture, "password", auth::LoginEventContext::default()).await.unwrap();
    let current = auth::require_current_user(&state, &jar).await.unwrap();
    assert_eq!(current.user.is_admin, 1);
    let client = test_refresh_client(&state).await;
    assert_eq!(client.require_s256_pkce, 1);
    let session_cookie = jar.get(&state.settings.security.cookie_name).unwrap();
    let challenge_verifier = "incumbent-generic-s256-wire-proof-01234567890123456789";
    let router = routes().with_state(state.clone());
    let authorize = || {
        let query = serde_urlencoded::to_string([
            ("response_type", "code"), ("client_id", client.client_id.as_str()),
            ("redirect_uri", callback.as_str()), ("scope", "openid"), ("resource", audience),
            ("state", "incumbent-generic"), ("code_challenge_method", "S256"),
            ("code_challenge", &util::sha256_base64url(challenge_verifier)),
        ]).unwrap();
        let mut request = Request::builder()
            .uri(format!("/oauth2/authorize?{query}"))
            .header(header::COOKIE, format!("{}={}", session_cookie.name(),session_cookie.value()))
            .body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43001))));
        request
    };
    let before = router.clone().oneshot(authorize()).await.unwrap();
    assert_eq!(before.status(), StatusCode::SEE_OTHER);
    let location = redirect_url(&before);
    assert_eq!(location.path(), "/admin/api/auth/signet/callback");
    assert_eq!(query_value(&location, "state"), "incumbent-generic");
    let code = query_value(&location, "code");
    let exchange = |code: &str| {
        let body = serde_urlencoded::to_string([
            ("grant_type","authorization_code"), ("code",code),
            ("redirect_uri", callback.as_str()), ("code_verifier",challenge_verifier),
            ("client_id",client.client_id.as_str()),
        ]).unwrap();
        Request::post("/oauth2/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body)).unwrap()
    };
    let response = router.clone().oneshot(exchange(&code)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = oidc_http_body_json(response).await;
    let token = response["access_token"].as_str().unwrap();
    let claims = state.jwt.verify_access_token_for_introspection(token, &[issuer])
        .expect("fixture token must verify against the configured purpose issuer");
    assert_eq!(claims.sub, current.user.id);
    assert_eq!(claims.iss, issuer);
    assert_eq!(claims.aud, audience);
    let body: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap();
    assert!(body.get("axon_admin_authority_v3").is_none());
    let introspect = |hint: &str| {
        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{verifier_secret}", verifier.client_id));
        Request::post("/oauth2/introspect")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::AUTHORIZATION, format!("Basic {auth}"))
            .body(Body::from(format!("token_type_hint={hint}&token={token}"))).unwrap()
    };
    // The incumbent purpose verifier is not mounted for website registrations.
    // Its inactive response is a distinct observation, not positive authority.
    for (hint, active) in [("access_token", true), ("axon_admin_authority_v3", false)] {
        let result = router.clone().oneshot(introspect(hint)).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        let result = oidc_http_body_json(result).await;
        assert_eq!(result["active"], active, "{hint} before expiry");
        assert!(result.get("axon_admin_authority_v3").is_none());
    }
    let issued = router.clone().oneshot(authorize()).await.unwrap();
    assert_eq!(issued.status(), StatusCode::SEE_OTHER);
    let pending = query_value(&redirect_url(&issued), "code");
    assert_ne!(code, pending);
    #[derive(diesel::QueryableByName)]
    struct CodeState {
        #[diesel(sql_type = diesel::sql_types::Nullable<diesel::sql_types::BigInt>)]
        consumed_at: Option<i64>,
    }
    let consumed_at = || sql_query("SELECT consumed_at FROM authorization_codes WHERE code=?")
        .bind::<Text,_>(&pending)
        .get_result::<CodeState>(&mut pool.get().unwrap()).unwrap().consumed_at;
    assert_eq!(consumed_at(), None);
    let set_expiry = |expires| {
        sql_query("UPDATE application_discovery SET last_verified_expires_at=? WHERE application_id=?")
            .bind::<diesel::sql_types::BigInt,_>(expires).bind::<Text,_>(&app.id)
            .execute(&mut pool.get().unwrap()).unwrap();
    };
    set_expiry(util::now_ts()-1);
    let denied = router.clone().oneshot(exchange(&pending)).await.unwrap();
    assert!(denied.status().is_client_error());
    let denied = oidc_http_body_json(denied).await;
    assert!(denied.get("access_token").is_none());
    let consumed = consumed_at();
    assert!(consumed.is_some(), "expiry denial follows one-use consumption");
    for hint in ["access_token", "axon_admin_authority_v3"] {
        let result = router.clone().oneshot(introspect(hint)).await.unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert_eq!(oidc_http_body_json(result).await, json!({"active":false}), "{hint} after expiry");
    }
    assert!(state.db.list_user_sessions(&current.user.id).await.unwrap().iter()
        .any(|session| session.id == current.session_id && session.expires_at > util::now_ts()));
    set_expiry(util::now_ts()+600);
    let retry = router.clone().oneshot(exchange(&pending)).await.unwrap();
    assert!(retry.status().is_client_error(), "restoring site freshness cannot revive a code");
    assert_eq!(consumed_at(), consumed);
    let baseline = router.clone().oneshot(introspect("access_token")).await.unwrap();
    assert_eq!(oidc_http_body_json(baseline).await["active"], true);
    // Disable a website whose verified metadata and OAuth session remain
    // current. This isolates operator disablement from expiry and logout.
    let set_disabled = |disabled: i32| {
        sql_query("UPDATE application_discovery SET operator_disabled=? WHERE application_id=?")
            .bind::<diesel::sql_types::Integer,_>(disabled).bind::<Text,_>(&app.id)
            .execute(&mut pool.get().unwrap()).unwrap()
    };
    assert_eq!(set_disabled(1), 1);
    for hint in ["access_token", "axon_admin_authority_v3"] {
        let denied = router.clone().oneshot(introspect(hint)).await.unwrap();
        assert_eq!(denied.status(), StatusCode::OK);
        assert_eq!(oidc_http_body_json(denied).await, json!({"active":false}),
            "{hint} on a still-fresh but disabled website");
    }
    assert_eq!(set_disabled(0), 1);
    let restored = router.clone().oneshot(introspect("access_token")).await.unwrap();
    assert_eq!(restored.status(), StatusCode::OK);
    assert_eq!(oidc_http_body_json(restored).await["active"], true);
    let no_privilege = router.clone().oneshot(introspect("axon_admin_authority_v3")).await.unwrap();
    assert_eq!(no_privilege.status(), StatusCode::OK);
    assert_eq!(oidc_http_body_json(no_privilege).await, json!({"active":false}));
    set_expiry(util::now_ts()-1);
    let after = router.clone().oneshot(authorize()).await.unwrap();
    if after.status().is_redirection() {
        assert!(!redirect_url(&after).query_pairs().any(|(key,_)| key=="code"));
        assert!(redirect_url(&after).query_pairs().any(|(key,_)| key=="error"));
    } else {
        assert!(after.status().is_client_error(), "unexpected expired site's status: {}", after.status());
    }
    assert!(crate::oidc_authorization::AuthorizationSnapshot::load_runtime(&state, &client).await.is_err());
    assert!(crate::oidc_authorization::AuthorizationSnapshot::load(&state, &client, &current.user).await.is_err());

    let permissions = vec!["admin:session:read".to_string()];
    let enrollment = "explicit-incumbent-test";
    let policy = json!({"format":"axon.signet.application-admin.policy.v3",
        "organization_id":app.organization_id,"enrollment_id":enrollment,"application_id":app.slug,
        "issuer":issuer,"client_id":client.client_id,"audience":audience,"origin":origin,
        "revision":4,"generation":8,"permissions":permissions}).to_string();
    let digest = format!("sha256:{:x}", Sha256::digest(&policy));
    let claims = json!({"format":"axon.signet.application-admin.acceptance.v3","policy_sha256":digest,
        "revision":4,"generation":8,"aud":issuer,"iat":now,"exp":now+300}).to_string();
    let trusted = TrustedRegistration {
        organization_id: &app.organization_id, enrollment_id: enrollment, application_id: &app.slug,
        issuer, client_id: &client.client_id, audience, origin, permissions: &permissions,
        approval_audience: issuer, approval_jwks: &approved_jwks,
        floor: &TrustedFloor { policy_sha256: &digest, revision: 4, generation: 8, halted: false },
    };
    assert!(verify_acceptance(policy.as_bytes(), "", &trusted, now).is_err());
    assert!(verify_acceptance(policy.as_bytes(), &sign(&claims, 8, HEADER), &trusted, now).is_err());
    let approved = verify_acceptance(policy.as_bytes(), &sign(&claims, 9, HEADER), &trusted, now).unwrap();
    use crate::application_discovery::{axon_signer_pin, incumbent_preflight::{self, IncumbentPin, RequestScope}};
    let signer_pin = axon_signer_pin(&approved_jwks).unwrap();
    let pin = IncumbentPin {
        application_db_id: &app.id, client_db_id: &client.id,
        policy_sha256: &digest, signer_pin: &signer_pin, revision: 4, generation: 8, withdrawn: false,
    };
    let challenge = util::sha256_base64url(challenge_verifier);
    let request = authorize();
    let query = request.uri().query().unwrap();
    let resolved = ResolvedAuthorizeRequest::from_query(serde_urlencoded::from_str(query).unwrap()).unwrap();
    let wanted = RequestScope::from_resolved(issuer, &resolved).unwrap();
    let eligible = async |pin: Option<&IncumbentPin<'_>>, request: &RequestScope<'_>|
        incumbent_preflight::matches(&state, &jar, pin, &approved, request).await;
    assert!(eligible(Some(&pin), &wanted).await.unwrap());
    assert!(!eligible(None, &wanted).await.unwrap());
    let other_key = SigningKey::from_bytes(&[8; 32]).verifying_key();
    let other_jwks = json!({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"approval",
        "x":URL_SAFE_NO_PAD.encode(other_key.as_bytes())}]}).to_string();
    let other_trust = TrustedRegistration { approval_jwks: &other_jwks, ..trusted };
    let other_approval = verify_acceptance(policy.as_bytes(), &sign(&claims, 8, HEADER), &other_trust, now)
        .expect("the alternative key signed the same exact policy validly for a different trust input");
    assert!(!incumbent_preflight::matches(&state, &jar, Some(&pin), &other_approval, &wanted)
        .await.unwrap(), "cryptographically valid approval from the wrong enrolled signer must deny");
    #[cfg(feature = "axon-incumbent-storage")]
    {
        let mut next_policy: serde_json::Value = serde_json::from_str(approved.bytes()).unwrap();
        next_policy["revision"] = json!(5);
        next_policy["generation"] = json!(9);
        let next_policy = next_policy.to_string();
        let next_digest = format!("sha256:{:x}", Sha256::digest(&next_policy));
        let next_claims = json!({"format":"axon.signet.application-admin.acceptance.v3",
            "policy_sha256":next_digest,"revision":5,"generation":9,
            "aud":issuer,"iat":now,"exp":now+300}).to_string();
        let next = verify_acceptance(next_policy.as_bytes(), &sign(&next_claims, 9, HEADER),
            &TrustedRegistration { approval_jwks: &approved_jwks,
                floor: &TrustedFloor { policy_sha256: &next_digest, revision: 5, generation: 9, halted: false },
                ..other_trust
            }, now).unwrap();
        let next_pin = IncumbentPin { policy_sha256: &next_digest, revision: 5, generation: 9, ..pin };
        assert!(incumbent_preflight::matches(&state, &jar, Some(&next_pin), &next, &wanted)
            .await.unwrap());
        // Resolve the same real authorize request without the provisioning
        // runtime loader. Existing fixture settings waive consent for this client.
        let mut other_query: AuthorizeRequest = serde_urlencoded::from_str(query).unwrap();
        other_query.resource = Some("https://axon.example/other".to_owned());
        let wrong_resource = ResolvedAuthorizeRequest::from_query(other_query).unwrap();
        assert!(validate_authorize_request_for_client(&client, &wrong_resource).is_ok(),
            "standalone standard validation must not substitute for the exact signed audience");
        let scopes = normalize_and_validate_requested_scopes(
            &client, resolved.scope.as_deref(), &state.settings.oidc.supported_scopes,
        ).unwrap();
        assert!(!requires_authorization_consent(&state, &current.user, &client, &scopes).await.unwrap());
        let ip = state.request_ip(
            request.headers(),
            Some(SocketAddr::from(([127, 0, 0, 1], 43001))),
        ).await.unwrap();
        let credential = util::session_id_from_cookie(session_cookie.value()).unwrap();
        set_expiry(util::now_ts() + 600);
        let ordinary_issued = router.clone().oneshot(authorize()).await.unwrap();
        assert_eq!(ordinary_issued.status(), StatusCode::SEE_OTHER);
        let ordinary_code = query_value(&redirect_url(&ordinary_issued), "code");
        crate::application_discovery::incumbent_storage_tests::signed_file_bench(
            &path, &pin, &approved, &next, &other_approval, &approved_jwks,
            async |conn, gate, set_gate| {
                let admit_with = |conn: &mut diesel::SqliteConnection,
                    resolved: &ResolvedAuthorizeRequest,
                    setup: &dyn Fn(&mut diesel::SqliteConnection) -> AppResult<()>,
                    before_commit: &dyn Fn(&mut diesel::SqliteConnection) -> AppResult<()>,
                | {
                    store_incumbent_authorization_code(
                        conn,
                        IncumbentAuthorizationInput {
                            state: &state,
                            resolved,
                            issuer,
                            ip: ip.as_deref(),
                            credential: &credential,
                            session_id: &current.session_id,
                            user: &current.user,
                            pin: &pin,
                            approved: &approved,
                            gate,
                        },
                        setup,
                        before_commit,
                    )
                };
                let noop = |_: &mut diesel::SqliteConnection| Ok(());
                let admit = |conn: &mut diesel::SqliteConnection| admit_with(conn, &resolved, &noop, &noop);
                #[derive(diesel::QueryableByName)]
                struct Count {
                    #[diesel(sql_type = diesel::sql_types::BigInt)]
                    count: i64,
                }
                let count = |conn: &mut diesel::SqliteConnection| {
                    sql_query("SELECT COUNT(*) AS count FROM authorization_codes WHERE client_id=? AND user_id=?")
                        .bind::<Text,_>(&client.client_id).bind::<Text,_>(&fixture.id)
                        .get_result::<Count>(conn).unwrap().count
                };
                let available = |conn: &mut diesel::SqliteConnection, code: &str| {
                    sql_query("SELECT COUNT(*) AS count FROM authorization_codes WHERE code=? AND consumed_at IS NULL")
                        .bind::<Text,_>(code).get_result::<Count>(conn).unwrap().count
                };
                let redeem = |conn: &mut diesel::SqliteConnection, code: &str| {
                    exchange_incumbent_access_token(
                        conn, &state, issuer, gate, &pin, &approved, code,
                        &client.client_id, &callback, challenge_verifier,
                    )
                };
                assert_eq!(available(conn, &ordinary_code), 1);
                assert!(matches!(redeem(conn, &ordinary_code), Err(AppError::Forbidden)));
                assert_eq!(available(conn, &ordinary_code), 1, "ordinary code must stay untouched");
                let before = count(conn);
                let no_mismatch_insert = |_: &mut diesel::SqliteConnection| -> AppResult<()> {
                    panic!("a request with a different resource must never reach insertion")
                };
                assert!(matches!(admit_with(conn, &wrong_resource, &noop, &no_mismatch_insert),
                    Err(AppError::Forbidden)));
                assert_eq!(count(conn), before, "denied scope must not yield a code or code row");
                let code = admit(conn).unwrap();
                let inserted = sql_query("SELECT COUNT(*) AS count FROM authorization_codes
                    WHERE code=? AND application_id=? AND client_id=? AND user_id=? AND consumed_at IS NULL AND session_id=? AND code_challenge=? AND code_challenge_method='S256'")
                    .bind::<Text,_>(&code).bind::<Text,_>(&app.id).bind::<Text,_>(&client.client_id)
                    .bind::<Text,_>(&fixture.id).bind::<Text,_>(util::session_public_id(&current.session_id))
                    .bind::<Text,_>(&challenge).get_result::<Count>(conn).unwrap().count;
                assert_eq!(inserted, 1);
                assert_eq!(count(conn), before + 1);
                let generic = router.clone().oneshot(exchange(&code)).await.unwrap();
                assert!(generic.status().is_client_error());
                let rejected = oidc_http_body_json(generic).await;
                assert!(rejected.get("access_token").is_none());
                assert_eq!(available(conn, &code), 1,
                    "ordinary token exchange must refuse the mark without consuming the code");
                for role in [0, 1] {
                    sql_query("UPDATE users SET is_admin=? WHERE id=?")
                        .bind::<diesel::sql_types::Integer,_>(role).bind::<Text,_>(&fixture.id)
                        .execute(conn).unwrap();
                    if role == 0 {
                        assert!(matches!(admit(conn), Err(AppError::Forbidden)));
                        assert!(matches!(redeem(conn, &code), Err(AppError::Forbidden)));
                        assert_eq!(available(conn, &code), 1);
                    }
                }
                for jwks in [&other_jwks, &approved_jwks] {
                    sql_query("UPDATE application_discovery SET signing_public_jwks=? WHERE application_id=?")
                        .bind::<Text,_>(jwks).bind::<Text,_>(&app.id).execute(conn).unwrap();
                    if jwks == &other_jwks {
                        assert!(matches!(admit(conn), Err(AppError::Forbidden)));
                        assert!(matches!(redeem(conn, &code), Err(AppError::Forbidden)));
                        assert_eq!(available(conn, &code), 1);
                    }
                }
                let require_mfa = |conn: &mut diesel::SqliteConnection| {
                    sql_query("UPDATE clients SET require_mfa=1 WHERE id=?")
                        .bind::<Text,_>(&client.id).execute(conn)?;
                    Ok(())
                };
                let never_insert = |_: &mut diesel::SqliteConnection| -> AppResult<()> {
                    panic!("a client requiring new MFA must deny before inserting a code")
                };
                assert!(matches!(admit_with(conn, &resolved, &require_mfa, &never_insert), Err(AppError::Forbidden)));
                assert_eq!(count(conn), before + 1);
                let counts = |conn: &mut diesel::SqliteConnection| {
                    sql_query("SELECT COUNT(*) AS count FROM application_auth_contexts WHERE user_id=?")
                        .bind::<Text,_>(&fixture.id).get_result::<Count>(conn).unwrap().count
                };
                let contexts_before = counts(conn);
                let revoke_context = |conn: &mut diesel::SqliteConnection| {
                    sql_query("UPDATE application_auth_contexts SET revoked_at=0 WHERE user_id=?")
                        .bind::<Text,_>(&fixture.id).execute(conn)?;
                    Ok(())
                };
                let reached_insert = std::cell::Cell::new(false);
                assert!(matches!(admit_with(conn, &resolved, &revoke_context, &|conn| {
                    reached_insert.set(true);
                    assert_eq!(counts(conn), contexts_before + 1);
                    set_gate(false);
                    Ok(())
                }), Err(AppError::Forbidden)));
                assert!(reached_insert.get(), "restore change must roll back an attempted insert");
                assert!(matches!(admit(conn), Err(AppError::Forbidden)));
                assert_eq!(count(conn), before + 1, "denials and final gate rollback must not mint");
                assert_eq!(counts(conn), contexts_before, "new context rolled back with the code");
                assert!(matches!(redeem(conn, &code), Err(AppError::Forbidden)));
                assert_eq!(available(conn, &code), 1);
                set_gate(true);
                let markers = |conn: &mut diesel::SqliteConnection| {
                    sql_query("SELECT COUNT(*) AS count FROM axon_v3_incumbent_code_provenance
                        WHERE user_sha256=? AND session_public_id=?")
                        .bind::<Text,_>(util::sha256_base64url(&fixture.id))
                        .bind::<Text,_>(util::session_public_id(&current.session_id))
                        .get_result::<Count>(conn).unwrap().count
                };
                assert_eq!(markers(conn), 1, "failed admission must not leave a second marker");
                let set_profile = |conn: &mut diesel::SqliteConnection, profile_id: &str| {
                    sql_query("UPDATE application_client_bindings SET authorization_profile_id=? WHERE application_id=? AND client_db_id=?")
                        .bind::<Text,_>(profile_id).bind::<Text,_>(&app.id).bind::<Text,_>(&client.id)
                        .execute(conn).unwrap()
                };
                assert_eq!(set_profile(conn, "no-longer-the-code-profile"), 1);
                assert!(matches!(redeem(conn, &code), Err(AppError::Forbidden)));
                assert_eq!(available(conn, &code), 1);
                assert_eq!(markers(conn), 1, "profile denial must roll back consume and marker deletion");
                assert_eq!(set_profile(conn, &binding.authorization_profile_id), 1);
                let (redeemed, access_token) = redeem(conn, &code).unwrap();
                let token_claims = state.jwt.verify_access_token_for_introspection(&access_token, &[issuer])
                    .expect("ordinary signer returned the current scoped access token");
                assert_eq!(token_claims.iss, issuer);
                assert_eq!(token_claims.sub, current.user.id);
                assert_eq!(token_claims.aud, audience);
                assert_eq!(token_claims.client_id, client.client_id);
                assert_eq!(token_claims.scope, "openid");
                assert_eq!(token_claims.sid.as_deref(), Some(redeemed.public_sid()));
                assert_eq!(token_claims.exp - token_claims.iat, state.settings.oidc.access_token_ttl_seconds);
                let verify = |conn: &mut diesel::SqliteConnection, verifier_id: &str, bearer: &str| {
                    verify_incumbent_access_proof(conn, &state, verifier_id, issuer, &pin, &approved, bearer)
                        .unwrap()
                };
                assert!(verify(conn, &verifier.id, &access_token));
                let update_site_expiry = |conn: &mut diesel::SqliteConnection, expiry| {
                    sql_query("UPDATE application_discovery SET last_verified_expires_at=? WHERE application_id=?")
                        .bind::<diesel::sql_types::BigInt,_>(expiry).bind::<Text,_>(&app.id)
                        .execute(conn).unwrap()
                };
                assert_eq!(update_site_expiry(conn, util::now_ts() - 1), 1);
                assert!(verify(conn, &verifier.id, &access_token),
                    "the unchanged live incumbent proof does not inherit a separate site-metadata deadline");
                assert_eq!(update_site_expiry(conn, util::now_ts() + 600), 1);
                assert!(!verify(conn, &client.id, &access_token));
                assert!(!verify(conn, &verifier.id, token), "ordinary signed token does not acquire a purpose row");
                sql_query("UPDATE users SET is_admin=0 WHERE id=?")
                    .bind::<Text,_>(&fixture.id).execute(conn).unwrap();
                assert!(!verify(conn, &verifier.id, &access_token));
                sql_query("UPDATE users SET is_admin=1 WHERE id=?")
                    .bind::<Text,_>(&fixture.id).execute(conn).unwrap();
                set_gate(false);
                assert!(!verify(conn, &verifier.id, &access_token));
                set_gate(true);
                assert!(verify(conn, &verifier.id, &access_token));
                assert_eq!(sql_query("DELETE FROM axon_v3_incumbent_access_proof WHERE jti=?")
                    .bind::<Text,_>(token_claims.jti.as_deref().unwrap())
                    .execute(conn).unwrap(), 1);
                assert!(!verify(conn, &verifier.id, &access_token), "revoked JTI stays inactive");
                let signed_payload: serde_json::Value = serde_json::from_slice(
                    &URL_SAFE_NO_PAD.decode(access_token.split('.').nth(1).unwrap()).unwrap(),
                ).unwrap();
                for claim in ["axon_admin", "axon_admin_authority", "axon_admin_authority_v3"] {
                    assert!(signed_payload.get(claim).is_none());
                }
                assert_eq!(redeemed.public_sid(), util::session_public_id(&current.session_id));
                assert_eq!(redeemed.user_id(), current.user.id);
                assert_eq!(redeemed.scope(), "openid");
                assert_eq!(redeemed.application_db_id(), app.id);
                assert_eq!(redeemed.client_db_id(), client.id);
                assert_eq!(redeemed.profile_id(), binding.authorization_profile_id);
                assert!(!redeemed.auth_context_id().is_empty());
                assert_eq!(redeemed.approved_policy().sha256(), approved.sha256());
                assert_eq!(redeemed.approved_policy().policy().revision, approved.policy().revision);
                assert_eq!(redeemed.approved_policy().policy().generation, approved.policy().generation);
                assert_eq!(redeemed.code_assurance().acr, crate::assurance::ACR_PASSWORD);
                assert_eq!(redeemed.code_assurance().amr, ["pwd"]);
                assert_eq!(redeemed.code_assurance(), redeemed.session_assurance());
                assert_eq!(available(conn, &code), 0);
                assert!(redeem(conn, &code).is_err(), "the ordinary single-use CAS remains authoritative");
                assert_eq!(markers(conn), 0, "successful consumption retires the purpose marker");
            },
        ).await;
        let ordinary_token = router.clone().oneshot(exchange(&ordinary_code)).await.unwrap();
        assert_eq!(ordinary_token.status(), StatusCode::OK);
        let ordinary_body = oidc_http_body_json(ordinary_token).await;
        let ordinary_claims = state.jwt.verify_access_token(
            ordinary_body["access_token"].as_str().unwrap(),
        ).unwrap();
        assert_eq!(ordinary_claims.sub, current.user.id);
        set_expiry(util::now_ts() - 1);
    }
    for wrong in [
        RequestScope { issuer: "https://foreign.example", ..wanted },
        RequestScope { client_id: "unrelated-client", ..wanted },
        RequestScope { resource: "https://axon.example/other", ..wanted },
        RequestScope { redirected_to: "https://axon.example/other", ..wanted },
        RequestScope { scope: "openid email", ..wanted },
        RequestScope { challenge_method: "plain", ..wanted },
        RequestScope { challenge: "", ..wanted },
    ] {
        assert!(!eligible(Some(&pin), &wrong).await.unwrap());
    }
    for wrong in [
        IncumbentPin { generation: 7, ..pin },
        IncumbentPin { revision: 3, ..pin },
        IncumbentPin { withdrawn: true, ..pin },
        IncumbentPin { signer_pin: "different", ..pin },
        IncumbentPin { client_db_id: "another", ..pin },
        IncumbentPin { application_db_id: "another", ..pin },
    ] {
        assert!(!eligible(Some(&wrong), &wanted).await.unwrap());
    }
    assert!(!incumbent_preflight::matches(&state, &CookieJar::new(), Some(&pin),
        &approved, &wanted).await.unwrap());
    #[cfg(feature = "axon-incumbent-storage")]
    let checked_browser = || {
        let credential = util::session_id_from_cookie(session_cookie.value()).unwrap();
        pool.get().unwrap().immediate_transaction(|conn| {
            crate::db::axon_v3_incumbent_storage::sqlite::current_incumbent_browser_on_conn(
                conn, &credential, &current.session_id, &fixture.id, util::now_ts(),
            )
        }).unwrap()
    };
    #[cfg(feature = "axon-incumbent-storage")]
    {
        use crate::assurance::SessionAuthenticationAssurance;
        let session = checked_browser().expect("exact current incumbent browser");
        assert_eq!(session.user_id, fixture.id);
        assert_eq!(util::session_public_id(&session.id), util::session_public_id(&current.session_id));
        let assurance = session.authentication_assurance();
        assert_eq!(assurance.acr, crate::assurance::ACR_PASSWORD);
        assert_eq!(assurance.amr, ["pwd"]);
    }
    sql_query("UPDATE users SET is_admin=0 WHERE id=?")
        .bind::<Text,_>(&fixture.id).execute(&mut pool.get().unwrap()).unwrap();
    #[cfg(feature = "axon-incumbent-storage")]
    assert!(checked_browser().is_none());
    assert!(!eligible(Some(&pin), &wanted).await.unwrap());
    sql_query("UPDATE users SET is_admin=1 WHERE id=?")
        .bind::<Text,_>(&fixture.id).execute(&mut pool.get().unwrap()).unwrap();
    sql_query("UPDATE application_discovery SET operator_disabled=1 WHERE application_id=?")
        .bind::<Text,_>(&app.id).execute(&mut pool.get().unwrap()).unwrap();
    assert!(!eligible(Some(&pin), &wanted).await.unwrap());
    sql_query("UPDATE application_discovery SET operator_disabled=0 WHERE application_id=?")
        .bind::<Text,_>(&app.id).execute(&mut pool.get().unwrap()).unwrap();
    state.db.delete_session(&current.session_id).await.unwrap();
    #[cfg(feature = "axon-incumbent-storage")]
    assert!(checked_browser().is_none());
    assert!(!eligible(Some(&pin), &wanted).await.unwrap());
    // Acceptance checks the signed bytes only. It never enables a website
    // registration or tags an ordinary OAuth request with special authority.
    assert!(state.db.stage_axon_v3_policy(approved).await.is_err());
    assert!(crate::oidc_authorization::AuthorizationSnapshot::load_runtime(&state, &client).await.is_err());
    assert!(crate::oidc_authorization::AuthorizationSnapshot::load(&state, &client, &current.user).await.is_err());
    drop(state);
    std::fs::remove_file(path).unwrap();
}

#[cfg(all(feature = "sqlite", target_os = "linux"))]
#[tokio::test]
async fn axon_v3_introspection_uses_current_policy_and_restore_gate_without_personal_enrollment() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use diesel::{RunQueryDsl, connection::SimpleConnection, sql_query, sql_types::Text};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::PermissionsExt};

    let (mut state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "axon-v3").await;
    let demo = test_refresh_client(&state).await;
    let binding = state.db.find_application_client_binding_by_public_client_id(&demo.client_id)
        .await.unwrap().unwrap();
    let app = state.db.find_application_by_id(&binding.application_id).await.unwrap().unwrap();
    let verifier = insert_test_oidc_client(&state, "v3-verifier-fixture", "https://verifier.example/callback", "").await;
    let origin = "https://axon.example";
    let resource = "https://axon.example/admin";
    let redirect = format!("{origin}/admin/api/auth/signet/callback");
    let issuer = "https://signet.example".to_owned();
    state.settings.oidc.issuer = issuer.clone();
    let now = util::now_ts();
    let entry = json!({
        "format":"axon.signet.application-admin.policy.v3", "organization_id":app.organization_id,
        "enrollment_id":"v3-fixture", "application_id":app.slug, "issuer":issuer,
        "client_id":demo.client_id, "audience":resource, "origin":origin,
        "revision":4, "generation":8, "permissions":["admin:session:read"]
    }).to_string();
    let digest = format!("sha256:{:x}", Sha256::digest(&entry));
    let root = path.with_extension("v3-restore");
    fs::create_dir(&root).unwrap();
    let marker = root.join("current.json");
    let set_gate = |ready: bool| {
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let pending = root.join("next.json");
        fs::write(&pending, json!({"format":"signet-privileged-restore/v1",
            "state":if ready {"reconciled"} else {"held"}, "operation_id":uuid::Uuid::new_v4()}).to_string()).unwrap();
        fs::set_permissions(&pending, fs::Permissions::from_mode(0o400)).unwrap();
        fs::rename(pending, &marker).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();
    };
    state.settings.discovery.axon_admin_v3 = Some(crate::config::AxonAdminV3Enrollment {
        organization_id: app.organization_id.clone(), enrollment_id: "v3-fixture".into(),
        application_id: app.slug.clone(), issuer: issuer.clone(), client_id: demo.client_id.clone(),
        introspection_client_id: verifier.client_id.clone(), audience: resource.into(), origin: origin.into(),
        restore_marker_path: marker.clone(), restore_marker_owner_uid: rustix::process::geteuid().as_raw(),
    });
    let crate::db::Db::Sqlite(pool) = &state.db else { unreachable!() };
    let pool = pool.clone();
    let secret = "fixture-verifier-only";
    {
        let mut conn = pool.get().unwrap();
        sql_query("UPDATE users SET is_admin=1 WHERE id=?").bind::<Text,_>(&user.id).execute(&mut conn).unwrap();
        sql_query("DELETE FROM organization_members WHERE user_id=?").bind::<Text,_>(&user.id).execute(&mut conn).unwrap();
        sql_query("UPDATE clients SET organization_id=?, audience=?, redirect_uris=?, scopes='[\"openid\"]',
            grant_types='[\"authorization_code\"]', require_pkce=1, require_s256_pkce=1 WHERE id=?")
            .bind::<Text,_>(&app.organization_id).bind::<Text,_>(resource)
            .bind::<Text,_>(json!([redirect]).to_string()).bind::<Text,_>(&demo.id).execute(&mut conn).unwrap();
        sql_query("UPDATE clients SET organization_id=?, audience=?, token_endpoint_auth_method='client_secret_basic',
            client_secret_hash=? WHERE id=?")
            .bind::<Text,_>(&app.organization_id).bind::<Text,_>(resource)
            .bind::<Text,_>(util::hash_password(secret).unwrap()).bind::<Text,_>(&verifier.id).execute(&mut conn).unwrap();
        sql_query("INSERT INTO axon_v3_application_activation (
            application_db_id,organization_id,enrollment_id,client_db_id,revision,generation,policy_sha256,policy_json,withdrawn)
            VALUES (?,?,'v3-fixture',?,4,8,?,?,0)")
            .bind::<Text,_>(&app.id).bind::<Text,_>(&app.organization_id).bind::<Text,_>(&demo.id)
            .bind::<Text,_>(&digest).bind::<Text,_>(&entry).execute(&mut conn).unwrap();
    }
    let jar = auth::issue_session_with_login_event(&state, CookieJar::new(), &HeaderMap::new(),
        None, &user, "password", auth::LoginEventContext::default()).await.unwrap();
    let signed_in = auth::require_current_user(&state, &jar).await.unwrap();
    let sid = util::session_public_id(&signed_in.session_id);
    let code = "synthetic-durable-admin-code";
    let challenge_verifier = "fixture-verifier-for-s256-challenge-000000000";
    let client = test_refresh_client(&state).await;
    state.db.insert_authorization_code(NewAuthorizationCode {
        code: code.into(), client_id: client.client_id.clone(), user_id: user.id.clone(),
        application_id: Some(app.id), authorization_profile_id: Some(binding.authorization_profile_id),
        auth_context_id: None, session_id: Some(sid), redirect_uri: redirect.clone(), scope: "openid".into(),
        resource: Some(resource.into()), authorization_details: None, nonce: None,
        code_challenge: Some(util::sha256_base64url(challenge_verifier)), code_challenge_method: Some("S256".into()),
        auth_time: now, acr: assurance::ACR_PASSWORD.into(), amr: vec!["pwd".into()], expires_at: now+120,
    }).await.unwrap();
    let mut req = test_authorization_code_token_request(code);
    req.redirect_uri = Some(redirect);
    req.code_verifier = Some(challenge_verifier.into());
    let Json(tokens) = token_from_authorization_code(state.clone(), client, req, issuer.clone(), None).await.unwrap();
    assert!(tokens.refresh_token.is_none(), "openid-only client does not acquire offline access");
    let router = axum::Router::new().route("/oauth2/introspect", axum::routing::post(
        super::oidc_resource::introspect)).with_state(state.clone());
    let request = |hint: &str, client: &str, password: &str| Request::post("/oauth2/introspect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, format!("Basic {}", STANDARD.encode(format!("{client}:{password}"))))
        .body(Body::from(format!("token_type_hint={hint}&token={}", tokens.access_token))).unwrap();
    let exact = || request("axon_admin_authority_v3", &verifier.client_id, secret);
    let inactive = json!({"active":false});
    assert_eq!(oidc_http_body_json(router.clone().oneshot(exact()).await.unwrap()).await, inactive);
    set_gate(true);
    let claims = state.jwt.verify_access_token_for_introspection(&tokens.access_token, &[&issuer])
        .expect("fixture should have a valid access token for the configured issuer");
    assert_eq!(claims.scope, "openid");
    assert_eq!(claims.aud, resource);
    assert_eq!(claims.client_id, demo.client_id);
    let current_source = test_refresh_client(&state).await;
    assert!(super::oidc_token_liveness::introspected_access_token_is_live(
        &state, Some(&current_source), &claims,
    ).await.unwrap(), "standard current grant/binding check");
    assert!(state.db.list_user_sessions(&claims.sub).await.unwrap().iter().any(|s|
        Some(util::session_public_id(&s.id).as_str()) == claims.sid.as_deref()), "live session binding");
    let enrolled = state.settings.discovery.axon_admin_v3.as_ref().unwrap();
    let interlock = crate::application_discovery::axon_v3_restore::RestoreInterlock::new(
        enrolled.restore_marker_path.clone(), enrolled.restore_marker_owner_uid,
    );
    assert!(state.db.read_active_axon_v3_policy(crate::db::AxonV3CheckedScope {
        organization_id: enrolled.organization_id.clone(), enrollment_id: enrolled.enrollment_id.clone(),
        application_id: enrolled.application_id.clone(), issuer: claims.iss.clone(), client_id: claims.client_id.clone(),
        verifier_client_id: verifier.client_id.clone(), audience: claims.aud.clone(), origin: origin.into(),
        subject: claims.sub.clone(),
    }, &interlock).await.unwrap().is_some(), "registered active policy");
    let response = router.clone().oneshot(exact()).await.unwrap();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let active = oidc_http_body_json(response).await;
    assert_eq!(active["active"], true, "{active}");
    assert_eq!(active["sub"], user.id);
    assert_eq!(active["axon_admin_authority_v3"]["subject"], user.id);
    assert_eq!(active["axon_admin_authority_v3"]["policy_sha256"], digest);
    assert_eq!(active["axon_admin_authority_v3"]["permissions"], json!(["admin:session:read"]));
    assert!(active["axon_admin_authority_v3"].get("exp").is_none());
    let other = request("axon_admin_authority_v3", &demo.client_id, "demo-secret-change-me");
    assert_eq!(oidc_http_body_json(router.clone().oneshot(other).await.unwrap()).await, inactive);
    set_gate(false);
    assert_eq!(oidc_http_body_json(router.clone().oneshot(exact()).await.unwrap()).await, inactive);
    pool.get().unwrap().batch_execute("UPDATE users SET is_admin=0 WHERE is_admin=1").unwrap();
    set_gate(true);
    assert_eq!(oidc_http_body_json(router.clone().oneshot(exact()).await.unwrap()).await, inactive);
    let ordinary = request("access_token", &verifier.client_id, secret);
    let ordinary = oidc_http_body_json(router.clone().oneshot(ordinary).await.unwrap()).await;
    assert_eq!(ordinary["active"], true);
    assert!(ordinary.get("axon_admin_authority_v3").is_none());
    pool.get().unwrap().batch_execute("UPDATE users SET is_admin=1 WHERE username='refresh-axon-v3'").unwrap();
    state.db.delete_session(&signed_in.session_id).await.unwrap();
    assert_eq!(oidc_http_body_json(router.oneshot(exact()).await.unwrap()).await, inactive);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(root).unwrap();
    drop(state);
    fs::remove_file(path).unwrap();
}

#[cfg(all(feature = "sqlite", target_os = "linux"))]
#[tokio::test]
async fn axon_v2_ordinary_code_issues_full_access_only_and_rechecks_authority() {
    use base64::{Engine as _, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
    use diesel::{RunQueryDsl, connection::SimpleConnection, sql_query, sql_types::Text};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};
    use std::os::unix::fs::PermissionsExt;
    let (mut state, path) = test_app_state().await;
    let user = insert_refresh_test_user(&state, "axon-v2").await;
    let operator = insert_refresh_test_user(&state, "axon-v2-operator").await;
    let demo = test_refresh_client(&state).await;
    let binding = state.db.find_application_client_binding_by_public_client_id(&demo.client_id)
        .await.unwrap().unwrap();
    let app = state.db.find_application_by_id(&binding.application_id).await.unwrap().unwrap();
    let verifier = insert_test_oidc_client(&state, "v2-confidential-fixture", "https://verifier.test/callback", "").await;
    let origin = "https://axon.test";
    let resource = "https://axon.test/resource";
    let redirect = format!("{origin}/admin/api/auth/signet/callback");
    let now = util::now_ts();
    let issuer = state.settings.oidc.issuer.trim_end_matches('/').to_owned();
    let signing = SigningKey::from_bytes(&[81; 32]);
    let jwks = json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA",
        "x":URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()),"kid":"fixture"}]}).to_string();
    let pin = crate::application_discovery::axon_signer_pin(&jwks).unwrap();
    let permissions: Vec<String> = serde_json::from_str(include_str!(
        "../tests/fixtures/axon-admin-v2-catalog.json"
    )).unwrap();
    assert_eq!(permissions.len(), 171);
    let mapping = json!({"version":2,"source":"signet.is_admin","claim":"axon_admin_authority",
        "output":"access_token","client_id":demo.client_id,"audience":resource,"permissions":permissions});
    let body = json!({
        "format": "signet-application/v3", "application_id": app.slug, "revision": 3,
        "version": "fixture", "iss": origin, "aud": [issuer, format!("signet:application:{}", app.slug)],
        "iat": now, "exp": now+180,
        "modules": {"axon_admin_mapping":mapping, "clients":[{
            "client_id":demo.client_id,"protocol":"oidc","profiles":["web_oidc"],
            "redirect_uris":[redirect],"scopes":["openid"],"audiences":[resource],
            "grant_types":["authorization_code"],"response_types":["code"],
            "require_pkce":true,"require_s256_pkce":true
        }]}
    });
    let approved = crate::application_discovery::ApprovedAxonDeclaration {
        organization_id: &app.organization_id, application_id: &app.slug, revision: 3,
        website_origin: origin, discovery_issuer: origin, discovery_audience: &issuer,
        client_id: &demo.client_id, resource_audience: resource, pinned_jwks: &jwks,
        catalog: &permissions,
    };
    let verify_signed = |payload: &Value| {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","kid":"fixture"}"#);
        let data = format!("{header}.{}", URL_SAFE_NO_PAD.encode(payload.to_string()));
        let signature = URL_SAFE_NO_PAD.encode(signing.sign(data.as_bytes()).to_bytes());
        crate::application_discovery::verify_approved_axon_v2(
            format!("{data}.{signature}").as_bytes(), &app.organization_id, origin, &approved,
        )
    };
    let baseline = verify_signed(&body).expect("signed v2 baseline verified");
    let digest = baseline.manifest().digest.clone();
    let durable = baseline.manifest().redacted_payload.to_string();
    let anchor_dir = std::env::temp_dir().join(format!("signet-axon-floor-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&anchor_dir).unwrap();
    let marker = anchor_dir.join("authority-floor.json");
    let set_floor = |generation: i64, halted: bool| {
        std::fs::set_permissions(&anchor_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pending = anchor_dir.join("next.json");
        std::fs::write(&pending, json!({
            "organization_id": app.organization_id, "application_id": app.slug,
            "enrollment_id": "fixture-enrollment", "minimum_generation": generation,
            "revision": 3, "digest": digest, "halted": halted,
        }).to_string()).unwrap();
        let mut permissions = std::fs::metadata(&pending).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&pending, permissions).unwrap();
        std::fs::rename(pending, &marker).unwrap();
        std::fs::set_permissions(&anchor_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    };
    set_floor(1, false);
    state.settings.discovery.axon_admin_trust = Some(crate::config::AxonAdminTrust {
        origin: origin.into(), organization_id: app.organization_id.clone(),
        application_id: app.slug.clone(), client_id: demo.client_id.clone(),
        audience: resource.into(), signing_public_jwks: jwks.clone(),
    });
    state.settings.discovery.axon_admin_v2 = Some(crate::config::AxonAdminV2Policy {
        enrollment_id: "fixture-enrollment".into(), revision: 3, digest: digest.clone(),
        permissions: permissions.clone(), issuer: issuer.clone(),
        introspection_client_id: verifier.client_id.clone(), activation_epoch: now - 1,
        signed_withdrawal: false,
        rollback_marker_path: Some(marker.to_string_lossy().into_owned()),
        account_revocations: None,
        rollback_marker_owner_uid: Some(rustix::process::geteuid().as_raw()),
    });
    state.db.upsert_application_discovery(crate::db::NewApplicationDiscovery {
        application_id: app.id.clone(), management_mode: crate::application_discovery::MANAGEMENT_MODE_WEBSITE.into(),
        website_url: origin.into(), fetch_secret_ciphertext: String::new(), signing_public_jwks: jwks.clone(),
        last_verified_revision: Some(3), last_verified_version: Some("fixture".into()),
        last_verified_digest: Some(digest.clone()), last_verified_expires_at: Some(now+180),
        sync_status: crate::application_discovery_contract::SYNC_STATUS_SYNCED.into(),
        last_fetched_at: Some(now), last_success_at: Some(now), last_error: None,
        snapshot_json: Some(r#"{"modules":{}}"#.into()),
        operator_disabled: false,
    }).await.unwrap();
    let crate::db::Db::Sqlite(pool) = &state.db else { unreachable!() };
    let pool = pool.clone();
    let secret = "local-fixture-not-a-deployed-secret";
    {
        let mut conn = pool.get().unwrap();
        conn.batch_execute(include_str!("../../scripts/axon-admin-v2-tombstone.sql")).unwrap();
        sql_query("UPDATE users SET is_admin=1 WHERE id=?").bind::<Text,_>(&user.id).execute(&mut conn).unwrap();
        sql_query("UPDATE users SET is_admin=1 WHERE id=?").bind::<Text,_>(&operator.id).execute(&mut conn).unwrap();
        sql_query("UPDATE clients SET organization_id=?, audience=?, redirect_uris=?, scopes='[\"openid\"]',
            grant_types='[\"authorization_code\"]', require_pkce=1, require_s256_pkce=1 WHERE id=?")
            .bind::<Text,_>(&app.organization_id).bind::<Text,_>(resource)
            .bind::<Text,_>(json!([redirect]).to_string()).bind::<Text,_>(&demo.id).execute(&mut conn).unwrap();
        sql_query("UPDATE clients SET organization_id=?, audience=?, token_endpoint_auth_method='client_secret_basic',
            client_secret_hash=? WHERE id=?")
            .bind::<Text,_>(&app.organization_id).bind::<Text,_>(resource)
            .bind::<Text,_>(util::hash_password(secret).unwrap()).bind::<Text,_>(&verifier.id).execute(&mut conn).unwrap();
        sql_query("INSERT INTO axon_admin_authority_state
            (organization_id,application_slug,enrollment_id,revision,digest,generation,withdrawn,snapshot_json,expires_at)
            VALUES (?,?,'fixture-enrollment',3,?,1,0,?,?)")
            .bind::<Text,_>(&app.organization_id).bind::<Text,_>(&app.slug)
            .bind::<Text,_>(&digest).bind::<Text,_>(&durable)
            .bind::<diesel::sql_types::BigInt,_>(now+180).execute(&mut conn).unwrap();
    }
    let client = test_refresh_client(&state).await;
    let jar = auth::issue_session_with_login_event(&state, CookieJar::new(), &HeaderMap::new(),
        None, &user, "password", auth::LoginEventContext::default()).await.unwrap();
    let signed_in = auth::require_current_user(&state, &jar).await.unwrap();
    let sid = util::session_public_id(&signed_in.session_id);
    let enrollment = crate::db::AxonV2Enrollment {
        application_db_id: app.id.clone(), organization_id: app.organization_id.clone(),
        application_slug: app.slug.clone(), enrollment_id: "fixture-enrollment".into(),
        website_origin: origin.into(), signer_pin: pin.clone(),
    };
    assert!(state.db.live_axon_v2_snapshot(enrollment, user.id.clone(), 3, digest.clone(), 1)
        .await.unwrap().is_some(), "v2 enrolled current snapshot was not visible");
    let authz = crate::oidc_authorization::AuthorizationSnapshot::load(&state, &client, &user).await.unwrap();
    assert!(matches!(authz.binding.as_ref().unwrap().protocol.as_str(), "oidc" | "oauth2_oidc"));
    assert!(crate::oidc_authorization::project_axon_admin_v2(
        &state, &authz, &client, &user, Some(resource), &sid, "openid", &issuer,
    ).await.unwrap().is_some(), "v2 candidate projection prerequisites did not match");
    let challenge_verifier = "fixture-verifier-for-s256-challenge-000000000";
    let exchange = async |state: &AppState, code: &str| {
        let client = test_refresh_client(state).await;
        state.db.insert_authorization_code(NewAuthorizationCode {
            code: code.into(), client_id: client.client_id.clone(), user_id: user.id.clone(),
            application_id: Some(app.id.clone()), authorization_profile_id: Some(binding.authorization_profile_id.clone()),
            auth_context_id: None, session_id: Some(sid.clone()),
            redirect_uri: redirect.clone(), scope: "openid".into(), resource: Some(resource.into()),
            authorization_details: None, nonce: None,
            code_challenge: Some(util::sha256_base64url(challenge_verifier)), code_challenge_method: Some("S256".into()),
            auth_time: now, acr: assurance::ACR_PASSWORD.into(), amr: vec!["pwd".into()], expires_at: now+120,
        }).await.unwrap();
        let mut req = test_authorization_code_token_request(code);
        req.redirect_uri = Some(redirect.clone());
        req.code_verifier = Some(challenge_verifier.into());
        let Json(tokens) = token_from_authorization_code(state.clone(), client, req, issuer.clone(), None).await.unwrap();
        tokens
    };
    let tokens = exchange(&state, "synthetic-axon-admin-code").await;
    let read = |value: &str| -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(value.split('.').nth(1).unwrap()).unwrap()).unwrap()
    };
    let expected = json!({"version":2,"application_id":app.slug,"revision":3,"permissions":permissions});
    let claim = "axon_admin_authority";
    assert!(read(&tokens.access_token)[claim] == expected, "full v2 access claim did not match");
    assert!(tokens.access_token.len() < 32_768);
    assert!(read(tokens.id_token.as_deref().unwrap()).get(claim).is_none());
    assert!(tokens.refresh_token.is_none());
    let router = axum::Router::new().route("/oauth2/introspect", axum::routing::post(
        super::oidc_resource::introspect)).with_state(state.clone());
    let request = || Request::post("/oauth2/introspect")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, format!("Basic {}", STANDARD.encode(format!("{}:{secret}", verifier.client_id))))
        .body(Body::from(format!("token_type_hint=axon_admin_authority&token={}", tokens.access_token))).unwrap();
    let before = oidc_http_body_json(router.clone().oneshot(request()).await.unwrap()).await;
    assert!(before == json!({"active":true,"axon_admin_authority":expected}), "confidential live-authority assertion did not match");
    let commit = |verified| {
        let db = state.db.clone();
        let app_id = app.id.clone();
        let policy = state.settings.discovery.axon_admin_v2.clone().unwrap();
        let trust = state.settings.discovery.axon_admin_trust.clone().unwrap();
        async move {
            let owner = format!("test-renewal-{}", uuid::Uuid::new_v4());
            let lease = db.claim_application_discovery_lease(&app_id, &owner).await.unwrap().unwrap();
            let result = db.commit_axon_v2_discovery_if_owner(
                &app_id, &owner, lease.lease_generation, verified, policy, trust,
            ).await;
            db.release_application_discovery_lease(&app_id, &owner, lease.lease_generation).await.unwrap();
            result
        }
    };
    // Expire authority while retaining the same signed bearer and session.
    {
        let mut conn = pool.get().unwrap();
        sql_query("UPDATE axon_admin_authority_state SET expires_at=?")
            .bind::<diesel::sql_types::BigInt,_>(util::now_ts()-1)
            .execute(&mut conn).unwrap();
    }
    assert_eq!(oidc_http_body_json(router.clone().oneshot(request()).await.unwrap()).await,
        json!({"active":false}));
    let mut renewed = body.clone();
    renewed["iat"] = Value::from(now+1);
    renewed["exp"] = Value::from(now+400);
    let renewed_verified = verify_signed(&renewed).unwrap();
    assert_eq!(renewed_verified.manifest().digest, digest);
    let reconciled = commit(renewed_verified).await.unwrap();
    assert_eq!(reconciled.last_verified_revision, Some(3));
    assert_eq!(reconciled.last_verified_expires_at, Some(now+400));
    assert!(oidc_http_body_json(router.clone().oneshot(request()).await.unwrap()).await == before);
    let mut modified = renewed.clone();
    modified["modules"]["clients"][0]["require_mfa"] = Value::Bool(true);
    let changed = verify_signed(&modified).unwrap();
    assert_ne!(changed.manifest().digest, digest);
    assert!(commit(changed).await.is_err(), "same revision changed client authorization");
    let mut shorter = renewed.clone();
    shorter["exp"] = Value::from(now+300);
    assert!(commit(verify_signed(&shorter).unwrap()).await.is_err(), "same revision shortened trust");
    let mut expired = renewed.clone();
    expired["iat"] = Value::from(now-120);
    expired["exp"] = Value::from(now-1);
    assert!(verify_signed(&expired).is_err(), "expired signed renewal was accepted");
    let backup = std::env::temp_dir().join(format!("signet-axon-restore-{}.sqlite", uuid::Uuid::new_v4()));
    {
        let mut conn = pool.get().unwrap();
        sql_query("VACUUM INTO ?").bind::<Text,_>(backup.to_string_lossy().as_ref())
            .execute(&mut conn).unwrap();
    }
    let operator = state.db.find_user_by_id(&operator.id).await.unwrap().unwrap();
    let operator_jar = auth::issue_session_with_login_event(&state, CookieJar::new(), &HeaderMap::new(),
        None, &operator, "password", auth::LoginEventContext::default()).await.unwrap();
    let cookie = operator_jar.iter().map(|c| format!("{}={}", c.name(), c.value())).collect::<Vec<_>>().join("; ");
    let change = crate::admin::routes().with_state(state.clone()).oneshot(
        Request::put(format!("/api/admin/users/{}", user.id))
            .header(header::COOKIE, cookie).header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({
                "email":user.email,"username":user.username,"display_name":user.display_name,
                "phone":user.phone,"is_admin":false,"is_active":true,
            }).to_string())).unwrap()
    ).await.unwrap();
    assert_eq!(change.status(), StatusCode::OK, "actual admin route did not demote the fixture");
    let demoted = state.db.find_user_by_id(&user.id).await.unwrap().unwrap();
    assert_eq!((demoted.is_admin, demoted.is_active), (0,1));
    let ordinary = |fresh: &super::oidc_token::TokenResponse| {
        let id = read(fresh.id_token.as_deref().unwrap());
        assert_eq!(id["sub"], read(tokens.id_token.as_deref().unwrap())["sub"]);
        assert!(id.get(claim).is_none());
        assert!(read(&fresh.access_token).get(claim).is_none());
    };
    assert_eq!(oidc_http_body_json(router.clone().oneshot(request()).await.unwrap()).await, json!({"active":false}));
    ordinary(&exchange(&state, "synthetic-after-demotion").await);

    let mut restored_settings = state.settings.clone();
    restored_settings.database.url = backup.to_string_lossy().into_owned();
    let restored_db = crate::db::Db::connect(&restored_settings).unwrap();
    let restored = AppState::new(restored_settings, restored_db, state.jwt.clone());
    let restored_router = axum::Router::new().route("/oauth2/introspect", axum::routing::post(
        super::oidc_resource::introspect)).with_state(restored.clone());
    let legacy_user = restored.db.find_user_by_id(&user.id).await.unwrap().unwrap();
    assert_eq!(legacy_user.is_admin, 1, "backup predates demotion");
    // Negative control: the old role itself was in the backup. An unchanged
    // application floor does not independently remember account demotions.
    assert_eq!(oidc_http_body_json(restored_router.clone().oneshot(request()).await.unwrap()).await["active"], true);
    let mut prior_settings = restored.settings.clone();
    prior_settings.discovery.axon_admin_v2.as_mut().unwrap().rollback_marker_owner_uid = None;
    let prior = AppState::new(prior_settings, restored.db.clone(), state.jwt.clone());
    let prior_router = axum::Router::new().route("/oauth2/introspect", axum::routing::post(
        super::oidc_resource::introspect)).with_state(prior.clone());
    assert_eq!(oidc_http_body_json(prior_router.oneshot(request()).await.unwrap()).await, json!({"active":false}));
    ordinary(&exchange(&prior, "synthetic-restored-without-verified-owner").await);
    {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[13; 32]);
        let account_marker = anchor_dir.join("account-revocations.json");
        let sign = |ids: Vec<String>| {
            let payload = json!({
                "format":"signet-axon-account-revocations/v1",
                "organization_id":app.organization_id,"application_id":app.slug,
                "enrollment_id":"fixture-enrollment","minimum_generation":1,"revision":3,
                "digest":digest,"revoked_account_ids":ids,
            }).to_string();
            let digest = util::sha256_base64url(&payload);
            let signature = key.sign(payload.as_bytes());
            (digest, json!({"payload":URL_SAFE_NO_PAD.encode(payload),"signature":URL_SAFE_NO_PAD.encode(signature.to_bytes())}))
        };
        let write = |value: &Value| {
            std::fs::set_permissions(&anchor_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let next = anchor_dir.join("next-account.json");
            std::fs::write(&next, value.to_string()).unwrap();
            let mut permissions = std::fs::metadata(&next).unwrap().permissions();
            permissions.set_readonly(true);
            std::fs::set_permissions(&next, permissions).unwrap();
            std::fs::rename(next, &account_marker).unwrap();
            std::fs::set_permissions(&anchor_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        };
        let (old_digest, old) = sign(vec![]);
        let (new_digest, updated) = sign(vec![demoted.id.clone()]);
        let reopen = |digest: String| {
            let mut settings = restored.settings.clone();
            settings.discovery.axon_admin_v2.as_mut().unwrap().account_revocations =
                Some(crate::config::AxonAccountRevocations {
                    marker_path:account_marker.to_string_lossy().into_owned(),
                    signing_public_key:URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
                    payload_digest:digest,
                });
            let db = crate::db::Db::connect(&settings).unwrap();
            AppState::new(settings, db, state.jwt.clone())
        };
        let introspection = |s: AppState| axum::Router::new().route("/oauth2/introspect", axum::routing::post(
            super::oidc_resource::introspect)).with_state(s);
        write(&old);
        assert_eq!(oidc_http_body_json(introspection(reopen(old_digest)).oneshot(request()).await.unwrap()).await["active"], true);
        let fenced = reopen(new_digest.clone());
        assert_eq!(oidc_http_body_json(introspection(fenced.clone()).oneshot(request()).await.unwrap()).await, json!({"active":false}));
        write(&updated);
        assert_eq!(oidc_http_body_json(introspection(fenced.clone()).oneshot(request()).await.unwrap()).await, json!({"active":false}));
        ordinary(&exchange(&fenced, "synthetic-restored-signed-account-revocation").await);
        let operator_jar = auth::issue_session_with_login_event(&fenced, CookieJar::new(), &HeaderMap::new(),
            None, &operator, "password", auth::LoginEventContext::default()).await.unwrap();
        let operator_session = auth::require_current_user(&fenced, &operator_jar).await.unwrap();
        let operator_sid = util::session_public_id(&operator_session.session_id);
        let client = test_refresh_client(&fenced).await;
        let operator_binding = crate::oidc_authorization::AuthorizationSnapshot::load(&fenced, &client, &operator).await.unwrap();
        assert_eq!(crate::oidc_authorization::project_axon_admin_v2(
            &fenced, &operator_binding, &client, &operator, Some(resource), &operator_sid, "openid", &issuer,
        ).await.unwrap(), Some(expected.clone()), "another current global administrator is not revoked");
        write(&old);
        let restarted = reopen(new_digest);
        assert_eq!(oidc_http_body_json(introspection(restarted.clone()).oneshot(request()).await.unwrap()).await, json!({"active":false}));
        ordinary(&exchange(&restarted, "synthetic-restored-account-replay-denied").await);
    }
    set_floor(2, true);
    assert_eq!(
        oidc_http_body_json(restored_router.clone().oneshot(request()).await.unwrap()).await,
        json!({"active":false}),
    );
    ordinary(&exchange(&restored, "synthetic-restored-while-halted").await);
    assert_eq!(
        oidc_http_body_json(router.clone().oneshot(request()).await.unwrap()).await,
        json!({"active":false}),
    );
    let control = crate::application_discovery::run_axon_v2_operator_command(
        &state.settings, &state.db, &["disable".into(), "1".into()],
    ).await;
    assert!(control.is_ok(), "fixture's explicit scoped disable did not commit");
    let after_disable = oidc_http_body_json(router.oneshot(request()).await.unwrap()).await;
    assert_eq!(after_disable, json!({"active":false}));
    assert!(crate::application_discovery::run_axon_v2_operator_command(
        &state.settings, &state.db, &["reapprove".into(), "2".into()],
    ).await.is_err(), "same signed revision cannot reopen a disabled enrollment");
    // Restore only the SQLite backup. The independently retained marker is
    // intentionally not part of it. Even clearing halt leaves generation 2
    // as a floor, making the backup's previously live generation 1 inert.
    set_floor(2, false);
    assert!(commit(verify_signed(&renewed).unwrap()).await.is_err(),
        "normal same-revision sync must not reactivate a withdrawn enrollment");
    assert_eq!(
        oidc_http_body_json(restored_router.oneshot(request()).await.unwrap()).await,
        json!({"active":false}),
        "restoring a still-live same revision must not restore disabled authority",
    );
    ordinary(&exchange(&restored, "synthetic-restored-with-retained-floor").await);
    drop(restored);
    drop(state);
    let _ = std::fs::remove_file(backup);
    let _ = std::fs::set_permissions(&anchor_dir, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::remove_dir_all(anchor_dir);
    let _ = std::fs::remove_file(path);
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

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn existing_manager_refreshes_pinned_website_discovery_via_admin_routes() {
    use crate::{application_discovery, db::NewApplicationDiscovery};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use diesel::{RunQueryDsl, sql_query, sql_types::Text};
    use ed25519_dalek::SigningKey;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    let (mut state, path) = test_app_state_with_issuer(Some("https://sso.example")).await;
    state.settings.discovery.allow_private_networks = false;
    state.settings.discovery.encryption_key = URL_SAFE_NO_PAD.encode([23_u8; 32]);
    let client = test_refresh_client(&state).await;
    let organization_id = client.organization_id.as_deref().expect("seeded client organization");
    let app = state.db.find_application_by_slug_in_organization(organization_id, "axon")
        .await.unwrap().expect("seeded Axon application in the exact fixture organization");
    let manager = insert_refresh_test_user(&state, "discovery-manager").await;
    let other = insert_refresh_test_user(&state, "discovery-nonmanager").await;
    let crate::db::Db::Sqlite(pool) = &state.db else { unreachable!() };
    {
        let mut conn = pool.get().unwrap();
        sql_query("UPDATE users SET is_admin=1 WHERE id=?")
            .bind::<Text,_>(&manager.id).execute(&mut conn).unwrap();
        sql_query("DELETE FROM organization_members WHERE user_id=?")
            .bind::<Text,_>(&manager.id).execute(&mut conn).unwrap();
    }
    let manager_jar = auth::issue_session_with_login_event(&state, CookieJar::new(), &HeaderMap::new(),
        None, &manager, "password", auth::LoginEventContext::default()).await.unwrap();
    let other_jar = auth::issue_session_with_login_event(&state, CookieJar::new(), &HeaderMap::new(),
        None, &other, "password", auth::LoginEventContext::default()).await.unwrap();
    assert_eq!(auth::require_current_user(&state, &manager_jar).await.unwrap().user.is_admin, 1);

    // Use a policy-valid synthetic HTTPS origin. No HTTP client or DNS lookup
    // runs in this test; only the validated outbound transport supplies bytes.
    let website = "https://fixture-axon.example".to_owned();
    let fetch_secret = "discovery-local-fixture-secret";
    let key = SigningKey::from_bytes(&[24_u8; 32]);
    let (first, jwks) = application_discovery::signed_contract_fixture(&key, &website, 2);
    let payload = Arc::new(Mutex::new(first));
    let fetched = Arc::new(AtomicUsize::new(0));
    let site_payload = payload.clone();
    let site_counter = fetched.clone();
    let expected_url = application_discovery::default_discovery_url(&website).unwrap();
    let transport: application_discovery::DiscoveryTestTransport = Box::new(move |url, secret, challenge| {
        assert_eq!(url.as_str(), expected_url);
        assert_eq!(secret, Some(fetch_secret));
        assert!(challenge.is_none());
        site_counter.fetch_add(1, Ordering::Relaxed);
        Ok(site_payload.lock().unwrap().clone())
    });
    state.db.upsert_application_discovery(NewApplicationDiscovery {
        application_id: app.id.clone(),
        management_mode: application_discovery::MANAGEMENT_MODE_WEBSITE.into(),
        website_url: website.clone(),
        fetch_secret_ciphertext: util::encrypt_discovery_secret(
            &state.settings.discovery.encryption_key, fetch_secret,
        ).unwrap(),
        signing_public_jwks: jwks,
        last_verified_revision: None,
        last_verified_version: None,
        last_verified_digest: None,
        last_verified_expires_at: None,
        sync_status: application_discovery::SYNC_PENDING.into(),
        last_fetched_at: None,
        last_success_at: None,
        last_error: None,
        snapshot_json: None,
        operator_disabled: false,
    }).await.unwrap();

    let get_path = format!("/api/admin/applications/{}/discovery", app.id);
    let sync_path = format!("{get_path}/sync");
    application_discovery::DISCOVERY_TEST_TRANSPORT.scope(transport, async {
    let router = crate::admin::routes().with_state(state.clone());
    let request = |method, path: &str, jar: &CookieJar| {
        let cookie = jar.get(&state.settings.security.cookie_name).unwrap();
        Request::builder().method(method).uri(path)
            .header(header::COOKIE, format!("{}={}", cookie.name(), cookie.value()))
            .body(Body::empty()).unwrap()
    };
    let get = |jar| request(axum::http::Method::GET, &get_path, jar);
    let sync = |jar| request(axum::http::Method::POST, &sync_path, jar);
    let first = router.clone().oneshot(sync(&manager_jar)).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first = oidc_http_body_json(first).await;
    assert_eq!(first["last_verified_revision"], 2);
    let digest_before = first["last_verified_digest"].as_str().unwrap().to_owned();

    *payload.lock().unwrap() = application_discovery::signed_contract_fixture(&key, &website, 3).0;
    let calls = fetched.load(Ordering::Relaxed);
    for denied in [get(&other_jar), sync(&other_jar)] {
        let denied = router.clone().oneshot(denied).await.unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }
    assert_eq!(fetched.load(Ordering::Relaxed), calls);
    let unchanged = router.clone().oneshot(get(&manager_jar)).await.unwrap();
    assert_eq!(unchanged.status(), StatusCode::OK);
    let unchanged = oidc_http_body_json(unchanged).await;
    assert_eq!(unchanged["last_verified_revision"], 2);
    assert_eq!(unchanged["last_verified_digest"], digest_before);

    let update = router.clone().oneshot(sync(&manager_jar)).await.unwrap();
    assert_eq!(update.status(), StatusCode::OK);
    let readback = router.clone().oneshot(get(&manager_jar)).await.unwrap();
    assert_eq!(readback.status(), StatusCode::OK);
    let readback = oidc_http_body_json(readback).await;
    assert_eq!(readback["last_verified_revision"], 3);
    let digest = readback["last_verified_digest"].as_str().unwrap();
    assert_ne!(digest, digest_before);

    let wrong_signer = SigningKey::from_bytes(&[25_u8; 32]);
    *payload.lock().unwrap() = application_discovery::signed_contract_fixture(&wrong_signer, &website, 4).0;
    let invalid = router.clone().oneshot(sync(&manager_jar)).await.unwrap();
    assert!(invalid.status().is_client_error());
    let after = router.oneshot(get(&manager_jar)).await.unwrap();
    assert_eq!(after.status(), StatusCode::OK);
    let after = oidc_http_body_json(after).await;
    assert_eq!(after["last_verified_revision"], 3);
    assert_eq!(after["last_verified_digest"], digest);

    }).await;
    drop(state);
    std::fs::remove_file(path).unwrap();
}

async fn test_app_state() -> (AppState, PathBuf) {
    test_app_state_with_issuer(None).await
}

async fn test_app_state_with_issuer(issuer: Option<&str>) -> (AppState, PathBuf) {
    let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../config/default.toml");
    let raw = std::fs::read_to_string(config_path).unwrap();
    let mut settings: crate::Settings = toml::from_str(&raw).unwrap();
    if let Some(issuer) = issuer {
        settings.oidc.issuer = issuer.to_owned();
    }
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
            backchannel_logout_uri: String::new(),
            backchannel_logout_session_required: false,
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
    (AppState::new(settings, db, jwt), path)
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
