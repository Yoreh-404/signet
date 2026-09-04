use super::*;
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn mfa_totp_challenge_completion_is_single_use_under_concurrency() {
    let (db, path) = sqlite_test_db_with_pool_size(4).await;
    db.upsert_totp_method("mfa-user", "JBSWY3DPEHPK3PXP".to_string())
        .await
        .unwrap();
    let challenge = db
        .create_mfa_challenge("mfa-user", "api_login", None, 300)
        .await
        .unwrap();

    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(4));
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let db = db.clone();
        let barrier = barrier.clone();
        let challenge_id = challenge.id.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            db.complete_mfa_challenge_with_totp(&challenge_id, "mfa-user", 42)
                .await
        }));
    }

    let mut successful_completions = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            successful_completions += 1;
        }
    }
    assert_eq!(successful_completions, 1);
    assert!(
        db.find_mfa_challenge(&challenge.id)
            .await
            .unwrap()
            .unwrap()
            .consumed_at
            .is_some()
    );
    assert_eq!(
        db.find_totp_method("mfa-user")
            .await
            .unwrap()
            .unwrap()
            .last_used_step,
        Some(42)
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn mfa_recovery_code_challenge_completion_is_single_use_under_concurrency() {
    let (db, path) = sqlite_test_db_with_pool_size(4).await;
    db.replace_recovery_codes("mfa-user", vec!["hash".to_string()])
        .await
        .unwrap();
    let recovery_code = db
        .list_unused_recovery_codes("mfa-user")
        .await
        .unwrap()
        .pop()
        .unwrap();
    let challenge = db
        .create_mfa_challenge("mfa-user", "api_login", None, 300)
        .await
        .unwrap();

    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(4));
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let db = db.clone();
        let barrier = barrier.clone();
        let challenge_id = challenge.id.clone();
        let recovery_code_id = recovery_code.id.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            db.complete_mfa_challenge_with_recovery_code(
                &challenge_id,
                "mfa-user",
                &recovery_code_id,
            )
            .await
        }));
    }

    let mut successful_completions = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            successful_completions += 1;
        }
    }
    assert_eq!(successful_completions, 1);
    assert!(
        db.list_recovery_codes("mfa-user")
            .await
            .unwrap()
            .into_iter()
            .all(|code| code.used_at.is_some())
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_saml_replay_claim_is_atomic_and_reclaims_expired_keys() {
    let (db, path) = sqlite_test_db_with_pool_size(4).await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let db = db.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            db.claim_application_saml_replay("replay-key", "application-a", util::now_ts() + 300)
                .await
        }));
    }
    let mut successful_claims = 0;
    for task in tasks {
        if task.await.unwrap().unwrap() {
            successful_claims += 1;
        }
    }
    assert_eq!(successful_claims, 1);

    assert!(
        db.claim_application_saml_replay("expired-key", "application-a", util::now_ts() - 1,)
            .await
            .unwrap()
    );
    assert!(
        db.claim_application_saml_replay("expired-key", "application-a", util::now_ts() + 300,)
            .await
            .unwrap()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_saml_sessions_are_scoped_by_application_and_name_id() {
    let (db, path) = sqlite_test_db().await;
    db.insert_application_saml_session(NewApplicationSamlSession {
        session_index_hash: "session-index-a".to_string(),
        application_id: "application-a".to_string(),
        user_id: "user-a".to_string(),
        signet_session_id: "signet-session-a".to_string(),
        name_id_hash: "name-id-a".to_string(),
        expires_at: util::now_ts() + 300,
    })
    .await
    .unwrap();

    assert!(
        db.find_application_saml_session("session-index-a", "application-b")
            .await
            .unwrap()
            .is_none()
    );
    let record = db
        .find_application_saml_session("session-index-a", "application-a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.signet_session_id, "signet-session-a");
    assert_eq!(
        db.list_application_saml_sessions_by_name_id("name-id-a", "application-a")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        db.list_application_saml_sessions_by_indexes(
            &["session-index-a".to_string(), "missing".to_string()],
            "application-a",
        )
        .await
        .unwrap()
        .len(),
        1
    );
    db.delete_application_saml_session("session-index-a", "application-b")
        .await
        .unwrap();
    assert!(
        db.find_application_saml_session("session-index-a", "application-a")
            .await
            .unwrap()
            .is_some()
    );
    db.delete_application_saml_session("session-index-a", "application-a")
        .await
        .unwrap();
    assert!(
        db.find_application_saml_session("session-index-a", "application-a")
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_cas_tickets_bind_to_service_and_support_pgt_revocation() {
    let (db, path) = sqlite_test_db().await;
    db.insert_application_cas_ticket(NewApplicationCasTicket {
        ticket_hash: "service-ticket-hash".to_string(),
        application_id: "application-a".to_string(),
        ticket_type: "service".to_string(),
        service: "https://portal.example.test/cas".to_string(),
        user_id: "user-a".to_string(),
        parent_ticket_hash: None,
        pgt_iou: None,
        expires_at: util::now_ts() + 300,
    })
    .await
    .unwrap();
    assert!(
        db.consume_application_cas_ticket(
            "service-ticket-hash",
            "application-a",
            "https://other.example.test/cas",
            &["service"],
        )
        .await
        .is_err()
    );
    let consumed = db
        .consume_application_cas_ticket(
            "service-ticket-hash",
            "application-a",
            "https://portal.example.test/cas",
            &["service"],
        )
        .await
        .unwrap();
    assert_eq!(consumed.user_id, "user-a");
    assert!(
        db.consume_application_cas_ticket(
            "service-ticket-hash",
            "application-a",
            "https://portal.example.test/cas",
            &["service"],
        )
        .await
        .is_err()
    );

    db.insert_application_cas_ticket(NewApplicationCasTicket {
        ticket_hash: "pgt-hash".to_string(),
        application_id: "application-a".to_string(),
        ticket_type: "proxy_granting".to_string(),
        service: "https://portal.example.test/pgt".to_string(),
        user_id: "user-a".to_string(),
        parent_ticket_hash: None,
        pgt_iou: Some("pgt-iou".to_string()),
        expires_at: util::now_ts() + 300,
    })
    .await
    .unwrap();
    assert!(
        db.find_application_cas_ticket("pgt-hash", "application-a", "proxy_granting")
            .await
            .unwrap()
            .is_some()
    );
    db.revoke_application_cas_ticket("pgt-hash").await.unwrap();
    assert!(
        db.find_application_cas_ticket("pgt-hash", "application-a", "proxy_granting")
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
pub(crate) fn test_organization(slug: &str, name: &str) -> NewOrganization {
    NewOrganization {
        slug: slug.to_string(),
        name: name.to_string(),
        kind: ORGANIZATION_KIND_TENANT.to_string(),
        description: None,
        allowed_email_domains: Vec::new(),
        is_active: true,
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn test_application(
    organization_id: &str,
    slug: &str,
    access_mode: &str,
) -> NewApplication {
    NewApplication {
        organization_id: organization_id.to_string(),
        slug: slug.to_string(),
        name: format!("{slug} application"),
        description: None,
        access_mode: access_mode.to_string(),
        registration_mode: crate::applications::REGISTRATION_DISABLED.to_string(),
        account_selection_mode: crate::applications::ACCOUNT_SELECTION_OPTIONAL.to_string(),
        unique_identity_factors: Vec::new(),
        is_active: true,
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn test_ldap_provider(slug: &str, organization_id: Option<&str>) -> NewLdapProvider {
    NewLdapProvider {
        slug: slug.to_string(),
        display_name: format!("{slug} directory"),
        organization_id: organization_id.map(ToOwned::to_owned),
        url: "ldaps://directory.example.test".to_string(),
        starttls: false,
        bind_dn: "cn=reader,dc=example,dc=test".to_string(),
        bind_password: Some("secret".to_string()),
        base_dn: "dc=example,dc=test".to_string(),
        user_filter: "(&(objectClass=person)(uid={login}))".to_string(),
        user_id_attribute: "uid".to_string(),
        email_attribute: "mail".to_string(),
        username_attribute: "uid".to_string(),
        display_name_attribute: "cn".to_string(),
        phone_attribute: "telephoneNumber".to_string(),
        is_active: true,
        allow_login: true,
        allow_registration: true,
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn test_external_oidc_provider(
    slug: &str,
    display_name: &str,
    organization_id: Option<&str>,
) -> NewExternalOidcProvider {
    NewExternalOidcProvider {
        slug: slug.to_string(),
        display_name: display_name.to_string(),
        organization_id: organization_id.map(ToOwned::to_owned),
        issuer: format!("https://{slug}.example.test"),
        client_id: format!("{slug}-client"),
        client_secret: format!("{slug}-secret"),
        authorization_endpoint: format!("https://{slug}.example.test/authorize"),
        token_endpoint: format!("https://{slug}.example.test/token"),
        userinfo_endpoint: format!("https://{slug}.example.test/userinfo"),
        redirect_path: format!("/api/register/oidc/{slug}/callback"),
        scopes: vec!["openid".to_string()],
        email_domains: Vec::new(),
        is_active: true,
        allow_login: true,
        allow_registration: true,
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn test_client(client_id: &str, organization_id: &str) -> NewClient {
    NewClient {
        client_id: client_id.to_string(),
        client_secret_hash: None,
        client_name: format!("{client_id} client"),
        logo_uri: String::new(),
        organization_id: Some(organization_id.to_string()),
        redirect_uris: vec!["https://example.test/callback".to_string()],
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["openid".to_string()],
        audience: String::new(),
        grant_types: vec!["authorization_code".to_string()],
        response_types: vec!["code".to_string()],
        token_endpoint_auth_method: "none".to_string(),
        require_pkce: true,
        require_mfa: false,
        require_pushed_authorization_requests: false,
        require_s256_pkce: false,
        require_confidential_client: false,
        require_dpop: false,
        require_account_selection: false,
        trust_email_verified: false,
        authorization_details_types: Vec::new(),
        subject_type: crate::subject::SUBJECT_TYPE_PUBLIC.to_string(),
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
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn bootstrap_client(secret: &str) -> BootstrapClient {
    BootstrapClient {
        client_id: "bootstrap-worker".to_string(),
        client_name: "Bootstrap worker".to_string(),
        logo_uri: String::new(),
        client_secret: secret.to_string(),
        client_secret_env: None,
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["memory.service".to_string()],
        grant_types: vec!["client_credentials".to_string()],
        response_types: Vec::new(),
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        require_pkce: false,
        require_confidential_client: false,
        service_account_enabled: false,
        service_account_permissions: Vec::new(),
        audience: None,
        rotate_secret: false,
    }
}
