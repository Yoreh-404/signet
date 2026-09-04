use super::*;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn registered_user_creation_keeps_valid_code_when_identity_conflicts() {
    let (db, path) = sqlite_test_db().await;
    let email = "verified@example.com";
    let code = "123456";
    let verification_code = db
        .insert_verification_code(NewVerificationCode {
            channel: "email",
            target: email,
            purpose: "registration",
            code_hash: util::token_hash(code),
            ttl_seconds: 600,
            resend_interval_seconds: 1,
            max_attempts: 5,
        })
        .await
        .unwrap();
    db.insert_user(test_user(email, "existing")).await.unwrap();

    let result = db
        .insert_registered_user(
            test_user(email, "new-user"),
            false,
            vec![VerificationCodeClaim::new(
                "email",
                email,
                "registration",
                code,
            )],
        )
        .await;

    assert!(matches!(
        result,
        Err(AppError::BadRequest(message)) if message == "user email or username already exists"
    ));
    assert_eq!(
        load_verification_code(&db, &verification_code.id)
            .await
            .consumed_at,
        None
    );

    db.consume_verification_code("email", email, "registration", code)
        .await
        .unwrap();
    assert!(
        load_verification_code(&db, &verification_code.id)
            .await
            .consumed_at
            .is_some()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn external_oidc_user_creation_can_join_provider_organization() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(NewOrganization {
            slug: "corp".to_string(),
            name: "Corp".to_string(),
            kind: ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            allowed_email_domains: vec!["example.com".to_string()],
            is_active: true,
        })
        .await
        .unwrap();

    let user = db
        .insert_external_oidc_user(
            test_user("member@example.com", "member"),
            "corp-oidc",
            "external-subject",
            Some("member@example.com".to_string()),
            Some(organization.id.clone()),
            true,
        )
        .await
        .unwrap();

    let memberships = db.list_user_organizations(&user.id).await.unwrap();
    assert_eq!(memberships.len(), 1);
    assert_eq!(memberships[0].id, organization.id);
    assert_eq!(memberships[0].role, crate::organizations::ROLE_MEMBER);

    let members = db
        .list_organization_members(&organization.id)
        .await
        .unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].user_id, user.id);

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn external_oidc_provider_persists_login_switch() {
    let (db, path) = sqlite_test_db().await;
    let provider = NewExternalOidcProvider {
        slug: "corp".to_string(),
        display_name: "Corp OIDC".to_string(),
        organization_id: None,
        issuer: "https://idp.example.com".to_string(),
        client_id: "client".to_string(),
        client_secret: "secret".to_string(),
        authorization_endpoint: "https://idp.example.com/authorize".to_string(),
        token_endpoint: "https://idp.example.com/token".to_string(),
        userinfo_endpoint: "https://idp.example.com/userinfo".to_string(),
        redirect_path: "/api/register/oidc/corp/callback".to_string(),
        scopes: vec!["openid".to_string(), "email".to_string()],
        email_domains: vec!["example.com".to_string()],
        is_active: true,
        allow_login: false,
        allow_registration: true,
    };

    let created = db
        .insert_external_oidc_provider(provider.clone())
        .await
        .unwrap();
    assert_eq!(created.allow_login, 0);
    assert!(!created.clone().public().unwrap().allow_login);

    let mut updated = provider;
    updated.display_name = "Corp Login".to_string();
    updated.allow_login = true;
    updated.allow_registration = false;
    let saved = db
        .update_external_oidc_provider(&created.id, updated)
        .await
        .unwrap();

    assert_eq!(saved.allow_login, 1);
    assert_eq!(saved.allow_registration, 0);
    let public = saved.public().unwrap();
    assert!(public.allow_login);
    assert!(!public.allow_registration);

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn external_oidc_provider_listing_is_scoped_to_organization() {
    let (db, path) = sqlite_test_db().await;
    let organization_a = db
        .insert_organization(test_organization("oidc-org-a", "OIDC Org A"))
        .await
        .unwrap();
    let organization_b = db
        .insert_organization(test_organization("oidc-org-b", "OIDC Org B"))
        .await
        .unwrap();

    db.insert_external_oidc_provider(test_external_oidc_provider(
        "oidc-a-later",
        "Zulu A",
        Some(&organization_a.id),
    ))
    .await
    .unwrap();
    db.insert_external_oidc_provider(test_external_oidc_provider(
        "oidc-a-earlier",
        "Alpha A",
        Some(&organization_a.id),
    ))
    .await
    .unwrap();
    db.insert_external_oidc_provider(test_external_oidc_provider(
        "oidc-b",
        "Beta B",
        Some(&organization_b.id),
    ))
    .await
    .unwrap();
    db.insert_external_oidc_provider(test_external_oidc_provider("oidc-global", "Global", None))
        .await
        .unwrap();

    let scoped = db
        .list_external_oidc_providers_for_organization(&organization_a.id)
        .await
        .unwrap();
    assert_eq!(
        scoped
            .iter()
            .map(|provider| provider.slug.as_str())
            .collect::<Vec<_>>(),
        vec!["oidc-a-earlier", "oidc-a-later"]
    );

    let global = db.list_external_oidc_providers().await.unwrap();
    assert_eq!(
        global
            .iter()
            .map(|provider| provider.slug.as_str())
            .collect::<Vec<_>>(),
        vec!["oidc-a-earlier", "oidc-a-later", "oidc-b", "oidc-global"]
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn deleting_external_oidc_provider_removes_reusable_identity_links() {
    let (db, path) = sqlite_test_db().await;
    let user = db
        .insert_user(test_user("former-idp-user@example.com", "former-idp-user"))
        .await
        .unwrap();
    let provider = db
        .insert_external_oidc_provider(NewExternalOidcProvider {
            slug: "reusable-tenant-idp".to_string(),
            display_name: "Reusable tenant IdP".to_string(),
            organization_id: None,
            issuer: "https://idp.example.com".to_string(),
            client_id: "client".to_string(),
            client_secret: "secret".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: "https://idp.example.com/userinfo".to_string(),
            redirect_path: "/api/register/oidc/reusable-tenant-idp/callback".to_string(),
            scopes: vec!["openid".to_string()],
            email_domains: Vec::new(),
            is_active: true,
            allow_login: true,
            allow_registration: true,
        })
        .await
        .unwrap();
    db.insert_linked_identity(
        &user.id,
        &provider.slug,
        "former-subject",
        Some(user.email.clone()),
    )
    .await
    .unwrap();

    db.delete_external_oidc_provider(&provider.id)
        .await
        .unwrap();
    assert!(
        db.find_linked_identity(&provider.slug, "former-subject")
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn external_oidc_user_creation_respects_provider_organization_email_policy() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(NewOrganization {
            slug: "corp".to_string(),
            name: "Corp".to_string(),
            kind: ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            allowed_email_domains: vec!["example.com".to_string()],
            is_active: true,
        })
        .await
        .unwrap();

    let result = db
        .insert_external_oidc_user(
            test_user("member@other.test", "blocked-member"),
            "corp-oidc",
            "external-subject",
            Some("member@other.test".to_string()),
            Some(organization.id.clone()),
            true,
        )
        .await;

    assert!(matches!(result, Err(AppError::Forbidden)));
    assert!(
        db.list_organization_members(&organization.id)
            .await
            .unwrap()
            .is_empty()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn registered_user_creation_records_invalid_code_attempt_before_transaction() {
    let (db, path) = sqlite_test_db().await;
    let email = "wrong-code@example.com";
    let verification_code = db
        .insert_verification_code(NewVerificationCode {
            channel: "email",
            target: email,
            purpose: "registration",
            code_hash: util::token_hash("123456"),
            ttl_seconds: 600,
            resend_interval_seconds: 1,
            max_attempts: 5,
        })
        .await
        .unwrap();

    let result = db
        .insert_registered_user(
            test_user(email, "wrong-code"),
            false,
            vec![VerificationCodeClaim::new(
                "email",
                email,
                "registration",
                "000000",
            )],
        )
        .await;

    assert!(matches!(
        result,
        Err(AppError::BadRequest(message)) if message == "verification code is invalid"
    ));
    let record = load_verification_code(&db, &verification_code.id).await;
    assert_eq!(record.attempts, 1);
    assert_eq!(record.consumed_at, None);

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn registered_user_creation_consumes_valid_code_after_user_insert() {
    let (db, path) = sqlite_test_db().await;
    let email = "new-verified@example.com";
    let code = "123456";
    let verification_code = db
        .insert_verification_code(NewVerificationCode {
            channel: "email",
            target: email,
            purpose: "registration",
            code_hash: util::token_hash(code),
            ttl_seconds: 600,
            resend_interval_seconds: 1,
            max_attempts: 5,
        })
        .await
        .unwrap();

    let user = db
        .insert_registered_user(
            test_user(email, "new-verified"),
            false,
            vec![VerificationCodeClaim::new(
                "email",
                email,
                "registration",
                code,
            )],
        )
        .await
        .unwrap();

    assert_eq!(user.email, email);
    assert!(
        load_verification_code(&db, &verification_code.id)
            .await
            .consumed_at
            .is_some()
    );
    assert!(matches!(
        db.consume_verification_code("email", email, "registration", code)
            .await,
        Err(AppError::BadRequest(message)) if message == "verification code is missing"
    ));

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn deleting_ldap_provider_revokes_reusable_slug_identity_and_sync_state() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("ldap-owner", "LDAP Owner"))
        .await
        .unwrap();
    let provider = db
        .insert_ldap_provider(test_ldap_provider(
            "reusable-directory",
            Some(&organization.id),
        ))
        .await
        .unwrap();
    let user = db
        .insert_user(test_user("ldap-linked@example.com", "ldap-linked"))
        .await
        .unwrap();
    db.insert_linked_identity(
        &user.id,
        &provider.provider_key(),
        "external-subject",
        Some("ldap-linked@example.com".to_string()),
    )
    .await
    .unwrap();
    db.start_directory_sync_run("removed-application", &provider.id)
        .await
        .unwrap();

    db.delete_ldap_provider(&provider.id).await.unwrap();
    assert!(
        db.find_linked_identity(&provider.provider_key(), "external-subject")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.list_directory_sync_runs("removed-application", 20)
            .await
            .unwrap()
            .is_empty()
    );

    let replacement = db
        .insert_ldap_provider(test_ldap_provider("reusable-directory", None))
        .await
        .unwrap();
    assert!(
        db.find_linked_identity(&replacement.provider_key(), "external-subject")
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}
