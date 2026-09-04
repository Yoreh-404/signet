use super::*;
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn bootstrap_client_ensure_is_idempotent_and_secret_safe() {
    let (db, path) = sqlite_test_db().await;
    let mut settings: Settings =
        toml::from_str(include_str!("../../../../config/default.toml")).unwrap();
    settings.bootstrap.admin.create_on_startup = false;
    settings.external_oidc_providers.clear();
    settings.bootstrap.clients = vec![BootstrapClient {
        client_id: "ensure-worker".to_string(),
        client_name: "Ensure worker".to_string(),
        logo_uri: String::new(),
        client_secret: "first-secret".to_string(),
        client_secret_env: None,
        redirect_uris: Vec::new(),
        post_logout_redirect_uris: Vec::new(),
        scopes: vec!["memory.service".to_string()],
        grant_types: vec!["client_credentials".to_string()],
        response_types: Vec::new(),
        token_endpoint_auth_method: "client_secret_basic".to_string(),
        require_pkce: false,
        require_confidential_client: false,
        service_account_enabled: true,
        service_account_permissions: vec!["users.read".to_string(), " users.read ".to_string()],
        audience: Some("memory-atlas".to_string()),
        rotate_secret: false,
    }];

    db.seed(&settings).await.unwrap();
    let first = db
        .find_client_by_client_id("ensure-worker")
        .await
        .unwrap()
        .unwrap();
    let first_hash = first.client_secret_hash.clone().unwrap();
    assert!(util::verify_password(&first_hash, "first-secret"));
    assert_eq!(first.audience, "memory-atlas");
    assert_eq!(first.service_account_enabled, 1);
    assert_eq!(
        util::from_json::<Vec<String>>(&first.service_account_permissions).unwrap(),
        vec!["users.read".to_string()]
    );

    settings.bootstrap.clients[0].client_name = "Updated worker".to_string();
    settings.bootstrap.clients[0].client_secret = "second-secret".to_string();
    settings.bootstrap.clients[0].audience = Some("memory-atlas-v2".to_string());
    db.seed(&settings).await.unwrap();
    let preserved = db
        .find_client_by_client_id("ensure-worker")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(preserved.client_name, "Updated worker");
    assert_eq!(preserved.audience, "memory-atlas-v2");
    assert_eq!(preserved.client_secret_hash, Some(first_hash.clone()));
    assert!(util::verify_password(
        preserved.client_secret_hash.as_deref().unwrap(),
        "first-secret"
    ));
    assert!(!util::verify_password(
        preserved.client_secret_hash.as_deref().unwrap(),
        "second-secret"
    ));

    settings.bootstrap.clients[0].rotate_secret = true;
    db.seed(&settings).await.unwrap();
    let rotated = db
        .find_client_by_client_id("ensure-worker")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(rotated.client_secret_hash, Some(first_hash));
    assert!(util::verify_password(
        rotated.client_secret_hash.as_deref().unwrap(),
        "second-secret"
    ));

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn bootstrap_client_ensure_reads_secret_from_environment() {
    let (db, path) = sqlite_test_db().await;
    let system = db.system_organization().await.unwrap();
    let env_name = format!("SIGNET_BOOTSTRAP_TEST_SECRET_{}", uuid::Uuid::new_v4());
    // Rust 2024 makes process-environment mutation explicit because tests
    // may otherwise race with unrelated environment readers.
    unsafe { std::env::set_var(&env_name, "environment-secret") };

    let mut client = bootstrap_client("");
    client.client_secret_env = Some(env_name.clone());
    let record = db
        .ensure_bootstrap_client(&client, &system.id)
        .await
        .unwrap();
    assert!(util::verify_password(
        record.client_secret_hash.as_deref().unwrap(),
        "environment-secret"
    ));

    unsafe { std::env::remove_var(&env_name) };
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn system_organization_is_created_and_immutable() {
    let (db, path) = sqlite_test_db().await;
    let system = db.system_organization().await.unwrap();
    assert_eq!(system.id, SIGNET_ORGANIZATION_ID);
    assert_eq!(system.kind, ORGANIZATION_KIND_SYSTEM);
    assert!(
        db.update_organization(&system.id, test_organization("not-signet", "Not Signet"),)
            .await
            .is_err()
    );
    assert!(db.delete_organization(&system.id).await.is_err());

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn listing_organizations_with_member_counts_uses_left_join_semantics() {
    let (db, path) = sqlite_test_db().await;
    let empty = db
        .insert_organization(test_organization("empty-team", "Empty Team"))
        .await
        .unwrap();
    let populated = db
        .insert_organization(test_organization("populated-team", "Populated Team"))
        .await
        .unwrap();
    let first_member = db
        .insert_user(test_user("first-member@example.com", "first-member"))
        .await
        .unwrap();
    let second_member = db
        .insert_user(test_user("second-member@example.com", "second-member"))
        .await
        .unwrap();
    db.upsert_organization_member(
        &populated.id,
        &first_member.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();
    db.upsert_organization_member(
        &populated.id,
        &second_member.id,
        crate::organizations::ROLE_ADMIN,
    )
    .await
    .unwrap();

    let organizations = db.list_organizations_with_member_counts().await.unwrap();
    let counts = organizations
        .into_iter()
        .map(|(organization, member_count)| (organization.id, member_count))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(counts.get(&empty.id), Some(&0));
    assert_eq!(counts.get(&populated.id), Some(&2));

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn active_organization_membership_query_filters_inactive_organizations() {
    let (db, path) = sqlite_test_db().await;
    let user = db
        .insert_user(test_user("manager@example.com", "manager"))
        .await
        .unwrap();
    let active = db
        .insert_organization(test_organization("active-membership", "Active Membership"))
        .await
        .unwrap();
    let inactive = db
        .insert_organization(NewOrganization {
            is_active: false,
            ..test_organization("inactive-membership", "Inactive Membership")
        })
        .await
        .unwrap();
    db.upsert_organization_member(&active.id, &user.id, crate::organizations::ROLE_OWNER)
        .await
        .unwrap();
    db.upsert_organization_member(&inactive.id, &user.id, crate::organizations::ROLE_ADMIN)
        .await
        .unwrap();

    let membership = db
        .find_active_organization_membership(&user.id, &active.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(membership.id, active.id);
    assert_eq!(membership.role, crate::organizations::ROLE_OWNER);
    assert!(
        db.find_active_organization_membership(&user.id, &inactive.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.find_active_organization_membership(&user.id, "missing-organization")
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn organization_context_and_application_access_are_tenant_scoped() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("acme", "Acme"))
        .await
        .unwrap();
    let member = db
        .insert_user(test_user("member@example.com", "member"))
        .await
        .unwrap();
    let outsider = db
        .insert_user(test_user("outsider@example.com", "outsider"))
        .await
        .unwrap();
    db.upsert_organization_member(
        &organization.id,
        &member.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();
    let context = db
        .set_active_user_organization(&member.id, &organization.id)
        .await
        .unwrap();
    assert_eq!(context.id, organization.id);
    assert!(
        db.set_active_user_organization(&outsider.id, &organization.id)
            .await
            .is_err()
    );

    let organization_app = db
        .insert_application(test_application(
            &organization.id,
            "member-portal",
            crate::applications::ACCESS_ORGANIZATION_MEMBERS,
        ))
        .await
        .unwrap();
    assert!(
        db.user_can_access_application(&organization_app, &member.id)
            .await
            .unwrap()
    );
    assert!(
        db.user_can_access_application(&organization_app, &outsider.id)
            .await
            .unwrap()
    );
    // Application membership rows are retained only for migration and
    // audit compatibility. They never deny a Signet account at login.
    db.replace_application_members(
        &organization_app.id,
        vec![NewApplicationMember {
            user_id: member.id.clone(),
            role: "member".to_string(),
            is_active: false,
        }],
    )
    .await
    .unwrap();
    assert!(
        db.user_can_access_application(&organization_app, &member.id)
            .await
            .unwrap()
    );
    db.replace_application_members(&organization_app.id, Vec::new())
        .await
        .unwrap();
    assert!(
        db.user_can_access_application(&organization_app, &member.id)
            .await
            .unwrap()
    );

    let assigned_app = db
        .insert_application(test_application(
            &organization.id,
            "restricted-portal",
            crate::applications::ACCESS_ASSIGNED_ACCOUNTS,
        ))
        .await
        .unwrap();
    assert!(
        db.user_can_access_application(&assigned_app, &member.id)
            .await
            .unwrap()
    );
    db.replace_application_members(
        &assigned_app.id,
        vec![NewApplicationMember {
            user_id: member.id.clone(),
            role: "member".to_string(),
            is_active: true,
        }],
    )
    .await
    .unwrap();
    assert!(
        db.user_can_access_application(&assigned_app, &outsider.id)
            .await
            .unwrap()
    );
    // Removing an enterprise membership changes enterprise entitlements,
    // not the Signet login gate for an active account.
    db.replace_organization_members(&organization.id, Vec::new())
        .await
        .unwrap();
    assert!(
        db.user_can_access_application(&assigned_app, &member.id)
            .await
            .unwrap()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}
