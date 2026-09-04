use super::*;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn normal_application_enrollment_code_creates_a_reusable_enterprise_member() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("normal-enroll", "Normal Enroll"))
        .await
        .unwrap();
    let mut application = test_application(
        &organization.id,
        "employee-app",
        crate::applications::ACCESS_ASSIGNED_ACCOUNTS,
    );
    application.registration_mode = crate::applications::REGISTRATION_INVITATION.to_string();
    let application = db.insert_application(application).await.unwrap();
    let client = db
        .insert_client_for_application(
            &application.id,
            test_client("employee-app-client", &organization.id),
        )
        .await
        .unwrap();

    let mut invitation = test_invitation(
        AuthorizationCodeType::Registration,
        LoginCodeLevel::AccountRecovery,
        None,
        None,
        vec![client.client_id],
    );
    invitation.organization_id = Some(organization.id.clone());
    invitation.organization_role = Some(crate::organizations::ROLE_MEMBER.to_string());
    invitation.expires_at = Some(util::now_ts() + 300);
    invitation.max_uses = Some(1);
    let (invitation, code) = db.insert_invitation(invitation).await.unwrap();
    db.link_application_enrollment_code(&application.id, &invitation.id)
        .await
        .unwrap();
    assert_eq!(
        db.find_application_for_enrollment_code(&invitation.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        application.id
    );

    let user = db
        .redeem_registration_code_for_new_user(
            &code,
            NewUser {
                email: "employee@example.com".to_string(),
                username: "employee".to_string(),
                display_name: None,
                phone: None,
                password_hash: "hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert!(
        db.list_user_organizations(&user.id)
            .await
            .unwrap()
            .iter()
            .any(|membership| membership.id == organization.id)
    );
    assert!(
        db.user_can_access_application(&application, &user.id)
            .await
            .unwrap()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn managed_client_starts_with_a_locked_explicit_application() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("locked-client", "Locked Client"))
        .await
        .unwrap();
    let client = db
        .insert_client(test_client("locked-client-oidc", &organization.id))
        .await
        .unwrap();
    let compatibility = db
        .find_application_for_client(&client.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        compatibility.access_mode,
        crate::applications::ACCESS_ALL_SIGNET_USERS
    );

    let application = db.harden_new_client_application(&client.id).await.unwrap();
    assert_eq!(application.organization_id, organization.id);
    assert_eq!(
        application.access_mode,
        crate::applications::ACCESS_ALL_SIGNET_USERS
    );
    assert_eq!(
        application.registration_mode,
        crate::applications::REGISTRATION_DISABLED
    );
    assert_eq!(application.is_active, 1);

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn website_manifest_removes_profiles_and_client_links_from_the_snapshot() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("website-snapshot", "Website Snapshot"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "website-snapshot",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    db.upsert_application_discovery(NewApplicationDiscovery {
        application_id: application.id.clone(),
        management_mode: crate::application_discovery_contract::MANAGEMENT_MODE_WEBSITE.to_string(),
        website_url: "https://website.example".to_string(),
        fetch_secret_ciphertext: "encrypted-fetch-secret".to_string(),
        signing_public_jwks: "{}".to_string(),
        last_verified_revision: None,
        last_verified_version: None,
        last_verified_digest: None,
        last_verified_expires_at: None,
        sync_status: crate::application_discovery_contract::SYNC_PENDING.to_string(),
        last_fetched_at: None,
        last_success_at: None,
        last_error: None,
        snapshot_json: None,
        operator_disabled: false,
    })
    .await
    .unwrap();

    let old_client = test_client("website-old-client", &organization.id);
    let old_client_id = old_client.client_id.clone();
    let profile = ApplicationDiscoveryProfile {
        permissions: vec![ApplicationDiscoveryPermission {
            key: "website.read".to_string(),
            label: "Website read".to_string(),
            description: None,
        }],
        roles: vec![ApplicationDiscoveryRole {
            key: "member".to_string(),
            name: "Member".to_string(),
            description: None,
            permissions: vec!["website.read".to_string()],
            is_default: true,
        }],
    };
    let mut profiles = BTreeMap::new();
    profiles.insert("default".to_string(), profile.clone());
    profiles.insert(old_client_id.clone(), profile);
    db.apply_application_contract(
        &application.id,
        ApplicationDiscoveryManifest {
            revision: 1,
            version: "v1".to_string(),
            digest: "digest-1".to_string(),
            expires_at: util::now_ts() + 300,
            revoke_removed_clients: true,
            clients: vec![old_client],
            client_protocols: [(old_client_id.clone(), "oidc".to_string())]
                .into_iter()
                .collect(),
            protocols: serde_json::json!({
                "website_url": "https://website.example",
                "oauth2_oidc": {"enabled": true, "client_ids": [old_client_id]}
            }),
            login_adapters: serde_json::json!({
                "enabled": true,
                "allow_signet_password": true,
                "provider_ids": []
            }),
            directory_sync: serde_json::json!({
                "enabled": false,
                "scim_enabled": false,
                "sync_groups": false
            }),
            authorization: serde_json::json!({
                "inherit_enterprise_roles": true,
                "default_role": "member",
                "claims": []
            }),
            authorization_mappings: Default::default(),
            profiles,
            redacted_payload: serde_json::json!({}),
        },
    )
    .await
    .unwrap();
    let old_profile = db
        .find_application_authorization_profile(&application.id, &old_client_id)
        .await
        .unwrap()
        .unwrap();

    let mut default_profiles = BTreeMap::new();
    default_profiles.insert(
        "default".to_string(),
        ApplicationDiscoveryProfile {
            permissions: vec![ApplicationDiscoveryPermission {
                key: "website.read".to_string(),
                label: "Website read".to_string(),
                description: None,
            }],
            roles: vec![ApplicationDiscoveryRole {
                key: "member".to_string(),
                name: "Member".to_string(),
                description: None,
                permissions: vec!["website.read".to_string()],
                is_default: true,
            }],
        },
    );
    db.apply_application_contract(
        &application.id,
        ApplicationDiscoveryManifest {
            revision: 2,
            version: "v2".to_string(),
            digest: "digest-2".to_string(),
            expires_at: util::now_ts() + 300,
            revoke_removed_clients: false,
            clients: Vec::new(),
            client_protocols: BTreeMap::new(),
            protocols: serde_json::json!({
                "website_url": "https://website.example",
                "oauth2_oidc": {"enabled": false, "client_ids": []}
            }),
            login_adapters: serde_json::json!({
                "enabled": true,
                "allow_signet_password": true,
                "provider_ids": []
            }),
            directory_sync: serde_json::json!({
                "enabled": false,
                "scim_enabled": false,
                "sync_groups": false
            }),
            authorization: serde_json::json!({
                "inherit_enterprise_roles": true,
                "default_role": "member",
                "claims": []
            }),
            authorization_mappings: Default::default(),
            profiles: default_profiles,
            redacted_payload: serde_json::json!({}),
        },
    )
    .await
    .unwrap();

    assert!(
        db.find_application_authorization_profile(&application.id, &old_client_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.list_application_profile_roles(&old_profile.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db.list_application_authorization_profiles(&application.id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        db.find_client_by_client_id(&old_client_id)
            .await
            .unwrap()
            .unwrap()
            .is_active,
        1
    );
    assert_eq!(
        db.find_application_for_client(
            &db.find_client_by_client_id(&old_client_id)
                .await
                .unwrap()
                .unwrap()
                .id,
        )
        .await
        .unwrap()
        .unwrap()
        .id,
        application.id
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}
