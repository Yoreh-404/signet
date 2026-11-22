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

fn single_client_website_manifest(
    client: NewClient,
    revision: i64,
) -> ApplicationDiscoveryManifest {
    let client_id = client.client_id.clone();
    let mut profiles = BTreeMap::new();
    profiles.insert(
        "default".to_string(),
        ApplicationDiscoveryProfile {
            permissions: Vec::new(),
            roles: Vec::new(),
        },
    );
    ApplicationDiscoveryManifest {
        revision,
        version: format!("v{revision}"),
        digest: format!("digest-{revision}"),
        expires_at: util::now_ts() + 300,
        revoke_removed_clients: true,
        clients: vec![client],
        client_protocols: [(client_id.clone(), "oidc".to_string())]
            .into_iter()
            .collect(),
        protocols: serde_json::json!({
            "website_url": "https://website.example",
            "oauth2_oidc": {"enabled": true, "client_ids": [client_id]}
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
            "claims": []
        }),
        authorization_mappings: Default::default(),
        profiles,
        redacted_payload: serde_json::json!({}),
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_discovery_metadata_cannot_restore_removed_axon_mapping() {
    use crate::application_discovery_contract::{MANAGEMENT_MODE_WEBSITE, SYNC_PENDING, SYNC_SYNCED};
    let (db, path) = sqlite_test_db().await;
    let org = db.insert_organization(test_organization("discovery-race", "Discovery Race")).await.unwrap();
    let app = db.insert_application(test_application(&org.id, "race-app", crate::applications::ACCESS_ALL_SIGNET_USERS)).await.unwrap();
    let input = |revision, has_mapping, signer: &str, disabled| NewApplicationDiscovery {
        application_id: app.id.clone(), management_mode: MANAGEMENT_MODE_WEBSITE.into(),
        website_url: "https://website.example".into(), fetch_secret_ciphertext: String::new(),
        signing_public_jwks: signer.into(), last_verified_revision: Some(revision),
        last_verified_version: Some(format!("v{revision}")), last_verified_digest: Some(format!("digest-{revision}")),
        last_verified_expires_at: Some(1000 + revision), sync_status: SYNC_SYNCED.into(),
        last_fetched_at: Some(revision), last_success_at: Some(revision), last_error: None,
        snapshot_json: Some(serde_json::json!({"has_mapping":has_mapping}).to_string()),
        operator_disabled: disabled,
    };
    let original = db.upsert_application_discovery(input(1, true, "key-a", false)).await.unwrap();
    let stale = input(1, true, "key-a", false);
    let fresh = db.upsert_application_discovery(input(2, false, "key-a", true)).await.unwrap();
    let preserved = db.update_application_discovery_metadata(stale, None, Some(&original)).await.unwrap();
    assert_eq!(preserved.last_verified_revision, Some(2));
    assert_eq!(preserved.last_verified_digest, fresh.last_verified_digest);
    assert_eq!(preserved.last_verified_expires_at, fresh.last_verified_expires_at);
    assert_eq!(preserved.snapshot_json, fresh.snapshot_json);
    assert_eq!(preserved.sync_status, SYNC_SYNCED);
    assert_eq!(preserved.operator_disabled, 1);
    let mut new_trust = input(1, true, "key-b", false);
    new_trust.sync_status = SYNC_PENDING.into();
    let reset = db.update_application_discovery_metadata(new_trust, Some(false), Some(&preserved)).await.unwrap();
    assert_eq!(reset.last_verified_revision, None);
    assert_eq!(reset.snapshot_json, None);
    assert_eq!(reset.sync_status, SYNC_PENDING);
    assert!(reset.lease_generation > preserved.lease_generation);
    assert_eq!(reset.operator_disabled, 0);
    assert!(db.update_application_discovery_metadata(input(1, true, "key-a", false), None, Some(&original)).await.is_err());
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn website_manifest_adopts_generated_compatibility_owner_but_not_real_application() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("website-adopt", "Website Adopt"))
        .await
        .unwrap();
    let website = db
        .insert_application(test_application(
            &organization.id,
            "website-adopt",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    db.upsert_application_discovery(NewApplicationDiscovery {
        application_id: website.id.clone(),
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

    let generated_input = test_client("website-adopt-client", &organization.id);
    let generated = db.insert_client(generated_input.clone()).await.unwrap();
    let generated_owner = db
        .find_application_for_client(&generated.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        generated_owner.registration_mode,
        crate::applications::REGISTRATION_DISABLED
    );

    // An active compatibility owner is not a free-standing registration
    // capability. Retire it explicitly before the signed website takes over.
    db.update_application(
        &generated_owner.id,
        NewApplication {
            organization_id: generated_owner.organization_id.clone(),
            slug: generated_owner.slug.clone(),
            name: generated_owner.name.clone(),
            description: generated_owner.description.clone(),
            access_mode: generated_owner.access_mode.clone(),
            registration_mode: generated_owner.registration_mode.clone(),
            account_selection_mode: generated_owner.account_selection_mode.clone(),
            unique_identity_factors: Vec::new(),
            is_active: false,
        },
    )
    .await
    .unwrap();

    db.apply_application_contract(
        &website.id,
        single_client_website_manifest(generated_input, 1),
    )
    .await
    .unwrap();
    assert_eq!(
        db.find_application_for_client(&generated.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        website.id
    );
    assert_eq!(
        db.list_applications(Some(&organization.id))
            .await
            .unwrap()
            .into_iter()
            .find(|application| application.id == generated_owner.id)
            .unwrap()
            .is_active,
        0
    );

    let real_owner = db
        .insert_application(test_application(
            &organization.id,
            "real-owner",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let protected_input = test_client("website-protected-client", &organization.id);
    let protected = db
        .insert_client_for_application(&real_owner.id, protected_input.clone())
        .await
        .unwrap();
    let error = db
        .apply_application_contract(
            &website.id,
            single_client_website_manifest(protected_input.clone(), 2),
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("website-managed client belongs to another application")
    );
    assert_eq!(
        db.find_application_for_client(&protected.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        real_owner.id
    );

    db.update_application(
        &real_owner.id,
        NewApplication {
            organization_id: real_owner.organization_id.clone(),
            slug: real_owner.slug.clone(),
            name: real_owner.name.clone(),
            description: real_owner.description.clone(),
            access_mode: real_owner.access_mode.clone(),
            registration_mode: real_owner.registration_mode.clone(),
            account_selection_mode: real_owner.account_selection_mode.clone(),
            unique_identity_factors: Vec::new(),
            is_active: false,
        },
    )
    .await
    .unwrap();

    let error = db
        .apply_application_contract(
            &website.id,
            single_client_website_manifest(protected_input, 3),
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("website-managed client belongs to another application")
    );
    assert_eq!(
        db.find_application_for_client(&protected.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        real_owner.id
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn website_manifest_can_rebind_client_from_inactive_same_org_compatibility_application() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("website-rebind", "Website Rebind"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "website-rebind-target",
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

    let client_id = "website-rebind-client";
    let client = db
        .insert_client(test_client(client_id, &organization.id))
        .await
        .unwrap();
    let compatibility = db
        .find_application_for_client(&client.id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(compatibility.id, application.id);
    assert_eq!(compatibility.is_active, 1);

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
    let manifest = ApplicationDiscoveryManifest {
        revision: 1,
        version: "v1".to_string(),
        digest: "digest-rebind".to_string(),
        expires_at: util::now_ts() + 300,
        revoke_removed_clients: true,
        clients: vec![test_client(client_id, &organization.id)],
        client_protocols: [(client_id.to_string(), "oidc".to_string())]
            .into_iter()
            .collect(),
        protocols: serde_json::json!({
            "website_url": "https://website.example",
            "oauth2_oidc": {"enabled": true, "client_ids": [client_id]}
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
        profiles: [("default".to_string(), profile)].into_iter().collect(),
        redacted_payload: serde_json::json!({}),
    };

    let first_attempt = db.apply_application_contract(&application.id, manifest.clone()).await;
    assert!(matches!(
        first_attempt,
        Err(AppError::BadRequest(ref message))
            if message == "website-managed client belongs to another application"
    ), "first attempt expected locked-ownership error, got {first_attempt:?}");

    db.update_application(
        &compatibility.id,
        NewApplication {
            organization_id: compatibility.organization_id.clone(),
            slug: compatibility.slug.clone(),
            name: compatibility.name.clone(),
            description: compatibility.description.clone(),
            access_mode: compatibility.access_mode.clone(),
            registration_mode: compatibility.registration_mode.clone(),
            account_selection_mode: compatibility.account_selection_mode.clone(),
            unique_identity_factors: Vec::new(),
            is_active: false,
        },
    )
    .await
    .unwrap();

    db.apply_application_contract(&application.id, manifest)
        .await
        .unwrap();
    assert_eq!(
        db.find_application_for_client(&client.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        application.id
    );
    assert!(
        db.list_application_client_bindings(&compatibility.id)
            .await
            .unwrap()
            .is_empty()
    );

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
