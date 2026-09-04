use super::*;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_policy_snapshot_reads_profile_bindings_and_groups_together() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("snapshot-org", "Snapshot Org"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "snapshot-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let user = db
        .insert_user(test_user("snapshot-user@example.test", "snapshot-user"))
        .await
        .unwrap();
    db.upsert_organization_member(
        &organization.id,
        &user.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();
    let group = db
        .insert_group(NewGroup {
            name: "Snapshot Group".to_string(),
            description: None,
        })
        .await
        .unwrap();
    db.replace_group_members(&group.id, vec![user.id.clone()])
        .await
        .unwrap();
    let profile = default_authorization_profile(&db, &application.id).await;
    let role = db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: Some("snapshot-profile-role".to_string()),
            profile_id: profile.id.clone(),
            role_key: "snapshot-reader".to_string(),
            name: "Snapshot reader".to_string(),
            description: None,
            permissions: vec!["snapshot.read".to_string()],
            source: "manual".to_string(),
            is_default: false,
            is_active: true,
        })
        .await
        .unwrap();
    replace_test_authorization_bindings(
        &db,
        &application.id,
        &profile.id,
        AuthorizationBindingsUpdate {
            user_id: None,
            group_id: Some(group.id.clone()),
            user_role_ids: Vec::new(),
            user_permission_overrides: Vec::new(),
            group_role_ids: vec![role.id],
            organization_role_bindings: BTreeMap::new(),
        },
    )
    .await;

    let snapshot = db
        .load_application_policy_snapshot(&application.id, &user.id)
        .await
        .unwrap();
    assert!(snapshot.is_authorizable);
    assert_eq!(snapshot.user_id, user.id);
    assert_eq!(snapshot.application.as_ref().unwrap().id, application.id);
    assert_eq!(snapshot.profile.as_ref().unwrap().id, profile.id);
    assert_eq!(
        snapshot
            .groups
            .iter()
            .map(|item| item.name.as_str())
            .collect::<Vec<_>>(),
        ["Snapshot Group"]
    );
    assert_eq!(snapshot.profile_group_assignments.len(), 1);
    assert_eq!(snapshot.profile_roles.len(), 1);
    assert_eq!(snapshot.profile_roles[0].role_key, "snapshot-reader");
    assert_eq!(snapshot.profile_roles[0].permissions, "[\"snapshot.read\"]");

    drop(db);
    let _ = std::fs::remove_file(path);
}
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn audited_application_creation_rolls_back_when_audit_insert_fails() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("audit-rollback", "Audit Rollback"))
        .await
        .unwrap();
    with_conn!(db.clone(), |conn, _kind| {
        sql_query("DROP TABLE audit_events")
            .execute(&mut conn)
            .map(|_| ())
            .map_err(AppError::from)
    })
    .unwrap();

    let result = db
        .insert_application_with_audit(
            test_application(
                &organization.id,
                "audit-rollback-website",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ),
            crate::audit::management_event(
                "actor",
                "application.create",
                "application",
                None,
                serde_json::json!({}),
            ),
        )
        .await;
    assert!(result.is_err());
    assert!(
        db.find_application_by_slug_in_organization(&organization.id, "audit-rollback-website",)
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_creation_with_initial_module_is_atomic() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization(
            "atomic-application",
            "Atomic Application",
        ))
        .await
        .unwrap();

    with_conn!(db.clone(), |conn, _kind| {
        sql_query("DROP TABLE audit_events")
            .execute(&mut conn)
            .map(|_| ())
            .map_err(AppError::from)
    })
    .unwrap();

    let result = db
        .insert_application_with_module_with_audit(
            test_application(
                &organization.id,
                "atomic-application-website",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ),
            "protocols",
            r#"{"website_url":"https://atomic.example"}"#,
            false,
            crate::audit::management_event(
                "actor",
                "application.create",
                "application",
                None,
                serde_json::json!({}),
            ),
        )
        .await;
    assert!(result.is_err());
    assert!(
            db.find_application_by_slug_in_organization(
                &organization.id,
                "atomic-application-website",
            )
            .await
            .unwrap()
            .is_none()
        );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn legacy_application_authorization_migrates_into_one_profile_idempotently() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("legacy-auth-org", "Legacy Auth Org"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "legacy-auth-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let user = db
        .insert_user(test_user(
            "legacy-auth-user@example.com",
            "legacy-auth-user",
        ))
        .await
        .unwrap();
    db.upsert_organization_member(
        &organization.id,
        &user.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();
    let group = db
        .insert_group(NewGroup {
            name: "Legacy Auth Group".to_string(),
            description: None,
        })
        .await
        .unwrap();
    db.replace_group_members(&group.id, vec![user.id.clone()])
        .await
        .unwrap();

    let profile = db
        .find_application_authorization_profile(&application.id, "default")
        .await
        .unwrap()
        .unwrap();
    let existing_role = db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: Some("existing-profile-role".to_string()),
            profile_id: profile.id.clone(),
            role_key: "legacy".to_string(),
            name: "Existing legacy role".to_string(),
            description: None,
            permissions: vec!["existing.permission".to_string()],
            source: "manual".to_string(),
            is_default: false,
            is_active: true,
        })
        .await
        .unwrap();
    let other_role = db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: Some("other-profile-role".to_string()),
            profile_id: profile.id.clone(),
            role_key: "other".to_string(),
            name: "Other role".to_string(),
            description: None,
            permissions: Vec::new(),
            source: "manual".to_string(),
            is_default: true,
            is_active: true,
        })
        .await
        .unwrap();
    db.upsert_application_module(
        &application.id,
        "authorization",
        &serde_json::json!({
            "default_role": "legacy",
            "custom_roles": [{
                "name": "config-extra",
                "permissions": ["config.read"]
            }],
            "group_mappings": [{
                "group": group.name,
                "role": "config-extra"
            }],
            "organization_role_mappings": {
                "admin": "config-extra"
            }
        })
        .to_string(),
        true,
    )
    .await
    .unwrap();

    let application_id = application.id.clone();
    let user_id = user.id.clone();
    let group_id = group.id.clone();
    with_conn!(db.clone(), |conn, _kind| {
            sql_query(
                "INSERT INTO application_roles (id, application_id, name, description, permissions, is_default, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind::<Text, _>("legacy-role")
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>("legacy")
            .bind::<Nullable<Text>, _>(None::<String>)
            .bind::<Text, _>(r#"["legacy.read"]"#)
            .bind::<Integer, _>(1)
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(1_i64)
            .bind::<BigInt, _>(1_i64)
            .execute(&mut conn)
            .map_err(AppError::from)?;
            sql_query(
                "INSERT INTO application_user_roles (application_id, user_id, application_role_id, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>(&user_id)
            .bind::<Text, _>("legacy-role")
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(1_i64)
            .bind::<BigInt, _>(1_i64)
            .execute(&mut conn)
            .map_err(AppError::from)?;
            sql_query(
                "INSERT INTO application_group_roles (application_id, group_id, application_role_id, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>(&group_id)
            .bind::<Text, _>("legacy-role")
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(1_i64)
            .bind::<BigInt, _>(1_i64)
            .execute(&mut conn)
            .map_err(AppError::from)?;
            sql_query(
                "INSERT INTO application_organization_role_mappings (application_id, organization_role, application_role_id, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>("member")
            .bind::<Text, _>("legacy-role")
            .bind::<Integer, _>(1)
            .bind::<BigInt, _>(1_i64)
            .bind::<BigInt, _>(1_i64)
            .execute(&mut conn)
            .map_err(AppError::from)?;
            sql_query(
                "INSERT INTO application_user_permission_overrides (application_id, user_id, permission, effect, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind::<Text, _>(&application_id)
            .bind::<Text, _>(&user_id)
            .bind::<Text, _>("legacy.override")
            .bind::<Text, _>("allow")
            .bind::<BigInt, _>(1_i64)
            .bind::<BigInt, _>(1_i64)
            .execute(&mut conn)
            .map_err(AppError::from)?;
            Ok::<(), AppError>(())
        })
        .unwrap();

    db.migrate_legacy_application_authorization().await.unwrap();
    let first_snapshot = db
        .read_application_authorization_bindings(&application.id, &profile.id)
        .await
        .unwrap();
    let first_roles = db
        .list_application_profile_roles(&profile.id)
        .await
        .unwrap();
    assert_eq!(
        first_roles
            .iter()
            .filter(|role| role.is_default == 1)
            .map(|role| role.id.as_str())
            .collect::<Vec<_>>(),
        vec![existing_role.id.as_str()]
    );
    assert!(
        first_roles
            .iter()
            .any(|role| role.role_key == "config-extra")
    );
    assert!(
        !first_roles
            .iter()
            .any(|role| role.id == other_role.id && role.is_default == 1)
    );
    assert_eq!(
        first_snapshot.user_bindings[&user.id].user_role_ids,
        vec![existing_role.id.clone()]
    );
    let mut expected_group_role_ids = vec![
        existing_role.id.clone(),
        first_roles
            .iter()
            .find(|role| role.role_key == "config-extra")
            .unwrap()
            .id
            .clone(),
    ];
    expected_group_role_ids.sort();
    assert_eq!(
        first_snapshot.group_bindings[&group.id],
        expected_group_role_ids
    );
    assert_eq!(
        first_snapshot.organization_role_bindings["member"],
        vec![existing_role.id.clone()]
    );
    assert_eq!(
        first_snapshot.organization_role_bindings["admin"],
        vec![
            first_roles
                .iter()
                .find(|role| role.role_key == "config-extra")
                .unwrap()
                .id
                .clone()
        ]
    );
    assert_eq!(
        first_snapshot.user_bindings[&user.id].user_permission_overrides[0].permission,
        "legacy.override"
    );

    db.migrate_legacy_application_authorization().await.unwrap();
    let second_snapshot = db
        .read_application_authorization_bindings(&application.id, &profile.id)
        .await
        .unwrap();
    let second_roles = db
        .list_application_profile_roles(&profile.id)
        .await
        .unwrap();
    assert_eq!(first_snapshot, second_snapshot);
    assert_eq!(first_roles.len(), second_roles.len());

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_authorization_profile_counts_group_active_rows() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization(
            "profile-counts-org",
            "Profile Counts Org",
        ))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "profile-counts-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let default_profile = default_authorization_profile(&db, &application.id).await;
    let custom_profile = db
        .upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
            id: "profile-counts-custom".to_string(),
            application_id: application.id.clone(),
            profile_key: "custom".to_string(),
            connection_kind: "oidc".to_string(),
            connection_id: None,
            source_mode: "manual".to_string(),
            remote_version: None,
            remote_digest: None,
            sync_status: "manual".to_string(),
            last_synced_at: None,
            last_error: None,
        })
        .await
        .unwrap();
    db.replace_application_permission_definitions(
        &custom_profile.id,
        vec![
            NewApplicationPermissionDefinition {
                profile_id: custom_profile.id.clone(),
                permission_key: "profile.read".to_string(),
                label: "Profile read".to_string(),
                description: None,
                source: "manual".to_string(),
                is_active: true,
            },
            NewApplicationPermissionDefinition {
                profile_id: custom_profile.id.clone(),
                permission_key: "profile.write".to_string(),
                label: "Profile write".to_string(),
                description: None,
                source: "manual".to_string(),
                is_active: true,
            },
            NewApplicationPermissionDefinition {
                profile_id: custom_profile.id.clone(),
                permission_key: "profile.retired".to_string(),
                label: "Profile retired".to_string(),
                description: None,
                source: "manual".to_string(),
                is_active: false,
            },
        ],
    )
    .await
    .unwrap();
    for (id, role_key, is_active) in [
        ("profile-counts-role-reader", "reader", true),
        ("profile-counts-role-writer", "writer", true),
        ("profile-counts-role-retired", "retired", false),
    ] {
        db.upsert_application_profile_role(NewApplicationProfileRole {
            id: Some(id.to_string()),
            profile_id: custom_profile.id.clone(),
            role_key: role_key.to_string(),
            name: role_key.to_string(),
            description: None,
            permissions: Vec::new(),
            source: "manual".to_string(),
            is_default: false,
            is_active,
        })
        .await
        .unwrap();
    }

    let counts = db
        .list_application_authorization_profile_counts(&[
            custom_profile.id.clone(),
            default_profile.id.clone(),
            "missing-profile".to_string(),
        ])
        .await
        .unwrap();
    assert_eq!(counts.get(&custom_profile.id), Some(&(2, 2)));
    assert_eq!(counts.get(&default_profile.id), Some(&(0, 0)));
    assert!(!counts.contains_key("missing-profile"));

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn updating_application_role_preserves_id_bindings_and_default_invariant() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("role-org", "Role Org"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "role-website",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let user = db
        .insert_user(test_user("role-user@example.com", "role-user"))
        .await
        .unwrap();
    db.upsert_organization_member(
        &organization.id,
        &user.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();
    let profile = default_authorization_profile(&db, &application.id).await;
    let original = db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: None,
            profile_id: profile.id.clone(),
            role_key: "reader".to_string(),
            name: "reader".to_string(),
            source: "manual".to_string(),
            description: Some("Read access".to_string()),
            permissions: vec!["users.read".to_string()],
            is_default: true,
            is_active: true,
        })
        .await
        .unwrap();
    let other = db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: None,
            profile_id: profile.id.clone(),
            role_key: "operator".to_string(),
            name: "operator".to_string(),
            source: "manual".to_string(),
            description: None,
            permissions: vec!["users.manage".to_string()],
            is_default: false,
            is_active: true,
        })
        .await
        .unwrap();
    replace_test_authorization_bindings(
        &db,
        &application.id,
        &profile.id,
        AuthorizationBindingsUpdate {
            user_id: Some(user.id.clone()),
            group_id: None,
            user_role_ids: vec![original.id.clone()],
            user_permission_overrides: Vec::new(),
            group_role_ids: Vec::new(),
            organization_role_bindings: BTreeMap::new(),
        },
    )
    .await;

    let updated = db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: Some(original.id.clone()),
            profile_id: profile.id.clone(),
            role_key: "editor".to_string(),
            name: "editor".to_string(),
            source: "manual".to_string(),
            description: Some("Updated access".to_string()),
            permissions: vec!["users.manage".to_string()],
            is_default: true,
            is_active: true,
        })
        .await
        .unwrap();
    assert_eq!(updated.id, original.id);
    assert_eq!(updated.name, "editor");
    assert_eq!(
        db.read_application_authorization_bindings(&application.id, &profile.id)
            .await
            .unwrap()
            .user_bindings[&user.id]
            .user_role_ids,
        vec![original.id.clone()]
    );
    assert_eq!(
        db.list_application_profile_roles(&profile.id)
            .await
            .unwrap()
            .into_iter()
            .filter(|role| role.is_default == 1)
            .map(|role| role.id)
            .collect::<Vec<_>>(),
        vec![original.id.clone()]
    );
    assert!(
        db.upsert_application_profile_role(NewApplicationProfileRole {
            id: Some(other.id.clone()),
            profile_id: profile.id,
            role_key: "editor".to_string(),
            name: "editor".to_string(),
            source: "manual".to_string(),
            description: None,
            permissions: Vec::new(),
            is_default: false,
            is_active: true,
        })
        .await
        .is_err()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_role_lifecycle_cleans_mappings_and_rechecks_entitlements() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization(
            "role-lifecycle-org",
            "Role Lifecycle Org",
        ))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "role-lifecycle-website",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let user = db
        .insert_user(test_user("role-lifecycle@example.com", "role-lifecycle"))
        .await
        .unwrap();
    db.upsert_organization_member(&organization.id, &user.id, crate::organizations::ROLE_ADMIN)
        .await
        .unwrap();
    let group = db
        .insert_group(NewGroup {
            name: "Role lifecycle group".to_string(),
            description: None,
        })
        .await
        .unwrap();
    db.replace_group_members(&group.id, vec![user.id.clone()])
        .await
        .unwrap();

    let profile = default_authorization_profile(&db, &application.id).await;
    let default_role = db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: None,
            profile_id: profile.id.clone(),
            role_key: "base".to_string(),
            name: "base".to_string(),
            source: "manual".to_string(),
            description: None,
            permissions: vec!["app.read".to_string()],
            is_default: true,
            is_active: true,
        })
        .await
        .unwrap();
    let mapped_role = db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: None,
            profile_id: profile.id.clone(),
            role_key: "operator".to_string(),
            name: "operator".to_string(),
            source: "manual".to_string(),
            description: None,
            permissions: vec!["app.read".to_string(), "app.write".to_string()],
            is_default: false,
            is_active: true,
        })
        .await
        .unwrap();

    assert!(
        db.upsert_application_profile_role(NewApplicationProfileRole {
            id: None,
            profile_id: profile.id.clone(),
            role_key: "invalid-default".to_string(),
            name: "invalid-default".to_string(),
            source: "manual".to_string(),
            description: None,
            permissions: Vec::new(),
            is_default: true,
            is_active: false,
        })
        .await
        .is_err()
    );
    assert!(
        db.upsert_application_profile_role(NewApplicationProfileRole {
            id: Some(default_role.id.clone()),
            profile_id: profile.id.clone(),
            role_key: "base".to_string(),
            name: "base".to_string(),
            source: "manual".to_string(),
            description: None,
            permissions: vec!["app.read".to_string()],
            is_default: true,
            is_active: false,
        })
        .await
        .is_err()
    );
    assert!(
        db.delete_application_profile_role(&profile.id, &default_role.id)
            .await
            .is_err()
    );

    replace_test_authorization_bindings(
        &db,
        &application.id,
        &profile.id,
        AuthorizationBindingsUpdate {
            user_id: Some(user.id.clone()),
            group_id: Some(group.id.clone()),
            user_role_ids: vec![mapped_role.id.clone()],
            user_permission_overrides: vec![
                AuthorizationBindingPermissionOverride {
                    permission: "app.read".to_string(),
                    effect: "allow".to_string(),
                },
                AuthorizationBindingPermissionOverride {
                    permission: "app.write".to_string(),
                    effect: "deny".to_string(),
                },
            ],
            group_role_ids: vec![mapped_role.id.clone()],
            organization_role_bindings: BTreeMap::from([(
                crate::organizations::ROLE_ADMIN.to_string(),
                vec![mapped_role.id.clone()],
            )]),
        },
    )
    .await;

    let settings: crate::Settings =
        toml::from_str(include_str!("../../../../config/default.toml")).unwrap();
    let state = crate::AppState {
        jwt: crate::jwt::JwtManager::new(&settings).unwrap(),
        settings,
        db: db.clone(),
    };
    let entitlements = crate::authorization::resolve_entitlements(
        &state,
        &application,
        &db.find_user_by_id(&user.id).await.unwrap().unwrap(),
    )
    .await
    .unwrap();
    assert!(entitlements.roles.iter().any(|role| role == "base"));
    assert!(entitlements.roles.iter().any(|role| role == "operator"));
    assert!(
        entitlements
            .permissions
            .iter()
            .any(|permission| permission == "app.read")
    );
    assert!(
        !entitlements
            .permissions
            .iter()
            .any(|permission| permission == "app.write")
    );

    // The resolver reads active role rows on every call. Changing or
    // disabling a role therefore revokes its website entitlement without
    // waiting for a previously issued token to expire.
    db.upsert_application_profile_role(NewApplicationProfileRole {
        id: Some(mapped_role.id.clone()),
        profile_id: profile.id.clone(),
        role_key: "operator".to_string(),
        name: "operator".to_string(),
        source: "manual".to_string(),
        description: None,
        permissions: vec!["app.read".to_string()],
        is_default: false,
        is_active: false,
    })
    .await
    .unwrap();
    let entitlements = crate::authorization::resolve_entitlements(
        &state,
        &application,
        &db.find_user_by_id(&user.id).await.unwrap().unwrap(),
    )
    .await
    .unwrap();
    assert!(!entitlements.roles.iter().any(|role| role == "operator"));
    assert!(entitlements.roles.iter().any(|role| role == "base"));
    let inactive_binding_result = db
        .replace_application_authorization_bindings_with_audit(
            &application.id,
            &profile.id,
            AuthorizationBindingsUpdate {
                user_id: Some(user.id.clone()),
                group_id: None,
                user_role_ids: vec![mapped_role.id.clone()],
                user_permission_overrides: Vec::new(),
                group_role_ids: Vec::new(),
                organization_role_bindings: BTreeMap::new(),
            },
            audit::management_event(
                "authorization-profile-test",
                "application.authorization_profile.bindings.test",
                "application_authorization_profile",
                Some(profile.id.clone()),
                serde_json::json!({}),
            ),
        )
        .await;
    assert!(inactive_binding_result.is_err());

    // Deleting a non-default role removes all three kinds of binding in
    // the same transaction, leaving no dangling authorization edge.
    db.upsert_application_profile_role(NewApplicationProfileRole {
        id: Some(mapped_role.id.clone()),
        profile_id: profile.id.clone(),
        role_key: "operator".to_string(),
        name: "operator".to_string(),
        source: "manual".to_string(),
        description: None,
        permissions: vec!["app.read".to_string(), "app.write".to_string()],
        is_default: false,
        is_active: true,
    })
    .await
    .unwrap();
    db.delete_application_profile_role(&profile.id, &mapped_role.id)
        .await
        .unwrap();
    assert!(
        db.read_application_authorization_bindings(&application.id, &profile.id)
            .await
            .unwrap()
            .user_bindings
            .get(&user.id)
            .is_none_or(|binding| binding.user_role_ids.is_empty())
    );
    assert!(
        db.read_application_authorization_bindings(&application.id, &profile.id)
            .await
            .unwrap()
            .group_bindings
            .get(&group.id)
            .is_none_or(Vec::is_empty)
    );
    assert!(
        db.read_application_authorization_bindings(&application.id, &profile.id)
            .await
            .unwrap()
            .organization_role_bindings
            .get(crate::organizations::ROLE_ADMIN)
            .is_none_or(Vec::is_empty)
    );

    drop(state);
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_entitlements_keep_login_open_but_scope_policy_to_tenant_members() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("entitlement-scope", "Entitlement Scope"))
        .await
        .unwrap();
    let other_organization = db
        .insert_organization(test_organization("entitlement-other", "Entitlement Other"))
        .await
        .unwrap();
    let member = db
        .insert_user(test_user(
            "entitlement-member@example.com",
            "entitlement-member",
        ))
        .await
        .unwrap();
    let outsider = db
        .insert_user(test_user(
            "entitlement-outsider@example.com",
            "entitlement-outsider",
        ))
        .await
        .unwrap();
    db.upsert_organization_member(
        &organization.id,
        &member.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();
    db.upsert_organization_member(
        &other_organization.id,
        &outsider.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();

    let group = db
        .insert_group(NewGroup {
            name: "Mixed entitlement group".to_string(),
            description: None,
        })
        .await
        .unwrap();
    db.replace_group_members(&group.id, vec![member.id.clone(), outsider.id.clone()])
        .await
        .unwrap();
    let outsider_only_group = db
        .insert_group(NewGroup {
            name: "Outsider-only entitlement group".to_string(),
            description: None,
        })
        .await
        .unwrap();
    db.replace_group_members(&outsider_only_group.id, vec![outsider.id.clone()])
        .await
        .unwrap();
    let scoped_groups = db
        .list_application_authorization_groups(&organization.id)
        .await
        .unwrap();
    assert!(scoped_groups.iter().any(|value| value.id == group.id));
    assert!(
        !scoped_groups
            .iter()
            .any(|value| value.id == outsider_only_group.id)
    );
    let enterprise_role = db
        .insert_role(NewRole {
            name: "mixed-enterprise-role".to_string(),
            description: None,
            is_system: false,
            permissions: vec!["enterprise.mixed".to_string()],
        })
        .await
        .unwrap();
    db.replace_group_roles(&group.id, vec![enterprise_role.id])
        .await
        .unwrap();

    let normalized_application = db
        .insert_application(test_application(
            &organization.id,
            "scoped-application",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let profile = default_authorization_profile(&db, &normalized_application.id).await;
    let application_role = db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: None,
            profile_id: profile.id.clone(),
            role_key: "mixed-application-role".to_string(),
            name: "mixed-application-role".to_string(),
            source: "manual".to_string(),
            description: None,
            permissions: vec!["application.mixed".to_string()],
            is_default: false,
            is_active: true,
        })
        .await
        .unwrap();
    replace_test_authorization_bindings(
        &db,
        &normalized_application.id,
        &profile.id,
        AuthorizationBindingsUpdate {
            user_id: None,
            group_id: Some(group.id.clone()),
            user_role_ids: Vec::new(),
            user_permission_overrides: Vec::new(),
            group_role_ids: vec![application_role.id],
            organization_role_bindings: BTreeMap::new(),
        },
    )
    .await;

    let settings: crate::Settings =
        toml::from_str(include_str!("../../../../config/default.toml")).unwrap();
    let state = crate::AppState {
        jwt: crate::jwt::JwtManager::new(&settings).unwrap(),
        settings,
        db: db.clone(),
    };
    let member_record = db.find_user_by_id(&member.id).await.unwrap().unwrap();
    let outsider_record = db.find_user_by_id(&outsider.id).await.unwrap().unwrap();

    assert!(
        crate::authorization::check_login_access(&state, &normalized_application, &outsider.id,)
            .await
            .unwrap()
            .allowed
    );
    let member_entitlements =
        crate::authorization::resolve_entitlements(&state, &normalized_application, &member_record)
            .await
            .unwrap();
    assert!(
        member_entitlements
            .roles
            .iter()
            .any(|role| role == "mixed-application-role")
    );
    assert!(
        member_entitlements
            .roles
            .iter()
            .any(|role| role == "mixed-enterprise-role")
    );
    assert!(
        member_entitlements
            .permissions
            .iter()
            .any(|permission| permission == "application.mixed")
    );
    assert!(
        member_entitlements
            .groups
            .iter()
            .any(|name| name == "Mixed entitlement group")
    );

    let outsider_entitlements = crate::authorization::resolve_entitlements(
        &state,
        &normalized_application,
        &outsider_record,
    )
    .await
    .unwrap();
    assert!(
        !outsider_entitlements
            .roles
            .iter()
            .any(|role| role == "mixed-application-role")
    );
    assert!(
        !outsider_entitlements
            .roles
            .iter()
            .any(|role| role == "mixed-enterprise-role")
    );
    assert!(
        !outsider_entitlements
            .permissions
            .iter()
            .any(|permission| permission == "application.mixed")
    );
    assert!(outsider_entitlements.groups.is_empty());
    assert!(outsider_entitlements.organization_role.is_none());

    let legacy_application = db
        .insert_application(test_application(
            &organization.id,
            "legacy-scoped-application",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let legacy_profile = db
        .find_application_authorization_profile(&legacy_application.id, "default")
        .await
        .unwrap()
        .unwrap();
    db.upsert_application_profile_role(NewApplicationProfileRole {
        id: Some("legacy-member-role".to_string()),
        profile_id: legacy_profile.id.clone(),
        role_key: "legacy-member".to_string(),
        name: "Legacy member".to_string(),
        description: None,
        permissions: vec!["legacy.default".to_string()],
        source: "manual".to_string(),
        is_default: true,
        is_active: true,
    })
    .await
    .unwrap();
    let legacy_operator = db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: Some("legacy-operator-role".to_string()),
            profile_id: legacy_profile.id.clone(),
            role_key: "legacy-operator".to_string(),
            name: "Legacy operator".to_string(),
            description: None,
            permissions: vec!["legacy.mixed".to_string()],
            source: "manual".to_string(),
            is_default: false,
            is_active: true,
        })
        .await
        .unwrap();
    db.replace_application_authorization_bindings_with_audit(
        &legacy_application.id,
        &legacy_profile.id,
        AuthorizationBindingsUpdate {
            user_id: None,
            group_id: Some(group.id.clone()),
            user_role_ids: Vec::new(),
            user_permission_overrides: Vec::new(),
            group_role_ids: vec![legacy_operator.id],
            organization_role_bindings: BTreeMap::new(),
        },
        audit::management_event(
            "authorization-profile-test",
            "application.authorization_profile.bindings.update",
            "application_authorization_profile",
            Some(legacy_profile.id.clone()),
            serde_json::json!({}),
        ),
    )
    .await
    .unwrap();
    let member_legacy =
        crate::authorization::resolve_entitlements(&state, &legacy_application, &member_record)
            .await
            .unwrap();
    let outsider_legacy =
        crate::authorization::resolve_entitlements(&state, &legacy_application, &outsider_record)
            .await
            .unwrap();
    assert!(
        member_legacy
            .roles
            .iter()
            .any(|role| role == "legacy-operator")
    );
    assert!(
        member_legacy
            .permissions
            .iter()
            .any(|permission| permission == "legacy.mixed")
    );
    assert!(
        !outsider_legacy
            .roles
            .iter()
            .any(|role| role == "legacy-operator")
    );
    assert!(
        !outsider_legacy
            .permissions
            .iter()
            .any(|permission| permission == "legacy.mixed")
    );
    assert!(
        outsider_legacy
            .roles
            .iter()
            .any(|role| role == "legacy-member")
    );

    let profile_application = db
        .insert_application(test_application(
            &organization.id,
            "profile-scoped-application",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let profile = db
        .find_application_authorization_profile(&profile_application.id, "default")
        .await
        .unwrap()
        .unwrap();
    let profile_role = db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: None,
            profile_id: profile.id.clone(),
            role_key: "profile-operator".to_string(),
            name: "Profile operator".to_string(),
            description: None,
            permissions: vec!["profile.mixed".to_string()],
            source: "manual".to_string(),
            is_default: false,
            is_active: true,
        })
        .await
        .unwrap();
    db.replace_application_authorization_bindings_with_audit(
        &profile_application.id,
        &profile.id,
        AuthorizationBindingsUpdate {
            user_id: None,
            group_id: Some(group.id.clone()),
            user_role_ids: Vec::new(),
            user_permission_overrides: Vec::new(),
            group_role_ids: vec![profile_role.id],
            organization_role_bindings: BTreeMap::new(),
        },
        crate::audit::management_event(
            "authorization-profile-test",
            "application.authorization_profile.bindings.update",
            "application_authorization_profile",
            Some(profile.id.clone()),
            serde_json::json!({}),
        ),
    )
    .await
    .unwrap();
    let member_profile = crate::authorization::resolve_entitlements_for_profile(
        &state,
        &profile_application,
        &profile,
        &member_record,
    )
    .await
    .unwrap();
    let outsider_profile = crate::authorization::resolve_entitlements_for_profile(
        &state,
        &profile_application,
        &profile,
        &outsider_record,
    )
    .await
    .unwrap();
    assert!(
        member_profile
            .permissions
            .iter()
            .any(|permission| permission == "profile.mixed")
    );
    assert!(
        !outsider_profile
            .permissions
            .iter()
            .any(|permission| permission == "profile.mixed")
    );

    drop(state);
    drop(db);
    let _ = std::fs::remove_file(path);
}
