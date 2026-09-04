use super::*;
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn detached_or_deleted_application_clients_receive_a_locked_fallback() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("fallback-client", "Fallback Client"))
        .await
        .unwrap();

    let detached_client = db
        .insert_client(test_client("detach-client", &organization.id))
        .await
        .unwrap();
    let original = db
        .harden_new_client_application(&detached_client.id)
        .await
        .unwrap();
    db.unlink_client_from_application(&detached_client.id)
        .await
        .unwrap();
    let detached_fallback = db
        .find_application_for_client(&detached_client.id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(detached_fallback.id, original.id);
    assert_eq!(
        detached_fallback.access_mode,
        crate::applications::ACCESS_ALL_SIGNET_USERS
    );
    assert_eq!(
        detached_fallback.registration_mode,
        crate::applications::REGISTRATION_DISABLED
    );

    let deleted_client = db
        .insert_client(test_client("delete-client", &organization.id))
        .await
        .unwrap();
    let deleted_application = db
        .harden_new_client_application(&deleted_client.id)
        .await
        .unwrap();
    let deleted_jwt_client = db
        .upsert_application_jwt_client(
            &deleted_application.id,
            NewApplicationJwtClient {
                client_id: "delete-jwt-client".to_string(),
                client_type: "confidential".to_string(),
                is_active: true,
            },
        )
        .await
        .unwrap();
    db.rotate_application_jwt_secret(
        &deleted_application.id,
        &deleted_jwt_client.client_id,
        &util::hash_password("delete-secret").unwrap(),
        300,
    )
    .await
    .unwrap();
    db.delete_application(&deleted_application.id)
        .await
        .unwrap();
    let deleted_fallback = db
        .find_application_for_client(&deleted_client.id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(deleted_fallback.id, deleted_application.id);
    assert_eq!(
        deleted_fallback.access_mode,
        crate::applications::ACCESS_ALL_SIGNET_USERS
    );
    assert_eq!(
        deleted_fallback.registration_mode,
        crate::applications::REGISTRATION_DISABLED
    );
    assert_eq!(deleted_fallback.is_active, 1);

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn oidc_client_binding_is_exclusive_and_detach_delete_are_safe() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("binding-moves", "Binding Moves"))
        .await
        .unwrap();
    let first = db
        .insert_application(test_application(
            &organization.id,
            "binding-first",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let second = db
        .insert_application(test_application(
            &organization.id,
            "binding-second",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    db.upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
        id: "binding-second-profile".to_string(),
        application_id: second.id.clone(),
        profile_key: "binding-second".to_string(),
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
    let foreign_organization = db
        .insert_organization(test_organization("binding-foreign", "Binding Foreign"))
        .await
        .unwrap();
    let foreign_application = db
        .insert_application(test_application(
            &foreign_organization.id,
            "binding-foreign-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let client = db
        .insert_client_for_application(
            &first.id,
            test_client("binding-exclusive-client", &organization.id),
        )
        .await
        .unwrap();
    let client_profile_id = db
        .find_application_client_binding(&client.id)
        .await
        .unwrap()
        .unwrap()
        .authorization_profile_id;

    db.link_client_to_application(&first.id, &client.id, "oidc", &client_profile_id)
        .await
        .unwrap();
    assert_eq!(
        db.list_application_client_ids(&first.id).await.unwrap(),
        vec![client.id.clone()]
    );
    assert!(
        db.link_client_to_application(&foreign_application.id, &client.id, "oidc", "default")
            .await
            .is_err()
    );
    assert_eq!(
        db.find_application_for_client(&client.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        first.id
    );

    assert!(matches!(
        db.link_client_to_application(
            &first.id,
            &client.id,
            "oidc",
            "binding-second-profile"
        )
        .await,
        Err(AppError::BadRequest(message))
            if message == "authorization profile must belong to the application"
    ));

    db.upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
        id: "updated".to_string(),
        application_id: first.id.clone(),
        profile_key: "updated".to_string(),
        connection_kind: "oidc".to_string(),
        connection_id: Some(client.id.clone()),
        source_mode: "manual".to_string(),
        remote_version: None,
        remote_digest: None,
        sync_status: "manual".to_string(),
        last_synced_at: None,
        last_error: None,
    })
    .await
    .unwrap();

    db.link_client_to_application(&first.id, &client.id, "oidc", "updated")
        .await
        .unwrap();
    assert_eq!(
        db.find_application_client_binding(&client.id)
            .await
            .unwrap()
            .unwrap()
            .authorization_profile_id,
        "updated"
    );
    assert!(matches!(
        db.link_client_to_application(&second.id, &client.id, "oidc", "default")
            .await,
        Err(AppError::BadRequest(message)) if message == "OIDC client already belongs to another application"
    ));
    assert_eq!(
        db.list_application_client_ids(&first.id).await.unwrap(),
        vec![client.id.clone()]
    );
    assert!(
        db.list_application_client_ids(&second.id)
            .await
            .unwrap()
            .is_empty()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn find_application_oidc_client_requires_application_and_oidc_binding() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("oidc-client-read", "OIDC Client Read"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "oidc-client-read-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let other_application = db
        .insert_application(test_application(
            &organization.id,
            "oidc-client-read-other-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let oidc_client = db
        .insert_client_for_application(
            &application.id,
            test_client("oidc-client-read-client", &organization.id),
        )
        .await
        .unwrap();

    let resolved = db
        .find_application_oidc_client(&application.id, &oidc_client.id)
        .await
        .unwrap()
        .expect("the matching application OIDC binding should resolve");
    assert_eq!(resolved.client_db_id, oidc_client.id);
    assert_eq!(resolved.client_secret_hash, oidc_client.client_secret_hash);
    assert_eq!(resolved.audience, oidc_client.audience);

    assert!(
        db.find_application_oidc_client(&other_application.id, &oidc_client.id)
            .await
            .unwrap()
            .is_none()
    );

    let non_oidc_client = db
        .insert_client(test_client("saml-client-read-client", &organization.id))
        .await
        .unwrap();
    db.link_client_to_application(&application.id, &non_oidc_client.id, "saml", "default")
        .await
        .unwrap();
    assert!(
        db.find_application_oidc_client(&application.id, &non_oidc_client.id)
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_oidc_update_rejects_cross_organization_client_binding() {
    let (db, path) = sqlite_test_db().await;
    let application_organization = db
        .insert_organization(test_organization(
            "oidc-update-boundary",
            "OIDC Update Boundary",
        ))
        .await
        .unwrap();
    let client_organization = db
        .insert_organization(test_organization(
            "oidc-update-foreign",
            "OIDC Update Foreign",
        ))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &application_organization.id,
            "oidc-update-boundary-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let client = db
        .insert_client(test_client(
            "oidc-update-foreign-client",
            &client_organization.id,
        ))
        .await
        .unwrap();
    let application_id = application.id.clone();
    let client_id = client.id.clone();
    let binding_application_id = application_id.clone();
    let binding_client_id = client_id.clone();

    with_conn!(db.clone(), |conn, kind| {
            let sql = format!(
                "INSERT INTO application_client_bindings (application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8)
            );
            sql_query(sql)
                .bind::<Text, _>(&binding_application_id)
                .bind::<Text, _>(&binding_client_id)
                .bind::<Text, _>("oidc")
                .bind::<Text, _>("default")
                .bind::<Text, _>(format!("auth-domain:{}", application.id))
                .bind::<Integer, _>(1)
                .bind::<BigInt, _>(util::now_ts())
                .bind::<BigInt, _>(util::now_ts())
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();

    let result = db
        .update_application_oidc_client_graph(
            &application_id,
            &client_id,
            test_client(
                "oidc-update-foreign-client-renamed",
                &client_organization.id,
            ),
            Vec::new(),
        )
        .await;
    assert!(
        matches!(result, Err(AppError::BadRequest(message)) if message.contains("organization"))
    );
    let unchanged = db.find_client_by_id(&client_id).await.unwrap().unwrap();
    assert_eq!(unchanged.client_id, "oidc-update-foreign-client");
    assert_eq!(unchanged.organization_id, Some(client_organization.id));

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn dynamic_client_graph_rolls_back_when_registration_insert_fails() {
    let (db, path) = sqlite_test_db().await;
    let system = db.system_organization().await.unwrap();
    let client_id = "dynamic-registration-rollback";
    let applications_before = db
        .list_applications(Some(SIGNET_ORGANIZATION_ID))
        .await
        .unwrap()
        .len();

    // The trigger fails at the last graph write, after the client,
    // application, physical profile, and binding have been inserted.
    // This exercises the real database transaction rather than a
    // validation failure that happens before any row is written.
    with_conn!(db, |conn, _kind| {
            conn.batch_execute(
                "CREATE TRIGGER fail_dynamic_registration BEFORE INSERT ON client_registrations BEGIN SELECT RAISE(ABORT, 'forced dynamic registration failure'); END",
            )
            .map_err(AppError::from)
        })
        .unwrap();

    let result = db
        .register_dynamic_client_graph(
            test_client(client_id, &system.id),
            util::token_hash("dynamic-registration-token"),
        )
        .await;
    assert!(matches!(
        result,
        Err(AppError::Database(message))
            if message.contains("forced dynamic registration failure")
    ));
    assert!(
        db.find_client_by_client_id(client_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.list_applications(Some(SIGNET_ORGANIZATION_ID))
            .await
            .unwrap()
            .len(),
        applications_before
    );

    with_conn!(db, |conn, _kind| {
        conn.batch_execute("DROP TRIGGER fail_dynamic_registration")
            .map_err(AppError::from)
    })
    .unwrap();
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn dynamic_client_graph_allocates_a_bounded_collision_suffix() {
    let (db, path) = sqlite_test_db().await;
    let system = db.system_organization().await.unwrap();
    let client_id = "dynamic-slug-collision";
    let base_slug = application_slug_base(client_id);
    for slug in [&base_slug, &format!("{base_slug}-2")] {
        db.insert_application(test_application(
            &system.id,
            slug,
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    }

    let client = db
        .register_dynamic_client_graph(
            test_client(client_id, &system.id),
            util::token_hash("dynamic-slug-token"),
        )
        .await
        .unwrap();
    let application = db
        .find_application_for_client(&client.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        application.slug,
        application_slug_collision_candidate(&base_slug, client_id)
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[test]
fn application_slug_base_disambiguates_noncanonical_client_ids() {
    let canonical = application_slug_base("client-id");
    let disambiguated = application_slug_base("Client.ID");
    assert_ne!(canonical, disambiguated);
    assert!(disambiguated.len() <= 64);
    assert!(crate::applications::normalize_application_slug(&disambiguated).is_ok());
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_oidc_client_graph_is_atomic_and_profile_bound() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("graph-app", "Graph App"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "graph-application",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    // Force a failure after the client insert would have happened. A
    // profile-key collision must roll back the complete aggregate rather
    // than leave an unbound client for a later reconciliation pass.
    db.upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
        id: "graph-existing-profile".to_string(),
        application_id: application.id.clone(),
        profile_key: "graph-rollback-client".to_string(),
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
    let rollback_result = db
        .create_application_oidc_client_graph(
            &application.id,
            test_client("graph-rollback-client", &organization.id),
            Vec::new(),
        )
        .await;
    assert!(matches!(
        rollback_result,
        Err(AppError::BadRequest(message))
            if message == "authorization profile key is already used by another connection"
    ));
    assert!(
        db.find_client_by_client_id("graph-rollback-client")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.find_application_client_binding_by_public_client_id("graph-rollback-client")
            .await
            .unwrap()
            .is_none()
    );

    // Exercise a failure after the profile, auth domain, and binding have
    // already been written. A real database trigger is used here because
    // malformed mapper input is rejected before the aggregate transaction
    // in the HTTP layer and would not test rollback at the mapper step.
    with_conn!(db, |conn, _kind| {
            conn.batch_execute(
                "CREATE TRIGGER fail_graph_mapper BEFORE INSERT ON client_claim_mappers BEGIN SELECT RAISE(ABORT, 'forced graph mapper failure'); END",
            )
            .map_err(AppError::from)
        })
        .unwrap();
    let mapper_rollback_result = db
        .create_application_oidc_client_graph(
            &application.id,
            test_client("graph-mapper-rollback", &organization.id),
            vec![NewClientClaimMapper {
                claim_name: "department".to_string(),
                source: "static".to_string(),
                source_value: "engineering".to_string(),
                value_type: "string".to_string(),
                include_in_id_token: true,
                include_in_access_token: false,
                include_in_userinfo: false,
                is_active: true,
                sort_order: 0,
            }],
        )
        .await;
    assert!(matches!(
        mapper_rollback_result,
        Err(AppError::Database(message)) if message.contains("forced graph mapper failure")
    ));
    assert!(
        db.find_client_by_client_id("graph-mapper-rollback")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.find_application_authorization_profile(&application.id, "graph-mapper-rollback")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.find_application_client_binding_by_public_client_id("graph-mapper-rollback")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.find_application_auth_domain(&application.id)
            .await
            .unwrap()
            .is_none()
    );
    with_conn!(db, |conn, _kind| {
        conn.batch_execute("DROP TRIGGER fail_graph_mapper")
            .map_err(AppError::from)
    })
    .unwrap();
    let client_input = test_client("graph-client", &organization.id);
    let client = db
        .create_application_oidc_client_graph(
            &application.id,
            client_input.clone(),
            vec![NewClientClaimMapper {
                claim_name: "department".to_string(),
                source: "static".to_string(),
                source_value: "engineering".to_string(),
                value_type: "string".to_string(),
                include_in_id_token: true,
                include_in_access_token: true,
                include_in_userinfo: false,
                is_active: true,
                sort_order: 0,
            }],
        )
        .await
        .unwrap();
    let binding = db
        .find_application_client_binding(&client.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(binding.application_id, application.id);
    assert_ne!(binding.authorization_profile_id, "default");
    let profile = db
        .find_application_authorization_profile_by_id(&binding.authorization_profile_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(profile.profile_key, "graph-client");
    assert_eq!(profile.connection_id.as_deref(), Some(client.id.as_str()));
    assert_eq!(
        db.list_client_claim_mappers(&client.id)
            .await
            .unwrap()
            .len(),
        1
    );
    let graph = db.read_application_graph(&application.id).await.unwrap();
    assert_eq!(graph.bindings.len(), 1);
    assert_eq!(graph.clients.len(), 1);
    assert_eq!(graph.claim_mappers.len(), 1);
    assert_eq!(graph.organizations.len(), 1);
    assert_eq!(graph.profiles.len(), 3);
    assert!(
        graph
            .profiles
            .iter()
            .any(|profile| profile.profile_key == "graph-rollback-client")
    );
    assert!(
        graph
            .profiles
            .iter()
            .any(|profile| profile.profile_key == "graph-client")
    );

    let mut updated_input = client_input;
    updated_input.client_id = "graph-client-renamed".to_string();
    updated_input.client_name = "Graph Client Renamed".to_string();
    let updated = db
        .update_application_oidc_client_graph(
            &application.id,
            &client.id,
            updated_input,
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(updated.client_id, "graph-client-renamed");
    let updated_binding = db
        .find_application_client_binding(&client.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        updated_binding.authorization_profile_id,
        binding.authorization_profile_id
    );
    let renamed_profile = db
        .find_application_authorization_profile_by_id(&binding.authorization_profile_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(renamed_profile.profile_key, "graph-client-renamed");
    assert!(
        db.list_client_claim_mappers(&client.id)
            .await
            .unwrap()
            .is_empty()
    );

    db.delete_application_oidc_client_graph(&application.id, &client.id)
        .await
        .unwrap();
    assert!(db.find_client_by_id(&client.id).await.unwrap().is_none());
    assert!(
        db.find_application_authorization_profile_by_id(&binding.authorization_profile_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.find_application_client_binding(&client.id)
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_jwt_clients_support_rotation_revoke_and_one_time_codes() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("jwt-clients", "JWT Clients"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "jwt-client-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let user = db
        .insert_user(test_user("jwt-user@example.com", "jwt-user"))
        .await
        .unwrap();

    let public_client = db
        .upsert_application_jwt_client(
            &application.id,
            NewApplicationJwtClient {
                client_id: "public-client".to_string(),
                client_type: "public".to_string(),
                is_active: true,
            },
        )
        .await
        .unwrap();
    assert_eq!(public_client.client_type, "public");
    assert!(
        !db.verify_application_jwt_secret(&application.id, &public_client.client_id, "secret")
            .await
            .unwrap()
    );
    assert!(
        db.rotate_application_jwt_secret(
            &application.id,
            &public_client.client_id,
            &util::hash_password("secret").unwrap(),
            300,
        )
        .await
        .is_err()
    );

    let confidential_client = db
        .upsert_application_jwt_client(
            &application.id,
            NewApplicationJwtClient {
                client_id: "confidential-client".to_string(),
                client_type: "confidential".to_string(),
                is_active: true,
            },
        )
        .await
        .unwrap();
    let first_secret = "jwt-secret-first";
    let first_hash = util::hash_password(first_secret).unwrap();
    db.rotate_application_jwt_secret(
        &application.id,
        &confidential_client.client_id,
        &first_hash,
        300,
    )
    .await
    .unwrap();
    assert!(
        db.verify_application_jwt_secret(
            &application.id,
            &confidential_client.client_id,
            first_secret,
        )
        .await
        .unwrap()
    );
    assert!(
        !db.verify_application_jwt_secret(
            &application.id,
            &confidential_client.client_id,
            "wrong-secret",
        )
        .await
        .unwrap()
    );

    let second_secret = "jwt-secret-second";
    db.rotate_application_jwt_secret(
        &application.id,
        &confidential_client.client_id,
        &util::hash_password(second_secret).unwrap(),
        300,
    )
    .await
    .unwrap();
    assert!(
        db.verify_application_jwt_secret(
            &application.id,
            &confidential_client.client_id,
            first_secret,
        )
        .await
        .unwrap()
    );
    assert!(
        db.verify_application_jwt_secret(
            &application.id,
            &confidential_client.client_id,
            second_secret,
        )
        .await
        .unwrap()
    );
    let secrets = db
        .list_application_jwt_secrets(&application.id, &confidential_client.client_id)
        .await
        .unwrap();
    assert_eq!(secrets.len(), 2);
    assert!(secrets.iter().all(
            |record| record.secret_hash != first_secret && record.secret_hash != second_secret
        ));

    db.revoke_application_jwt_secrets(&application.id, &confidential_client.client_id)
        .await
        .unwrap();
    assert!(
        !db.verify_application_jwt_secret(
            &application.id,
            &confidential_client.client_id,
            first_secret,
        )
        .await
        .unwrap()
    );
    assert!(
        !db.verify_application_jwt_secret(
            &application.id,
            &confidential_client.client_id,
            second_secret,
        )
        .await
        .unwrap()
    );

    db.rotate_application_jwt_secret(
        &application.id,
        &confidential_client.client_id,
        &util::hash_password("disabled-secret").unwrap(),
        300,
    )
    .await
    .unwrap();
    db.upsert_application_jwt_client(
        &application.id,
        NewApplicationJwtClient {
            client_id: confidential_client.client_id.clone(),
            client_type: "confidential".to_string(),
            is_active: false,
        },
    )
    .await
    .unwrap();
    assert!(
        !db.verify_application_jwt_secret(
            &application.id,
            &confidential_client.client_id,
            "disabled-secret",
        )
        .await
        .unwrap()
    );

    let raw_code = "jwt-one-time-code";
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    let challenge = util::sha256_base64url(verifier);
    db.insert_application_jwt_code(NewApplicationJwtCode {
        code_hash: util::token_hash(raw_code),
        application_id: application.id.clone(),
        client_id: public_client.client_id.clone(),
        redirect_uri: "https://example.test/jwt/callback".to_string(),
        user_id: user.id.clone(),
        nonce: Some("nonce".to_string()),
        code_challenge: Some(challenge.clone()),
        code_challenge_method: Some("S256".to_string()),
        expires_at: util::now_ts() + 60,
    })
    .await
    .unwrap();
    let consumed = db
        .consume_application_jwt_code(
            &util::token_hash(raw_code),
            &application.id,
            &public_client.client_id,
            "https://example.test/jwt/callback",
            &challenge,
            "S256",
        )
        .await
        .unwrap();
    assert_eq!(consumed.user_id, user.id);
    assert!(
        db.consume_application_jwt_code(
            &util::token_hash(raw_code),
            &application.id,
            &public_client.client_id,
            "https://example.test/jwt/callback",
            &challenge,
            "S256",
        )
        .await
        .is_err()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}
