#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_saml_interactions_are_single_use_scoped_and_expire() {
    let (db, path) = super::sqlite_test_db().await;
    let handle_hash = "interaction-hash";
    db.insert_application_saml_interaction(crate::db::NewApplicationSamlInteraction {
        handle_hash: handle_hash.to_string(),
        application_id: "application-a".to_string(),
        request_id: "request-1".to_string(),
        sp_entity_id: "https://sp.example/metadata".to_string(),
        acs_url: "https://sp.example/acs".to_string(),
        relay_state: Some("state".to_string()),
        response_binding: "post".to_string(),
        expires_at: crate::util::now_ts() + 300,
    })
    .await
    .unwrap();

    assert!(
        db.consume_application_saml_interaction(handle_hash, "application-b")
            .await
            .is_err()
    );
    let consumed = db
        .consume_application_saml_interaction(handle_hash, "application-a")
        .await
        .unwrap();
    assert_eq!(consumed.request_id, "request-1");
    assert_eq!(consumed.relay_state.as_deref(), Some("state"));
    assert!(
        db.consume_application_saml_interaction(handle_hash, "application-a")
            .await
            .is_err()
    );

    db.insert_application_saml_interaction(crate::db::NewApplicationSamlInteraction {
        handle_hash: "expired-interaction".to_string(),
        application_id: "application-a".to_string(),
        request_id: String::new(),
        sp_entity_id: "https://sp.example/metadata".to_string(),
        acs_url: "https://sp.example/acs".to_string(),
        relay_state: None,
        response_binding: "post".to_string(),
        expires_at: crate::util::now_ts() - 1,
    })
    .await
    .unwrap();
    assert!(
        db.consume_application_saml_interaction("expired-interaction", "application-a")
            .await
            .is_err()
    );

    let organization = db
        .insert_organization(super::test_organization("saml-cleanup", "SAML Cleanup"))
        .await
        .unwrap();
    let application = db
        .insert_application(super::test_application(
            &organization.id,
            "saml-cleanup-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    assert!(
        db.claim_application_saml_replay(
            "cleanup-replay",
            &application.id,
            crate::util::now_ts() + 300,
        )
        .await
        .unwrap()
    );
    db.insert_application_saml_interaction(crate::db::NewApplicationSamlInteraction {
        handle_hash: "cleanup-interaction".to_string(),
        application_id: application.id.clone(),
        request_id: String::new(),
        sp_entity_id: "https://sp.example/metadata".to_string(),
        acs_url: "https://sp.example/acs".to_string(),
        relay_state: None,
        response_binding: "post".to_string(),
        expires_at: crate::util::now_ts() + 300,
    })
    .await
    .unwrap();
    db.delete_application(&application.id).await.unwrap();
    assert!(
        db.consume_application_saml_interaction("cleanup-interaction", &application.id)
            .await
            .is_err()
    );
    assert!(
        db.claim_application_saml_replay(
            "cleanup-replay",
            &application.id,
            crate::util::now_ts() + 300,
        )
        .await
        .unwrap()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_saml_interaction_consume_allows_only_one_concurrent_winner() {
    let (db, path) = super::sqlite_test_db_with_pool_size(4).await;
    db.insert_application_saml_interaction(crate::db::NewApplicationSamlInteraction {
        handle_hash: "concurrent-interaction".to_string(),
        application_id: "application-a".to_string(),
        request_id: "request-concurrent".to_string(),
        sp_entity_id: "https://sp.example/metadata".to_string(),
        acs_url: "https://sp.example/acs".to_string(),
        relay_state: None,
        response_binding: "post".to_string(),
        expires_at: crate::util::now_ts() + 300,
    })
    .await
    .unwrap();

    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(4));
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let db = db.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            db.consume_application_saml_interaction("concurrent-interaction", "application-a")
                .await
        }));
    }
    let mut successful_consumes = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            successful_consumes += 1;
        }
    }
    assert_eq!(successful_consumes, 1);

    drop(db);
    let _ = std::fs::remove_file(path);
}
