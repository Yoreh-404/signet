#[cfg(feature = "sqlite")]
#[tokio::test]
async fn session_revocation_paths_share_association_cleanup() {
    let (db, path) = super::sqlite_test_db().await;
    let user = db
        .insert_user(super::test_user(
            "session-revoke@example.com",
            "session-revoke",
        ))
        .await
        .unwrap();

    let session_id = super::insert_user_auth_state(&db, &user.id, "session-revoke").await;
    let saml_index = "session-revoke-saml";
    db.insert_application_saml_session(crate::db::NewApplicationSamlSession {
        session_index_hash: saml_index.to_string(),
        application_id: "session-revoke-application".to_string(),
        user_id: user.id.clone(),
        signet_session_id: session_id.clone(),
        name_id_hash: "session-revoke-name".to_string(),
        expires_at: crate::util::now_ts() + 600,
    })
    .await
    .unwrap();

    assert!(db.delete_user_session(&user.id, &session_id).await.unwrap());
    assert!(db.find_session(&session_id).await.unwrap().is_none());
    for table in ["session_credentials", "browser_context_accounts"] {
        assert_eq!(super::session_link_count(&db, table, &session_id).await, 0);
    }
    assert!(
        db.find_application_saml_session(saml_index, "session-revoke-application")
            .await
            .unwrap()
            .is_none()
    );

    let verified_session_id =
        super::insert_user_auth_state(&db, &user.id, "session-verified").await;
    assert!(
        db.delete_verified_user_session(&user.id, &verified_session_id)
            .await
            .unwrap()
    );
    assert!(
        db.find_session(&verified_session_id)
            .await
            .unwrap()
            .is_none()
    );
    for table in ["session_credentials", "browser_context_accounts"] {
        assert_eq!(
            super::session_link_count(&db, table, &verified_session_id).await,
            0
        );
    }

    drop(db);
    let _ = std::fs::remove_file(path);
}
