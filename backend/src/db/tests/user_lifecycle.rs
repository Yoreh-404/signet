#[cfg(feature = "sqlite")]
#[tokio::test]
async fn disabling_user_through_profile_update_clears_auth_state() {
    let (db, path) = super::sqlite_test_db().await;
    let user = db
        .insert_user(super::test_user("deactivate@example.com", "deactivate"))
        .await
        .unwrap();
    let _session_id = super::insert_user_auth_state(&db, &user.id, "deactivate").await;
    super::assert_user_auth_state_count(&db, &user.id, 1).await;

    let updated = db
        .update_user(crate::db::UserUpdate {
            id: &user.id,
            email: user.email.clone(),
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            phone: user.phone.clone(),
            is_admin: user.is_admin == 1,
            is_active: false,
        })
        .await
        .unwrap();

    assert_eq!(updated.is_active, 0);
    super::assert_user_auth_state_count(&db, &user.id, 0).await;

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn archive_user_clears_auth_state() {
    let (db, path) = super::sqlite_test_db().await;
    let user = db
        .insert_user(super::test_user("archive@example.com", "archive"))
        .await
        .unwrap();
    let _session_id = super::insert_user_auth_state(&db, &user.id, "archive").await;
    super::assert_user_auth_state_count(&db, &user.id, 1).await;

    db.archive_user(&user.id).await.unwrap();
    let archived = db.find_user_by_id(&user.id).await.unwrap().unwrap();

    assert_eq!(archived.is_active, 0);
    assert!(archived.archived_at.is_some());
    super::assert_user_auth_state_count(&db, &user.id, 0).await;

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn user_lifecycle_batch_is_atomic_deduplicated_and_cleans_auth_state() {
    let (db, path) = super::sqlite_test_db().await;
    let first = db
        .insert_user(super::test_user("batch-first@example.com", "batch-first"))
        .await
        .unwrap();
    let second = db
        .insert_user(super::test_user("batch-second@example.com", "batch-second"))
        .await
        .unwrap();
    super::insert_user_auth_state(&db, &first.id, "batch-first").await;
    super::insert_user_auth_state(&db, &second.id, "batch-second").await;

    let missing_id = "batch-missing".to_string();
    let rejected = db
        .apply_user_lifecycle_batch(
            "actor",
            vec![first.id.clone(), missing_id],
            crate::db::UserLifecycleBatchAction::Disable,
        )
        .await;
    assert!(matches!(rejected, Err(crate::error::AppError::NotFound)));
    assert_eq!(
        db.find_user_by_id(&first.id)
            .await
            .unwrap()
            .unwrap()
            .is_active,
        1
    );
    super::assert_user_auth_state_count(&db, &first.id, 1).await;

    let changed = db
        .apply_user_lifecycle_batch(
            "actor",
            vec![first.id.clone(), second.id.clone(), first.id.clone()],
            crate::db::UserLifecycleBatchAction::Disable,
        )
        .await
        .unwrap();
    assert_eq!(changed, 2);
    for user in [&first, &second] {
        assert_eq!(
            db.find_user_by_id(&user.id)
                .await
                .unwrap()
                .unwrap()
                .is_active,
            0
        );
        super::assert_user_auth_state_count(&db, &user.id, 0).await;
    }
    let events = db.list_audit_events(20).await.unwrap();
    assert!(events.iter().any(|event| {
        event.action == "user.bulk.disable"
            && event.target_kind == "user_bulk"
            && event.details.contains("\"count\":2")
    }));

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn permanent_user_deletion_is_complete_and_preserves_audit_history() {
    let (db, path) = super::sqlite_test_db().await;
    let user = db
        .insert_user(super::test_user("deleted@example.com", "deleted"))
        .await
        .unwrap();
    let session_id = super::insert_user_auth_state(&db, &user.id, "deleted").await;
    let (recovery_invitation, _recovery_code) = db
        .insert_invitation(super::test_invitation(
            crate::db::AuthorizationCodeType::Login,
            crate::db::LoginCodeLevel::AccountRecovery,
            Some(&user.username),
            Some(&user.id),
            Vec::new(),
        ))
        .await
        .unwrap();
    db.insert_audit_event(crate::audit::management_event(
        user.id.clone(),
        "user.test_event",
        "user",
        Some(user.id.clone()),
        serde_json::json!({ "email": user.email }),
    ))
    .await
    .unwrap();

    db.permanently_delete_user(&user.id).await.unwrap();

    assert!(db.find_user_by_id(&user.id).await.unwrap().is_none());
    super::assert_user_auth_state_count(&db, &user.id, 0).await;
    for table in ["session_credentials", "browser_context_accounts"] {
        assert_eq!(super::session_link_count(&db, table, &session_id).await, 0);
    }
    let invalidated = db
        .find_invitation_by_id(&recovery_invitation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(invalidated.is_active, 0);
    assert_eq!(
        invalidated.authorized_user_id.as_deref(),
        Some(user.id.as_str())
    );
    let audit_events = db.list_audit_events(10).await.unwrap();
    assert!(audit_events.iter().any(|event| {
        event.action == "user.test_event"
            && event.actor_user_id.as_deref() == Some(user.id.as_str())
            && event.target_id.as_deref() == Some(user.id.as_str())
    }));
    assert!(matches!(
        db.permanently_delete_user(&user.id).await,
        Err(crate::error::AppError::NotFound)
    ));

    drop(db);
    let _ = std::fs::remove_file(path);
}
