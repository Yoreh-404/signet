#[cfg(feature = "sqlite")]
#[tokio::test]
async fn concurrent_refresh_token_rotation_has_one_winner() {
    let (db, path) = super::sqlite_test_db_with_pool_size(4).await;
    let now = crate::util::now_ts();
    db.insert_refresh_token(
        "client".to_string(),
        crate::db::RefreshTokenInput {
            token_hash: "old-refresh-hash".to_string(),
            user_id: "user".to_string(),
            scope: "openid profile".to_string(),
            resource: Some("https://api.example/".to_string()),
            authorization_details: None,
            dpop_jkt: None,
            auth_context_id: None,
            expires_at: now + 600,
        },
    )
    .await
    .unwrap();

    let first_db = db.clone();
    let second_db = db.clone();
    let (first, second) = tokio::join!(
        first_db.rotate_refresh_token(
            "old-refresh-hash",
            "client",
            super::refresh_token_replacement("new-refresh-hash-1", "user"),
        ),
        second_db.rotate_refresh_token(
            "old-refresh-hash",
            "client",
            super::refresh_token_replacement("new-refresh-hash-2", "user"),
        )
    );

    let outcomes = [first.unwrap(), second.unwrap()];
    assert_eq!(outcomes.iter().filter(|&&rotated| rotated).count(), 1);
    let inserted = [
        db.find_refresh_token("new-refresh-hash-1")
            .await
            .unwrap()
            .is_some(),
        db.find_refresh_token("new-refresh-hash-2")
            .await
            .unwrap()
            .is_some(),
    ];
    assert_eq!(inserted.iter().filter(|&&exists| exists).count(), 1);
    assert!(
        db.find_refresh_token("old-refresh-hash")
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn refresh_token_rotation_rolls_back_revoke_when_insert_fails() {
    let (db, path) = super::sqlite_test_db().await;
    let now = crate::util::now_ts();
    for token_hash in ["old-refresh-hash", "duplicate-refresh-hash"] {
        db.insert_refresh_token(
            "client".to_string(),
            crate::db::RefreshTokenInput {
                token_hash: token_hash.to_string(),
                user_id: "user".to_string(),
                scope: "openid".to_string(),
                resource: None,
                authorization_details: None,
                dpop_jkt: None,
                auth_context_id: None,
                expires_at: now + 600,
            },
        )
        .await
        .unwrap();
    }

    assert!(
        db.rotate_refresh_token(
            "old-refresh-hash",
            "client",
            super::refresh_token_replacement("duplicate-refresh-hash", "user"),
        )
        .await
        .is_err()
    );
    assert_eq!(
        db.find_refresh_token("old-refresh-hash")
            .await
            .unwrap()
            .unwrap()
            .revoked_at,
        None
    );
    assert!(
        db.rotate_refresh_token(
            "old-refresh-hash",
            "client",
            super::refresh_token_replacement("unique-refresh-hash", "user"),
        )
        .await
        .unwrap()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}
