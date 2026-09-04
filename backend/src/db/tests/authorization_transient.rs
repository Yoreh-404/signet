#[cfg(feature = "sqlite")]
#[tokio::test]
async fn interaction_request_update_requires_live_unconsumed_client_binding() {
    let (db, path) = super::sqlite_test_db().await;
    db.insert_pushed_authorization_request(crate::db::NewPushedAuthorizationRequest {
        request_uri_hash: "reauth-interaction-hash".to_string(),
        client_id: "client".to_string(),
        request_json: "{\"state\":\"pending\"}".to_string(),
        expires_at: crate::util::now_ts() + 600,
    })
    .await
    .unwrap();

    assert!(
        db.update_unconsumed_pushed_authorization_request(
            "reauth-interaction-hash",
            "other-client",
            "{\"state\":\"pending\"}",
            "{\"state\":\"forged\"}",
        )
        .await
        .is_err()
    );
    let updated = db
        .update_unconsumed_pushed_authorization_request(
            "reauth-interaction-hash",
            "client",
            "{\"state\":\"pending\"}",
            "{\"state\":\"complete\"}",
        )
        .await
        .unwrap();
    assert_eq!(updated.request_json, "{\"state\":\"complete\"}");
    db.consume_pushed_authorization_request("reauth-interaction-hash")
        .await
        .unwrap();
    assert!(
        db.update_unconsumed_pushed_authorization_request(
            "reauth-interaction-hash",
            "client",
            "{\"state\":\"complete\"}",
            "{\"state\":\"replayed\"}",
        )
        .await
        .is_err()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn concurrent_interaction_request_compare_and_swap_has_one_winner() {
    let (db, path) = super::sqlite_test_db_with_pool_size(4).await;
    db.insert_pushed_authorization_request(crate::db::NewPushedAuthorizationRequest {
        request_uri_hash: "concurrent-reauth-interaction".to_string(),
        client_id: "client".to_string(),
        request_json: "{\"state\":\"pending\"}".to_string(),
        expires_at: crate::util::now_ts() + 600,
    })
    .await
    .unwrap();

    let first_db = db.clone();
    let second_db = db.clone();
    let (first, second) = tokio::join!(
        first_db.update_unconsumed_pushed_authorization_request(
            "concurrent-reauth-interaction",
            "client",
            "{\"state\":\"pending\"}",
            "{\"state\":\"first\"}",
        ),
        second_db.update_unconsumed_pushed_authorization_request(
            "concurrent-reauth-interaction",
            "client",
            "{\"state\":\"pending\"}",
            "{\"state\":\"second\"}",
        )
    );
    assert_eq!(
        [first.is_ok(), second.is_ok()]
            .into_iter()
            .filter(|won| *won)
            .count(),
        1
    );
    let stored = db
        .find_pushed_authorization_request("concurrent-reauth-interaction")
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        stored.request_json.as_str(),
        "{\"state\":\"first\"}" | "{\"state\":\"second\"}"
    ));

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn pushed_authorization_request_consumption_has_one_concurrent_winner() {
    let (db, path) = super::sqlite_test_db_with_pool_size(4).await;
    db.insert_pushed_authorization_request(crate::db::NewPushedAuthorizationRequest {
        request_uri_hash: "concurrent-request-uri-hash".to_string(),
        client_id: "client".to_string(),
        request_json: "{}".to_string(),
        expires_at: crate::util::now_ts() + 600,
    })
    .await
    .unwrap();

    let first_db = db.clone();
    let second_db = db.clone();
    let (first, second) = tokio::join!(
        first_db.consume_pushed_authorization_request("concurrent-request-uri-hash"),
        second_db.consume_pushed_authorization_request("concurrent-request-uri-hash")
    );
    assert_eq!(
        [first.is_ok(), second.is_ok()]
            .into_iter()
            .filter(|ok| *ok)
            .count(),
        1
    );
    assert!(
        db.consume_pushed_authorization_request("concurrent-request-uri-hash")
            .await
            .is_err()
    );
    assert!(
        db.find_pushed_authorization_request("concurrent-request-uri-hash")
            .await
            .unwrap()
            .unwrap()
            .consumed_at
            .is_some()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}
