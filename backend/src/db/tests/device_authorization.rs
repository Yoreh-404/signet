#[cfg(feature = "sqlite")]
#[tokio::test]
async fn device_authorization_persists_resource_and_authorization_details() {
    let (db, path) = super::sqlite_test_db().await;
    let details =
        r#"[{"type":"resource_access","locations":["https://api.example/"],"actions":["read"]}]"#;

    let created = db
        .insert_device_authorization(crate::db::NewDeviceAuthorization {
            device_code_hash: "device-hash".to_string(),
            user_code_hash: "user-hash".to_string(),
            user_code_display: "ABCD-EFGH".to_string(),
            client_id: "client".to_string(),
            scope: "openid".to_string(),
            resource: Some("https://api.example/".to_string()),
            authorization_details: Some(details.to_string()),
            expires_at: crate::util::now_ts() + 600,
            interval_seconds: 5,
        })
        .await
        .unwrap();

    assert_eq!(created.resource.as_deref(), Some("https://api.example/"));
    assert_eq!(created.authorization_details.as_deref(), Some(details));
    let fetched = db
        .find_device_authorization_by_device_code_hash("device-hash")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.resource.as_deref(), Some("https://api.example/"));
    assert_eq!(fetched.authorization_details.as_deref(), Some(details));

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn device_authorization_transitions_are_atomic_and_report_current_state() {
    let (db, path) = super::sqlite_test_db_with_pool_size(4).await;
    let now = crate::util::now_ts();
    db.insert_device_authorization(crate::db::NewDeviceAuthorization {
        device_code_hash: "atomic-device-code".to_string(),
        user_code_hash: "atomic-user-code".to_string(),
        user_code_display: "ABCD-EFGH".to_string(),
        client_id: "client".to_string(),
        scope: "openid".to_string(),
        resource: None,
        authorization_details: None,
        expires_at: now + 600,
        interval_seconds: 5,
    })
    .await
    .unwrap();

    let first_db = db.clone();
    let second_db = db.clone();
    let (first_poll, second_poll) = tokio::join!(
        first_db.poll_device_authorization("atomic-device-code", now),
        second_db.poll_device_authorization("atomic-device-code", now),
    );
    let first_poll = first_poll.unwrap();
    let second_poll = second_poll.unwrap();
    assert_eq!(
        usize::from(first_poll.changed) + usize::from(second_poll.changed),
        1
    );
    assert!(
        (first_poll.status == crate::db::DeviceAuthorizationStatus::Pending
            && second_poll.status == crate::db::DeviceAuthorizationStatus::SlowDown)
            || (second_poll.status == crate::db::DeviceAuthorizationStatus::Pending
                && first_poll.status == crate::db::DeviceAuthorizationStatus::SlowDown)
    );

    let approved = db
        .authorize_device_authorization("atomic-user-code", "user-1")
        .await
        .unwrap();
    assert!(approved.changed);
    assert_eq!(
        approved.status,
        crate::db::DeviceAuthorizationStatus::Authorized
    );

    let denied_after_approval = db
        .deny_device_authorization("atomic-user-code")
        .await
        .unwrap();
    assert!(!denied_after_approval.changed);
    assert_eq!(
        denied_after_approval.status,
        crate::db::DeviceAuthorizationStatus::Authorized
    );

    let first_db = db.clone();
    let second_db = db.clone();
    let (first_consume, second_consume) = tokio::join!(
        first_db.consume_device_authorization("atomic-device-code"),
        second_db.consume_device_authorization("atomic-device-code"),
    );
    let first_consume = first_consume.unwrap();
    let second_consume = second_consume.unwrap();
    assert_eq!(
        usize::from(first_consume.changed) + usize::from(second_consume.changed),
        1
    );
    assert_eq!(
        first_consume.status,
        crate::db::DeviceAuthorizationStatus::Consumed
    );
    assert_eq!(
        second_consume.status,
        crate::db::DeviceAuthorizationStatus::Consumed
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn device_authorization_approve_and_deny_have_one_winner() {
    let (db, path) = super::sqlite_test_db_with_pool_size(4).await;
    let now = crate::util::now_ts();
    db.insert_device_authorization(crate::db::NewDeviceAuthorization {
        device_code_hash: "approve-deny-device-code".to_string(),
        user_code_hash: "approve-deny-user-code".to_string(),
        user_code_display: "IJKL-MNOP".to_string(),
        client_id: "client".to_string(),
        scope: "openid".to_string(),
        resource: None,
        authorization_details: None,
        expires_at: now + 600,
        interval_seconds: 5,
    })
    .await
    .unwrap();

    let approve_db = db.clone();
    let deny_db = db.clone();
    let (approve, deny) = tokio::join!(
        approve_db.authorize_device_authorization("approve-deny-user-code", "user-1"),
        deny_db.deny_device_authorization("approve-deny-user-code"),
    );
    let approve = approve.unwrap();
    let deny = deny.unwrap();
    assert_eq!(usize::from(approve.changed) + usize::from(deny.changed), 1);
    if approve.changed {
        assert_eq!(
            approve.status,
            crate::db::DeviceAuthorizationStatus::Authorized
        );
        assert_eq!(
            deny.status,
            crate::db::DeviceAuthorizationStatus::Authorized
        );
    } else {
        assert_eq!(deny.status, crate::db::DeviceAuthorizationStatus::Denied);
        assert_eq!(approve.status, crate::db::DeviceAuthorizationStatus::Denied);
    }

    drop(db);
    let _ = std::fs::remove_file(path);
}
