use super::*;
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn organization_creation_rolls_back_owner_and_context_when_audit_fails() {
    let (db, path) = sqlite_test_db().await;
    let user = db
        .insert_user(test_user(
            "organization-atomic@example.test",
            "organization-atomic",
        ))
        .await
        .unwrap();
    with_conn!(db.clone(), |conn, _kind| {
            conn.batch_execute(
                "CREATE TRIGGER fail_organization_audit_outbox BEFORE INSERT ON audit_webhook_outbox BEGIN SELECT RAISE(ABORT, 'forced organization audit failure'); END",
            )
            .map_err(AppError::from)
        })
        .unwrap();
    let result = db
        .create_organization_with_owner_and_audit(
            NewOrganization {
                slug: "organization-atomic".to_string(),
                name: "Organization Atomic".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            },
            &user.id,
            crate::audit::management_event(
                user.id.clone(),
                "organization.self_service_create",
                "organization",
                None,
                serde_json::json!({ "slug": "organization-atomic" }),
            ),
        )
        .await;
    assert!(
        matches!(result, Err(AppError::Database(message)) if message.contains("forced organization audit failure"))
    );
    with_conn!(db.clone(), |conn, _kind| {
        conn.batch_execute("DROP TRIGGER fail_organization_audit_outbox")
            .map_err(AppError::from)
    })
    .unwrap();
    assert!(
        db.list_organizations()
            .await
            .unwrap()
            .into_iter()
            .all(|organization| organization.slug != "organization-atomic")
    );
    assert!(
        db.active_user_organization(&user.id)
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn audit_webhook_outbox_claim_retry_and_expired_lease_recovery_are_fenced() {
    let (db, path) = sqlite_test_db_with_pool_size(4).await;
    db.insert_audit_event(crate::audit::management_event(
        "outbox-actor",
        "outbox.test",
        "test",
        Some("outbox-target".to_string()),
        serde_json::json!({}),
    ))
    .await
    .unwrap();

    let first = db.claim_audit_webhook_outbox(10).await.unwrap();
    assert_eq!(first.len(), 1);
    let first_id = first[0].id.clone();
    let first_attempts = first[0].attempts;
    let owner = first[0].lease_owner.clone().unwrap();
    assert!(
        !db.complete_audit_webhook_outbox(&first_id, "wrong-owner")
            .await
            .unwrap()
    );
    assert!(
        db.retry_audit_webhook_outbox(
            &first_id,
            &owner,
            first_attempts,
            "temporary failure".into()
        )
        .await
        .unwrap()
    );

    // Backoff keeps the row out of the next claim until it is due.
    let first_id_for_future = first_id.clone();
    with_conn!(db.clone(), |conn, kind| {
        let sql = format!(
            "UPDATE audit_webhook_outbox SET next_attempt_at = {} WHERE id = {}",
            ph(kind, 1),
            ph(kind, 2)
        );
        sql_query(sql)
            .bind::<BigInt, _>(util::now_ts() + 60)
            .bind::<Text, _>(first_id_for_future)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(AppError::from)
    })
    .unwrap();
    assert!(db.claim_audit_webhook_outbox(10).await.unwrap().is_empty());
    let first_id_for_due = first_id.clone();
    with_conn!(db.clone(), |conn, kind| {
        let sql = format!(
            "UPDATE audit_webhook_outbox SET next_attempt_at = {} WHERE id = {}",
            ph(kind, 1),
            ph(kind, 2)
        );
        sql_query(sql)
            .bind::<BigInt, _>(util::now_ts() - 1)
            .bind::<Text, _>(first_id_for_due)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(AppError::from)
    })
    .unwrap();

    let second = db.claim_audit_webhook_outbox(10).await.unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].attempts, 1);
    let second_id = second[0].id.clone();
    let second_owner = second[0].lease_owner.clone().unwrap();

    // A worker that stopped without acknowledging the row is reclaimed
    // by the next claimant after its lease expires.
    let second_id_for_expiry = second_id.clone();
    with_conn!(db.clone(), |conn, kind| {
        let sql = format!(
            "UPDATE audit_webhook_outbox SET lease_expires_at = {} WHERE id = {}",
            ph(kind, 1),
            ph(kind, 2)
        );
        sql_query(sql)
            .bind::<BigInt, _>(util::now_ts() - 1)
            .bind::<Text, _>(second_id_for_expiry)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(AppError::from)
    })
    .unwrap();
    let reclaimed = db.claim_audit_webhook_outbox(10).await.unwrap();
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].id, second_id);
    assert_ne!(
        reclaimed[0].lease_owner.as_deref(),
        Some(second_owner.as_str())
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn scim_user_mutation_rejects_a_stale_row_snapshot() {
    let (db, path) = sqlite_test_db().await;
    let user = db
        .insert_user(test_user("scim-cas@example.test", "scim-cas"))
        .await
        .unwrap();
    let expected_version = user.scim_concurrency_version();
    db.set_user_password(&user.id, "new-password-hash".to_string())
        .await
        .unwrap();

    let result = db
        .apply_scim_user_mutation(ScimUserMutationPlan {
            id: user.id.clone(),
            expected_version,
            email: "scim-cas-renamed@example.test".to_string(),
            username: "scim-cas-renamed".to_string(),
            display_name: user.display_name.clone(),
            phone: user.phone.clone(),
            is_admin: user.is_admin == 1,
            is_active: user.is_active == 1,
            password_hash: None,
            scope: None,
        })
        .await;
    assert!(matches!(
        result,
        Err(AppError::OAuth {
            status: StatusCode::CONFLICT,
            ..
        })
    ));
    let unchanged = db.find_user_by_id(&user.id).await.unwrap().unwrap();
    assert_eq!(unchanged.email, "scim-cas@example.test");
    assert_eq!(unchanged.username, "scim-cas");
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn scim_user_mutation_rechecks_application_scope_inside_write_transaction() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("scim-scope", "SCIM Scope"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "scim-scope-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let user = db
        .insert_user(test_user("scim-scope@example.test", "scim-scope"))
        .await
        .unwrap();
    db.upsert_organization_member(
        &organization.id,
        &user.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();
    let expected_version = user.scim_concurrency_version();
    let user_id = user.id.clone();
    let organization_id = organization.id.clone();
    let application_id = application.id.clone();
    let sql_user_id = user_id.clone();
    let sql_organization_id = organization_id.clone();
    with_conn!(db.clone(), |conn, kind| {
        let sql = format!(
            "DELETE FROM organization_members WHERE organization_id = {} AND user_id = {}",
            ph(kind, 1),
            ph(kind, 2)
        );
        sql_query(sql)
            .bind::<Text, _>(&sql_organization_id)
            .bind::<Text, _>(&sql_user_id)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(AppError::from)
    })
    .unwrap();

    let result = db
        .apply_scim_user_mutation(ScimUserMutationPlan {
            id: user_id.clone(),
            expected_version,
            email: "scim-scope-renamed@example.test".to_string(),
            username: "scim-scope-renamed".to_string(),
            display_name: user.display_name.clone(),
            phone: user.phone.clone(),
            is_admin: user.is_admin == 1,
            is_active: user.is_active == 1,
            password_hash: None,
            scope: Some(ScimUserMutationScope {
                application_id: Some(application_id),
                organization_id: Some(organization_id),
            }),
        })
        .await;
    assert!(matches!(
        result,
        Err(AppError::OAuth {
            status: StatusCode::CONFLICT,
            ..
        })
    ));
    let unchanged = db.find_user_by_id(&user_id).await.unwrap().unwrap();
    assert_eq!(unchanged.email, "scim-scope@example.test");
    assert_eq!(unchanged.username, "scim-scope");

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn scim_group_patch_rejects_a_stale_aggregate_version() {
    let (db, path) = sqlite_test_db().await;
    let group = db
        .insert_group(NewGroup {
            name: "SCIM CAS group".to_string(),
            description: None,
        })
        .await
        .unwrap();
    let first = db
        .apply_group_patch_plan(GroupPatchPlan {
            application_id: None,
            group_id: group.id.clone(),
            name: "SCIM CAS group v2".to_string(),
            description: None,
            member_ids: Vec::new(),
            create: false,
            expected_version: Some(group.version),
        })
        .await
        .unwrap();
    assert_eq!(first.version, group.version + 1);
    let result = db
        .apply_group_patch_plan(GroupPatchPlan {
            application_id: None,
            group_id: group.id.clone(),
            name: "stale overwrite".to_string(),
            description: None,
            member_ids: Vec::new(),
            create: false,
            expected_version: Some(group.version),
        })
        .await;
    assert!(matches!(
        result,
        Err(AppError::OAuth {
            status: StatusCode::CONFLICT,
            ..
        })
    ));
    assert_eq!(
        db.find_group_by_id(&group.id).await.unwrap().unwrap().name,
        "SCIM CAS group v2"
    );
    drop(db);
    let _ = std::fs::remove_file(path);
}
