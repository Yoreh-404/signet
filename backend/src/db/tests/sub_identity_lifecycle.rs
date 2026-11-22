use super::*;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn anonymous_sub_identity_requires_explicit_active_website_opt_in() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("sub-policy", "Sub Identity Policy"))
        .await.unwrap();
    let app = db
        .insert_application(test_application(
            &organization.id, "sub-policy-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await.unwrap();
    let existing = db.insert_user(test_user("owner@example.test", "owner")).await.unwrap();
    assert!(!db.anonymous_sub_identity_creation_allowed(&app.id).await.unwrap());

    let rejected = db.insert_external_oidc_anonymous_sub_identity(
        test_user("no-auto@example.test", "no-auto"),
        "wechat-mini:example", "external-1", None, &app.id,
    ).await;
    assert!(matches!(rejected, Err(AppError::Forbidden)));
    assert!(db.find_user_by_email("no-auto@example.test").await.unwrap().is_none());
    assert!(db.find_linked_identity("wechat-mini:example", "external-1").await.unwrap().is_none());

    db.set_anonymous_sub_identity_creation_allowed(&app.id, true).await.unwrap();
    assert!(db.anonymous_sub_identity_creation_allowed(&app.id).await.unwrap());
    let sub = db.insert_external_oidc_anonymous_sub_identity(
        test_user("new-wechat@example.test", "wechat-sub"),
        "wechat-mini:example", "external-2", None, &app.id,
    ).await.unwrap();
    assert_ne!(sub.id, existing.id);
    assert_eq!(sub.is_admin, 0);
    assert_eq!(db.find_sub_identity(&sub.id).await.unwrap().unwrap().primary_user_id, None);
    assert_eq!(
        db.find_sub_identity(&sub.id).await.unwrap().unwrap().origin_application_id.as_deref(),
        Some(app.id.as_str()),
    );
    assert_eq!(
        db.find_linked_identity("wechat-mini:example", "external-2").await.unwrap().unwrap().user_id,
        sub.id,
    );

    db.set_anonymous_sub_identity_creation_allowed(&app.id, false).await.unwrap();
    assert!(!db.anonymous_sub_identity_creation_allowed(&app.id).await.unwrap());
    assert!(matches!(db.insert_external_oidc_anonymous_sub_identity(
        test_user("blocked@example.test", "blocked"), "wechat-mini:example", "external-3", None, &app.id,
    ).await, Err(AppError::Forbidden)));
    // Disabling creation does not delete or unbind existing Signet subjects.
    assert!(db.find_user_by_id(&sub.id).await.unwrap().is_some());
    assert!(db.find_linked_identity("wechat-mini:example", "external-2").await.unwrap().is_some());
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn managed_sub_identity_is_distinct_and_cannot_manage_another_sub_identity() {
    let (db, path) = sqlite_test_db().await;
    let mut owner_input = test_user("main-owner@example.test", "main-owner");
    owner_input.is_admin = true;
    let owner = db.insert_user(owner_input).await.unwrap();
    let independent_password = "independent-sub-password-2026";
    let mut child_input = test_user("child@example.test", "child");
    child_input.password_hash = util::hash_password(independent_password).unwrap();
    let child = db.create_managed_sub_identity(&owner.id, child_input).await.unwrap();
    assert_ne!(owner.id, child.id);
    assert_eq!(child.is_admin, 0, "sub-identity must not inherit primary admin rights");
    assert!(util::verify_password(&child.password_hash, independent_password),
        "child must retain independent Signet password authentication");
    assert_eq!(db.find_sub_identity(&child.id).await.unwrap().unwrap().primary_user_id.as_deref(), Some(owner.id.as_str()));
    assert_eq!(db.list_managed_sub_identities(&owner.id).await.unwrap().len(), 1);
    assert!(matches!(db.create_managed_sub_identity(
        &child.id, test_user("grandchild@example.test", "grandchild"),
    ).await, Err(AppError::Forbidden)));
    assert!(db.find_user_by_email("grandchild@example.test").await.unwrap().is_none());

    assert!(matches!(db.issue_anonymous_sub_identity_link_claim(&child.id).await, Err(AppError::Forbidden)));
    let wrong = db.create_managed_sub_identity(
        &owner.id, test_user("child@example.test", "different-name"),
    ).await;
    assert!(wrong.is_err());
    assert_eq!(db.list_managed_sub_identities(&owner.id).await.unwrap().len(), 1);
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn anonymous_sub_identity_link_is_explicit_one_time_and_detachable() {
    let (db, path) = sqlite_test_db().await;
    let alice = db.insert_user(test_user("alice-main@example.test", "alice-main")).await.unwrap();
    let bob = db.insert_user(test_user("bob-main@example.test", "bob-main")).await.unwrap();
    assert!(matches!(db.issue_anonymous_sub_identity_link_claim(&alice.id).await, Err(AppError::Forbidden)));
    let sub = db.create_managed_sub_identity(
        &alice.id, test_user("portable-sub@example.test", "portable-sub"),
    ).await.unwrap();
    db.detach_managed_sub_identity(&alice.id, &sub.id).await.unwrap();
    assert_eq!(db.find_sub_identity(&sub.id).await.unwrap().unwrap().primary_user_id, None);
    assert!(db.list_managed_sub_identities(&alice.id).await.unwrap().is_empty());

    let original_code = db.issue_anonymous_sub_identity_link_claim(&sub.id).await.unwrap();
    let code = db.issue_anonymous_sub_identity_link_claim(&sub.id).await.unwrap();
    assert!(matches!(db.attach_claimed_sub_identity(&bob.id, &original_code).await, Err(AppError::Unauthorized)));
    assert!(matches!(db.attach_claimed_sub_identity(&bob.id, "forged-claim-123456789012345678901234567890123456789").await, Err(AppError::Unauthorized)));
    db.attach_claimed_sub_identity(&bob.id, &code).await.unwrap();
    assert!(matches!(db.attach_claimed_sub_identity(&alice.id, &code).await, Err(AppError::Unauthorized)));
    assert!(matches!(db.detach_managed_sub_identity(&alice.id, &sub.id).await, Err(AppError::NotFound)));
    assert_eq!(db.find_sub_identity(&sub.id).await.unwrap().unwrap().primary_user_id.as_deref(), Some(bob.id.as_str()));
    db.detach_managed_sub_identity(&bob.id, &sub.id).await.unwrap();
    assert_eq!(db.find_sub_identity(&sub.id).await.unwrap().unwrap().primary_user_id, None);
    assert!(db.find_user_by_id(&sub.id).await.unwrap().is_some(), "detaching cannot destroy sub-account");
    drop(db);
    let _ = std::fs::remove_file(path);
}
