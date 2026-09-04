use super::*;
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn deleting_an_organization_removes_members_and_cleans_authorization_codes() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(NewOrganization {
            slug: "deleted-team".to_string(),
            name: "Deleted Team".to_string(),
            kind: ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            allowed_email_domains: vec!["example.com".to_string()],
            is_active: true,
        })
        .await
        .unwrap();
    let member = db
        .insert_user(test_user("member@example.com", "member"))
        .await
        .unwrap();
    db.replace_organization_members(
        &organization.id,
        vec![OrganizationMemberInput {
            user_id: member.id.clone(),
            role: crate::organizations::ROLE_MEMBER.to_string(),
        }],
    )
    .await
    .unwrap();

    let mut trial_code = test_invitation(
        AuthorizationCodeType::Login,
        LoginCodeLevel::TrialEnrollment,
        None,
        None,
        vec!["trial-client".to_string()],
    );
    trial_code.organization_id = Some(organization.id.clone());
    trial_code.organization_role = Some(crate::organizations::ROLE_MEMBER.to_string());
    trial_code.expires_at = Some(util::now_ts() + 300);
    trial_code.max_uses = Some(2);
    let (trial_invitation, trial_secret) = db.insert_invitation(trial_code).await.unwrap();
    let trial_user = db
        .redeem_trial_enrollment_code_for_new_user(
            &trial_secret,
            NewTrialEnrollmentUser {
                email: "trial-user@example.com".to_string(),
                username: "trial-user".to_string(),
                display_name: None,
                password_hash: "hash".to_string(),
            },
        )
        .await
        .unwrap()
        .user;

    // The API rejects this shape, but old/manual data can contain it.
    // It has an independent allowed-client scope, so deletion removes only
    // the stale organization metadata instead of destroying the code.
    let mut legacy_code = test_invitation(
        AuthorizationCodeType::Login,
        LoginCodeLevel::AdminUniversal,
        None,
        None,
        vec!["other-client".to_string()],
    );
    legacy_code.organization_id = Some(organization.id.clone());
    legacy_code.organization_role = Some(crate::organizations::ROLE_ADMIN.to_string());
    let (legacy_invitation, _) = db.insert_invitation(legacy_code).await.unwrap();

    assert_eq!(
        db.list_organization_member_counts()
            .await
            .unwrap()
            .get(&organization.id),
        Some(&2)
    );

    db.delete_organization(&organization.id).await.unwrap();

    assert!(
        db.find_organization_by_id(&organization.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.list_organization_members(&organization.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db.list_user_organizations(&member.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db.list_user_organizations(&trial_user.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db.find_invitation_by_id(&trial_invitation.id)
            .await
            .unwrap()
            .is_none()
    );

    let enrollment = db
        .find_trial_enrollment_for_user(&trial_user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(enrollment.revoked_at.is_some());
    assert!(
        db.find_active_trial_enrollment_for_user(&trial_user.id)
            .await
            .unwrap()
            .is_none()
    );

    let legacy_after = db
        .find_invitation_by_id(&legacy_invitation.id)
        .await
        .unwrap()
        .unwrap();
    assert!(legacy_after.organization_id.is_none());
    assert!(legacy_after.organization_role.is_none());

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn account_recovery_code_stays_bound_to_the_user_id_after_a_username_rename() {
    let (db, path) = sqlite_test_db().await;
    let user = db
        .insert_user(test_user("rename-target@example.com", "rename-target"))
        .await
        .unwrap();
    let (invitation, code) = db
        .insert_invitation(test_invitation(
            AuthorizationCodeType::Login,
            LoginCodeLevel::AccountRecovery,
            Some("rename-target"),
            Some(&user.id),
            Vec::new(),
        ))
        .await
        .unwrap();
    db.update_user(UserUpdate {
        id: &user.id,
        email: user.email.clone(),
        username: "renamed-target".to_string(),
        display_name: user.display_name.clone(),
        phone: user.phone.clone(),
        is_admin: false,
        is_active: true,
    })
    .await
    .unwrap();

    let original_name = db
        .redeem_account_recovery_code(&code, &user.id, &user.email)
        .await
        .unwrap();
    let current_name = db
        .redeem_account_recovery_code(&code, &user.id, &user.email)
        .await
        .unwrap();

    assert!(
        db.redeem_account_recovery_code(&code, &user.id, "different@example.com")
            .await
            .is_err()
    );

    assert_eq!(original_name.user.id, user.id);
    assert_eq!(current_name.user.id, user.id);
    let stored = db
        .find_invitation_by_id(&invitation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.authorized_user_id.as_deref(), Some(user.id.as_str()));
    assert_eq!(stored.uses_count, 2);

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn account_recovery_code_never_falls_back_after_bound_user_deletion() {
    let (db, path) = sqlite_test_db().await;
    let original = db
        .insert_user(test_user("deleted-target@example.com", "reused-name"))
        .await
        .unwrap();
    let (invitation, code) = db
        .insert_invitation(test_invitation(
            AuthorizationCodeType::Login,
            LoginCodeLevel::AccountRecovery,
            Some("reused-name"),
            Some(&original.id),
            Vec::new(),
        ))
        .await
        .unwrap();
    db.permanently_delete_user(&original.id).await.unwrap();
    let replacement = db
        .insert_user(test_user("replacement@example.com", "reused-name"))
        .await
        .unwrap();

    assert!(
        db.redeem_account_recovery_code(&code, &replacement.id, &replacement.email)
            .await
            .is_err()
    );
    let stored = db
        .find_invitation_by_id(&invitation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.authorized_user_id.as_deref(),
        Some(original.id.as_str())
    );
    assert_eq!(stored.is_active, 0);
    assert_eq!(stored.uses_count, 0);
    assert_ne!(replacement.id, original.id);

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn account_recovery_code_rejects_an_unbound_or_missing_account() {
    let (db, path) = sqlite_test_db().await;
    let (invitation, code) = db
        .insert_invitation(test_invitation(
            AuthorizationCodeType::Login,
            LoginCodeLevel::AccountRecovery,
            Some("new-temporary-user"),
            None,
            Vec::new(),
        ))
        .await
        .unwrap();

    assert!(
        db.redeem_account_recovery_code(&code, "missing-user-id", "missing@example.com")
            .await
            .is_err()
    );
    assert!(
        db.find_user_by_username("new-temporary-user")
            .await
            .unwrap()
            .is_none()
    );
    let stored = db
        .find_invitation_by_id(&invitation.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.authorized_user_id, None);
    assert_eq!(stored.uses_count, 0);

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn temporary_account_detection_ignores_registration_and_universal_redemptions() {
    let (db, path) = sqlite_test_db().await;
    let (registration, registration_code) = db
        .insert_invitation(test_invitation(
            AuthorizationCodeType::Registration,
            LoginCodeLevel::AccountRecovery,
            None,
            None,
            Vec::new(),
        ))
        .await
        .unwrap();
    let registered = db
        .redeem_registration_code_for_new_user(
            &registration_code,
            test_user("registered-only@example.com", "registered-only"),
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        registered.registration_source,
        UserRegistrationSource::AuthorizationCode.as_str()
    );
    assert!(
        !db.user_has_invitation_redemption(&registered.id)
            .await
            .unwrap()
    );

    let universal_user = db
        .insert_user(test_user("universal-only@example.com", "universal-only"))
        .await
        .unwrap();
    assert_eq!(
        universal_user.registration_source,
        UserRegistrationSource::Local.as_str()
    );
    let (_universal, universal_code) = db
        .insert_invitation(test_invitation(
            AuthorizationCodeType::Login,
            LoginCodeLevel::AdminUniversal,
            None,
            None,
            vec!["client-a".to_string()],
        ))
        .await
        .unwrap();
    assert!(
            db.redeem_account_recovery_code(
                &universal_code,
                &universal_user.id,
                &universal_user.email,
            )
            .await
            .is_err()
        );
    db.redeem_admin_login_code_for_oidc_grant(AdminLoginCodeRedemptionInput {
        code: &universal_code,
        user_id: &universal_user.id,
        email: &universal_user.email,
        trusted_client_id: "client-a",
        interaction_request_hash: "universal-interaction-hash",
        credential_hash: "universal-credential-hash",
        ttl_seconds: 60,
    })
    .await
    .unwrap();
    assert!(
        !db.user_has_invitation_redemption(&universal_user.id)
            .await
            .unwrap()
    );

    let recovery_user = db
        .insert_user(test_user("recovery-only@example.com", "recovery-only"))
        .await
        .unwrap();
    assert_eq!(
        recovery_user.registration_source,
        UserRegistrationSource::Local.as_str()
    );
    let (_recovery, recovery_code) = db
        .insert_invitation(test_invitation(
            AuthorizationCodeType::Login,
            LoginCodeLevel::AccountRecovery,
            Some("recovery-only"),
            Some(&recovery_user.id),
            Vec::new(),
        ))
        .await
        .unwrap();
    db.redeem_account_recovery_code(&recovery_code, &recovery_user.id, &recovery_user.email)
        .await
        .unwrap();
    assert!(
        db.user_has_invitation_redemption(&recovery_user.id)
            .await
            .unwrap()
    );
    assert!(
        db.find_invitation_by_id(&registration.id)
            .await
            .unwrap()
            .is_some()
    );

    // Simulate an installation that existed before registration_source
    // was introduced. A repeated migration must restore only the account
    // that was actually created by a registration code, not an ordinary
    // user who later redeemed a login-only recovery code.
    let db_for_update = db.clone();
    let registered_id = registered.id.clone();
    with_conn!(db_for_update, |conn, kind| {
        let sql = format!(
            "UPDATE users SET registration_source = {} WHERE id = {}",
            ph(kind, 1),
            ph(kind, 2)
        );
        sql_query(sql)
            .bind::<Text, _>(UserRegistrationSource::Local.as_str())
            .bind::<Text, _>(registered_id)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(AppError::from)
    })
    .unwrap();
    db.migrate().await.unwrap();

    let backfilled_registered = db.find_user_by_id(&registered.id).await.unwrap().unwrap();
    let backfilled_recovery = db
        .find_user_by_id(&recovery_user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        backfilled_registered.registration_source,
        UserRegistrationSource::AuthorizationCode.as_str()
    );
    assert_eq!(
        backfilled_recovery.registration_source,
        UserRegistrationSource::Local.as_str()
    );
    let authorization_code_users = db
        .list_users(UserListScope::AuthorizationCode)
        .await
        .unwrap();
    assert_eq!(authorization_code_users.len(), 1);
    assert_eq!(authorization_code_users[0].id, registered.id);

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn disabling_an_invitation_revokes_outstanding_oidc_login_grants() {
    let (db, path) = sqlite_test_db().await;
    let user = db
        .insert_user(test_user("grant-revoke@example.com", "grant-revoke"))
        .await
        .unwrap();
    let (invitation, code) = db
        .insert_invitation(test_invitation(
            AuthorizationCodeType::Login,
            LoginCodeLevel::AdminUniversal,
            None,
            None,
            vec!["client-a".to_string()],
        ))
        .await
        .unwrap();
    db.redeem_admin_login_code_for_oidc_grant(AdminLoginCodeRedemptionInput {
        code: &code,
        user_id: &user.id,
        email: &user.email,
        trusted_client_id: "client-a",
        interaction_request_hash: "revoke-interaction-hash",
        credential_hash: "revoke-credential-hash",
        ttl_seconds: 60,
    })
    .await
    .unwrap();
    assert!(
        db.find_oidc_login_grant("revoke-credential-hash", "revoke-interaction-hash")
            .await
            .unwrap()
            .is_some()
    );

    let disabled = db
        .update_invitation(InvitationUpdate {
            id: &invitation.id,
            description: invitation.description.clone(),
            authorized_email: invitation.authorized_email.clone(),
            authorized_username: invitation.authorized_username.clone(),
            authorized_display_name: invitation.authorized_display_name.clone(),
            expires_at: invitation.expires_at,
            max_uses: invitation.max_uses,
            is_active: false,
        })
        .await
        .unwrap();
    assert_eq!(disabled.is_active, 0);
    assert!(
        db.find_oidc_login_grant("revoke-credential-hash", "revoke-interaction-hash")
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}
