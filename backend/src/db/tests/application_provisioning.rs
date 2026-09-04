use super::*;
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_scim_group_create_rolls_back_binding_and_group_on_invalid_member() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("scim-group-create", "SCIM Group Create"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "scim-group-create-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let unbound_user = db
        .insert_user(test_user(
            "scim-group-unbound@example.com",
            "scim-group-unbound",
        ))
        .await
        .unwrap();
    let group_id = "scim-group-atomic-create".to_string();

    let result = db
        .apply_group_patch_plan(GroupPatchPlan {
            application_id: Some(application.id.clone()),
            group_id: group_id.clone(),
            name: "Atomic create".to_string(),
            description: None,
            member_ids: vec![unbound_user.id],
            create: true,
            expected_version: None,
        })
        .await;
    assert!(matches!(result, Err(AppError::BadRequest(_))));
    assert!(
        db.find_application_scim_group(&application.id, &group_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.list_application_scim_groups(&application.id)
            .await
            .unwrap()
            .is_empty()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn audited_application_mutations_commit_business_and_audit_together() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("audited-app", "Audited App"))
        .await
        .unwrap();
    let application = db
        .insert_application_with_audit(
            test_application(
                &organization.id,
                "audited-website",
                crate::applications::ACCESS_ALL_SIGNET_USERS,
            ),
            crate::audit::management_event(
                "actor",
                "application.create",
                "application",
                None,
                serde_json::json!({ "source": "test" }),
            ),
        )
        .await
        .unwrap();
    let module = db
        .upsert_application_module_with_audit(
            &application.id,
            "protocols",
            r#"{"oauth2_oidc":{"enabled":true}}"#,
            true,
            crate::audit::management_event(
                "actor",
                "application.module.update",
                "application",
                Some(application.id.clone()),
                serde_json::json!({ "module": "protocols" }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(module.is_enabled, 1);

    let jwt_client = db
        .upsert_application_jwt_client(
            &application.id,
            NewApplicationJwtClient {
                client_id: "audited-jwt".to_string(),
                client_type: "confidential".to_string(),
                is_active: true,
            },
        )
        .await
        .unwrap();
    let jwt_secret = db
        .rotate_application_jwt_secret_with_audit(
            &application.id,
            &jwt_client.client_id,
            &util::hash_password("audited-secret").unwrap(),
            300,
            crate::audit::management_event(
                "actor",
                "application.jwt_client.secret.rotate",
                "application",
                Some(application.id.clone()),
                serde_json::json!({ "client_id": jwt_client.client_id }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(jwt_secret.jwt_client_id, jwt_client.id);

    let token = db
        .insert_application_scim_token_with_audit(
            NewApplicationScimToken {
                id: "audited-scim-token".to_string(),
                application_id: application.id.clone(),
                token_prefix: "scim_v1_audited".to_string(),
                token_hash: util::token_hash("scim_v1_audited_secret"),
                scopes: vec!["scim.read".to_string()],
                expires_at: None,
            },
            crate::audit::management_event(
                "actor",
                "application.scim_token.create",
                "application",
                Some(application.id.clone()),
                serde_json::json!({ "token_id": "audited-scim-token" }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(token.token_hash, util::token_hash("scim_v1_audited_secret"));

    let events = db.list_audit_events(20).await.unwrap();
    for action in [
        "application.create",
        "application.module.update",
        "application.jwt_client.secret.rotate",
        "application.scim_token.create",
    ] {
        assert!(
            events.iter().any(|event| event.action == action
                && event.target_id.as_deref() == Some(application.id.as_str())),
            "missing committed audit event: {action}"
        );
    }

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_scim_tokens_are_hash_only_scoped_and_single_use_by_state() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("scim-token-org", "SCIM Token Org"))
        .await
        .unwrap();
    let first = db
        .insert_application(test_application(
            &organization.id,
            "scim-first",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let second = db
        .insert_application(test_application(
            &organization.id,
            "scim-second",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let raw_token = "scim_v1_first_secret";
    let token = db
        .insert_application_scim_token(NewApplicationScimToken {
            id: "scim-token-first".to_string(),
            application_id: first.id.clone(),
            token_prefix: "scim_v1_first".to_string(),
            token_hash: util::token_hash(raw_token),
            scopes: vec!["scim.read".to_string()],
            expires_at: None,
        })
        .await
        .unwrap();
    assert_eq!(token.token_hash, util::token_hash(raw_token));
    assert_eq!(token.scopes, r#"["scim.read"]"#);
    assert!(
        db.find_active_application_scim_token(&util::token_hash(raw_token))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        db.find_active_application_scim_token(&util::token_hash("wrong"))
            .await
            .unwrap()
            .is_none()
    );

    db.touch_application_scim_token(&util::token_hash(raw_token))
        .await
        .unwrap();
    let touched = db
        .find_active_application_scim_token(&util::token_hash(raw_token))
        .await
        .unwrap()
        .unwrap();
    assert!(touched.last_used_at.is_some());

    let expired = "scim_v1_expired";
    db.insert_application_scim_token(NewApplicationScimToken {
        id: "scim-token-expired".to_string(),
        application_id: first.id.clone(),
        token_prefix: "scim_v1_expired".to_string(),
        token_hash: util::token_hash(expired),
        scopes: vec!["scim.read".to_string(), "scim.write".to_string()],
        expires_at: Some(util::now_ts() - 1),
    })
    .await
    .unwrap();
    assert!(
        db.find_active_application_scim_token(&util::token_hash(expired))
            .await
            .unwrap()
            .is_none()
    );

    let second_raw = "scim_v1_second_secret";
    db.insert_application_scim_token(NewApplicationScimToken {
        id: "scim-token-second".to_string(),
        application_id: second.id.clone(),
        token_prefix: "scim_v1_second".to_string(),
        token_hash: util::token_hash(second_raw),
        scopes: vec!["scim.write".to_string()],
        expires_at: None,
    })
    .await
    .unwrap();
    db.revoke_application_scim_token(&first.id, "scim-token-second")
        .await
        .unwrap();
    assert!(
        db.find_active_application_scim_token(&util::token_hash(second_raw))
            .await
            .unwrap()
            .is_some()
    );
    db.revoke_application_scim_token(&second.id, "scim-token-second")
        .await
        .unwrap();
    assert!(
        db.find_active_application_scim_token(&util::token_hash(second_raw))
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn directory_sync_deprovision_preserves_manual_members_and_other_owners() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization(
            "directory-boundary",
            "Directory Boundary",
        ))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "directory-boundary-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let other_application = db
        .insert_application(test_application(
            &organization.id,
            "directory-boundary-other-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();

    let manual = db
        .insert_user(test_user("manual@example.com", "manual"))
        .await
        .unwrap();
    db.upsert_organization_member(
        &organization.id,
        &manual.id,
        crate::organizations::ROLE_ADMIN,
    )
    .await
    .unwrap();
    db.upsert_directory_sync_membership(
        &application.id,
        "ldap-primary",
        &manual.id,
        false,
        util::now_ts(),
    )
    .await
    .unwrap();
    assert!(
        !db.deprovision_directory_sync_membership(
            &application.id,
            "ldap-primary",
            &organization.id,
            &manual.id,
        )
        .await
        .unwrap()
    );
    assert_eq!(
        db.list_organization_members(&organization.id)
            .await
            .unwrap()
            .into_iter()
            .find(|member| member.user_id == manual.id)
            .unwrap()
            .role,
        crate::organizations::ROLE_ADMIN
    );

    let synced = db
        .insert_user(test_user("synced@example.com", "synced"))
        .await
        .unwrap();
    db.upsert_organization_member(
        &organization.id,
        &synced.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();
    db.upsert_directory_sync_membership(
        &application.id,
        "ldap-primary",
        &synced.id,
        true,
        util::now_ts() + 10,
    )
    .await
    .unwrap();
    assert!(
        db.deprovision_directory_sync_membership(
            &application.id,
            "ldap-primary",
            &organization.id,
            &synced.id,
        )
        .await
        .unwrap()
    );
    assert!(
        !db.user_belongs_to_organization(&organization.id, &synced.id)
            .await
            .unwrap()
    );

    let shared = db
        .insert_user(test_user("shared@example.com", "shared"))
        .await
        .unwrap();
    db.upsert_organization_member(
        &organization.id,
        &shared.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();
    db.upsert_directory_sync_membership(
        &application.id,
        "ldap-primary",
        &shared.id,
        true,
        util::now_ts() + 10,
    )
    .await
    .unwrap();
    db.upsert_directory_sync_membership(
        &other_application.id,
        "ldap-secondary",
        &shared.id,
        true,
        util::now_ts() + 10,
    )
    .await
    .unwrap();
    assert!(
        !db.deprovision_directory_sync_membership(
            &application.id,
            "ldap-primary",
            &organization.id,
            &shared.id,
        )
        .await
        .unwrap()
    );
    assert!(
        db.user_belongs_to_organization(&organization.id, &shared.id)
            .await
            .unwrap()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_scim_groups_are_application_and_organization_scoped() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("group-boundary", "Group Boundary"))
        .await
        .unwrap();
    let other_organization = db
        .insert_organization(test_organization(
            "other-group-boundary",
            "Other Group Boundary",
        ))
        .await
        .unwrap();
    let first = db
        .insert_application(test_application(
            &organization.id,
            "group-first",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let second = db
        .insert_application(test_application(
            &organization.id,
            "group-second",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let same_org_user = db
        .insert_user(test_user("same-org@example.com", "same-org"))
        .await
        .unwrap();
    let other_org_user = db
        .insert_user(test_user("other-org@example.com", "other-org"))
        .await
        .unwrap();
    db.upsert_organization_member(
        &organization.id,
        &same_org_user.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();
    db.upsert_organization_member(
        &other_organization.id,
        &other_org_user.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();

    let group = db
        .insert_application_scim_group(
            &first.id,
            NewGroup {
                name: "Directory group".to_string(),
                description: None,
            },
        )
        .await
        .unwrap();
    db.replace_application_scim_group_members(&first.id, &group.id, vec![same_org_user.id.clone()])
        .await
        .unwrap();
    assert_eq!(
        db.list_application_scim_group_members(&first.id, &group.id)
            .await
            .unwrap()
            .len(),
        1
    );
    let (user_total, users) = db
        .list_users_page(
            UserListScope::Live,
            Some(&organization.id),
            Some(UserListFilter::UserName("SAME-ORG".to_string())),
            0,
            10,
        )
        .await
        .unwrap();
    assert_eq!(user_total, 1);
    assert_eq!(users[0].id, same_org_user.id);
    let (group_total, groups) = db
        .list_groups_page(
            Some(&first.id),
            Some(GroupListFilter::DisplayName("DIRECTORY GROUP".to_string())),
            0,
            10,
        )
        .await
        .unwrap();
    assert_eq!(group_total, 1);
    assert_eq!(groups[0].id, group.id);
    let member_refs = db
        .list_scim_group_member_refs_page(
            Some(&first.id),
            Some(GroupListFilter::Id(group.id.clone())),
            0,
            10,
        )
        .await
        .unwrap();
    assert_eq!(member_refs.len(), 1);
    assert_eq!(member_refs[0].user_id, same_org_user.id);
    assert!(
        db.list_application_scim_groups(&second.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db.find_application_scim_group(&second.id, &group.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.replace_application_scim_group_members(&first.id, &group.id, vec![other_org_user.id],)
            .await
            .is_err()
    );

    db.delete_application_scim_group(&first.id, &group.id)
        .await
        .unwrap();
    assert!(db.find_group_by_id(&group.id).await.unwrap().is_none());

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn active_signet_accounts_do_not_need_application_membership() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("active-account", "Active Account"))
        .await
        .unwrap();
    let user = db
        .insert_user(test_user("active@example.com", "active"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "active-website",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();

    assert!(
        db.user_can_access_application(&application, &user.id)
            .await
            .unwrap()
    );

    // A historical application_members row is not a login gate and does
    // not trigger a self-enrollment write on the next login.
    db.replace_application_members(
        &application.id,
        vec![NewApplicationMember {
            user_id: user.id.clone(),
            role: "member".to_string(),
            is_active: false,
        }],
    )
    .await
    .unwrap();
    assert!(
        db.user_can_access_application(&application, &user.id)
            .await
            .unwrap()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_identity_factor_collision_is_local_and_roster_updates_release_it() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("factor-co", "Factor Co"))
        .await
        .unwrap();
    let first = db
        .insert_user(test_user("first@example.com", "first"))
        .await
        .unwrap();
    let second = db
        .insert_user(test_user("second@example.com", "second"))
        .await
        .unwrap();
    for user in [&first, &second] {
        db.upsert_organization_member(
            &organization.id,
            &user.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
    }
    let application = db
        .insert_application(test_application(
            &organization.id,
            "unique-contact",
            crate::applications::ACCESS_ASSIGNED_ACCOUNTS,
        ))
        .await
        .unwrap();
    db.replace_application_members(
        &application.id,
        vec![
            NewApplicationMember {
                user_id: first.id.clone(),
                role: "member".to_string(),
                is_active: true,
            },
            NewApplicationMember {
                user_id: second.id.clone(),
                role: "member".to_string(),
                is_active: true,
            },
        ],
    )
    .await
    .unwrap();
    db.replace_application_identity_bindings(
        &application.id,
        &first.id,
        vec![(
            crate::applications::FACTOR_EMAIL.to_string(),
            "digest".to_string(),
        )],
    )
    .await
    .unwrap();
    assert!(
        !db.application_identity_factor_is_available(
            &application.id,
            crate::applications::FACTOR_EMAIL,
            "digest",
            &second.id,
        )
        .await
        .unwrap()
    );
    // Keeping an unchanged assigned-account roster must not temporarily
    // release the first member's uniqueness reservation.
    db.replace_application_members(
        &application.id,
        vec![
            NewApplicationMember {
                user_id: first.id.clone(),
                role: "member".to_string(),
                is_active: true,
            },
            NewApplicationMember {
                user_id: second.id.clone(),
                role: "member".to_string(),
                is_active: true,
            },
        ],
    )
    .await
    .unwrap();
    assert!(
        !db.application_identity_factor_is_available(
            &application.id,
            crate::applications::FACTOR_EMAIL,
            "digest",
            &second.id,
        )
        .await
        .unwrap()
    );
    db.replace_application_members(
        &application.id,
        vec![NewApplicationMember {
            user_id: second.id.clone(),
            role: "member".to_string(),
            is_active: true,
        }],
    )
    .await
    .unwrap();
    assert!(
        db.application_identity_factor_is_available(
            &application.id,
            crate::applications::FACTOR_EMAIL,
            "digest",
            &second.id,
        )
        .await
        .unwrap()
    );

    // The same preservation rule applies to an enterprise roster edit:
    // a member that stays in the tenant keeps the reservation, while a
    // removed member releases it.
    db.replace_application_members(
        &application.id,
        vec![
            NewApplicationMember {
                user_id: first.id.clone(),
                role: "member".to_string(),
                is_active: true,
            },
            NewApplicationMember {
                user_id: second.id.clone(),
                role: "member".to_string(),
                is_active: true,
            },
        ],
    )
    .await
    .unwrap();
    db.replace_application_identity_bindings(
        &application.id,
        &first.id,
        vec![(
            crate::applications::FACTOR_EMAIL.to_string(),
            "digest".to_string(),
        )],
    )
    .await
    .unwrap();
    db.replace_organization_members(
        &organization.id,
        vec![
            OrganizationMemberInput {
                user_id: first.id.clone(),
                role: crate::organizations::ROLE_MEMBER.to_string(),
            },
            OrganizationMemberInput {
                user_id: second.id.clone(),
                role: crate::organizations::ROLE_MEMBER.to_string(),
            },
        ],
    )
    .await
    .unwrap();
    assert!(
        !db.application_identity_factor_is_available(
            &application.id,
            crate::applications::FACTOR_EMAIL,
            "digest",
            &second.id,
        )
        .await
        .unwrap()
    );
    db.replace_organization_members(
        &organization.id,
        vec![OrganizationMemberInput {
            user_id: second.id.clone(),
            role: crate::organizations::ROLE_MEMBER.to_string(),
        }],
    )
    .await
    .unwrap();
    assert!(
        db.application_identity_factor_is_available(
            &application.id,
            crate::applications::FACTOR_EMAIL,
            "digest",
            &second.id,
        )
        .await
        .unwrap()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn contact_changes_and_deactivation_release_the_correct_identity_leases() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("contact-leases", "Contact Leases"))
        .await
        .unwrap();
    let mut first_input = test_user("first-contact@example.com", "first-contact");
    first_input.phone = Some("+12025550123".to_string());
    first_input.email_verified_at = Some(util::now_ts());
    first_input.phone_verified_at = Some(util::now_ts());
    let first = db.insert_user(first_input).await.unwrap();
    let second = db
        .insert_user(test_user("second-contact@example.com", "second-contact"))
        .await
        .unwrap();
    for user in [&first, &second] {
        db.upsert_organization_member(
            &organization.id,
            &user.id,
            crate::organizations::ROLE_MEMBER,
        )
        .await
        .unwrap();
    }
    let application = db
        .insert_application(test_application(
            &organization.id,
            "contact-uniqueness",
            crate::applications::ACCESS_ASSIGNED_ACCOUNTS,
        ))
        .await
        .unwrap();
    db.replace_application_members(
        &application.id,
        vec![
            NewApplicationMember {
                user_id: first.id.clone(),
                role: "member".to_string(),
                is_active: true,
            },
            NewApplicationMember {
                user_id: second.id.clone(),
                role: "member".to_string(),
                is_active: true,
            },
        ],
    )
    .await
    .unwrap();
    let leases = || {
        vec![
            (
                crate::applications::FACTOR_EMAIL.to_string(),
                "old-email".to_string(),
            ),
            (
                crate::applications::FACTOR_PHONE.to_string(),
                "phone".to_string(),
            ),
        ]
    };
    db.replace_application_identity_bindings(&application.id, &first.id, leases())
        .await
        .unwrap();

    let updated = db
        .update_user(UserUpdate {
            id: &first.id,
            email: "first-contact-new@example.com".to_string(),
            username: first.username.clone(),
            display_name: first.display_name.clone(),
            phone: first.phone.clone(),
            is_admin: first.is_admin == 1,
            is_active: true,
        })
        .await
        .unwrap();
    assert!(updated.email_verified_at.is_none());
    assert!(updated.phone_verified_at.is_some());
    assert!(
        db.application_identity_factor_is_available(
            &application.id,
            crate::applications::FACTOR_EMAIL,
            "old-email",
            &second.id,
        )
        .await
        .unwrap()
    );
    assert!(
        !db.application_identity_factor_is_available(
            &application.id,
            crate::applications::FACTOR_PHONE,
            "phone",
            &second.id,
        )
        .await
        .unwrap()
    );

    let updated = db
        .update_user(UserUpdate {
            id: &updated.id,
            email: updated.email.clone(),
            username: updated.username.clone(),
            display_name: updated.display_name.clone(),
            phone: Some("+12025550124".to_string()),
            is_admin: updated.is_admin == 1,
            is_active: true,
        })
        .await
        .unwrap();
    assert!(updated.phone_verified_at.is_none());
    assert!(
        db.application_identity_factor_is_available(
            &application.id,
            crate::applications::FACTOR_PHONE,
            "phone",
            &second.id,
        )
        .await
        .unwrap()
    );

    // Deactivation through the profile update, the dedicated disable
    // endpoint and archival all release every remaining lease.
    db.replace_application_identity_bindings(&application.id, &updated.id, leases())
        .await
        .unwrap();
    let deactivated = db
        .update_user(UserUpdate {
            id: &updated.id,
            email: updated.email.clone(),
            username: updated.username.clone(),
            display_name: updated.display_name.clone(),
            phone: updated.phone.clone(),
            is_admin: updated.is_admin == 1,
            is_active: false,
        })
        .await
        .unwrap();
    assert_eq!(deactivated.is_active, 0);
    for (factor, digest) in leases() {
        assert!(
            db.application_identity_factor_is_available(
                &application.id,
                &factor,
                &digest,
                &second.id,
            )
            .await
            .unwrap()
        );
    }

    db.enable_user(&updated.id).await.unwrap();
    db.replace_application_identity_bindings(&application.id, &updated.id, leases())
        .await
        .unwrap();
    db.disable_user(&updated.id).await.unwrap();
    for (factor, digest) in leases() {
        assert!(
            db.application_identity_factor_is_available(
                &application.id,
                &factor,
                &digest,
                &second.id,
            )
            .await
            .unwrap()
        );
    }

    db.enable_user(&updated.id).await.unwrap();
    db.replace_application_identity_bindings(&application.id, &updated.id, leases())
        .await
        .unwrap();
    db.archive_user(&updated.id).await.unwrap();
    for (factor, digest) in leases() {
        assert!(
            db.application_identity_factor_is_available(
                &application.id,
                &factor,
                &digest,
                &second.id,
            )
            .await
            .unwrap()
        );
    }

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn browser_context_accounts_are_ordered_by_session_login_time() {
    let (db, path) = sqlite_test_db().await;
    let older_user = db
        .insert_user(test_user("older-session@example.com", "older-session"))
        .await
        .unwrap();
    let newer_user = db
        .insert_user(test_user("newer-session@example.com", "newer-session"))
        .await
        .unwrap();
    let context_id = "browser-context-login-time";
    db.insert_browser_context(context_id, "csrf", 600)
        .await
        .unwrap();
    let (older_session, _) = db
        .insert_session(&older_user.id, 600, SessionMetadata::default())
        .await
        .unwrap();
    let (newer_session, _) = db
        .insert_session(&newer_user.id, 600, SessionMetadata::default())
        .await
        .unwrap();
    let older_account = db
        .attach_browser_context_account(context_id, &older_user.id, &older_session.id)
        .await
        .unwrap();
    let newer_account = db
        .attach_browser_context_account(context_id, &newer_user.id, &newer_session.id)
        .await
        .unwrap();

    // Make selection recency deliberately disagree with login recency.
    // The list must follow the session's successful-login timestamp.
    let older_session_id = older_session.id.clone();
    let newer_session_id = newer_session.id.clone();
    let older_account_id = older_account.id.clone();
    let newer_account_id = newer_account.id.clone();
    with_conn!(db, |conn, kind| {
        let update_session = format!(
            "UPDATE sessions SET created_at = {} WHERE id = {}",
            ph(kind, 1),
            ph(kind, 2)
        );
        sql_query(&update_session)
            .bind::<BigInt, _>(10)
            .bind::<Text, _>(older_session_id)
            .execute(&mut conn)
            .map_err(AppError::from)?;
        sql_query(update_session)
            .bind::<BigInt, _>(20)
            .bind::<Text, _>(newer_session_id)
            .execute(&mut conn)
            .map_err(AppError::from)?;

        let update_selection = format!(
            "UPDATE browser_context_accounts SET last_selected_at = {} WHERE id = {}",
            ph(kind, 1),
            ph(kind, 2)
        );
        sql_query(&update_selection)
            .bind::<BigInt, _>(30)
            .bind::<Text, _>(older_account_id)
            .execute(&mut conn)
            .map_err(AppError::from)?;
        sql_query(update_selection)
            .bind::<BigInt, _>(5)
            .bind::<Text, _>(newer_account_id)
            .execute(&mut conn)
            .map_err(AppError::from)
    })
    .unwrap();

    let accounts = db.list_browser_context_accounts(context_id).await.unwrap();
    assert_eq!(accounts.len(), 2);
    assert_eq!(accounts[0].id, newer_account.id);
    assert_eq!(accounts[1].id, older_account.id);

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn bulk_provisioning_creates_memberships_and_rolls_back_the_entire_batch() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(NewOrganization {
            slug: "corp".to_string(),
            name: "Corp".to_string(),
            kind: ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            allowed_email_domains: vec!["example.com".to_string()],
            is_active: true,
        })
        .await
        .unwrap();

    let rejected = db
        .insert_bulk_provisioned_users(vec![
            test_bulk_user(
                "first@example.com",
                "first",
                Some(&organization.id),
                Some(crate::organizations::ROLE_MEMBER),
            ),
            test_bulk_user(
                "blocked@other.test",
                "blocked",
                Some(&organization.id),
                Some(crate::organizations::ROLE_ADMIN),
            ),
        ])
        .await;
    assert!(matches!(
        rejected,
        Err(AppError::BadRequest(message))
            if message == "email is not allowed by the organization policy"
    ));
    assert!(
        db.find_user_by_email("first@example.com")
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

    let created = db
        .insert_bulk_provisioned_users(vec![
            test_bulk_user(
                "owner@example.com",
                "owner",
                Some(&organization.id),
                Some(crate::organizations::ROLE_OWNER),
            ),
            test_bulk_user(
                "member@example.com",
                "member",
                Some(&organization.id),
                Some(crate::organizations::ROLE_MEMBER),
            ),
        ])
        .await
        .unwrap();
    assert_eq!(created.len(), 2);
    let memberships = db
        .list_organization_members(&organization.id)
        .await
        .unwrap();
    assert_eq!(memberships.len(), 2);
    assert!(memberships.iter().any(|membership| {
        membership.user_id == created[0].id && membership.role == crate::organizations::ROLE_OWNER
    }));
    assert!(memberships.iter().any(|membership| {
        membership.user_id == created[1].id && membership.role == crate::organizations::ROLE_MEMBER
    }));

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn bulk_provisioning_never_overwrites_an_existing_identity() {
    let (db, path) = sqlite_test_db().await;
    let existing = db
        .insert_user(test_user("existing@example.com", "existing"))
        .await
        .unwrap();

    let result = db
        .insert_bulk_provisioned_users(vec![test_bulk_user(
            "existing@example.com",
            "different",
            None,
            None,
        )])
        .await;
    assert!(matches!(
        result,
        Err(AppError::BadRequest(message))
            if message == "user email or username already exists"
    ));
    let after = db
        .find_user_by_email("existing@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.id, existing.id);
    assert_eq!(after.username, "existing");
    assert!(
        db.find_user_by_username("different")
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn trial_enrollment_code_creates_only_new_restricted_organization_members() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(NewOrganization {
            slug: "trial-team".to_string(),
            name: "Trial Team".to_string(),
            kind: ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            allowed_email_domains: vec!["example.com".to_string()],
            is_active: true,
        })
        .await
        .unwrap();
    db.insert_user(test_user("taken@example.com", "taken"))
        .await
        .unwrap();
    let mut invitation = test_invitation(
        AuthorizationCodeType::Login,
        LoginCodeLevel::TrialEnrollment,
        None,
        None,
        vec!["trial-client".to_string()],
    );
    invitation.organization_id = Some(organization.id.clone());
    invitation.organization_role = Some(crate::organizations::ROLE_MEMBER.to_string());
    invitation.expires_at = Some(util::now_ts() + 300);
    invitation.max_uses = Some(2);
    let (stored, code) = db.insert_invitation(invitation).await.unwrap();

    let collision = db
        .redeem_trial_enrollment_code_for_new_user(
            &code,
            NewTrialEnrollmentUser {
                email: "taken@example.com".to_string(),
                username: "new-name".to_string(),
                display_name: None,
                password_hash: "hash".to_string(),
            },
        )
        .await;
    assert!(
        matches!(collision, Err(AppError::BadRequest(message)) if message.contains("existing account"))
    );
    assert_eq!(
        db.find_invitation_by_id(&stored.id)
            .await
            .unwrap()
            .unwrap()
            .uses_count,
        0
    );

    let redemption = db
        .redeem_trial_enrollment_code_for_new_user(
            &code,
            NewTrialEnrollmentUser {
                email: "visitor@example.com".to_string(),
                username: "visitor".to_string(),
                display_name: Some("Visitor".to_string()),
                password_hash: "hash".to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(redemption.organization_id, organization.id);
    assert_eq!(redemption.user.is_admin, 0);
    assert_eq!(
        redemption.user.registration_source,
        UserRegistrationSource::AuthorizationCode.as_str()
    );
    let enrollment = db
        .find_trial_enrollment_for_user(&redemption.user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(enrollment.invitation_id, stored.id);
    assert!(enrollment.allows_client("trial-client").unwrap());
    assert!(!enrollment.allows_client("other-client").unwrap());
    let members = db
        .list_organization_members(&organization.id)
        .await
        .unwrap();
    assert!(members.iter().any(|member| {
        member.user_id == redemption.user.id && member.role == crate::organizations::ROLE_MEMBER
    }));
    let authorization_code_users = db
        .list_users(UserListScope::AuthorizationCode)
        .await
        .unwrap();
    assert_eq!(authorization_code_users.len(), 1);
    assert_eq!(authorization_code_users[0].id, redemption.user.id);

    db.update_invitation(InvitationUpdate {
        id: &stored.id,
        description: None,
        authorized_email: None,
        authorized_username: None,
        authorized_display_name: None,
        expires_at: Some(util::now_ts() + 300),
        max_uses: Some(2),
        is_active: false,
    })
    .await
    .unwrap();
    let revoked = db
        .find_trial_enrollment_for_user(&redemption.user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(revoked.revoked_at.is_some());
    assert!(
        db.find_active_trial_enrollment_for_user(&redemption.user.id)
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}
