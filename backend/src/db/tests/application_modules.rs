use super::*;
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_modules_are_persisted_independently_per_website() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("module-org", "Module Org"))
        .await
        .unwrap();
    let first = db
        .insert_application(test_application(
            &organization.id,
            "first-website",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let second = db
        .insert_application(test_application(
            &organization.id,
            "second-website",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();

    let protocols = db
        .upsert_application_module(
            &first.id,
            "protocols",
            r#"{"oauth2_oidc":{"enabled":true}}"#,
            true,
        )
        .await
        .unwrap();
    assert_eq!(protocols.application_id, first.id);
    assert_eq!(protocols.module_key, "protocols");
    assert_eq!(protocols.is_enabled, 1);

    db.upsert_application_module(
        &first.id,
        "authorization",
        r#"{"inherit_enterprise_roles":true,"permissions":["support.read"]}"#,
        false,
    )
    .await
    .unwrap();
    let modules = db.list_application_modules(&first.id).await.unwrap();
    assert_eq!(modules.len(), 2);
    assert_eq!(modules[0].module_key, "authorization");
    assert_eq!(modules[1].module_key, "protocols");

    let updated = db
        .upsert_application_module(
            &first.id,
            "protocols",
            r#"{"oauth2_oidc":{"enabled":false},"saml2":{"enabled":true}}"#,
            false,
        )
        .await
        .unwrap();
    assert_eq!(updated.is_enabled, 0);
    assert!(updated.config_json.contains("saml2"));
    assert!(
        db.list_application_modules(&second.id)
            .await
            .unwrap()
            .is_empty()
    );

    db.delete_application_module(&first.id, "authorization")
        .await
        .unwrap();
    let remaining = db.list_application_modules(&first.id).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].module_key, "protocols");

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_scim_group_patch_validates_members_in_the_bound_application() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("scim-group-bound", "SCIM Group Bound"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "scim-group-bound-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let group = db
        .insert_application_scim_group(
            &application.id,
            NewGroup {
                name: "Bound group".to_string(),
                description: None,
            },
        )
        .await
        .unwrap();
    let first = db
        .insert_user(test_user(
            "scim-group-first@example.com",
            "scim-group-first",
        ))
        .await
        .unwrap();
    let second = db
        .insert_user(test_user(
            "scim-group-second@example.com",
            "scim-group-second",
        ))
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

    db.apply_group_patch_plan(GroupPatchPlan {
        application_id: Some(application.id.clone()),
        group_id: group.id.clone(),
        name: "Bound group".to_string(),
        description: None,
        member_ids: vec![first.id.clone(), second.id.clone()],
        create: false,
        expected_version: None,
    })
    .await
    .unwrap();
    let members = db
        .list_application_scim_group_members(&application.id, &group.id)
        .await
        .unwrap();
    assert_eq!(
        members
            .into_iter()
            .map(|member| member.id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([first.id, second.id])
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}
