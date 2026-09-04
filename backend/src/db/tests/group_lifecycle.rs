use crate::{
    config::DatabaseKind,
    db::{AuthorizationBindingsUpdate, NewApplicationProfileRole, NewGroup},
    error::AppError,
};
use diesel::{RunQueryDsl, sql_query};
use std::collections::BTreeMap;

use super::{Db, blocking};

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn audited_group_mutation_rolls_back_when_audit_insert_fails() {
    let (db, path) = super::sqlite_test_db().await;
    let group = db
        .insert_group(NewGroup {
            name: "audited-group".to_string(),
            description: None,
        })
        .await
        .unwrap();
    let user = db
        .insert_user(super::test_user(
            "audited-group@example.com",
            "audited-group",
        ))
        .await
        .unwrap();

    with_conn!(db.clone(), |conn, _kind| {
        sql_query("DROP TABLE audit_events")
            .execute(&mut conn)
            .map(|_| ())
            .map_err(AppError::from)
    })
    .unwrap();

    assert!(
        db.replace_group_members_with_audit(
            &group.id,
            vec![user.id.clone()],
            crate::audit::management_event(
                "actor",
                "group.members.update",
                "group",
                Some(group.id.clone()),
                serde_json::json!({ "user_ids": [user.id] }),
            ),
        )
        .await
        .is_err()
    );
    assert!(db.list_group_members(&group.id).await.unwrap().is_empty());

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn deleting_group_cleans_application_and_profile_edges() {
    let (db, path) = super::sqlite_test_db().await;
    let organization = db
        .insert_organization(super::test_organization("group-delete", "Group Delete"))
        .await
        .unwrap();
    let application = db
        .insert_application(super::test_application(
            &organization.id,
            "group-delete-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let member = db
        .insert_user(super::test_user("group-delete@example.com", "group-delete"))
        .await
        .unwrap();
    db.upsert_organization_member(
        &organization.id,
        &member.id,
        crate::organizations::ROLE_MEMBER,
    )
    .await
    .unwrap();
    let group = db
        .insert_application_scim_group(
            &application.id,
            NewGroup {
                name: "application-group".to_string(),
                description: None,
            },
        )
        .await
        .unwrap();
    db.replace_group_members(&group.id, vec![member.id.clone()])
        .await
        .unwrap();
    let profile = super::default_authorization_profile(&db, &application.id).await;
    let role = db
        .upsert_application_profile_role(NewApplicationProfileRole {
            id: None,
            profile_id: profile.id.clone(),
            role_key: "group-role".to_string(),
            name: "group-role".to_string(),
            source: "manual".to_string(),
            description: None,
            permissions: vec!["group.read".to_string()],
            is_default: false,
            is_active: true,
        })
        .await
        .unwrap();
    super::replace_test_authorization_bindings(
        &db,
        &application.id,
        &profile.id,
        AuthorizationBindingsUpdate {
            user_id: None,
            group_id: Some(group.id.clone()),
            user_role_ids: Vec::new(),
            user_permission_overrides: Vec::new(),
            group_role_ids: vec![role.id],
            organization_role_bindings: BTreeMap::new(),
        },
    )
    .await;

    db.delete_group(&group.id).await.unwrap();
    assert!(db.find_group_by_id(&group.id).await.unwrap().is_none());
    assert!(
        db.list_application_scim_groups(&application.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db.read_application_authorization_bindings(&application.id, &profile.id)
            .await
            .unwrap()
            .group_bindings
            .get(&group.id)
            .is_none_or(Vec::is_empty)
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}
