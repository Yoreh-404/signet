#![cfg(feature = "sqlite")]

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::Value;
use sso_backend::{
    AppState, Settings, admin, audit, authorization,
    config::DatabaseKind,
    db::{
        ApplicationAuthorizationProfileRecord, ApplicationRecord,
        AuthorizationBindingPermissionOverride, AuthorizationBindingsUpdate, Db, GroupRecord,
        NewApplication, NewApplicationAuthorizationProfile, NewApplicationDiscovery,
        NewApplicationProfileRole, NewGroup, NewOrganization, NewRole, NewUser, SessionMetadata,
        UserRecord,
    },
    jwt::JwtManager,
};
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
};
use tower::util::ServiceExt;

struct Fixture {
    state: AppState,
    http: Router,
    db: Db,
    path: PathBuf,
    a_user: UserRecord,
    b_user: UserRecord,
    application: ApplicationRecord,
    legacy_application: ApplicationRecord,
    profile: ApplicationAuthorizationProfileRecord,
    group: GroupRecord,
    cookie: String,
}

impl Fixture {
    async fn new() -> Self {
        let mut settings: Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "signet-authorization-entitlements-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.database.run_migrations = true;
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();

        let db = Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();

        let manager = insert_user(&db, "authorization-manager", true).await;
        let a_user = insert_user(&db, "authorization-a", false).await;
        let b_user = insert_user(&db, "authorization-b", false).await;
        let organization_a = insert_organization(&db, "authorization-org-a").await;
        let organization_b = insert_organization(&db, "authorization-org-b").await;
        db.upsert_organization_member(&organization_a.id, &manager.id, "owner")
            .await
            .unwrap();
        db.upsert_organization_member(&organization_a.id, &a_user.id, "admin")
            .await
            .unwrap();
        db.upsert_organization_member(&organization_b.id, &b_user.id, "member")
            .await
            .unwrap();

        let direct_role = db
            .insert_role(NewRole {
                name: "enterprise-direct".to_string(),
                description: None,
                is_system: false,
                permissions: vec!["users.read".to_string()],
            })
            .await
            .unwrap();
        let group_role = db
            .insert_role(NewRole {
                name: "enterprise-group".to_string(),
                description: None,
                is_system: false,
                permissions: vec!["security.manage".to_string()],
            })
            .await
            .unwrap();
        db.replace_user_roles(&a_user.id, vec![direct_role.id.clone()])
            .await
            .unwrap();
        db.replace_user_roles(&b_user.id, vec![direct_role.id.clone()])
            .await
            .unwrap();

        let group = db
            .insert_group(NewGroup {
                name: "mixed-global".to_string(),
                description: None,
            })
            .await
            .unwrap();
        db.replace_group_members(&group.id, vec![a_user.id.clone(), b_user.id.clone()])
            .await
            .unwrap();
        db.replace_group_roles(&group.id, vec![group_role.id.clone()])
            .await
            .unwrap();

        let application = insert_application(&db, &organization_a.id, "authorization-app").await;
        db.upsert_application_module(
            &application.id,
            "authorization",
            &serde_json::json!({
                "inherit_enterprise_roles": true,
                "permissions": ["public.read"]
            })
            .to_string(),
            true,
        )
        .await
        .unwrap();
        let application_profile = db
            .find_application_authorization_profile(&application.id, "default")
            .await
            .unwrap()
            .unwrap();
        let app_default = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("application-default-role".to_string()),
                profile_id: application_profile.id.clone(),
                role_key: "app-default".to_string(),
                name: "app-default".to_string(),
                description: None,
                permissions: vec!["app.default".to_string()],
                is_default: true,
                is_active: true,
                source: "manual".to_string(),
            })
            .await
            .unwrap();
        let app_user = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("application-user-role".to_string()),
                profile_id: application_profile.id.clone(),
                role_key: "app-user".to_string(),
                name: "app-user".to_string(),
                description: None,
                permissions: vec!["app.user".to_string()],
                is_default: false,
                is_active: true,
                source: "manual".to_string(),
            })
            .await
            .unwrap();
        let app_group = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("application-group-role".to_string()),
                profile_id: application_profile.id.clone(),
                role_key: "app-group".to_string(),
                name: "app-group".to_string(),
                description: None,
                permissions: vec!["app.group".to_string()],
                is_default: false,
                is_active: true,
                source: "manual".to_string(),
            })
            .await
            .unwrap();
        let app_org = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("application-organization-role".to_string()),
                profile_id: application_profile.id.clone(),
                role_key: "app-org".to_string(),
                name: "app-org".to_string(),
                description: None,
                permissions: vec!["app.org".to_string()],
                is_default: false,
                is_active: true,
                source: "manual".to_string(),
            })
            .await
            .unwrap();
        assert_ne!(app_default.id, app_user.id);
        replace_profile_bindings(ProfileBindingInput {
            db: &db,
            application_id: &application.id,
            profile_id: &application_profile.id,
            user_id: Some(&a_user.id),
            group_id: Some(&group.id),
            user_role_ids: vec![app_user.id.clone()],
            user_permission_overrides: vec![("a.override".to_string(), "allow".to_string())],
            group_role_ids: vec![app_group.id.clone()],
            organization_role_bindings: BTreeMap::from([(
                "admin".to_string(),
                vec![app_org.id.clone()],
            )]),
        })
        .await;

        let profile = db
            .upsert_application_authorization_profile(NewApplicationAuthorizationProfile {
                id: "authorization-profile".to_string(),
                application_id: application.id.clone(),
                profile_key: "web".to_string(),
                connection_kind: "oidc".to_string(),
                connection_id: None,
                source_mode: "manual".to_string(),
                remote_version: None,
                remote_digest: None,
                sync_status: "ready".to_string(),
                last_synced_at: None,
                last_error: None,
            })
            .await
            .unwrap();
        let profile_default = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("profile-default-role".to_string()),
                profile_id: profile.id.clone(),
                role_key: "profile-default".to_string(),
                name: "Profile default".to_string(),
                description: None,
                permissions: vec!["profile.default".to_string()],
                source: "manual".to_string(),
                is_default: true,
                is_active: true,
            })
            .await
            .unwrap();
        let profile_user = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("profile-user-role".to_string()),
                profile_id: profile.id.clone(),
                role_key: "profile-user".to_string(),
                name: "Profile user".to_string(),
                description: None,
                permissions: vec!["profile.user".to_string()],
                source: "manual".to_string(),
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        let profile_group = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("profile-group-role".to_string()),
                profile_id: profile.id.clone(),
                role_key: "profile-group".to_string(),
                name: "Profile group".to_string(),
                description: None,
                permissions: vec!["profile.group".to_string()],
                source: "manual".to_string(),
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        let profile_org = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("profile-org-role".to_string()),
                profile_id: profile.id.clone(),
                role_key: "profile-org".to_string(),
                name: "Profile organization role".to_string(),
                description: None,
                permissions: vec!["profile.org".to_string()],
                source: "manual".to_string(),
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        assert_eq!(profile_default.role_key, "profile-default");
        replace_profile_bindings(ProfileBindingInput {
            db: &db,
            application_id: &application.id,
            profile_id: &profile.id,
            user_id: Some(&a_user.id),
            group_id: Some(&group.id),
            user_role_ids: vec![profile_user.id.clone()],
            user_permission_overrides: vec![("profile.override".to_string(), "allow".to_string())],
            group_role_ids: vec![profile_group.id.clone()],
            organization_role_bindings: BTreeMap::from([(
                "admin".to_string(),
                vec![profile_org.id.clone()],
            )]),
        })
        .await;

        let legacy_application =
            insert_application(&db, &organization_a.id, "authorization-legacy-app").await;
        db.upsert_application_module(
            &legacy_application.id,
            "authorization",
            &serde_json::json!({
                "inherit_enterprise_roles": true,
                "permissions": ["legacy.public"]
            })
            .to_string(),
            true,
        )
        .await
        .unwrap();
        let legacy_profile = db
            .find_application_authorization_profile(&legacy_application.id, "default")
            .await
            .unwrap()
            .unwrap();
        let legacy_group_role = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("legacy-group-role-id".to_string()),
                profile_id: legacy_profile.id.clone(),
                role_key: "legacy-group-role".to_string(),
                name: "Legacy group role".to_string(),
                description: None,
                permissions: vec!["legacy.group".to_string()],
                source: "manual".to_string(),
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        let legacy_org_role = db
            .upsert_application_profile_role(NewApplicationProfileRole {
                id: Some("legacy-org-role-id".to_string()),
                profile_id: legacy_profile.id.clone(),
                role_key: "legacy-org-role".to_string(),
                name: "Legacy organization role".to_string(),
                description: None,
                permissions: vec!["legacy.org".to_string()],
                source: "manual".to_string(),
                is_default: false,
                is_active: true,
            })
            .await
            .unwrap();
        replace_profile_bindings(ProfileBindingInput {
            db: &db,
            application_id: &legacy_application.id,
            profile_id: &legacy_profile.id,
            user_id: None,
            group_id: Some(&group.id),
            user_role_ids: Vec::new(),
            user_permission_overrides: Vec::new(),
            group_role_ids: vec![legacy_group_role.id],
            organization_role_bindings: BTreeMap::from([(
                "admin".to_string(),
                vec![legacy_org_role.id],
            )]),
        })
        .await;

        let (_, session_token) = db
            .insert_session(
                &manager.id,
                settings.security.session_ttl_seconds,
                SessionMetadata::default(),
            )
            .await
            .unwrap();
        let cookie = format!("{}={session_token}", settings.security.cookie_name);
        let jwt = JwtManager::new(&settings).unwrap();
        let state = AppState {
            settings,
            db: db.clone(),
            jwt,
        };
        let http = admin::routes().with_state(state.clone());

        Self {
            state,
            http,
            db,
            path,
            a_user,
            b_user,
            application,
            legacy_application,
            profile,
            group,
            cookie,
        }
    }

    async fn get(&self, uri: &str) -> Value {
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .header("cookie", &self.cookie)
            .body(Body::empty())
            .unwrap();
        let response = self.http.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "GET {uri} returned {status}: {}",
            String::from_utf8_lossy(&body)
        );
        serde_json::from_slice(&body).unwrap()
    }

    fn cleanup(self) {
        drop(self.http);
        drop(self.state);
        drop(self.db);
        let _ = std::fs::remove_file(self.path);
    }
}

async fn insert_user(db: &Db, username: &str, is_admin: bool) -> UserRecord {
    db.insert_user(NewUser {
        email: format!("{username}@example.test"),
        username: username.to_string(),
        display_name: None,
        phone: None,
        password_hash: "test-hash".to_string(),
        email_verified_at: None,
        phone_verified_at: None,
        is_admin,
        is_active: true,
        archived_at: None,
    })
    .await
    .unwrap()
}

async fn insert_organization(db: &Db, slug: &str) -> sso_backend::db::OrganizationRecord {
    db.insert_organization(NewOrganization {
        slug: slug.to_string(),
        name: slug.to_string(),
        kind: "tenant".to_string(),
        description: None,
        allowed_email_domains: Vec::new(),
        is_active: true,
    })
    .await
    .unwrap()
}

async fn insert_application(db: &Db, organization_id: &str, slug: &str) -> ApplicationRecord {
    db.insert_application(NewApplication {
        organization_id: organization_id.to_string(),
        slug: slug.to_string(),
        name: slug.to_string(),
        description: None,
        access_mode: "all_users".to_string(),
        registration_mode: "disabled".to_string(),
        account_selection_mode: "optional".to_string(),
        unique_identity_factors: Vec::new(),
        is_active: true,
    })
    .await
    .unwrap()
}

struct ProfileBindingInput<'a> {
    db: &'a Db,
    application_id: &'a str,
    profile_id: &'a str,
    user_id: Option<&'a str>,
    group_id: Option<&'a str>,
    user_role_ids: Vec<String>,
    user_permission_overrides: Vec<(String, String)>,
    group_role_ids: Vec<String>,
    organization_role_bindings: BTreeMap<String, Vec<String>>,
}

async fn replace_profile_bindings(input: ProfileBindingInput<'_>) {
    input
        .db
        .replace_application_authorization_bindings_with_audit(
            input.application_id,
            input.profile_id,
            AuthorizationBindingsUpdate {
                user_id: input.user_id.map(ToOwned::to_owned),
                group_id: input.group_id.map(ToOwned::to_owned),
                user_role_ids: input.user_role_ids,
                user_permission_overrides: input
                    .user_permission_overrides
                    .into_iter()
                    .map(
                        |(permission, effect)| AuthorizationBindingPermissionOverride {
                            permission,
                            effect,
                        },
                    )
                    .collect(),
                group_role_ids: input.group_role_ids,
                organization_role_bindings: input.organization_role_bindings,
            },
            audit::management_event(
                "authorization-entitlements-test",
                "application.authorization_profile.bindings.update",
                "application_authorization_profile",
                Some(input.profile_id.to_string()),
                serde_json::json!({}),
            ),
        )
        .await
        .unwrap();
}

fn assert_missing(values: &[String], forbidden: &[&str]) {
    let actual = values.iter().cloned().collect::<HashSet<_>>();
    for value in forbidden {
        assert!(!actual.contains(*value), "unexpected entitlement: {value}");
    }
}

#[tokio::test]
async fn application_entitlements_are_scoped_without_changing_all_users_access() {
    let fixture = Fixture::new().await;

    let decision =
        authorization::check_login_access(&fixture.state, &fixture.application, &fixture.b_user.id)
            .await
            .unwrap();
    assert!(
        decision.allowed,
        "all_users must keep active B accounts eligible"
    );
    assert_eq!(decision.reason, "active_account");

    let b_entitlements =
        authorization::resolve_entitlements(&fixture.state, &fixture.application, &fixture.b_user)
            .await
            .unwrap();
    assert!(b_entitlements.roles.contains(&"app-default".to_string()));
    assert!(
        b_entitlements
            .permissions
            .contains(&"app.default".to_string())
    );
    assert!(
        b_entitlements
            .permissions
            .contains(&"public.read".to_string())
    );
    assert!(b_entitlements.groups.is_empty());
    assert!(b_entitlements.organization_role.is_none());
    assert_missing(
        &b_entitlements.roles,
        &[
            "enterprise-direct",
            "enterprise-group",
            "app-user",
            "app-group",
            "app-org",
        ],
    );
    assert_missing(
        &b_entitlements.permissions,
        &[
            "users.read",
            "security.manage",
            "app.user",
            "app.group",
            "app.org",
            "b.override",
        ],
    );
    assert_eq!(b_entitlements.claims["groups"], serde_json::json!([]));
    assert!(!b_entitlements.claims.contains_key("organization_role"));

    let a_entitlements =
        authorization::resolve_entitlements(&fixture.state, &fixture.application, &fixture.a_user)
            .await
            .unwrap();
    for role in [
        "enterprise-direct",
        "enterprise-group",
        "enterprise:admin",
        "app-default",
        "app-user",
        "app-group",
        "app-org",
    ] {
        assert!(
            a_entitlements.roles.iter().any(|value| value == role),
            "missing role {role}"
        );
    }
    for permission in [
        "users.read",
        "security.manage",
        "app.default",
        "app.user",
        "app.group",
        "app.org",
        "public.read",
        "a.override",
    ] {
        assert!(
            a_entitlements
                .permissions
                .iter()
                .any(|value| value == permission),
            "missing permission {permission}"
        );
    }
    assert_eq!(a_entitlements.groups, vec!["mixed-global".to_string()]);
    assert_eq!(a_entitlements.organization_role.as_deref(), Some("admin"));

    let legacy_b = authorization::resolve_entitlements(
        &fixture.state,
        &fixture.legacy_application,
        &fixture.b_user,
    )
    .await
    .unwrap();
    assert!(legacy_b.permissions.contains(&"legacy.public".to_string()));
    assert_missing(
        &legacy_b.roles,
        &[
            "enterprise-direct",
            "enterprise-group",
            "legacy-group-role",
            "legacy-org-role",
        ],
    );
    assert_missing(&legacy_b.permissions, &["legacy.group", "legacy.org"]);
    assert!(legacy_b.groups.is_empty());
    assert!(legacy_b.organization_role.is_none());

    let legacy_a = authorization::resolve_entitlements(
        &fixture.state,
        &fixture.legacy_application,
        &fixture.a_user,
    )
    .await
    .unwrap();
    assert!(legacy_a.roles.contains(&"legacy-group-role".to_string()));
    assert!(legacy_a.roles.contains(&"legacy-org-role".to_string()));
    assert!(legacy_a.permissions.contains(&"legacy.group".to_string()));
    assert!(legacy_a.permissions.contains(&"legacy.org".to_string()));

    let http_preview = fixture
        .get(&format!(
            "/api/admin/applications/{}/authorization/{}",
            fixture.application.id, fixture.a_user.id
        ))
        .await;
    assert_eq!(http_preview["decision"]["allowed"], Value::Bool(true));
    assert_eq!(
        http_preview["entitlements"]["organization_role"],
        Value::String("admin".to_string())
    );
    assert!(
        http_preview["entitlements"]["groups"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "mixed-global")
    );

    fixture.cleanup();
}

#[tokio::test]
async fn website_managed_discovery_without_verified_snapshot_closes_login_gate() {
    let fixture = Fixture::new().await;
    fixture
        .db
        .upsert_application_discovery(NewApplicationDiscovery {
            application_id: fixture.application.id.clone(),
            management_mode: sso_backend::application_discovery::MANAGEMENT_MODE_WEBSITE
                .to_string(),
            website_url: "https://authorization-app.example".to_string(),
            fetch_secret_ciphertext: "encrypted-fetch-secret".to_string(),
            signing_public_jwks: "{}".to_string(),
            last_verified_revision: None,
            last_verified_version: None,
            last_verified_digest: None,
            last_verified_expires_at: None,
            sync_status: sso_backend::application_discovery::SYNC_PENDING.to_string(),
            last_fetched_at: None,
            last_success_at: None,
            last_error: None,
            snapshot_json: None,
            operator_disabled: false,
        })
        .await
        .unwrap();

    let decision =
        authorization::check_login_access(&fixture.state, &fixture.application, &fixture.b_user.id)
            .await
            .unwrap();
    assert!(
        !decision.allowed,
        "website_managed applications must fail closed before the first verified snapshot"
    );
    fixture.cleanup();
}

#[tokio::test]
async fn profile_entitlements_keep_public_defaults_and_scope_assignments() {
    let fixture = Fixture::new().await;

    let b_entitlements = authorization::resolve_entitlements_for_profile(
        &fixture.state,
        &fixture.application,
        &fixture.profile,
        &fixture.b_user,
    )
    .await
    .unwrap();
    assert!(
        b_entitlements
            .roles
            .contains(&"profile-default".to_string())
    );
    assert!(
        b_entitlements
            .permissions
            .contains(&"profile.default".to_string())
    );
    assert!(
        b_entitlements
            .permissions
            .contains(&"public.read".to_string())
    );
    assert!(b_entitlements.groups.is_empty());
    assert!(b_entitlements.organization_role.is_none());
    assert_missing(
        &b_entitlements.roles,
        &[
            "enterprise-direct",
            "enterprise-group",
            "enterprise:member",
            "profile-user",
            "profile-group",
            "profile-org",
        ],
    );
    assert_missing(
        &b_entitlements.permissions,
        &[
            "users.read",
            "security.manage",
            "profile.user",
            "profile.group",
            "profile.org",
            "profile.leaked",
        ],
    );
    assert_eq!(b_entitlements.claims["groups"], serde_json::json!([]));
    assert!(!b_entitlements.claims.contains_key("organization_role"));

    let a_entitlements = authorization::resolve_entitlements_for_profile(
        &fixture.state,
        &fixture.application,
        &fixture.profile,
        &fixture.a_user,
    )
    .await
    .unwrap();
    for role in [
        "enterprise-direct",
        "enterprise-group",
        "enterprise:admin",
        "profile-default",
        "profile-user",
        "profile-group",
        "profile-org",
    ] {
        assert!(
            a_entitlements.roles.iter().any(|value| value == role),
            "missing role {role}"
        );
    }
    for permission in [
        "users.read",
        "security.manage",
        "profile.default",
        "profile.user",
        "profile.group",
        "profile.org",
        "public.read",
        "profile.override",
    ] {
        assert!(
            a_entitlements
                .permissions
                .iter()
                .any(|value| value == permission),
            "missing permission {permission}"
        );
    }
    assert_eq!(a_entitlements.groups, vec!["mixed-global".to_string()]);
    assert_eq!(a_entitlements.organization_role.as_deref(), Some("admin"));
    assert_eq!(
        a_entitlements.claims["authorization_profile"],
        Value::String("web".to_string())
    );

    let http_preview = fixture
        .get(&format!(
            "/api/admin/applications/{}/authorization/profiles/{}/{}",
            fixture.application.id, fixture.profile.id, fixture.a_user.id
        ))
        .await;
    assert_eq!(
        http_preview["entitlements"]["authorization_profile"],
        Value::String("web".to_string())
    );
    assert!(
        http_preview["entitlements"]["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "profile-group")
    );

    // Removing a profile group assignment deactivates its mapping row. The
    // batched resolver must not resurrect that historical row on the next
    // authorization calculation.
    replace_profile_bindings(ProfileBindingInput {
        db: &fixture.db,
        application_id: &fixture.application.id,
        profile_id: &fixture.profile.id,
        user_id: Some(&fixture.a_user.id),
        group_id: Some(&fixture.group.id),
        user_role_ids: vec!["profile-user-role".to_string()],
        user_permission_overrides: vec![("profile.override".to_string(), "allow".to_string())],
        group_role_ids: Vec::new(),
        organization_role_bindings: BTreeMap::from([(
            "admin".to_string(),
            vec!["profile-org-role".to_string()],
        )]),
    })
    .await;
    let after_group_removal = authorization::resolve_entitlements_for_profile(
        &fixture.state,
        &fixture.application,
        &fixture.profile,
        &fixture.a_user,
    )
    .await
    .unwrap();
    assert_missing(&after_group_removal.roles, &["profile-group"]);
    assert_missing(&after_group_removal.permissions, &["profile.group"]);

    fixture.cleanup();
}
