#![cfg(feature = "sqlite")]

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chrono::Utc;
use serde_json::Value;
use sso_backend::{
    AppState, Settings, admin,
    config::DatabaseKind,
    db::{Db, NewOrganization, NewUser, SessionMetadata, UserRecord},
    jwt::JwtManager,
};
use std::{collections::HashSet, path::PathBuf};
use tower::util::ServiceExt;

struct TestContext {
    app: Router,
    db: Db,
    cookie: String,
    path: PathBuf,
}

impl TestContext {
    async fn new() -> Self {
        let mut settings: Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "signet-admin-user-directory-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.database.run_migrations = true;
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();

        let db = Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        let manager = db
            .insert_user(NewUser {
                email: "directory-test-manager@example.test".to_string(),
                username: "directory-test-manager".to_string(),
                display_name: Some("Directory Test Manager".to_string()),
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: None,
                phone_verified_at: None,
                is_admin: true,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        let (_, cookie_value) = db
            .insert_session(
                &manager.id,
                settings.security.session_ttl_seconds,
                SessionMetadata::default(),
            )
            .await
            .unwrap();
        let cookie = format!("{}={cookie_value}", settings.security.cookie_name);
        let jwt = JwtManager::new(&settings).unwrap();
        let state = AppState {
            settings,
            db: db.clone(),
            jwt,
        };
        let app = admin::routes().with_state(state);

        Self {
            app,
            db,
            cookie,
            path,
        }
    }

    async fn get(&self, uri: &str) -> Value {
        let request = Request::builder()
            .method("GET")
            .uri(uri)
            .header("cookie", &self.cookie)
            .body(Body::empty())
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
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
        drop(self.app);
        drop(self.db);
        let _ = std::fs::remove_file(self.path);
    }
}

async fn insert_user(
    context: &TestContext,
    email: &str,
    username: &str,
    display_name: Option<&str>,
    phone: Option<&str>,
    is_admin: bool,
) -> UserRecord {
    context
        .db
        .insert_user(NewUser {
            email: email.to_string(),
            username: username.to_string(),
            display_name: display_name.map(str::to_string),
            phone: phone.map(str::to_string),
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

fn item_ids(page: &Value) -> Vec<String> {
    page["items"]
        .as_array()
        .expect("user directory response must contain an items array")
        .iter()
        .map(|item| {
            item["id"]
                .as_str()
                .expect("user directory item must contain an id")
                .to_string()
        })
        .collect()
}

fn assert_envelope(page: &Value, expected_page: u64, expected_page_size: u64, expected_total: i64) {
    assert!(page["items"].is_array());
    assert_eq!(page["page"].as_u64(), Some(expected_page));
    assert_eq!(page["page_size"].as_u64(), Some(expected_page_size));
    assert_eq!(
        page["total"].as_i64(),
        Some(expected_total),
        "unexpected user directory envelope: {page}"
    );
}

fn assert_contains_exactly(page: &Value, expected_ids: &[String]) {
    let actual = item_ids(page).into_iter().collect::<HashSet<_>>();
    let expected = expected_ids.iter().cloned().collect::<HashSet<_>>();
    assert_eq!(actual, expected);
}

async fn insert_organization(
    context: &TestContext,
    slug: &str,
) -> sso_backend::db::OrganizationRecord {
    context
        .db
        .insert_organization(NewOrganization {
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

#[tokio::test]
async fn admin_user_directory_returns_an_envelope_for_offset_zero_and_stable_pages() {
    let context = TestContext::new().await;
    for index in 0..5 {
        insert_user(
            &context,
            &format!("page-user-{index}@example.test"),
            &format!("page-user-{index}"),
            Some(&format!("Page User {index}")),
            None,
            false,
        )
        .await;
    }

    let full = context
        .get("/api/admin/users?search=page-user&page_size=50")
        .await;
    assert_envelope(&full, 1, 50, 5);
    let expected_ids = item_ids(&full);

    let first_page = context
        .get("/api/admin/users?search=page-user&page=1&page_size=2")
        .await;
    let first_page_again = context
        .get("/api/admin/users?search=page-user&page=1&page_size=2")
        .await;
    assert_envelope(&first_page, 1, 2, 5);
    assert_eq!(item_ids(&first_page), item_ids(&first_page_again));

    let offset_zero = context
        .get("/api/admin/users?search=page-user&offset=0&limit=2")
        .await;
    assert_envelope(&offset_zero, 1, 2, 5);
    assert_eq!(item_ids(&offset_zero), item_ids(&first_page));

    let mut paged_ids = Vec::new();
    for page_number in 1..=3 {
        let page = context
            .get(&format!(
                "/api/admin/users?search=page-user&page={page_number}&page_size=2"
            ))
            .await;
        assert_envelope(&page, page_number, 2, 5);
        paged_ids.extend(item_ids(&page));
    }
    assert_eq!(paged_ids, expected_ids);
    assert_eq!(
        paged_ids.iter().collect::<HashSet<_>>().len(),
        expected_ids.len()
    );

    context.cleanup();
}

#[tokio::test]
async fn admin_user_directory_cursor_walks_each_keyset_page_without_count() {
    let context = TestContext::new().await;
    for index in 0..5 {
        insert_user(
            &context,
            &format!("cursor-user-{index}@example.test"),
            &format!("cursor-user-{index}"),
            Some(&format!("Cursor User {index}")),
            None,
            false,
        )
        .await;
    }

    let mut uri = "/api/admin/users/cursor?search=cursor-user&page_size=2".to_string();
    let mut ids = Vec::new();
    let mut page_count = 0;
    loop {
        let page = context.get(&uri).await;
        page_count += 1;
        let page_ids = item_ids(&page);
        assert!(
            !page_ids.is_empty(),
            "cursor page must not be empty before the end"
        );
        assert!(page["page"].is_null());
        assert!(page["total"].is_null());
        ids.extend(page_ids);
        match page["next_cursor"].as_str() {
            Some(cursor) => {
                uri = format!(
                    "/api/admin/users/cursor?search=cursor-user&page_size=2&cursor={cursor}"
                );
            }
            None => break,
        }
    }

    assert_eq!(page_count, 3);
    assert_eq!(ids.len(), 5);
    assert_eq!(ids.iter().collect::<HashSet<_>>().len(), ids.len());
    context.cleanup();
}

#[tokio::test]
async fn admin_user_directory_enforces_organization_and_linked_identity_boundaries() {
    let context = TestContext::new().await;
    let organization_a = insert_organization(&context, "directory-org-a").await;
    let organization_b = insert_organization(&context, "directory-org-b").await;

    let a_linked = insert_user(
        &context,
        "boundary-a-linked@example.test",
        "boundary-a-linked",
        None,
        None,
        false,
    )
    .await;
    let a_unlinked = insert_user(
        &context,
        "boundary-a-unlinked@example.test",
        "boundary-a-unlinked",
        None,
        None,
        false,
    )
    .await;
    let b_linked = insert_user(
        &context,
        "boundary-b-linked@example.test",
        "boundary-b-linked",
        None,
        None,
        false,
    )
    .await;
    let outside = insert_user(
        &context,
        "boundary-outside@example.test",
        "boundary-outside",
        None,
        None,
        false,
    )
    .await;

    context
        .db
        .upsert_organization_member(&organization_a.id, &a_linked.id, "member")
        .await
        .unwrap();
    context
        .db
        .upsert_organization_member(&organization_a.id, &a_unlinked.id, "member")
        .await
        .unwrap();
    context
        .db
        .upsert_organization_member(&organization_b.id, &b_linked.id, "member")
        .await
        .unwrap();
    context
        .db
        .insert_linked_identity(
            &a_linked.id,
            "directory-oidc",
            "subject-a",
            Some(a_linked.email.clone()),
        )
        .await
        .unwrap();
    context
        .db
        .insert_linked_identity(
            &b_linked.id,
            "directory-oidc",
            "subject-b",
            Some(b_linked.email.clone()),
        )
        .await
        .unwrap();

    let org_a = context
        .get(&format!(
            "/api/admin/users?search=boundary-&organization_id={}&page_size=50",
            organization_a.id
        ))
        .await;
    assert_envelope(&org_a, 1, 50, 2);
    assert_contains_exactly(&org_a, &[a_linked.id.clone(), a_unlinked.id.clone()]);

    let org_b = context
        .get(&format!(
            "/api/admin/users?search=boundary-&organization_id={}&page_size=50",
            organization_b.id
        ))
        .await;
    assert_envelope(&org_b, 1, 50, 1);
    assert_contains_exactly(&org_b, std::slice::from_ref(&b_linked.id));
    assert!(!item_ids(&org_a).contains(&b_linked.id));
    assert!(!item_ids(&org_a).contains(&outside.id));

    let a_linked_page = context
        .get(&format!(
            "/api/admin/users?search=boundary-&organization_id={}&linked_identity=linked&page_size=50",
            organization_a.id
        ))
        .await;
    assert_envelope(&a_linked_page, 1, 50, 1);
    assert_contains_exactly(&a_linked_page, std::slice::from_ref(&a_linked.id));

    let a_unlinked_page = context
        .get(&format!(
            "/api/admin/users?search=boundary-&organization_id={}&linked_identity=unlinked&page_size=50",
            organization_a.id
        ))
        .await;
    assert_envelope(&a_unlinked_page, 1, 50, 1);
    assert_contains_exactly(&a_unlinked_page, std::slice::from_ref(&a_unlinked.id));

    context.cleanup();
}

#[tokio::test]
async fn admin_user_directory_applies_search_identity_role_status_and_time_filters() {
    let context = TestContext::new().await;
    let filters_admin = insert_user(
        &context,
        "filters-admin@example.test",
        "filters-admin",
        Some("Alice Admin"),
        Some("13800000001"),
        true,
    )
    .await;
    let filters_user = insert_user(
        &context,
        "filters-user@example.test",
        "filters-user",
        Some("Overseas User"),
        Some("13800000002"),
        false,
    )
    .await;
    let filters_disabled = insert_user(
        &context,
        "filters-disabled@example.test",
        "filters-disabled",
        Some("Disabled User"),
        None,
        false,
    )
    .await;
    context.db.disable_user(&filters_disabled.id).await.unwrap();
    context
        .db
        .record_login_event(
            &filters_admin.id,
            Some("10.0.0.10".to_string()),
            None,
            "password",
            None,
            None,
        )
        .await
        .unwrap();
    context
        .db
        .record_login_event(
            &filters_user.id,
            Some("8.8.8.8".to_string()),
            None,
            "password",
            None,
            None,
        )
        .await
        .unwrap();

    let search = context
        .get("/api/admin/users?search=Alice&page_size=50")
        .await;
    assert_envelope(&search, 1, 50, 1);
    assert_contains_exactly(&search, std::slice::from_ref(&filters_admin.id));

    let email = context
        .get("/api/admin/users?email=filters-user%40example.test&page_size=50")
        .await;
    assert_envelope(&email, 1, 50, 1);
    assert_contains_exactly(&email, std::slice::from_ref(&filters_user.id));

    let phone = context
        .get("/api/admin/users?phone=13800000001&page_size=50")
        .await;
    assert_envelope(&phone, 1, 50, 1);
    assert_contains_exactly(&phone, std::slice::from_ref(&filters_admin.id));

    let admins = context
        .get("/api/admin/users?search=filters-&role=admin&page_size=50")
        .await;
    assert_envelope(&admins, 1, 50, 1);
    assert_contains_exactly(&admins, std::slice::from_ref(&filters_admin.id));

    let users = context
        .get("/api/admin/users?search=filters-&status=active&role=user&page_size=50")
        .await;
    assert_envelope(&users, 1, 50, 1);
    assert_contains_exactly(&users, std::slice::from_ref(&filters_user.id));

    let disabled = context
        .get("/api/admin/users?search=filters-&status=disabled&page_size=50")
        .await;
    assert_envelope(&disabled, 1, 50, 1);
    assert_contains_exactly(&disabled, std::slice::from_ref(&filters_disabled.id));

    let created_from = filters_admin.created_at.min(filters_user.created_at);
    let created_to = filters_admin
        .created_at
        .max(filters_user.created_at)
        .saturating_add(1);
    let registration_window = context
        .get(&format!(
            "/api/admin/users?search=filters-&status=active&registration_from={created_from}&registration_to={created_to}&page_size=50"
        ))
        .await;
    assert_envelope(&registration_window, 1, 50, 2);
    assert_contains_exactly(
        &registration_window,
        &[filters_admin.id.clone(), filters_user.id.clone()],
    );

    let login_window_start = Utc::now().timestamp().saturating_sub(60);
    let login_window_end = Utc::now().timestamp().saturating_add(60);
    let login_window = context
        .get(&format!(
            "/api/admin/users?search=filters-&last_login_from={login_window_start}&last_login_to={login_window_end}&page_size=50"
        ))
        .await;
    assert_envelope(&login_window, 1, 50, 2);
    assert_contains_exactly(
        &login_window,
        &[filters_admin.id.clone(), filters_user.id.clone()],
    );

    let domestic = context
        .get("/api/admin/users?search=filters-&login_region=domestic&page_size=50")
        .await;
    assert_envelope(&domestic, 1, 50, 1);
    assert_contains_exactly(&domestic, std::slice::from_ref(&filters_admin.id));

    let overseas = context
        .get("/api/admin/users?search=filters-&login_region=overseas&page_size=50")
        .await;
    assert_envelope(&overseas, 1, 50, 1);
    assert_contains_exactly(&overseas, std::slice::from_ref(&filters_user.id));

    context.cleanup();
}
