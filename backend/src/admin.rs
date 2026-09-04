use crate::{
    AppState, applications, audit, auth, billing,
    db::{ApplicationRecord, NewApplicationBillingSettings, NewIapApplication},
    error::{AppError, AppResult},
    iap, mutations, util,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
};
use axum_extra::extract::cookie::CookieJar;

#[path = "admin_client_policy.rs"]
mod admin_client_policy;
#[path = "admin_client_types.rs"]
mod admin_client_types;
#[path = "admin_defaults.rs"]
mod admin_defaults;
#[path = "admin_guards.rs"]
mod admin_guards;
#[path = "admin_providers.rs"]
mod admin_providers;
#[path = "admin_settings.rs"]
mod admin_settings;
#[path = "admin_user_import.rs"]
mod admin_user_import;
#[path = "admin_user_types.rs"]
mod admin_user_types;
use admin_client_policy::{
    client_input_to_claim_mappers, client_input_to_new, validate_client_input,
};
#[cfg(test)]
use admin_client_types::ClientInput;
#[path = "admin_organization_scope.rs"]
mod admin_organization_scope;
#[path = "admin_organization_types.rs"]
mod admin_organization_types;
use admin_organization_scope::client_organization_from_context;
#[path = "admin_application_authorization_preview.rs"]
mod admin_application_authorization_preview;
#[path = "admin_application_authorization_read.rs"]
mod admin_application_authorization_read;
#[path = "admin_application_authorization_scope.rs"]
mod admin_application_authorization_scope;
#[path = "admin_application_authorization_write.rs"]
mod admin_application_authorization_write;
#[path = "admin_application_auto_discovery.rs"]
mod admin_application_auto_discovery;
#[path = "admin_application_crud.rs"]
mod admin_application_crud;
#[path = "admin_application_directory_sync.rs"]
mod admin_application_directory_sync;
#[path = "admin_application_discovery.rs"]
mod admin_application_discovery;
#[path = "admin_application_enrollment.rs"]
mod admin_application_enrollment;
#[path = "admin_application_iap.rs"]
mod admin_application_iap;
#[path = "admin_application_response.rs"]
mod admin_application_response;
#[path = "admin_application_scope.rs"]
mod admin_application_scope;
#[path = "admin_assignment_policy.rs"]
mod admin_assignment_policy;
#[path = "admin_audit.rs"]
mod admin_audit;
#[path = "admin_client_response.rs"]
mod admin_client_response;
#[path = "admin_management_scope.rs"]
mod admin_management_scope;
#[path = "admin_overview.rs"]
mod admin_overview;
#[path = "admin_security.rs"]
mod admin_security;
use admin_application_iap::IapApplicationInput;
use admin_application_scope::ensure_website_application_modules_editable;
#[path = "admin_application_billing.rs"]
mod admin_application_billing;
#[path = "admin_application_modules.rs"]
mod admin_application_modules;
#[path = "admin_application_oidc.rs"]
mod admin_application_oidc;
#[path = "admin_authorization_code_policy.rs"]
mod admin_authorization_code_policy;
#[path = "admin_authorization_code_read.rs"]
mod admin_authorization_code_read;
#[path = "admin_authorization_code_write.rs"]
mod admin_authorization_code_write;
use admin_application_response::{
    ApplicationModuleResponse, MissingApplicationClientPolicy,
    application_client_binding_responses_from_graph, application_module_response,
};
use admin_client_response::public_client_with_claim_mappers;
use admin_management_scope::normalize_client_organization_id;
#[path = "admin_application_jwt.rs"]
mod admin_application_jwt;
#[path = "admin_application_scim.rs"]
mod admin_application_scim;
#[path = "admin_user_directory.rs"]
mod admin_user_directory;
#[path = "admin_user_query.rs"]
mod admin_user_query;
#[cfg(test)]
use crate::{
    archived_accounts,
    db::{
        NewOrganization, NewUser, UserListLinkedIdentityFilter, UserListRoleFilter, UserListScope,
        UserOrganizationRecord,
    },
    organizations,
};
#[cfg(test)]
use admin_assignment_policy::ensure_account_metadata_update_allowed;
#[cfg(test)]
use admin_guards::{
    CLIENT_READ_PERMISSIONS, ORGANIZATION_OPTION_PERMISSIONS, ORGANIZATION_READ_PERMISSIONS,
};
#[cfg(test)]
use admin_user_import::normalize_user_input;
#[cfg(test)]
use admin_user_query::USER_DIRECTORY_DEFAULT_PAGE_SIZE;
#[cfg(test)]
use admin_user_query::{UserListQuery, parse_user_list_query, user_list_scope};

#[cfg(test)]
use crate::db::QuickLink;
#[cfg(test)]
use crate::subject;
#[cfg(test)]
use admin_providers::{
    ExternalOidcProviderInput, LdapProviderInput, apply_external_provider_secret_update,
    normalize_external_provider_input, normalize_ldap_provider_input,
};
#[cfg(test)]
use admin_settings::{normalize_brand_logo_url, normalize_email_domains, normalize_quick_links};
#[cfg(test)]
use admin_user_import::{BulkImportQuery, parse_bulk_import_csv};
#[cfg(test)]
use axum::{http::StatusCode, response::Response};

#[path = "admin_access.rs"]
mod admin_access;
#[path = "admin_access_types.rs"]
mod admin_access_types;
#[path = "admin_account_context.rs"]
mod admin_account_context;
#[path = "admin_account_security.rs"]
mod admin_account_security;
#[path = "admin_account_sessions.rs"]
mod admin_account_sessions;
#[path = "admin_auth.rs"]
mod admin_auth;
#[path = "admin_organizations.rs"]
mod admin_organizations;
#[path = "admin_routes.rs"]
mod admin_routes;
#[path = "admin_user_access.rs"]
mod admin_user_access;
#[path = "admin_users.rs"]
mod admin_users;

pub fn routes() -> Router<AppState> {
    admin_routes::routes()
}

async fn get_mutation_receipt(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<mutations::PublicMutationReceipt>> {
    auth::require_current_user(&state, &jar).await?;
    let scope_key = mutations::scope_key(&headers, &state.settings.security.cookie_name);
    let receipt = state
        .db
        .find_mutation_receipt(&id, &scope_key)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(receipt.into()))
}

async fn iap_application_input_to_new(
    state: &AppState,
    application: &ApplicationRecord,
    payload: IapApplicationInput,
) -> AppResult<NewIapApplication> {
    let required_organization_id =
        normalize_client_organization_id(state, payload.required_organization_id).await?;
    if required_organization_id
        .as_deref()
        .is_some_and(|organization_id| organization_id != application.organization_id)
    {
        return Err(AppError::Forbidden);
    }
    iap::normalize_iap_application(NewIapApplication {
        application_id: application.id.clone(),
        slug: payload.slug,
        name: payload.name,
        description: payload.description,
        external_host: payload.external_host,
        path_prefix: payload.path_prefix,
        required_organization_id,
        required_organization_roles: payload.required_organization_roles,
        required_permissions: payload.required_permissions,
        is_active: payload.is_active,
    })
}

#[cfg(test)]
mod tests {
    use super::admin_authorization_code_policy::{
        ensure_admin_universal_manager, immutable_allowed_client_ids, immutable_recovery_username,
        recovery_target_user_id, validate_login_code_binding_metadata,
    };
    use super::admin_settings::LoginSettingsInput;
    use super::admin_user_import::{import_users_csv, validate_bulk_import_duplicates};
    use super::admin_user_types::UserInput;
    use super::*;
    use crate::access::Permission;
    use crate::db::{AuthorizationCodeType, LoginCodeLevel, NewRole};
    use axum::extract::Query;

    #[test]
    fn user_list_scope_accepts_authorization_code_accounts() {
        assert!(matches!(
            user_list_scope(Some("authorization_code")),
            Ok(UserListScope::AuthorizationCode)
        ));
    }

    #[test]
    fn user_list_query_defaults_to_a_bounded_first_page() {
        let parsed = parse_user_list_query(UserListQuery::default()).unwrap();
        assert_eq!(parsed.page, 1);
        assert_eq!(parsed.page_size, USER_DIRECTORY_DEFAULT_PAGE_SIZE);
        assert_eq!(parsed.offset, 0);
        assert!(parsed.filters.organization_id.is_none());
    }

    #[test]
    fn user_list_query_accepts_zero_offset_and_normalizes_day_end() {
        let parsed = parse_user_list_query(UserListQuery {
            offset: Some("0".to_string()),
            limit: Some("50".to_string()),
            created_from: Some("2026-01-01".to_string()),
            created_to: Some("2026-01-31".to_string()),
            linked_identity: Some("linked".to_string()),
            role: Some("admin".to_string()),
            ..UserListQuery::default()
        })
        .unwrap();
        assert_eq!(parsed.page, 1);
        assert_eq!(parsed.page_size, 50);
        assert_eq!(parsed.offset, 0);
        assert_eq!(
            parsed.filters.linked_identity,
            UserListLinkedIdentityFilter::Linked
        );
        assert_eq!(parsed.filters.role, UserListRoleFilter::Admin);
        assert_eq!(parsed.filters.created_from, Some(1_767_225_600));
        assert_eq!(parsed.filters.created_to, Some(1_769_904_000));
    }

    #[test]
    fn client_read_permissions_include_read_and_manage_access() {
        assert_eq!(
            CLIENT_READ_PERMISSIONS,
            &[Permission::ClientsRead, Permission::ClientsManage]
        );
    }

    #[test]
    fn bulk_csv_parser_normalizes_fields_and_rejects_duplicate_identities() {
        let batch = parse_bulk_import_csv(
            "email,username,display_name,organization_slug,organization_role,is_active\n\
             Alice@Example.com,alice,\"Alice, Example\",Corp,ADMIN,true\n\
             bob@example.com,bob,,,,0\n",
        )
        .unwrap();

        assert_eq!(batch.rows.len(), 2);
        assert_eq!(batch.rows[0].email.as_deref(), Some("alice@example.com"));
        assert_eq!(
            batch.candidates[0].organization_slug.as_deref(),
            Some("corp")
        );
        assert_eq!(
            batch.candidates[0].organization_role.as_deref(),
            Some("admin")
        );
        assert!(!batch.candidates[1].is_active);

        let mut duplicate_batch = parse_bulk_import_csv(
            "email,username,display_name,organization_slug,organization_role,is_active\n\
             first@example.com,duplicate,,,,true\n\
             second@example.com,duplicate,,,,false\n",
        )
        .unwrap();
        validate_bulk_import_duplicates(&mut duplicate_batch);
        assert_eq!(duplicate_batch.rows[0].outcome, "invalid");
        assert_eq!(duplicate_batch.rows[1].outcome, "invalid");
        assert!(
            duplicate_batch.rows[0]
                .error
                .as_deref()
                .is_some_and(|message| message.contains("username duplicates CSV row"))
        );
    }

    #[test]
    fn bulk_csv_parser_requires_exact_headers_and_boolean_status() {
        assert!(
            parse_bulk_import_csv(
                "email,username,display_name,organization_slug,organization_role\n\
             alice@example.com,alice,,,,true\n"
            )
            .is_err()
        );

        let batch = parse_bulk_import_csv(
            "\u{feff}email,username,display_name,organization_slug,organization_role,is_active\n\
             alice@example.com,alice,,,,sometimes\n",
        )
        .unwrap();
        assert_eq!(batch.rows[0].outcome, "invalid");
        assert_eq!(
            batch.rows[0].error.as_deref(),
            Some("is_active must be true or false")
        );
    }

    #[cfg(feature = "sqlite")]
    async fn bulk_import_test_state(
        permissions: &[Permission],
    ) -> (AppState, std::path::PathBuf, CookieJar) {
        let mut settings: crate::Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
        let path = std::env::temp_dir().join(format!(
            "gpt-sso-admin-bulk-import-test-{}.sqlite3",
            uuid::Uuid::new_v4()
        ));
        settings.database.kind = crate::config::DatabaseKind::Sqlite;
        settings.database.url = path.to_string_lossy().into_owned();
        settings.database.run_migrations = true;
        settings.bootstrap.admin.create_on_startup = false;
        settings.bootstrap.clients.clear();
        let db = crate::db::Db::connect(&settings).unwrap();
        db.migrate().await.unwrap();
        db.seed(&settings).await.unwrap();
        let jwt = crate::jwt::JwtManager::new(&settings).unwrap();
        let state = AppState { settings, db, jwt };
        let user = state
            .db
            .insert_user(NewUser {
                email: "bulk-manager@example.com".to_string(),
                username: "bulk-manager".to_string(),
                display_name: None,
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        if !permissions.is_empty() {
            let role = state
                .db
                .insert_role(NewRole {
                    name: format!("bulk-import-manager-{}", uuid::Uuid::new_v4()),
                    description: None,
                    is_system: false,
                    permissions: permissions
                        .iter()
                        .map(|permission| permission.as_str().to_string())
                        .collect(),
                })
                .await
                .unwrap();
            state
                .db
                .replace_user_roles(&user.id, vec![role.id])
                .await
                .unwrap();
        }
        let (_session, cookie_value) = state
            .db
            .insert_session(
                &user.id,
                state.settings.security.session_ttl_seconds,
                crate::db::SessionMetadata::default(),
            )
            .await
            .unwrap();
        let jar = CookieJar::new().add(axum_extra::extract::cookie::Cookie::new(
            state.settings.security.cookie_name.clone(),
            cookie_value,
        ));
        (state, path, jar)
    }

    #[cfg(feature = "sqlite")]
    async fn bulk_import_body(response: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bulk_import_dry_run_is_insert_only_and_records_row_results() {
        let (state, path, jar) =
            bulk_import_test_state(&[Permission::UsersManage, Permission::OrganizationsManage])
                .await;
        let organization = state
            .db
            .insert_organization(NewOrganization {
                slug: "corp".to_string(),
                name: "Corp".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: vec!["example.com".to_string()],
                is_active: true,
            })
            .await
            .unwrap();

        let response = import_users_csv(
            State(state.clone()),
            jar,
            Query(BulkImportQuery { dry_run: true }),
            "email,username,display_name,organization_slug,organization_role,is_active\n\
             alice@example.com,alice,Alice,corp,member,true\n"
                .to_string(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = bulk_import_body(response).await;
        assert_eq!(body["dry_run"], true);
        assert_eq!(body["committed"], false);
        assert_eq!(body["summary"]["would_create"], 1);
        assert_eq!(body["rows"][0]["outcome"], "would_create");
        assert!(
            state
                .db
                .find_user_by_email("alice@example.com")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .db
                .list_organization_members(&organization.id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            state
                .db
                .list_audit_events(10)
                .await
                .unwrap()
                .iter()
                .any(|event| event.action == "user.bulk_import.dry_run")
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bulk_import_requires_organization_manage_for_organization_roles() {
        let (state, path, jar) = bulk_import_test_state(&[Permission::UsersManage]).await;
        let result = import_users_csv(
            State(state.clone()),
            jar,
            Query(BulkImportQuery { dry_run: true }),
            "email,username,display_name,organization_slug,organization_role,is_active\n\
             alice@example.com,alice,Alice,corp,owner,true\n"
                .to_string(),
        )
        .await;
        assert!(matches!(result, Err(AppError::Forbidden)));
        assert!(
            state
                .db
                .find_user_by_email("alice@example.com")
                .await
                .unwrap()
                .is_none()
        );

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn enterprise_resource_inputs_cannot_override_selected_context() {
        let organization = UserOrganizationRecord {
            id: "selected-organization".to_string(),
            slug: "selected".to_string(),
            name: "Selected".to_string(),
            kind: organizations::ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            is_active: 1,
            role: organizations::ROLE_ADMIN.to_string(),
            membership_created_at: 1,
            membership_updated_at: 1,
        };

        assert_eq!(
            client_organization_from_context(None, &organization).unwrap(),
            Some(organization.id.clone())
        );
        assert_eq!(
            client_organization_from_context(Some(organization.id.clone()), &organization).unwrap(),
            Some(organization.id.clone())
        );
        assert!(matches!(
            client_organization_from_context(Some("other-organization".to_string()), &organization,),
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            client_organization_from_context(
                Some("  other-organization  ".to_string()),
                &organization,
            ),
            Err(AppError::Forbidden)
        ));
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bulk_import_commits_roles_atomically_and_rejects_existing_identities() {
        let (state, path, jar) =
            bulk_import_test_state(&[Permission::UsersManage, Permission::OrganizationsManage])
                .await;
        let organization = state
            .db
            .insert_organization(NewOrganization {
                slug: "corp".to_string(),
                name: "Corp".to_string(),
                kind: crate::organizations::ORGANIZATION_KIND_TENANT.to_string(),
                description: None,
                allowed_email_domains: Vec::new(),
                is_active: true,
            })
            .await
            .unwrap();
        let existing = state
            .db
            .insert_user(NewUser {
                email: "existing@example.com".to_string(),
                username: "existing".to_string(),
                display_name: None,
                phone: None,
                password_hash: "test-hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            })
            .await
            .unwrap();
        let invalid_response = import_users_csv(
            State(state.clone()),
            jar.clone(),
            Query(BulkImportQuery { dry_run: false }),
            "email,username,display_name,organization_slug,organization_role,is_active\n\
             new@example.com,new,New,corp,member,true\n\
             existing@example.com,different,Existing,corp,admin,true\n"
                .to_string(),
        )
        .await
        .unwrap();
        assert_eq!(invalid_response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let invalid_body = bulk_import_body(invalid_response).await;
        assert_eq!(invalid_body["summary"]["invalid"], 1);
        assert_eq!(invalid_body["summary"]["not_committed"], 1);
        assert!(
            state
                .db
                .find_user_by_email("new@example.com")
                .await
                .unwrap()
                .is_none()
        );

        let success_response = import_users_csv(
            State(state.clone()),
            jar,
            Query(BulkImportQuery { dry_run: false }),
            "email,username,display_name,organization_slug,organization_role,is_active\n\
             owner@example.com,owner,Owner,corp,owner,true\n\
             member@example.com,member,Member,corp,member,false\n"
                .to_string(),
        )
        .await
        .unwrap();
        assert_eq!(success_response.status(), StatusCode::OK);
        let success_body = bulk_import_body(success_response).await;
        assert_eq!(success_body["committed"], true);
        assert_eq!(success_body["summary"]["created"], 2);
        let memberships = state
            .db
            .list_organization_members(&organization.id)
            .await
            .unwrap();
        assert!(memberships.iter().any(|membership| {
            membership.email == "owner@example.com" && membership.role == organizations::ROLE_OWNER
        }));
        assert!(memberships.iter().any(|membership| {
            membership.email == "member@example.com"
                && membership.role == organizations::ROLE_MEMBER
                && membership.is_active == 0
        }));
        let existing_after = state
            .db
            .find_user_by_email("existing@example.com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(existing_after.id, existing.id);

        drop(state);
        let _ = std::fs::remove_file(path);
    }

    fn user(archived_at: Option<i64>) -> crate::db::UserRecord {
        crate::db::UserRecord {
            id: "user-id".to_string(),
            email: "user@example.com".to_string(),
            username: "user".to_string(),
            display_name: None,
            phone: None,
            password_hash: "hash".to_string(),
            email_verified_at: None,
            phone_verified_at: None,
            is_admin: 0,
            is_active: 1,
            archived_at,
            registration_source: "local".to_string(),
            last_login_at: None,
            last_login_ip: None,
            last_oidc_client_id: None,
            last_login_method: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn archived_users_are_not_editable() {
        assert!(archived_accounts::ensure_user_record_editable(&user(None)).is_ok());
        assert!(matches!(
            archived_accounts::ensure_user_record_editable(&user(Some(100))),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn profile_updates_cannot_bypass_lifecycle_or_self_role_guards() {
        let mut current = user(None);
        current.is_admin = 1;
        let target = current.clone();

        assert!(ensure_account_metadata_update_allowed(&current, &target, true, true).is_ok());
        assert!(matches!(
            ensure_account_metadata_update_allowed(&current, &target, false, true),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            ensure_account_metadata_update_allowed(&current, &target, true, false),
            Err(AppError::BadRequest(_))
        ));

        let mut other = target.clone();
        other.id = "other-user-id".to_string();
        assert!(ensure_account_metadata_update_allowed(&current, &other, false, true).is_ok());
        assert!(matches!(
            ensure_account_metadata_update_allowed(&current, &other, false, false),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn user_input_is_normalized_before_admin_writes() {
        let input = normalize_user_input(UserInput {
            email: " User@Example.COM ".to_string(),
            username: " alice ".to_string(),
            display_name: Some(" Alice ".to_string()),
            phone: Some("  ".to_string()),
            password: Some("  ".to_string()),
            is_admin: false,
            is_active: true,
        })
        .unwrap();

        assert_eq!(input.email, "user@example.com");
        assert_eq!(input.username, "alice");
        assert_eq!(input.display_name.as_deref(), Some("Alice"));
        assert_eq!(input.phone, None);
        assert_eq!(input.password, None);
    }

    #[test]
    fn admin_universal_code_creation_and_updates_require_a_true_administrator() {
        let delegated_manager = user(None);
        assert!(matches!(
            ensure_admin_universal_manager(
                &delegated_manager,
                AuthorizationCodeType::Login,
                LoginCodeLevel::AdminUniversal,
            ),
            Err(AppError::Forbidden)
        ));
        assert!(
            ensure_admin_universal_manager(
                &delegated_manager,
                AuthorizationCodeType::Login,
                LoginCodeLevel::AccountRecovery,
            )
            .is_ok()
        );

        let mut administrator = delegated_manager;
        administrator.is_admin = 1;
        assert!(
            ensure_admin_universal_manager(
                &administrator,
                AuthorizationCodeType::Login,
                LoginCodeLevel::AdminUniversal,
            )
            .is_ok()
        );
    }

    #[test]
    fn account_recovery_target_must_be_an_exact_active_existing_user() {
        assert!(matches!(
            recovery_target_user_id("user", None),
            Err(AppError::BadRequest(message))
                if message.contains("existing account")
        ));

        let mut case_mismatch = user(None);
        case_mismatch.username = "User".to_string();
        assert!(matches!(
            recovery_target_user_id("user", Some(case_mismatch)),
            Err(AppError::BadRequest(message))
                if message.contains("exactly match")
        ));

        let mut disabled = user(None);
        disabled.is_active = 0;
        assert!(matches!(
            recovery_target_user_id("user", Some(disabled)),
            Err(AppError::BadRequest(message))
                if message.contains("active account")
        ));
        assert!(matches!(
            recovery_target_user_id("user", Some(user(Some(1)))),
            Err(AppError::BadRequest(message))
                if message.contains("active account")
        ));
        assert_eq!(
            recovery_target_user_id("user", Some(user(None))).unwrap(),
            "user-id"
        );
    }

    #[test]
    fn admin_universal_codes_reject_account_binding_metadata() {
        assert!(matches!(
            validate_login_code_binding_metadata(
                LoginCodeLevel::AdminUniversal,
                None,
                Some("user"),
                None,
            ),
            Err(AppError::BadRequest(message))
                if message.contains("cannot set account binding metadata")
        ));
        assert!(
            validate_login_code_binding_metadata(LoginCodeLevel::AdminUniversal, None, None, None,)
                .is_ok()
        );
    }

    #[test]
    fn all_login_codes_reject_unused_email_and_display_name_metadata() {
        for level in [
            LoginCodeLevel::AccountRecovery,
            LoginCodeLevel::AdminUniversal,
            LoginCodeLevel::TrialEnrollment,
        ] {
            for (email, display_name) in [(Some("user@example.com"), None), (None, Some("User"))] {
                assert!(matches!(
                    validate_login_code_binding_metadata(
                        level,
                        email,
                        (level == LoginCodeLevel::AccountRecovery).then_some("user"),
                        display_name,
                    ),
                    Err(AppError::BadRequest(message))
                        if message.contains("cannot set email or display-name metadata")
                ));
            }
        }
        assert!(
            validate_login_code_binding_metadata(
                LoginCodeLevel::AccountRecovery,
                None,
                Some("user"),
                None,
            )
            .is_ok()
        );
        assert!(matches!(
            validate_login_code_binding_metadata(
                LoginCodeLevel::TrialEnrollment,
                None,
                Some("user"),
                None,
            ),
            Err(AppError::BadRequest(message)) if message.contains("cannot set account binding metadata")
        ));
    }

    #[test]
    fn authorization_code_client_allowlist_is_immutable() {
        let existing = vec!["client-b".to_string(), "client-a".to_string()];
        assert_eq!(
            immutable_allowed_client_ids(existing.clone(), None).unwrap(),
            vec!["client-a".to_string(), "client-b".to_string()]
        );
        assert!(
            immutable_allowed_client_ids(
                existing.clone(),
                Some(vec![
                    " client-a ".to_string(),
                    "client-b".to_string(),
                    "client-a".to_string(),
                ]),
            )
            .is_ok()
        );
        assert!(matches!(
            immutable_allowed_client_ids(existing, Some(vec!["client-c".to_string()])),
            Err(AppError::BadRequest(message))
                if message == "allowed_client_ids cannot be changed after creation"
        ));
    }

    #[test]
    fn account_recovery_username_is_immutable_and_missing_put_field_is_preserved() {
        assert_eq!(
            immutable_recovery_username(Some("recovery-user"), None).unwrap(),
            Some("recovery-user".to_string())
        );
        assert_eq!(
            immutable_recovery_username(
                Some("recovery-user"),
                Some(" recovery-user ".to_string()),
            )
            .unwrap(),
            Some("recovery-user".to_string())
        );
        assert!(matches!(
            immutable_recovery_username(
                Some("recovery-user"),
                Some("different-user".to_string()),
            ),
            Err(AppError::BadRequest(message)) if message.contains("cannot be changed")
        ));
        assert!(matches!(
            immutable_recovery_username(Some("recovery-user"), Some(" ".to_string())),
            Err(AppError::BadRequest(message)) if message.contains("cannot be cleared")
        ));
    }

    fn external_provider_input() -> ExternalOidcProviderInput {
        ExternalOidcProviderInput {
            slug: "Corp_OIDC".to_string(),
            display_name: " Corp OIDC ".to_string(),
            organization_id: None,
            issuer: "https://idp.example.com/".to_string(),
            client_id: " client ".to_string(),
            client_secret: " secret ".to_string(),
            clear_client_secret: false,
            authorization_endpoint: "https://idp.example.com/oauth2/authorize/".to_string(),
            token_endpoint: "https://idp.example.com/oauth2/token/".to_string(),
            userinfo_endpoint: "https://idp.example.com/oauth2/userinfo/".to_string(),
            redirect_path: "/api/register/oidc/corp_oidc/callback".to_string(),
            scopes: vec![
                " openid ".to_string(),
                "email".to_string(),
                "openid".to_string(),
            ],
            email_domains: vec![
                " @Example.COM. ".to_string(),
                "team.example.com".to_string(),
                "example.com".to_string(),
            ],
            is_active: true,
            allow_login: true,
            allow_registration: true,
        }
    }

    fn ldap_provider_input() -> LdapProviderInput {
        LdapProviderInput {
            slug: "Corp_LDAP".to_string(),
            display_name: " Corp LDAP ".to_string(),
            organization_id: None,
            url: "ldap://ldap.example.com/".to_string(),
            starttls: true,
            bind_dn: " cn=reader,dc=example,dc=com ".to_string(),
            bind_password: Some(" secret ".to_string()),
            clear_bind_password: false,
            base_dn: " dc=example,dc=com ".to_string(),
            user_filter: " (&(objectClass=person)(|(mail={login})(uid={login}))) ".to_string(),
            user_id_attribute: " DN ".to_string(),
            email_attribute: " mail ".to_string(),
            username_attribute: " uid ".to_string(),
            display_name_attribute: " cn ".to_string(),
            phone_attribute: " telephoneNumber ".to_string(),
            is_active: true,
            allow_login: true,
            allow_registration: true,
        }
    }

    #[test]
    fn external_provider_input_is_normalized_and_path_bound_to_slug() {
        let provider = normalize_external_provider_input(external_provider_input(), None).unwrap();

        assert_eq!(provider.slug, "corp_oidc");
        assert_eq!(provider.display_name, "Corp OIDC");
        assert_eq!(provider.issuer, "https://idp.example.com");
        assert_eq!(
            provider.authorization_endpoint,
            "https://idp.example.com/oauth2/authorize/"
        );
        assert_eq!(
            provider.redirect_path,
            "/api/register/oidc/corp_oidc/callback"
        );
        assert_eq!(
            provider.scopes,
            vec!["email".to_string(), "openid".to_string()]
        );
        assert_eq!(
            provider.email_domains,
            vec!["example.com".to_string(), "team.example.com".to_string()]
        );
        assert!(provider.allow_login);
    }

    #[test]
    fn external_provider_input_rejects_unsafe_urls_and_paths() {
        let mut provider = external_provider_input();
        provider.authorization_endpoint = "javascript:alert(1)".to_string();
        assert!(matches!(
            normalize_external_provider_input(provider, None),
            Err(AppError::BadRequest(_))
        ));

        let mut provider = external_provider_input();
        provider.redirect_path = "/api/register/oidc/other/callback".to_string();
        assert!(matches!(
            normalize_external_provider_input(provider, None),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn external_provider_update_preserves_or_explicitly_clears_secret() {
        let mut payload = external_provider_input();
        payload.client_secret = " ".to_string();
        let mut provider = normalize_external_provider_input(payload, None).unwrap();
        apply_external_provider_secret_update(&mut provider, "stored-secret", false);
        assert_eq!(provider.client_secret, "stored-secret");

        apply_external_provider_secret_update(&mut provider, "stored-secret", true);
        assert!(provider.client_secret.is_empty());

        let mut provider =
            normalize_external_provider_input(external_provider_input(), None).unwrap();
        apply_external_provider_secret_update(&mut provider, "stored-secret", false);
        assert_eq!(provider.client_secret, "secret");
    }

    #[test]
    fn organization_options_do_not_grant_full_member_read_access() {
        for permission in [
            Permission::ClientsManage,
            Permission::IapRead,
            Permission::IapManage,
            Permission::ProvidersManage,
        ] {
            assert!(ORGANIZATION_OPTION_PERMISSIONS.contains(&permission));
            assert!(!ORGANIZATION_READ_PERMISSIONS.contains(&permission));
        }
    }

    #[test]
    fn active_external_provider_requires_runtime_fields() {
        let mut provider = external_provider_input();
        provider.client_id = " ".to_string();
        assert!(matches!(
            normalize_external_provider_input(provider, None),
            Err(AppError::BadRequest(_))
        ));

        let mut provider = external_provider_input();
        provider.is_active = false;
        provider.client_id = " ".to_string();
        assert!(normalize_external_provider_input(provider, None).is_ok());
    }

    #[test]
    fn ldap_provider_input_is_normalized() {
        let provider = normalize_ldap_provider_input(ldap_provider_input(), None).unwrap();

        assert_eq!(provider.slug, "corp_ldap");
        assert_eq!(provider.display_name, "Corp LDAP");
        assert_eq!(provider.url, "ldap://ldap.example.com");
        assert_eq!(provider.bind_dn, "cn=reader,dc=example,dc=com");
        assert_eq!(provider.bind_password.as_deref(), Some("secret"));
        assert_eq!(provider.base_dn, "dc=example,dc=com");
        assert_eq!(provider.user_id_attribute, "dn");
        assert_eq!(provider.email_attribute, "mail");
        assert_eq!(provider.username_attribute, "uid");
    }

    #[test]
    fn ldap_provider_input_rejects_unsafe_runtime_values() {
        let mut provider = ldap_provider_input();
        provider.url = "http://ldap.example.com".to_string();
        assert!(matches!(
            normalize_ldap_provider_input(provider, None),
            Err(AppError::BadRequest(_))
        ));

        let mut provider = ldap_provider_input();
        provider.user_filter = "(objectClass=person)".to_string();
        assert!(matches!(
            normalize_ldap_provider_input(provider, None),
            Err(AppError::BadRequest(_))
        ));

        let mut provider = ldap_provider_input();
        provider.email_attribute = "mail)(uid=*".to_string();
        assert!(matches!(
            normalize_ldap_provider_input(provider, None),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn inactive_ldap_provider_can_be_saved_incomplete() {
        let mut provider = ldap_provider_input();
        provider.is_active = false;
        provider.url = String::new();
        provider.base_dn = String::new();
        provider.user_filter = String::new();

        let provider = normalize_ldap_provider_input(provider, None).unwrap();
        assert_eq!(provider.url, "");
        assert!(provider.user_filter.contains("{login}"));
    }

    fn client_input() -> ClientInput {
        ClientInput {
            client_id: "demo-web".to_string(),
            client_name: "Demo Web".to_string(),
            logo_uri: String::new(),
            organization_id: None,
            client_secret: None,
            redirect_uris: vec![
                " https://app.example.com/callback ".to_string(),
                "https://app.example.com/callback".to_string(),
                "https://app.example.com/alt".to_string(),
                " ".to_string(),
            ],
            post_logout_redirect_uris: vec![" https://app.example.com/logout ".to_string()],
            scopes: vec!["openid".to_string(), "profile".to_string()],
            audience: None,
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "none".to_string(),
            require_pkce: true,
            require_mfa: false,
            require_pushed_authorization_requests: false,
            require_s256_pkce: false,
            require_confidential_client: false,
            require_dpop: false,
            require_account_selection: false,
            trust_email_verified: false,
            authorization_details_types: Vec::new(),
            subject_type: subject::SUBJECT_TYPE_PUBLIC.to_string(),
            sector_identifier_uri: String::new(),
            jwks_uri: String::new(),
            jwks: String::new(),
            backchannel_logout_uri: String::new(),
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: " https://app.example.com/front-logout ".to_string(),
            frontchannel_logout_session_required: false,
            service_account_enabled: false,
            service_account_permissions: Vec::new(),
            is_active: true,
            claim_mappers: Vec::new(),
        }
    }

    #[test]
    fn client_redirect_uris_are_validated_and_normalized() {
        let input = client_input();
        validate_client_input(&input).unwrap();

        let client = client_input_to_new(input, None, None, None).unwrap();
        assert_eq!(
            client.redirect_uris,
            vec![
                "https://app.example.com/callback".to_string(),
                "https://app.example.com/alt".to_string()
            ]
        );
        assert_eq!(
            client.post_logout_redirect_uris,
            vec!["https://app.example.com/logout".to_string()]
        );
        assert_eq!(
            client.frontchannel_logout_uri,
            "https://app.example.com/front-logout"
        );
    }

    #[test]
    fn client_update_preserves_secret_when_omitted_and_clears_when_auth_is_public() {
        let mut initial_input = client_input();
        initial_input.token_endpoint_auth_method = "client_secret_basic".to_string();
        initial_input.client_secret = Some("initial-secret".to_string());
        let initial = client_input_to_new(initial_input, None, None, None).unwrap();
        let initial_hash = initial.client_secret_hash.clone().unwrap();

        let mut preserve_input = client_input();
        preserve_input.token_endpoint_auth_method = "client_secret_basic".to_string();
        let preserved =
            client_input_to_new(preserve_input, Some(initial_hash.clone()), None, None).unwrap();
        assert_eq!(preserved.client_secret_hash, Some(initial_hash.clone()));

        let mut clear_input = client_input();
        clear_input.token_endpoint_auth_method = "none".to_string();
        let cleared = client_input_to_new(clear_input, Some(initial_hash), None, None).unwrap();
        assert_eq!(cleared.client_secret_hash, None);
    }

    #[test]
    fn client_logo_uri_is_normalized_and_rejects_unsafe_urls() {
        let mut input = client_input();
        input.logo_uri = " https://assets.example.com/signet.svg ".to_string();
        validate_client_input(&input).unwrap();
        let client = client_input_to_new(input, None, None, None).unwrap();
        assert_eq!(client.logo_uri, "https://assets.example.com/signet.svg");

        for logo_uri in [
            "javascript:alert(1)",
            "https://user:secret@assets.example.com/logo.svg",
            "https://assets.example.com/logo.svg#fragment",
        ] {
            let mut input = client_input();
            input.logo_uri = logo_uri.to_string();
            assert!(matches!(
                validate_client_input(&input),
                Err(AppError::BadRequest(_))
            ));
        }
    }

    #[test]
    fn client_redirect_uris_reject_fragments_and_non_http_schemes() {
        let mut input = client_input();
        input.redirect_uris = vec!["https://app.example.com/callback#fragment".to_string()];
        assert!(matches!(
            validate_client_input(&input),
            Err(AppError::BadRequest(_))
        ));

        let mut input = client_input();
        input.post_logout_redirect_uris = vec!["javascript:alert(1)".to_string()];
        assert!(matches!(
            validate_client_input(&input),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn client_security_policy_rejects_incoherent_settings() {
        let mut input = client_input();
        input.require_s256_pkce = true;
        input.require_pkce = false;
        assert!(matches!(
            validate_client_input(&input),
            Err(AppError::BadRequest(_))
        ));

        let mut input = client_input();
        input.require_confidential_client = true;
        input.token_endpoint_auth_method = "none".to_string();
        assert!(matches!(
            validate_client_input(&input),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn email_domains_are_normalized_and_deduplicated() {
        assert_eq!(
            normalize_email_domains(vec![
                "@Example.COM.".to_string(),
                "example.com".to_string(),
                "corp".to_string(),
                " ".to_string()
            ])
            .unwrap(),
            vec!["example.com".to_string(), "corp".to_string()]
        );
    }

    #[test]
    fn invalid_email_domains_are_rejected() {
        assert!(matches!(
            normalize_email_domains(vec!["bad/domain".to_string()]),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            normalize_email_domains(vec!["bad domain".to_string()]),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            normalize_email_domains(vec!["bad\\domain".to_string()]),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            normalize_email_domains(vec!["bad..domain".to_string()]),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn quick_links_are_normalized_for_login_entry_configuration() {
        let links = normalize_quick_links(vec![
            QuickLink {
                id: " OpenAI Link! ".to_string(),
                label: " OpenAI ".to_string(),
                url: " https://chatgpt.com/auth/login?sso=true&connection=conn_01KTR8HRA3ZQR9S3EGT32TY3WT ".to_string(),
                icon: " openai! ".to_string(),
                is_active: true,
            },
            QuickLink {
                id: "".to_string(),
                label: "".to_string(),
                url: "".to_string(),
                icon: "".to_string(),
                is_active: false,
            },
        ])
        .unwrap();

        assert_eq!(links.len(), 1);
        assert_eq!(links[0].id, "OpenAILink");
        assert_eq!(links[0].label, "OpenAI");
        assert_eq!(
            links[0].url,
            "https://chatgpt.com/auth/login?sso=true&connection=conn_01KTR8HRA3ZQR9S3EGT32TY3WT"
        );
        assert!(links[0].icon.is_empty());
        assert!(links[0].is_active);
    }

    #[test]
    fn invalid_or_duplicate_quick_links_are_rejected() {
        assert!(matches!(
            normalize_quick_links(vec![QuickLink {
                id: "bad".to_string(),
                label: "Bad".to_string(),
                url: "javascript:alert(1)".to_string(),
                icon: "link".to_string(),
                is_active: true,
            }]),
            Err(AppError::BadRequest(_))
        ));

        assert!(matches!(
            normalize_quick_links(vec![
                QuickLink {
                    id: "open-ai".to_string(),
                    label: "OpenAI".to_string(),
                    url: "https://chatgpt.com".to_string(),
                    icon: "openai".to_string(),
                    is_active: true,
                },
                QuickLink {
                    id: "open-ai".to_string(),
                    label: "OpenAI duplicate".to_string(),
                    url: "https://chatgpt.com/auth/login".to_string(),
                    icon: "openai".to_string(),
                    is_active: true,
                },
            ]),
            Err(AppError::BadRequest(message)) if message == "quick link id must be unique"
        ));
    }

    #[test]
    fn brand_logo_url_allows_blank_and_rejects_unsafe_urls() {
        assert_eq!(normalize_brand_logo_url("  ".to_string()).unwrap(), "");
        assert_eq!(
            normalize_brand_logo_url(" https://cdn.example.com/signet.svg ".to_string()).unwrap(),
            "https://cdn.example.com/signet.svg"
        );
        assert!(matches!(
            normalize_brand_logo_url("javascript:alert(1)".to_string()),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            normalize_brand_logo_url("/signet.svg".to_string()),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            normalize_brand_logo_url(format!("https://cdn.example.com/{}", "a".repeat(2048))),
            Err(AppError::BadRequest(_))
        ));
    }

    #[test]
    fn login_settings_input_preserves_compatibility_with_clients_without_brand_logo_url() {
        let input: LoginSettingsInput = serde_json::from_value(serde_json::json!({
            "email_domains": [],
            "quick_links": []
        }))
        .unwrap();

        assert!(input.brand_logo_url.is_none());
    }
}
