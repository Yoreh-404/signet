use super::*;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn directory_sync_snapshot_rejects_identity_collisions_before_publishing() {
    let (db, path) = sqlite_test_db().await;
    let context = DirectorySyncApplyContext {
        application_id: "application".to_string(),
        provider_id: "provider".to_string(),
        run_id: "run".to_string(),
        provider_key: "ldap:provider".to_string(),
        organization_id: "organization".to_string(),
        provider_display_name: "Directory".to_string(),
        reactivate_users: true,
        expected_application_updated_at: None,
        expected_provider_updated_at: None,
        expected_organization_updated_at: None,
    };
    let cases = [
        (
            DirectorySyncUserPlan {
                subject: "subject-a".to_string(),
                dn: "uid=a,dc=example".to_string(),
                email: "same@example.test".to_string(),
                username: "user-a".to_string(),
                display_name: None,
                phone: None,
                password_hash: None,
            },
            DirectorySyncUserPlan {
                subject: "subject-b".to_string(),
                dn: "uid=b,dc=example".to_string(),
                email: "same@example.test".to_string(),
                username: "user-b".to_string(),
                display_name: None,
                phone: None,
                password_hash: None,
            },
            "email",
        ),
        (
            DirectorySyncUserPlan {
                subject: "subject-a".to_string(),
                dn: "uid=same,dc=example".to_string(),
                email: "a@example.test".to_string(),
                username: "user-a".to_string(),
                display_name: None,
                phone: None,
                password_hash: None,
            },
            DirectorySyncUserPlan {
                subject: "subject-b".to_string(),
                dn: "uid=same,dc=example".to_string(),
                email: "b@example.test".to_string(),
                username: "user-b".to_string(),
                display_name: None,
                phone: None,
                password_hash: None,
            },
            "DN",
        ),
    ];

    for (first, second, detail) in cases {
        let result = db
            .apply_directory_sync_snapshot(
                context.clone(),
                DirectorySyncSnapshotPlan {
                    users: vec![first, second],
                    groups: Vec::new(),
                },
            )
            .await;
        assert!(matches!(result, Err(AppError::BadRequest(message)) if message.contains(detail)));
        assert!(
            db.find_user_by_email("same@example.test")
                .await
                .unwrap()
                .is_none()
        );
    }

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn directory_sync_snapshot_fences_stale_control_plane_state_atomically() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("sync-fence-org", "Sync Fence Org"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "sync-fence-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let provider = db
        .insert_ldap_provider(NewLdapProvider {
            slug: "sync-fence-provider".to_string(),
            display_name: "Sync Fence Provider".to_string(),
            organization_id: Some(organization.id.clone()),
            url: "ldaps://directory.example.test".to_string(),
            starttls: false,
            bind_dn: "cn=reader,dc=example".to_string(),
            bind_password: Some("secret".to_string()),
            base_dn: "dc=example".to_string(),
            user_filter: "(uid={login})".to_string(),
            user_id_attribute: "uid".to_string(),
            email_attribute: "mail".to_string(),
            username_attribute: "uid".to_string(),
            display_name_attribute: "cn".to_string(),
            phone_attribute: "telephoneNumber".to_string(),
            is_active: true,
            allow_login: true,
            allow_registration: true,
        })
        .await
        .unwrap();
    let run = db
        .start_directory_sync_run(&application.id, &provider.id)
        .await
        .unwrap();
    let result = db
        .apply_directory_sync_snapshot(
            DirectorySyncApplyContext {
                application_id: application.id.clone(),
                provider_id: provider.id.clone(),
                run_id: run.id,
                provider_key: provider.provider_key(),
                organization_id: organization.id.clone(),
                provider_display_name: provider.display_name,
                reactivate_users: true,
                expected_application_updated_at: Some(application.updated_at - 1),
                expected_provider_updated_at: Some(provider.updated_at),
                expected_organization_updated_at: Some(organization.updated_at),
            },
            DirectorySyncSnapshotPlan {
                users: vec![DirectorySyncUserPlan {
                    subject: "subject-fenced".to_string(),
                    dn: "uid=fenced,dc=example".to_string(),
                    email: "fenced@example.test".to_string(),
                    username: "fenced".to_string(),
                    display_name: Some("Fenced User".to_string()),
                    phone: None,
                    password_hash: None,
                }],
                groups: Vec::new(),
            },
        )
        .await;
    assert!(
        matches!(result, Err(AppError::BadRequest(message)) if message.contains("control-plane"))
    );
    assert!(
        db.find_user_by_email("fenced@example.test")
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn effective_permission_queries_include_direct_and_group_roles() {
    let (db, path) = sqlite_test_db().await;
    let user = db
        .insert_user(test_user(
            "permission-query@example.test",
            "permission-query",
        ))
        .await
        .unwrap();
    let direct_role = db
        .insert_role(NewRole {
            name: "permission-query-direct".to_string(),
            description: None,
            is_system: false,
            permissions: vec!["account.read".to_string(), "shared.read".to_string()],
        })
        .await
        .unwrap();
    let group_role = db
        .insert_role(NewRole {
            name: "permission-query-group".to_string(),
            description: None,
            is_system: false,
            permissions: vec!["group.read".to_string(), "shared.read".to_string()],
        })
        .await
        .unwrap();
    db.replace_user_roles(&user.id, vec![direct_role.id.clone()])
        .await
        .unwrap();
    let group = db
        .insert_group(NewGroup {
            name: "Permission Query Group".to_string(),
            description: None,
        })
        .await
        .unwrap();
    db.replace_group_members(&group.id, vec![user.id.clone()])
        .await
        .unwrap();
    db.replace_group_roles(&group.id, vec![group_role.id])
        .await
        .unwrap();

    assert!(
        db.has_effective_permission(&user.id, "account.read")
            .await
            .unwrap()
    );
    assert!(
        db.has_effective_permission(&user.id, "group.read")
            .await
            .unwrap()
    );
    assert!(
        db.has_any_effective_permission(&user.id, &["missing", "group.read"])
            .await
            .unwrap()
    );
    assert!(
        !db.has_any_effective_permission(&user.id, &[])
            .await
            .unwrap()
    );
    assert_eq!(
        db.list_effective_permissions(&user.id).await.unwrap(),
        vec!["account.read", "group.read", "shared.read"]
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[test]
fn default_quick_link_is_merged_without_overwriting_existing_links() {
    let existing_link = QuickLink {
        id: "help".to_string(),
        label: "Help".to_string(),
        url: "https://help.example".to_string(),
        icon: "help".to_string(),
        is_active: true,
    };
    let record = LoginSettingsRecord {
        id: "default".to_string(),
        brand_logo_url: String::new(),
        email_domains: "[]".to_string(),
        quick_links: util::to_json(&vec![existing_link.clone()]).unwrap(),
        updated_at: 1,
    };

    let merged = merge_missing_quick_links(&record, &[default_openai_quick_link()])
        .unwrap()
        .unwrap();
    let links = util::from_json::<Vec<QuickLink>>(&merged).unwrap();

    assert_eq!(links.len(), 2);
    assert!(links.iter().any(|link| link.id == existing_link.id));
    assert!(links.iter().any(|link| link.id == "openai"));
}

#[test]
fn default_quick_link_merge_is_idempotent() {
    let openai = default_openai_quick_link();
    let record = LoginSettingsRecord {
        id: "default".to_string(),
        brand_logo_url: String::new(),
        email_domains: "[]".to_string(),
        quick_links: util::to_json(&vec![openai.clone()]).unwrap(),
        updated_at: 1,
    };

    assert!(
        merge_missing_quick_links(&record, &[openai])
            .unwrap()
            .is_none()
    );
}

#[test]
fn migration_duplicate_errors_are_ignored_only_for_idempotent_shapes() {
    assert!(is_ignorable_migration_error(
        "ALTER TABLE users ADD COLUMN archived_at BIGINT NULL",
        "Duplicate column name 'archived_at'",
    ));
    assert!(is_ignorable_migration_error(
        "CREATE INDEX idx_login_events_user_id ON login_events(user_id, login_at)",
        "Duplicate key name 'idx_login_events_user_id'",
    ));
    assert!(is_ignorable_migration_error(
        "CREATE INDEX idx_login_events_user_id ON login_events(user_id, login_at)",
        "relation \"idx_login_events_user_id\" already exists",
    ));
    assert!(is_ignorable_migration_error(
        "CREATE UNIQUE INDEX idx_users_email ON users(email)",
        "Duplicate key name 'idx_users_email'",
    ));
    assert!(!is_ignorable_migration_error(
        "CREATE TABLE users (id TEXT PRIMARY KEY)",
        "syntax error near users",
    ));
    assert!(!is_ignorable_migration_error(
        "UPDATE users SET email = 'duplicate'",
        "duplicate key value violates unique constraint",
    ));
}

#[test]
fn mysql_migrations_do_not_use_text_defaults() {
    for statement in MYSQL_MIGRATIONS {
        assert!(
            !statement.contains("TEXT NOT NULL DEFAULT")
                && !statement.contains("TEXT NULL DEFAULT"),
            "MySQL migration uses an incompatible default column type: {statement}"
        );
        assert!(
            !statement
                .trim_start()
                .to_ascii_uppercase()
                .starts_with("UPDATE ")
                && !statement
                    .trim_start()
                    .to_ascii_uppercase()
                    .contains(" MODIFY COLUMN "),
            "MySQL startup migration must not rewrite existing tables: {statement}"
        );
    }

    for statement in [
        "ALTER TABLE clients ADD COLUMN authorization_details_types TEXT NULL",
        "ALTER TABLE clients ADD COLUMN service_account_permissions TEXT NULL",
        "ALTER TABLE authorization_codes ADD COLUMN amr TEXT NULL",
        "ALTER TABLE security_policy ADD COLUMN trusted_ip_cidrs TEXT NULL",
        "ALTER TABLE security_policy ADD COLUMN allowed_ip_cidrs TEXT NULL",
        "ALTER TABLE security_policy ADD COLUMN blocked_ip_cidrs TEXT NULL",
        "ALTER TABLE security_policy ADD COLUMN allowed_email_domains TEXT NULL",
        "ALTER TABLE security_policy ADD COLUMN blocked_email_domains TEXT NULL",
        "ALTER TABLE organizations ADD COLUMN allowed_email_domains TEXT NULL",
        "ALTER TABLE external_oidc_providers ADD COLUMN email_domains TEXT NULL",
    ] {
        assert!(
            MYSQL_MIGRATIONS.contains(&statement),
            "missing nullable legacy JSON migration: {statement}"
        );
    }
}

#[test]
fn login_settings_brand_logo_url_migrations_cover_all_database_engines() {
    assert!(SQLITE_MIGRATIONS.contains(
        &"ALTER TABLE login_settings ADD COLUMN brand_logo_url TEXT NOT NULL DEFAULT ''"
    ));
    assert!(POSTGRES_MIGRATIONS.contains(
            &"ALTER TABLE login_settings ADD COLUMN IF NOT EXISTS brand_logo_url TEXT NOT NULL DEFAULT ''"
        ));
    assert!(MYSQL_MIGRATIONS.contains(
        &"ALTER TABLE login_settings ADD COLUMN brand_logo_url VARCHAR(2048) NOT NULL DEFAULT ''"
    ));
}

#[test]
fn client_audience_migrations_cover_all_database_engines() {
    assert!(
        SQLITE_MIGRATIONS
            .contains(&"ALTER TABLE clients ADD COLUMN audience TEXT NOT NULL DEFAULT ''")
    );
    assert!(POSTGRES_MIGRATIONS.contains(
        &"ALTER TABLE clients ADD COLUMN IF NOT EXISTS audience TEXT NOT NULL DEFAULT ''"
    ));
    assert!(
        MYSQL_MIGRATIONS
            .contains(&"ALTER TABLE clients ADD COLUMN audience VARCHAR(2048) NOT NULL DEFAULT ''")
    );
}

#[test]
fn application_authorization_profile_migrations_cover_all_database_engines() {
    let required_tables = [
        "application_authorization_profiles",
        "application_authorization_migration_state",
        "application_permission_definitions",
        "application_profile_roles",
        "application_profile_user_roles",
        "application_profile_group_roles",
        "application_profile_organization_roles",
        "application_profile_permission_overrides",
    ];
    for (kind, migrations) in [
        (DatabaseKind::Sqlite, SQLITE_MIGRATIONS),
        (DatabaseKind::Postgres, POSTGRES_MIGRATIONS),
        (DatabaseKind::Mysql, MYSQL_MIGRATIONS),
    ] {
        for table in required_tables {
            assert!(
                migrations.iter().any(|statement| {
                    statement.contains(&format!("CREATE TABLE IF NOT EXISTS {table}"))
                }),
                "{kind:?} is missing {table}"
            );
        }
    }
}

#[test]
fn application_discovery_idempotency_migrations_cover_all_database_engines() {
    for (kind, migrations) in [
        (DatabaseKind::Sqlite, SQLITE_MIGRATIONS),
        (DatabaseKind::Postgres, POSTGRES_MIGRATIONS),
        (DatabaseKind::Mysql, MYSQL_MIGRATIONS),
    ] {
        assert!(
            migrations.iter().any(|statement| {
                statement.contains("CREATE TABLE IF NOT EXISTS application_discovery_idempotency")
                    && statement.contains("claim_token")
                    && statement.contains("request_hash")
            }),
            "{kind:?} is missing application discovery idempotency storage"
        );
    }
}

#[test]
fn billing_migrations_cover_wallet_orders_refunds_and_all_database_engines() {
    let required_tables = [
        "application_billing_settings",
        "wallet_accounts",
        "wallet_transactions",
        "wallet_entries",
        "wallet_holds",
        "payment_orders",
        "payment_refunds",
    ];
    for (kind, migrations) in [
        (DatabaseKind::Sqlite, SQLITE_MIGRATIONS),
        (DatabaseKind::Postgres, POSTGRES_MIGRATIONS),
        (DatabaseKind::Mysql, MYSQL_MIGRATIONS),
    ] {
        for table in required_tables {
            assert!(
                migrations.iter().any(|statement| {
                    statement.contains(&format!("CREATE TABLE IF NOT EXISTS {table}"))
                }),
                "{kind:?} is missing {table}"
            );
        }
        assert!(
            migrations.iter().any(|statement| {
                statement.contains("idempotency_key") && statement.contains("payment_refunds")
            }),
            "{kind:?} is missing payment refund idempotency compatibility"
        );
        assert!(
            migrations.iter().any(|statement| {
                statement.contains("payment_orders")
                    && statement.contains("idempotency_key")
                    && statement.contains("UNIQUE")
            }),
            "{kind:?} is missing payment order idempotency uniqueness"
        );
    }
}

#[test]
fn application_jwt_migrations_cover_clients_secrets_and_bound_codes() {
    for (kind, migrations) in [
        (DatabaseKind::Sqlite, SQLITE_MIGRATIONS),
        (DatabaseKind::Postgres, POSTGRES_MIGRATIONS),
        (DatabaseKind::Mysql, MYSQL_MIGRATIONS),
    ] {
        let has_code_table = migrations.iter().any(|statement| {
            statement.contains("CREATE TABLE IF NOT EXISTS application_jwt_codes")
        });
        let has_client_table = migrations.iter().any(|statement| {
            statement.contains("CREATE TABLE IF NOT EXISTS application_jwt_clients")
        });
        let has_secret_table = migrations.iter().any(|statement| {
            statement.contains("CREATE TABLE IF NOT EXISTS application_jwt_client_secrets")
        });
        assert!(has_code_table, "{kind:?} is missing application JWT codes");
        assert!(
            has_client_table,
            "{kind:?} is missing application JWT clients"
        );
        assert!(
            has_secret_table,
            "{kind:?} is missing application JWT secrets"
        );

        let code_schema = migrations
            .iter()
            .find(|statement| {
                statement.contains("CREATE TABLE IF NOT EXISTS application_jwt_codes")
            })
            .expect("application JWT code table must have a create statement");
        assert!(
            code_schema.contains("client_id")
                && code_schema.contains("application_id")
                && code_schema.contains("code_challenge"),
            "{kind:?} application JWT codes must bind client and PKCE"
        );

        let secret_schema = migrations
            .iter()
            .find(|statement| {
                statement.contains("CREATE TABLE IF NOT EXISTS application_jwt_client_secrets")
            })
            .expect("application JWT secret table must have a create statement");
        assert!(secret_schema.contains("jwt_client_id"));
        assert!(secret_schema.contains("secret_hash"));
        assert!(secret_schema.contains("expires_at"));
        assert!(secret_schema.contains("revoked_at"));
    }
}

#[test]
fn application_scim_token_migrations_cover_all_database_engines() {
    for (kind, migrations) in [
        (DatabaseKind::Sqlite, SQLITE_MIGRATIONS),
        (DatabaseKind::Postgres, POSTGRES_MIGRATIONS),
        (DatabaseKind::Mysql, MYSQL_MIGRATIONS),
    ] {
        let schema = migrations
            .iter()
            .find(|statement| {
                statement.contains("CREATE TABLE IF NOT EXISTS application_scim_tokens")
            })
            .expect("application SCIM token table must have a create statement");
        for column in [
            "application_id",
            "token_prefix",
            "token_hash",
            "scopes",
            "expires_at",
            "revoked_at",
            "last_used_at",
        ] {
            assert!(
                schema.contains(column),
                "{kind:?} SCIM token schema missing {column}"
            );
        }
        assert!(
            migrations
                .iter()
                .any(|statement| { statement.contains("idx_application_scim_tokens_application") }),
            "{kind:?} is missing the application SCIM token index"
        );
    }
}

#[test]
fn directory_sync_migrations_cover_runs_checkpoints_memberships_and_groups() {
    for (kind, migrations) in [
        (DatabaseKind::Sqlite, SQLITE_MIGRATIONS),
        (DatabaseKind::Postgres, POSTGRES_MIGRATIONS),
        (DatabaseKind::Mysql, MYSQL_MIGRATIONS),
    ] {
        for table in [
            "directory_sync_runs",
            "directory_sync_leases",
            "directory_sync_checkpoints",
            "directory_sync_memberships",
            "directory_sync_groups",
        ] {
            assert!(
                migrations.iter().any(|statement| {
                    statement.contains(&format!("CREATE TABLE IF NOT EXISTS {table}"))
                }),
                "{kind:?} is missing directory sync table {table}"
            );
        }
        let run_schema = migrations
            .iter()
            .find(|statement| statement.contains("CREATE TABLE IF NOT EXISTS directory_sync_runs"))
            .expect("directory sync run table must have a create statement");
        for column in [
            "application_id",
            "provider_id",
            "status",
            "total_seen",
            "created_count",
            "updated_count",
            "disabled_count",
            "cursor",
        ] {
            assert!(
                run_schema.contains(column),
                "{kind:?} directory sync run schema missing {column}"
            );
        }
        assert!(
            migrations
                .iter()
                .any(|statement| { statement.contains("idx_directory_sync_runs_application") }),
            "{kind:?} is missing the directory sync run index"
        );
        assert!(
            migrations
                .iter()
                .any(|statement| { statement.contains("idx_directory_sync_leases_expiry") }),
            "{kind:?} is missing the directory sync lease expiry index"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn directory_sync_leases_serialize_runs_and_reclaim_expired_workers() {
    let (db, path) = sqlite_test_db_with_pool_size(4).await;
    let left = db.clone();
    let right = db.clone();
    let (left, right) = tokio::join!(
        left.start_directory_sync_run("lease-app", "lease-provider"),
        right.start_directory_sync_run("lease-app", "lease-provider")
    );
    assert!(left.is_ok() ^ right.is_ok());
    let run = left.or(right).unwrap();
    assert!(
        db.renew_directory_sync_lease("lease-app", "lease-provider", &run.id)
            .await
            .is_ok()
    );

    let expired_at = util::now_ts() - 1;
    with_conn!(db.clone(), |conn, kind| {
            let sql = format!(
                "UPDATE directory_sync_leases SET expires_at = {} WHERE application_id = {} AND provider_id = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<BigInt, _>(expired_at)
                .bind::<Text, _>("lease-app")
                .bind::<Text, _>("lease-provider")
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();

    let reclaimed = db
        .start_directory_sync_run("lease-app", "lease-provider")
        .await
        .unwrap();
    assert_ne!(reclaimed.id, run.id);
    assert_eq!(
        db.list_directory_sync_runs("lease-app", 20)
            .await
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.id == run.id)
            .unwrap()
            .status,
        "failed"
    );
    assert!(
        db.renew_directory_sync_lease("lease-app", "lease-provider", &run.id)
            .await
            .is_err()
    );
    db.finish_directory_sync_run(DirectorySyncRunUpdate {
        run_id: &reclaimed.id,
        status: "succeeded",
        total_seen: 0,
        created_count: 0,
        updated_count: 0,
        disabled_count: 0,
        error: None,
        cursor: None,
    })
    .await
    .unwrap();
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[test]
fn ldap_provider_organization_migrations_cover_all_database_engines() {
    for (kind, migrations, organization_definition) in [
        (
            DatabaseKind::Sqlite,
            SQLITE_MIGRATIONS,
            "organization_id TEXT",
        ),
        (
            DatabaseKind::Postgres,
            POSTGRES_MIGRATIONS,
            "organization_id TEXT",
        ),
        (
            DatabaseKind::Mysql,
            MYSQL_MIGRATIONS,
            "organization_id VARCHAR(64) NULL",
        ),
    ] {
        let schema = migrations
            .iter()
            .find(|statement| statement.contains("CREATE TABLE IF NOT EXISTS ldap_providers"))
            .expect("LDAP provider table must have a create statement");
        assert!(
            schema.contains(organization_definition),
            "{kind:?} LDAP provider schema must include organization ownership"
        );
        assert!(
            migrations.iter().any(|statement| {
                statement.contains("ALTER TABLE ldap_providers ADD COLUMN")
                    && statement.contains("organization_id")
            }),
            "{kind:?} must migrate existing LDAP provider tables"
        );
        assert!(
            migrations
                .iter()
                .any(|statement| { statement.contains("idx_ldap_providers_organization") }),
            "{kind:?} is missing the LDAP provider organization index"
        );
    }
    assert!(external_identities::select_ldap_provider_sql().contains("organization_id"));
}

#[test]
fn user_identity_conflicts_cover_email_username_and_current_user_exclusion() {
    for kind in [
        DatabaseKind::Sqlite,
        DatabaseKind::Postgres,
        DatabaseKind::Mysql,
    ] {
        let sql = count_user_identity_conflicts_sql(kind);
        assert!(sql.contains("email ="));
        assert!(sql.contains("username ="));
        assert!(!sql.contains("phone"));
        assert!(sql.contains("id <>"));
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn scim_user_mutation_rolls_back_profile_password_and_active_state_together() {
    let (db, path) = sqlite_test_db().await;
    let first = db
        .insert_user(test_user("scim-first@example.test", "scim-first"))
        .await
        .unwrap();
    let second = db
        .insert_user(test_user("scim-second@example.test", "scim-second"))
        .await
        .unwrap();

    assert!(
        db.apply_scim_user_mutation(ScimUserMutationPlan {
            id: first.id.clone(),
            expected_version: first.scim_concurrency_version(),
            email: second.email.clone(),
            username: "scim-first-renamed".to_string(),
            display_name: Some("would roll back".to_string()),
            phone: None,
            is_admin: false,
            is_active: false,
            password_hash: Some("would-also-roll-back".to_string()),
            scope: None,
        })
        .await
        .is_err()
    );
    let unchanged = db.find_user_by_id(&first.id).await.unwrap().unwrap();
    assert_eq!(unchanged.email, "scim-first@example.test");
    assert_eq!(unchanged.username, "scim-first");
    assert_eq!(unchanged.display_name, None);
    assert!(unchanged.is_active == 1);
    assert_eq!(unchanged.password_hash, "test-hash");

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn password_replacement_revokes_sessions_and_audits_atomically() {
    let (db, path) = sqlite_test_db().await;
    let user = db
        .insert_user(test_user(
            "credential-rotation@example.test",
            "credential-rotation",
        ))
        .await
        .unwrap();
    let (session, _) = db
        .insert_session(&user.id, 600, SessionMetadata::default())
        .await
        .unwrap();

    let updated = db
        .replace_user_password_with_audit(
            &user.id,
            "rotated-password-hash".to_string(),
            crate::audit::management_event(
                "credential-actor",
                "user.password.set",
                "user",
                Some(user.id.clone()),
                serde_json::json!({}),
            ),
        )
        .await
        .unwrap();

    assert_eq!(updated.password_hash, "rotated-password-hash");
    assert!(db.find_session(&session.id).await.unwrap().is_none());
    assert!(
        db.list_audit_events(20)
            .await
            .unwrap()
            .iter()
            .any(|event| event.action == "user.password.set")
    );
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn mfa_enable_rolls_back_setup_and_recovery_codes_when_audit_fails() {
    let (db, path) = sqlite_test_db().await;
    let user = db
        .insert_user(test_user("mfa-atomic@example.test", "mfa-atomic"))
        .await
        .unwrap();
    let setup = db
        .create_mfa_totp_setup(&user.id, "encrypted-totp-secret".to_string(), 300)
        .await
        .unwrap();
    with_conn!(db.clone(), |conn, _kind| {
            conn.batch_execute(
                "CREATE TRIGGER fail_mfa_audit_outbox BEFORE INSERT ON audit_webhook_outbox BEGIN SELECT RAISE(ABORT, 'forced mfa audit failure'); END",
            )
            .map_err(AppError::from)
        })
        .unwrap();

    let result = db
        .confirm_totp_setup_with_audit(
            &user.id,
            &setup.id,
            vec!["recovery-hash".to_string()],
            crate::audit::management_event(
                user.id.clone(),
                "mfa.totp.enable",
                "user",
                Some(user.id.clone()),
                serde_json::json!({ "method": "totp" }),
            ),
        )
        .await;
    assert!(
        matches!(result, Err(AppError::Database(message)) if message.contains("forced mfa audit failure"))
    );

    with_conn!(db.clone(), |conn, _kind| {
        conn.batch_execute("DROP TRIGGER fail_mfa_audit_outbox")
            .map_err(AppError::from)
    })
    .unwrap();
    assert!(db.find_mfa_totp_setup(&setup.id).await.unwrap().is_some());
    assert!(db.find_totp_method(&user.id).await.unwrap().is_none());
    assert!(db.list_recovery_codes(&user.id).await.unwrap().is_empty());

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_phone_uniqueness_migration_allows_shared_phone_insert_and_update() {
    for (case_name, phone_definition, explicit_phone_index) in [
        ("inline unique constraint", "phone TEXT UNIQUE", false),
        ("explicit unique index", "phone TEXT", true),
    ] {
        let mut conn = SqliteConnection::establish(":memory:").unwrap();
        let explicit_index_sql = explicit_phone_index.then_some(
                "CREATE UNIQUE INDEX IF NOT EXISTS \"legacy_users_phone_unique\" ON \"users\" (\"phone\" DESC);",
            );
        conn.batch_execute(&format!(
                "CREATE TABLE users (
                    id TEXT PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL UNIQUE,
                    display_name TEXT,
                    {phone_definition},
                    password_hash TEXT NOT NULL,
                    email_verified_at INTEGER,
                    phone_verified_at INTEGER,
                    is_admin INTEGER NOT NULL,
                    is_active INTEGER NOT NULL,
                    archived_at INTEGER,
                    registration_source TEXT NOT NULL DEFAULT 'local',
                    last_login_at INTEGER,
                    last_login_ip TEXT,
                    last_oidc_client_id TEXT,
                    last_login_method TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                {}
                INSERT INTO users (id, email, username, phone, password_hash, is_admin, is_active, registration_source, created_at, updated_at)
                VALUES ('first', 'first@example.com', 'first', '+15550000000', 'hash', 0, 1, 'local', 1, 1);",
                explicit_index_sql.unwrap_or_default(),
            ))
            .unwrap();

        migrate_sqlite_phone_uniqueness(&mut conn).unwrap();
        migrate_sqlite_phone_uniqueness(&mut conn).unwrap();

        if explicit_phone_index {
            let index_count = sql_query(
                    "SELECT COUNT(*) AS count FROM sqlite_master WHERE type = 'index' AND name = 'legacy_users_phone_unique'",
                )
                .get_result::<CountRow>(&mut conn)
                .unwrap()
                .count;
            assert_eq!(index_count, 0, "{case_name}");
        }

        conn.batch_execute(
                "INSERT INTO users (id, email, username, phone, password_hash, is_admin, is_active, registration_source, created_at, updated_at)
                 VALUES ('second', 'second@example.com', 'second', '+15550000000', 'hash', 0, 1, 'local', 1, 1);
                 INSERT INTO users (id, email, username, phone, password_hash, is_admin, is_active, registration_source, created_at, updated_at)
                 VALUES ('third', 'third@example.com', 'third', '+15551111111', 'hash', 0, 1, 'local', 1, 1);
                 UPDATE users SET phone = '+15550000000' WHERE id = 'third';",
            )
            .unwrap();
        let shared_phone_count =
            sql_query("SELECT COUNT(*) AS count FROM users WHERE phone = '+15550000000'")
                .get_result::<CountRow>(&mut conn)
                .unwrap()
                .count;
        assert_eq!(shared_phone_count, 3, "{case_name}");
    }
}

#[test]
fn first_user_registration_state_is_rechecked_inside_transaction() {
    assert!(ensure_first_user_registration_state(true, 0).is_ok());
    assert!(ensure_first_user_registration_state(false, 10).is_ok());
    assert!(matches!(
        ensure_first_user_registration_state(true, 1),
        Err(AppError::BadRequest(_))
    ));
    assert_eq!(count_all_users_sql(), "SELECT COUNT(*) AS count FROM users");
}

#[test]
fn first_registered_user_admin_is_an_invariant() {
    assert!(registered_user_is_admin(true));
    assert!(!registered_user_is_admin(false));

    let settings = RegistrationSettingsRecord {
        id: "default".to_string(),
        allow_password_registration: 1,
        require_email_verification: 0,
        require_phone_verification: 0,
        allow_external_oidc_registration: 1,
        require_invitation: 0,
        first_user_direct_admin: 0,
        default_user_active: 1,
        updated_at: 1,
    };
    assert!(settings.public().first_user_direct_admin);
}

#[test]
fn external_oidc_user_creation_can_check_existing_identity_inside_transaction() {
    for kind in [
        DatabaseKind::Sqlite,
        DatabaseKind::Postgres,
        DatabaseKind::Mysql,
    ] {
        let sql = external_identities::count_linked_identity_sql(kind);
        assert!(sql.contains("SELECT COUNT(*) AS count FROM linked_identities"));
        assert!(sql.contains("provider_slug ="));
        assert!(sql.contains("external_subject ="));
    }
}

#[test]
fn verification_code_sql_targets_latest_unconsumed_code() {
    for kind in [
        DatabaseKind::Sqlite,
        DatabaseKind::Postgres,
        DatabaseKind::Mysql,
    ] {
        let select_sql = select_latest_verification_code_sql(kind);
        assert!(select_sql.contains("channel ="));
        assert!(select_sql.contains("target ="));
        assert!(select_sql.contains("purpose ="));
        assert!(select_sql.contains("consumed_at IS NULL"));
        assert!(select_sql.contains("ORDER BY created_at DESC, id DESC LIMIT 1"));

        let consume_sql = consume_verification_code_sql(kind);
        assert!(consume_sql.contains("SET consumed_at ="));
        assert!(consume_sql.contains("consumed_at IS NULL"));
    }
}

#[test]
fn verification_resend_policy_uses_latest_issue_time() {
    let mut latest = verification_record("latest", "hash", 0, 5, 2_000);
    latest.created_at = 1_000;
    assert!(ensure_verification_resend_allowed(Some(&latest), 1_060, 60).is_ok());
    assert!(ensure_verification_resend_allowed(None, 1_000, 60).is_ok());
    assert!(matches!(
        ensure_verification_resend_allowed(Some(&latest), 1_030, 60),
        Err(AppError::BadRequest(message))
            if message == "verification code was sent too recently; retry after 30 seconds"
    ));
}

#[test]
fn verification_code_verifier_distinguishes_code_states() {
    let now = 1_000;
    let code_hash = util::token_hash("123456");
    let valid = verification_record("code-id", &code_hash, 0, 5, now + 60);

    assert_eq!(
        valid.verify_hash(&code_hash, now).unwrap(),
        VerificationCodeDecision::Accepted("code-id".to_string())
    );
    assert_eq!(
        valid.verify_hash(&util::token_hash("000000"), now).unwrap(),
        VerificationCodeDecision::RejectedAttempt("code-id".to_string())
    );
    assert!(matches!(
        verification_record("expired", &code_hash, 0, 5, now - 1).verify_hash(&code_hash, now),
        Err(AppError::BadRequest(message)) if message == "verification code expired"
    ));
    assert!(matches!(
        verification_record("attempts", &code_hash, 5, 5, now + 60)
            .verify_hash(&code_hash, now),
        Err(AppError::BadRequest(message)) if message == "verification code attempts exceeded"
    ));
}

pub(crate) fn verification_record(
    id: &str,
    code_hash: &str,
    attempts: i32,
    max_attempts: i32,
    expires_at: i64,
) -> VerificationCodeRecord {
    VerificationCodeRecord {
        id: id.to_string(),
        channel: "email".to_string(),
        target: "user@example.com".to_string(),
        purpose: "registration".to_string(),
        code_hash: code_hash.to_string(),
        attempts,
        max_attempts,
        expires_at,
        consumed_at: None,
        created_at: 1,
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn test_user(email: &str, username: &str) -> NewUser {
    NewUser {
        email: email.to_string(),
        username: username.to_string(),
        display_name: None,
        phone: None,
        password_hash: "test-hash".to_string(),
        email_verified_at: None,
        phone_verified_at: None,
        is_admin: false,
        is_active: true,
        archived_at: None,
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn test_bulk_user(
    email: &str,
    username: &str,
    organization_id: Option<&str>,
    organization_role: Option<&str>,
) -> NewBulkProvisionedUser {
    NewBulkProvisionedUser {
        user: test_user(email, username),
        organization_id: organization_id.map(ToOwned::to_owned),
        organization_role: organization_role.map(ToOwned::to_owned),
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn test_invitation(
    code_type: AuthorizationCodeType,
    login_code_level: LoginCodeLevel,
    authorized_username: Option<&str>,
    authorized_user_id: Option<&str>,
    allowed_client_ids: Vec<String>,
) -> NewInvitation {
    NewInvitation {
        code_type,
        login_code_level,
        allowed_client_ids,
        organization_id: None,
        organization_role: None,
        description: None,
        authorized_email: None,
        authorized_username: authorized_username.map(ToOwned::to_owned),
        authorized_user_id: authorized_user_id.map(ToOwned::to_owned),
        authorized_display_name: None,
        expires_at: None,
        max_uses: None,
        is_active: true,
        created_by: None,
    }
}

#[cfg(feature = "sqlite")]
pub(crate) async fn sqlite_test_db() -> (Db, std::path::PathBuf) {
    sqlite_test_db_with_pool_size(1).await
}

#[cfg(feature = "sqlite")]
pub(crate) async fn sqlite_test_db_with_pool_size(pool_size: u32) -> (Db, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("gpt-sso-test-{}.sqlite3", uuid::Uuid::new_v4()));
    let db = connect_sqlite(&DatabaseSettings {
        kind: DatabaseKind::Sqlite,
        url: path.to_string_lossy().into_owned(),
        pool_size,
        run_migrations: true,
    })
    .unwrap();
    db.migrate().await.unwrap();
    (db, path)
}

#[cfg(feature = "sqlite")]
pub(crate) async fn default_authorization_profile(
    db: &Db,
    application_id: &str,
) -> ApplicationAuthorizationProfileRecord {
    db.find_application_authorization_profile(application_id, "default")
        .await
        .unwrap()
        .expect("application migrations create a default authorization profile")
}

#[cfg(feature = "sqlite")]
pub(crate) async fn replace_test_authorization_bindings(
    db: &Db,
    application_id: &str,
    profile_id: &str,
    update: AuthorizationBindingsUpdate,
) {
    db.replace_application_authorization_bindings_with_audit(
        application_id,
        profile_id,
        update,
        audit::management_event(
            "authorization-profile-test",
            "application.authorization_profile.bindings.test",
            "application_authorization_profile",
            Some(profile_id.to_string()),
            serde_json::json!({ "application_id": application_id }),
        ),
    )
    .await
    .unwrap();
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn organization_registration_invitation_creates_a_normal_member_account() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(NewOrganization {
            slug: "invite-team".to_string(),
            name: "Invite Team".to_string(),
            kind: ORGANIZATION_KIND_TENANT.to_string(),
            description: None,
            allowed_email_domains: vec!["example.com".to_string()],
            is_active: true,
        })
        .await
        .unwrap();
    let mut invitation = test_invitation(
        AuthorizationCodeType::Registration,
        LoginCodeLevel::AccountRecovery,
        None,
        None,
        Vec::new(),
    );
    invitation.organization_id = Some(organization.id.clone());
    invitation.organization_role = Some(crate::organizations::ROLE_MEMBER.to_string());
    invitation.authorized_email = Some("invited@example.com".to_string());
    invitation.expires_at = Some(util::now_ts() + 300);
    invitation.max_uses = Some(1);
    let (stored, code) = db.insert_invitation(invitation).await.unwrap();

    let user = db
        .redeem_registration_code_for_new_user(
            &code,
            NewUser {
                email: "invited@example.com".to_string(),
                username: "invited".to_string(),
                display_name: Some("Invited member".to_string()),
                phone: None,
                password_hash: "hash".to_string(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: true,
                archived_at: None,
            },
            Vec::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        user.registration_source,
        UserRegistrationSource::AuthorizationCode.as_str()
    );
    let memberships = db.list_user_organizations(&user.id).await.unwrap();
    assert!(memberships.iter().any(|membership| {
        membership.id == organization.id && membership.role == crate::organizations::ROLE_MEMBER
    }));
    assert_eq!(
        db.list_organization_registration_invitations(&organization.id)
            .await
            .unwrap()
            .into_iter()
            .map(|invitation| invitation.id)
            .collect::<Vec<_>>(),
        vec![stored.id]
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_enrollment_codes_grant_only_their_own_assigned_application() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization(
            "app-enrollment",
            "Application Enrollment",
        ))
        .await
        .unwrap();
    let mut application = test_application(
        &organization.id,
        "restricted-app",
        crate::applications::ACCESS_ASSIGNED_ACCOUNTS,
    );
    application.registration_mode = crate::applications::REGISTRATION_INVITATION.to_string();
    let application = db.insert_application(application).await.unwrap();
    let client = db
        .insert_client_for_application(
            &application.id,
            test_client("restricted-enrollment-client", &organization.id),
        )
        .await
        .unwrap();

    let mut unrelated = test_invitation(
        AuthorizationCodeType::Login,
        LoginCodeLevel::TrialEnrollment,
        None,
        None,
        vec![client.client_id.clone()],
    );
    unrelated.organization_id = Some(organization.id.clone());
    unrelated.organization_role = Some(crate::organizations::ROLE_MEMBER.to_string());
    unrelated.expires_at = Some(util::now_ts() + 300);
    unrelated.max_uses = Some(1);
    let (_, unrelated_code) = db.insert_invitation(unrelated).await.unwrap();
    let unrelated_user = db
        .redeem_trial_enrollment_code_for_new_user(
            &unrelated_code,
            NewTrialEnrollmentUser {
                email: "unrelated@example.com".to_string(),
                username: "unrelated".to_string(),
                display_name: None,
                password_hash: "hash".to_string(),
            },
        )
        .await
        .unwrap()
        .user;
    assert!(
        db.user_can_access_application(&application, &unrelated_user.id)
            .await
            .unwrap()
    );

    let mut invitation = test_invitation(
        AuthorizationCodeType::Login,
        LoginCodeLevel::TrialEnrollment,
        None,
        None,
        vec![client.client_id.clone()],
    );
    invitation.organization_id = Some(organization.id.clone());
    invitation.organization_role = Some(crate::organizations::ROLE_MEMBER.to_string());
    invitation.expires_at = Some(util::now_ts() + 300);
    invitation.max_uses = Some(1);
    let (invitation, enrollment_code) = db.insert_invitation(invitation).await.unwrap();
    db.link_application_enrollment_code(&application.id, &invitation.id)
        .await
        .unwrap();
    let enrollment = db
        .redeem_trial_enrollment_code_for_new_user(
            &enrollment_code,
            NewTrialEnrollmentUser {
                email: "application-member@example.com".to_string(),
                username: "application-member".to_string(),
                display_name: None,
                password_hash: "hash".to_string(),
            },
        )
        .await
        .unwrap();
    assert!(
        db.user_can_access_application(&application, &enrollment.user.id)
            .await
            .unwrap()
    );
    assert_eq!(
        db.list_application_enrollment_codes(&application.id)
            .await
            .unwrap()
            .len(),
        1
    );

    db.delete_invitation(&invitation.id).await.unwrap();
    assert!(
        db.list_application_enrollment_codes(&application.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        db.find_active_trial_enrollment_for_user(&enrollment.user.id)
            .await
            .unwrap()
            .is_none()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
pub(crate) async fn user_auth_state_row_count(
    db: &Db,
    table: &str,
    column: &str,
    user_id: &str,
) -> i64 {
    let table = table.to_string();
    let column = column.to_string();
    let user_id = user_id.to_string();
    with_conn!(db, |conn, kind| {
        let sql = format!(
            "SELECT COUNT(*) AS count FROM {table} WHERE {column} = {}",
            ph(kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>(user_id)
            .get_result::<CountRow>(&mut conn)
            .map(|row| row.count)
            .map_err(AppError::from)
    })
    .unwrap()
}

#[cfg(feature = "sqlite")]
pub(crate) async fn assert_user_auth_state_count(db: &Db, user_id: &str, expected: i64) {
    for (table, column) in USER_AUTH_STATE_TABLES {
        assert_eq!(
            user_auth_state_row_count(db, table, column, user_id).await,
            expected,
            "{table}.{column} should have {expected} rows for user {user_id}"
        );
    }
}

#[cfg(feature = "sqlite")]
pub(crate) async fn insert_user_auth_state(db: &Db, user_id: &str, suffix: &str) -> String {
    let now = util::now_ts();
    let (session, _cookie_value) = db
        .insert_session(user_id, 600, SessionMetadata::default())
        .await
        .unwrap();
    let browser_context_id = format!("browser-context-{suffix}");
    db.insert_browser_context(&browser_context_id, "csrf", 600)
        .await
        .unwrap();
    let account = db
        .attach_browser_context_account(&browser_context_id, user_id, &session.id)
        .await
        .unwrap();
    db.mint_browser_account_session_credential(&browser_context_id, &account.id)
        .await
        .unwrap();
    db.insert_authorization_code(NewAuthorizationCode {
        code: format!("auth-code-{suffix}"),
        client_id: "client".to_string(),
        user_id: user_id.to_string(),
        application_id: None,
        authorization_profile_id: None,
        auth_context_id: None,
        session_id: None,
        redirect_uri: "https://client.example/callback".to_string(),
        scope: "openid".to_string(),
        resource: None,
        authorization_details: None,
        nonce: None,
        code_challenge: None,
        code_challenge_method: None,
        auth_time: now,
        acr: crate::assurance::ACR_PASSWORD.to_string(),
        amr: vec!["pwd".to_string()],
        expires_at: now + 600,
    })
    .await
    .unwrap();
    db.insert_refresh_token(
        "client".to_string(),
        RefreshTokenInput {
            token_hash: format!("refresh-token-{suffix}"),
            user_id: user_id.to_string(),
            scope: "openid".to_string(),
            resource: None,
            authorization_details: None,
            dpop_jkt: None,
            auth_context_id: None,
            expires_at: now + 600,
        },
    )
    .await
    .unwrap();
    let user_code_hash = format!("user-code-hash-{suffix}");
    db.insert_device_authorization(NewDeviceAuthorization {
        device_code_hash: format!("device-code-hash-{suffix}"),
        user_code_hash: user_code_hash.clone(),
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
    db.authorize_device_authorization(&user_code_hash, user_id)
        .await
        .unwrap();
    db.create_webauthn_challenge(Some(user_id), "login", "{}".to_string(), 600)
        .await
        .unwrap();
    let user_id = user_id.to_string();
    let suffix = suffix.to_string();
    with_conn!(db, |conn, kind| {
            let sql = format!(
                "INSERT INTO oidc_login_grants (credential_hash, invitation_id, user_id, client_id, interaction_request_hash, auth_time, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
                ph(kind, 9)
            );
            sql_query(sql)
                .bind::<Text, _>(format!("credential-{suffix}"))
                .bind::<Text, _>(format!("invitation-{suffix}"))
                .bind::<Text, _>(user_id)
                .bind::<Text, _>("client")
                .bind::<Text, _>(format!("interaction-{suffix}"))
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now + 600)
                .bind::<Nullable<BigInt>, _>(None::<i64>)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map(|_| ())
                .map_err(AppError::from)
        })
        .unwrap();
    session.id
}

#[cfg(feature = "sqlite")]
pub(crate) async fn session_link_count(db: &Db, table: &str, session_id: &str) -> i64 {
    let table = table.to_string();
    let session_id = session_id.to_string();
    with_conn!(db, |conn, kind| {
        let sql = format!(
            "SELECT COUNT(*) AS count FROM {table} WHERE session_id = {}",
            ph(kind, 1)
        );
        sql_query(sql)
            .bind::<Text, _>(session_id)
            .get_result::<CountRow>(&mut conn)
            .map(|row| row.count)
            .map_err(AppError::from)
    })
    .unwrap()
}

#[cfg(feature = "sqlite")]
pub(crate) fn refresh_token_replacement(token_hash: &str, user_id: &str) -> RefreshTokenInput {
    RefreshTokenInput {
        token_hash: token_hash.to_string(),
        user_id: user_id.to_string(),
        scope: "openid profile".to_string(),
        resource: Some("https://api.example/".to_string()),
        authorization_details: None,
        dpop_jkt: None,
        auth_context_id: None,
        expires_at: util::now_ts() + 600,
    }
}

#[cfg(feature = "sqlite")]
pub(crate) async fn load_verification_code(db: &Db, id: &str) -> VerificationCodeRecord {
    let id = id.to_string();
    with_conn!(db, |conn, kind| {
        sql_query(select_verification_code_by_id_sql(kind))
            .bind::<Text, _>(id)
            .get_result::<VerificationCodeRecord>(&mut conn)
            .map_err(AppError::from)
    })
    .unwrap()
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn iap_application_crud_normalizes_policy_fields() {
    let (db, path) = sqlite_test_db().await;
    let organization = db
        .insert_organization(test_organization("iap-crud", "IAP CRUD"))
        .await
        .unwrap();
    let application = db
        .insert_application(test_application(
            &organization.id,
            "iap-crud-app",
            crate::applications::ACCESS_ALL_SIGNET_USERS,
        ))
        .await
        .unwrap();
    let created = db
        .insert_iap_application(NewIapApplication {
            application_id: application.id.clone(),
            slug: "docs".to_string(),
            name: "Docs".to_string(),
            description: Some("Internal docs".to_string()),
            external_host: "docs.example.com".to_string(),
            path_prefix: "/private".to_string(),
            required_organization_id: Some("org-id".to_string()),
            required_organization_roles: vec![
                "member".to_string(),
                "admin".to_string(),
                "member".to_string(),
            ],
            required_permissions: vec!["users.read".to_string()],
            is_active: true,
        })
        .await
        .unwrap();

    assert_eq!(created.slug, "docs");
    assert_eq!(
        created.required_organization_roles().unwrap(),
        vec!["admin".to_string(), "member".to_string()]
    );
    assert_eq!(
        created.required_permissions().unwrap(),
        vec!["users.read".to_string()]
    );
    assert_eq!(db.list_active_iap_applications().await.unwrap().len(), 1);

    let updated = db
        .update_iap_application(
            &created.id,
            NewIapApplication {
                application_id: application.id.clone(),
                slug: "docs".to_string(),
                name: "Docs".to_string(),
                description: None,
                external_host: "docs.example.com".to_string(),
                path_prefix: "/".to_string(),
                required_organization_id: None,
                required_organization_roles: Vec::new(),
                required_permissions: vec!["users.manage".to_string()],
                is_active: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.path_prefix, "/");
    assert_eq!(updated.is_active, 0);
    assert!(db.list_active_iap_applications().await.unwrap().is_empty());

    let bad_permission = db
        .insert_iap_application(NewIapApplication {
            application_id: application.id,
            slug: "bad".to_string(),
            name: "Bad".to_string(),
            description: None,
            external_host: "bad.example.com".to_string(),
            path_prefix: "/".to_string(),
            required_organization_id: None,
            required_organization_roles: Vec::new(),
            required_permissions: vec!["unknown.permission".to_string()],
            is_active: true,
        })
        .await;
    assert!(matches!(
        bad_permission,
        Err(AppError::BadRequest(message)) if message == "unknown permission: unknown.permission"
    ));

    db.delete_iap_application(&created.id).await.unwrap();
    assert!(db.list_iap_applications().await.unwrap().is_empty());

    drop(db);
    let _ = std::fs::remove_file(path);
}
