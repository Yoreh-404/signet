use super::*;
use base64::Engine as _;
use diesel::{RunQueryDsl, connection::SimpleConnection, sql_query, sql_types::{BigInt, Integer, Text}};

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn generic_credentials_are_scoped_by_type_identifier_and_application() {
    let (db, path) = sqlite_test_db().await;
    let organization_a = db.insert_organization(test_organization("mini-one", "Mini One")).await.unwrap();
    let organization_b = db.insert_organization(test_organization("mini-two", "Mini Two")).await.unwrap();
    let app_a = db.insert_application(test_application(
        &organization_a.id, "store", crate::applications::ACCESS_ALL_SIGNET_USERS,
    )).await.unwrap();
    let app_b = db.insert_application(test_application(
        &organization_b.id, "store", crate::applications::ACCESS_ALL_SIGNET_USERS,
    )).await.unwrap();
    let external_id = "wx1234567890abcdef";
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let encrypted = util::encrypt_application_auth_secret(
        &key, &app_a.id, WECHAT_MINI_TYPE, external_id, "wechat-secret-only-for-store-one"
    ).unwrap();
    let event = || audit::management_event(
        "mini-manager", "application.auth_credential.upsert", "application_auth_credential",
        Some(external_id.to_owned()), serde_json::json!({}),
    );
    let options = serde_json::json!({"scopes":["openid"],"allow_registration":false}).to_string();

    let first = db.upsert_application_auth_credential(
        &app_a.id, WECHAT_MINI_TYPE, external_id, Some(&encrypted), &options, true, event(),
    ).await.unwrap();
    assert_ne!(first.secret_ciphertext, "wechat-secret-only-for-store-one");
    assert_eq!(util::decrypt_application_auth_secret(
        &key, &app_a.id, WECHAT_MINI_TYPE, external_id, &first.secret_ciphertext,
    ).unwrap(), "wechat-secret-only-for-store-one");
    assert!(util::decrypt_application_auth_secret(
        &key, &app_b.id, WECHAT_MINI_TYPE, external_id, &first.secret_ciphertext,
    ).is_err());
    assert!(util::decrypt_application_auth_secret(
        &key, &app_a.id, "oauth_client", external_id, &first.secret_ciphertext,
    ).is_err());
    assert!(util::decrypt_application_auth_secret(
        &key, &app_a.id, WECHAT_MINI_TYPE, "wxabcdef1234567890", &first.secret_ciphertext,
    ).is_err());

    assert!(matches!(db.upsert_application_auth_credential(
        &app_b.id, WECHAT_MINI_TYPE, external_id, Some(&encrypted), &options, true, event(),
    ).await, Err(AppError::Forbidden)));
    let updated = serde_json::json!({"scopes":["openid","profile"],"allow_registration":true}).to_string();
    let second = db.upsert_application_auth_credential(
        &app_a.id, WECHAT_MINI_TYPE, external_id, None, &updated, false, event(),
    ).await.unwrap();
    assert_eq!(first.secret_ciphertext, second.secret_ciphertext);
    assert!(second.config_json.contains("profile"));
    assert_eq!(second.is_active, 0);
    assert_eq!(db.list_application_auth_credentials(&app_a.id, WECHAT_MINI_TYPE).await.unwrap().len(), 1);
    assert_eq!(db.list_application_auth_credentials(&app_b.id, WECHAT_MINI_TYPE).await.unwrap().len(), 0);

    // A second provider type is supported without a database migration or
    // new dedicated table; identifiers are namespaced by credential type.
    let second_type = "oauth_client";
    let oauth_cipher = util::encrypt_application_auth_secret(
        &key, &app_b.id, second_type, external_id, "oauth-client-secret-for-second-site"
    ).unwrap();
    db.upsert_application_auth_credential(
        &app_b.id, second_type, external_id, Some(&oauth_cipher), r#"{"issuer":"https://issuer.example"}"#, true, event(),
    ).await.unwrap();
    assert_eq!(db.list_application_auth_credentials(&app_b.id, second_type).await.unwrap().len(), 1);

    assert!(!db.delete_application_auth_credential(&app_b.id, WECHAT_MINI_TYPE, external_id, event()).await.unwrap());
    assert!(db.find_application_auth_credential(WECHAT_MINI_TYPE, external_id).await.unwrap().is_some());
    assert!(db.delete_application_auth_credential(&app_a.id, WECHAT_MINI_TYPE, external_id, event()).await.unwrap());
    assert!(db.find_application_auth_credential(WECHAT_MINI_TYPE, external_id).await.unwrap().is_none());
    assert!(db.find_application_auth_credential(second_type, external_id).await.unwrap().is_some());
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn legacy_wechat_credentials_migrate_into_generic_table_without_plaintext() {
    use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
    let (db, path) = sqlite_test_db().await;
    let org = db.insert_organization(test_organization("legacy-auth", "Legacy Auth")).await.unwrap();
    let app = db.insert_application(test_application(
        &org.id, "old-mini", crate::applications::ACCESS_ALL_SIGNET_USERS,
    )).await.unwrap();
    let external_id = "wxlegacy1234567890";
    let secret = "existing-encrypted-app-secret";
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
    let cipher = Aes256Gcm::new_from_slice(&[7_u8; 32]).unwrap();
    let nonce = [11_u8; 12];
    let aad = format!("signet:wechat-mini-app-secret:v1:{external_id}");
    let encrypted = cipher.encrypt(&Nonce::try_from(&nonce[..]).unwrap(),
        aes_gcm::aead::Payload { msg: secret.as_bytes(), aad: aad.as_bytes() }).unwrap();
    let legacy = format!("signet-wechat-secret:v1.{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encrypted));

    let application_id = app.id.clone();
    with_conn!(db, |conn, kind| {
        conn.batch_execute(
            "CREATE TABLE IF NOT EXISTS wechat_mini_application_credentials (
                app_id VARCHAR(64) PRIMARY KEY, application_id VARCHAR(255) NOT NULL,
                app_secret_ciphertext TEXT NOT NULL, scopes_json TEXT NOT NULL,
                allow_registration INTEGER NOT NULL, is_active INTEGER NOT NULL,
                created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL
            )"
        ).map_err(AppError::from)?;
        let sql = format!("INSERT INTO wechat_mini_application_credentials (app_id,application_id,app_secret_ciphertext,scopes_json,allow_registration,is_active,created_at,updated_at) VALUES ({},{},{},{},{},{},{},{})",
            ph(kind,1),ph(kind,2),ph(kind,3),ph(kind,4),ph(kind,5),ph(kind,6),ph(kind,7),ph(kind,8));
        sql_query(sql).bind::<Text,_>(external_id).bind::<Text,_>(application_id)
            .bind::<Text,_>(legacy).bind::<Text,_>(r#"["openid"]"#)
            .bind::<Integer,_>(1).bind::<Integer,_>(1)
            .bind::<BigInt,_>(12).bind::<BigInt,_>(13)
            .execute(&mut conn).map_err(AppError::from)?;
        Ok(())
    }).unwrap();

    db.migrate_legacy_wechat_application_credentials().await.unwrap();
    db.migrate_legacy_wechat_application_credentials().await.unwrap();
    let migrated = db.find_application_auth_credential(WECHAT_MINI_TYPE, external_id)
        .await.unwrap().unwrap();
    assert_eq!(migrated.application_id, app.id);
    assert_eq!(migrated.created_at, 12);
    assert_eq!(migrated.updated_at, 13);
    assert!(migrated.config_json.contains("allow_registration"));
    assert_eq!(util::decrypt_application_auth_secret(
        &key, &app.id, WECHAT_MINI_TYPE, external_id, &migrated.secret_ciphertext,
    ).unwrap(), secret);
    with_conn!(db, |conn, _kind| {
        let old = sql_query("SELECT COUNT(*) AS count FROM sqlite_master WHERE type='table' AND name='wechat_mini_application_credentials'")
            .get_result::<CountRow>(&mut conn).map_err(AppError::from)?;
        assert_eq!(old.count, 0);
        Ok(())
    }).unwrap();
    drop(db);
    let _ = std::fs::remove_file(path);
}
