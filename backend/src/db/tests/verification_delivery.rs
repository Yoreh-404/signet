use crate::{
    config::DatabaseKind,
    db::{Db, NewVerificationCode, VerificationCodeRecord},
    error::AppError,
    util,
};
use diesel::{OptionalExtension, RunQueryDsl, sql_query};

use super::blocking;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn verification_code_issue_respects_resend_interval() {
    let (db, path) = super::sqlite_test_db().await;
    let first = db
        .insert_verification_code(NewVerificationCode {
            channel: "email",
            target: "resend@example.com",
            purpose: "registration",
            code_hash: util::token_hash("123456"),
            ttl_seconds: 600,
            resend_interval_seconds: 60,
            max_attempts: 5,
        })
        .await
        .unwrap();

    let second = db
        .insert_verification_code(NewVerificationCode {
            channel: "email",
            target: "resend@example.com",
            purpose: "registration",
            code_hash: util::token_hash("654321"),
            ttl_seconds: 600,
            resend_interval_seconds: 60,
            max_attempts: 5,
        })
        .await;

    assert!(matches!(
        second,
        Err(AppError::BadRequest(message))
            if message.starts_with("verification code was sent too recently")
    ));
    assert_eq!(
        super::load_verification_code(&db, &first.id)
            .await
            .code_hash,
        util::token_hash("123456")
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn verification_delivery_cleanup_allows_retry_without_resend_delay() {
    let (db, path) = super::sqlite_test_db().await;
    let first = db
        .insert_verification_code(NewVerificationCode {
            channel: "email",
            target: "cleanup@example.com",
            purpose: "registration",
            code_hash: util::token_hash("123456"),
            ttl_seconds: 600,
            resend_interval_seconds: 60,
            max_attempts: 5,
        })
        .await
        .unwrap();

    assert!(
        db.delete_unconsumed_verification_code(&first.id)
            .await
            .unwrap()
    );

    let second = db
        .insert_verification_code(NewVerificationCode {
            channel: "email",
            target: "cleanup@example.com",
            purpose: "registration",
            code_hash: util::token_hash("654321"),
            ttl_seconds: 600,
            resend_interval_seconds: 60,
            max_attempts: 5,
        })
        .await
        .unwrap();
    assert_eq!(second.target, "cleanup@example.com");
    let first_id = first.id.clone();
    let first_after_cleanup = with_conn!(db, |conn, kind| {
        sql_query(super::select_verification_code_by_id_sql(kind))
            .bind::<diesel::sql_types::Text, _>(first_id)
            .get_result::<VerificationCodeRecord>(&mut conn)
            .optional()
            .map_err(AppError::from)
    })
    .unwrap();
    assert!(first_after_cleanup.is_none());

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn verification_cleanup_does_not_delete_consumed_codes() {
    let (db, path) = super::sqlite_test_db().await;
    let code = "123456";
    let record = db
        .insert_verification_code(NewVerificationCode {
            channel: "email",
            target: "consumed-cleanup@example.com",
            purpose: "registration",
            code_hash: util::token_hash(code),
            ttl_seconds: 600,
            resend_interval_seconds: 1,
            max_attempts: 5,
        })
        .await
        .unwrap();

    db.consume_verification_code(
        "email",
        "consumed-cleanup@example.com",
        "registration",
        code,
    )
    .await
    .unwrap();
    assert!(
        !db.delete_unconsumed_verification_code(&record.id)
            .await
            .unwrap()
    );
    assert!(
        super::load_verification_code(&db, &record.id)
            .await
            .consumed_at
            .is_some()
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}
