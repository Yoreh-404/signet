use crate::error::AppError;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn captcha_challenge_is_one_time_use() {
    let (db, path) = super::sqlite_test_db().await;
    let record = db
        .create_captcha_challenge("user@example.com", "2 + 3 = ?", "5", 300)
        .await
        .unwrap();

    db.consume_captcha_challenge(&record.id, "user@example.com", "5")
        .await
        .unwrap();
    assert!(matches!(
        db.consume_captcha_challenge(&record.id, "user@example.com", "5")
            .await,
        Err(AppError::BadRequest(message)) if message == "captcha challenge is invalid"
    ));

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn captcha_concurrent_correct_answers_have_one_winner() {
    let (db, path) = super::sqlite_test_db_with_pool_size(4).await;
    let record = db
        .create_captcha_challenge("concurrent@example.com", "2 + 3 = ?", "5", 300)
        .await
        .unwrap();
    let id = record.id.clone();
    let first_db = db.clone();
    let second_db = db.clone();
    let (first, second) = tokio::join!(
        first_db.consume_captcha_challenge(&id, "concurrent@example.com", "5"),
        second_db.consume_captcha_challenge(&id, "concurrent@example.com", "5"),
    );

    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(first.is_err() || second.is_err());

    drop(db);
    let _ = std::fs::remove_file(path);
}
