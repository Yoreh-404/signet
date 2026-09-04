use super::*;
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn mutation_receipts_claim_once_and_preserve_replay_metadata() {
    let (db, path) = sqlite_test_db().await;
    let first = db
        .claim_mutation_receipt(
            "dedupe-receipt-test",
            "session:test",
            "POST",
            "/api/admin/applications",
            "key-1",
            "request-a",
        )
        .await
        .unwrap();
    let second = db
        .claim_mutation_receipt(
            "dedupe-receipt-test",
            "session:test",
            "POST",
            "/api/admin/applications",
            "key-1",
            "request-a",
        )
        .await
        .unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(second.status, "in_progress");
    assert_eq!(second.owner_token, first.owner_token);

    assert!(
        db.finalize_mutation_receipt(MutationReceiptFinalization {
            id: &first.id,
            owner_token: first.owner_token.as_deref().unwrap(),
            status: "committed",
            response_status: 200,
            response_body: Some(r#"{"id":"application-1"}"#.to_string()),
            response_content_type: Some("application/json".to_string()),
            error_code: None,
        })
        .await
        .unwrap()
    );
    let completed = db
        .find_mutation_receipt(&first.id, "session:test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.status, "committed");
    assert_eq!(completed.response_status, Some(200));
    assert_eq!(
        completed.response_content_type.as_deref(),
        Some("application/json")
    );
    assert!(completed.response_body.is_some());

    let same_key_different_request = db
        .claim_mutation_receipt(
            "dedupe-receipt-test",
            "session:test",
            "POST",
            "/api/admin/applications",
            "key-1",
            "request-b",
        )
        .await
        .unwrap();
    assert_eq!(same_key_different_request.id, first.id);
    assert_eq!(same_key_different_request.request_hash, "request-a");
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn mutation_receipt_reclaim_fences_the_old_owner() {
    let (db, path) = sqlite_test_db().await;
    let first = db
        .claim_mutation_receipt_with_owner(MutationReceiptClaim {
            dedupe_hash: "reclaim-receipt-test",
            scope_key: "session:test",
            method: "POST",
            path: "/api/admin/applications",
            idempotency_key: "key-1",
            request_hash: "request-a",
            owner_token: "owner-a",
        })
        .await
        .unwrap();

    let first_id = first.id.clone();
    with_conn!(db.clone(), |conn, kind| {
        let sql = format!(
            "UPDATE mutation_receipts SET lease_expires_at = {} WHERE id = {}",
            ph(kind, 1),
            ph(kind, 2)
        );
        sql_query(sql)
            .bind::<BigInt, _>(util::now_ts() - 1)
            .bind::<Text, _>(&first_id)
            .execute(&mut conn)
            .map(|_| ())
            .map_err(AppError::from)
    })
    .unwrap();

    let reclaimed = db
        .claim_mutation_receipt_with_owner(MutationReceiptClaim {
            dedupe_hash: "reclaim-receipt-test",
            scope_key: "session:test",
            method: "POST",
            path: "/api/admin/applications",
            idempotency_key: "key-1",
            request_hash: "request-a",
            owner_token: "owner-b",
        })
        .await
        .unwrap();
    assert_eq!(reclaimed.id, first.id);
    assert_eq!(reclaimed.owner_token.as_deref(), Some("owner-b"));
    assert!(reclaimed.lease_expires_at.unwrap() > util::now_ts());

    assert!(
        !db.finalize_mutation_receipt(MutationReceiptFinalization {
            id: &first.id,
            owner_token: "owner-a",
            status: "committed",
            response_status: 200,
            response_body: Some("old".to_string()),
            response_content_type: None,
            error_code: None,
        })
        .await
        .unwrap()
    );
    assert!(
        db.finalize_mutation_receipt(MutationReceiptFinalization {
            id: &first.id,
            owner_token: "owner-b",
            status: "committed",
            response_status: 200,
            response_body: Some("new".to_string()),
            response_content_type: None,
            error_code: None,
        })
        .await
        .unwrap()
    );
    let completed = db
        .find_mutation_receipt(&first.id, "session:test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.response_body.as_deref(), Some("new"));
    assert!(completed.owner_token.is_none());
    assert!(completed.lease_expires_at.is_none());

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn application_discovery_idempotency_claims_and_replays_completed_result() {
    let (db, path) = sqlite_test_db().await;
    let first = db
        .claim_application_discovery_idempotency(
            "org-1",
            "request-1",
            "hash-1",
            "https://example.test",
        )
        .await
        .unwrap();
    let claim_token = match first {
        ApplicationDiscoveryIdempotencyClaim::Claimed { claim_token } => claim_token,
        other => panic!("expected a new claim, got {other:?}"),
    };
    assert_eq!(
        db.claim_application_discovery_idempotency(
            "org-1",
            "request-1",
            "hash-1",
            "https://example.test",
        )
        .await
        .unwrap(),
        ApplicationDiscoveryIdempotencyClaim::InProgress
    );
    db.complete_application_discovery_idempotency(
        "org-1",
        "request-1",
        &claim_token,
        "application-1",
    )
    .await
    .unwrap();
    assert_eq!(
        db.claim_application_discovery_idempotency(
            "org-1",
            "request-1",
            "hash-1",
            "https://example.test",
        )
        .await
        .unwrap(),
        ApplicationDiscoveryIdempotencyClaim::Completed {
            application_id: "application-1".to_string()
        }
    );
    assert!(matches!(
        db.claim_application_discovery_idempotency(
            "org-1",
            "request-1",
            "different-hash",
            "https://example.test",
        )
        .await,
        Err(AppError::BadRequest(_))
    ));
    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn billing_read_queries_preserve_filters_ordering_and_optional_results() {
    let (db, path) = sqlite_test_db().await;
    let application_id = "billing-read-application";
    assert!(
        db.find_application_billing_settings(application_id)
            .await
            .unwrap()
            .is_none()
    );
    let settings = db
        .ensure_application_billing_settings(application_id)
        .await
        .unwrap();
    let found_settings = db
        .find_application_billing_settings(application_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found_settings.application_id, settings.application_id);
    assert_eq!(found_settings.wallet_mode, "shared");

    let user = db
        .insert_user(test_user("billing-read@example.com", "billing-read-user"))
        .await
        .unwrap();
    let usd_wallet = db
        .ensure_user_wallet_account(&user.id, "USD")
        .await
        .unwrap();
    let cny_wallet = db
        .ensure_user_wallet_account(&user.id, "CNY")
        .await
        .unwrap();

    assert_eq!(
        db.find_wallet_account_by_id(&usd_wallet.id)
            .await
            .unwrap()
            .unwrap()
            .id,
        usd_wallet.id
    );
    assert!(
        db.find_wallet_account_by_id("missing-billing-read-wallet")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.list_user_wallet_accounts(&user.id, Some("USD"))
            .await
            .unwrap()
            .into_iter()
            .map(|wallet| wallet.currency)
            .collect::<Vec<_>>(),
        vec!["USD"]
    );
    assert_eq!(
        db.list_user_wallet_accounts(&user.id, None)
            .await
            .unwrap()
            .into_iter()
            .map(|wallet| wallet.currency)
            .collect::<Vec<_>>(),
        vec!["CNY", "USD"]
    );

    db.adjust_wallet(WalletAdjustment {
        wallet_id: &cny_wallet.id,
        user_id: Some(&user.id),
        application_id: None,
        currency: "CNY",
        amount_delta_minor: 100,
        idempotency_key: "billing-read-adjustment-1",
        metadata: serde_json::json!({"test": true}),
    })
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    db.adjust_wallet(WalletAdjustment {
        wallet_id: &cny_wallet.id,
        user_id: Some(&user.id),
        application_id: None,
        currency: "CNY",
        amount_delta_minor: 200,
        idempotency_key: "billing-read-adjustment-2",
        metadata: serde_json::json!({"test": true}),
    })
    .await
    .unwrap();
    let transactions = db
        .list_wallet_transactions_for_user(&user.id, 0)
        .await
        .unwrap();
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].idempotency_key, "billing-read-adjustment-2");
    let transactions = db
        .list_wallet_transactions_for_user(&user.id, 501)
        .await
        .unwrap();
    assert_eq!(transactions.len(), 2);
    assert_eq!(
        transactions
            .iter()
            .map(|transaction| transaction.idempotency_key.as_str())
            .collect::<Vec<_>>(),
        vec!["billing-read-adjustment-2", "billing-read-adjustment-1"]
    );

    drop(db);
    let _ = std::fs::remove_file(path);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn billing_wallet_lifecycle_is_atomic_idempotent_and_non_negative() {
    let (db, path) = sqlite_test_db().await;
    let user = db
        .insert_user(test_user("billing@example.com", "billing-user"))
        .await
        .unwrap();
    let application_id = "billing-application";
    let global = db
        .ensure_user_wallet_account(&user.id, "CNY")
        .await
        .unwrap();
    let application_wallet = db
        .ensure_application_wallet_account(&user.id, application_id, "CNY")
        .await
        .unwrap();
    let settlement = db
        .ensure_settlement_wallet_account(application_id, "CNY")
        .await
        .unwrap();

    db.adjust_wallet(WalletAdjustment {
        wallet_id: &global.id,
        user_id: Some(&user.id),
        application_id: None,
        currency: "CNY",
        amount_delta_minor: 10_000,
        idempotency_key: "seed-balance",
        metadata: serde_json::json!({"test": true}),
    })
    .await
    .unwrap();

    let hold = db
        .reserve_wallet_hold(WalletHoldReservation {
            wallet_id: &global.id,
            user_id: &user.id,
            application_id,
            currency: "CNY",
            amount_minor: 4_000,
            reference: "charge-1",
            idempotency_key: "reserve-1",
            expires_at: util::now_ts() + 900,
        })
        .await
        .unwrap();
    let duplicate_hold = db
        .reserve_wallet_hold(WalletHoldReservation {
            wallet_id: &global.id,
            user_id: &user.id,
            application_id,
            currency: "CNY",
            amount_minor: 4_000,
            reference: "charge-1",
            idempotency_key: "reserve-1",
            expires_at: util::now_ts() + 900,
        })
        .await
        .unwrap();
    assert_eq!(hold.id, duplicate_hold.id);
    let held_global = db
        .ensure_user_wallet_account(&user.id, "CNY")
        .await
        .unwrap();
    assert_eq!(held_global.available_minor, 6_000);
    assert_eq!(held_global.reserved_minor, 4_000);

    let committed_hold = db
        .commit_wallet_hold(&hold.id, &settlement.id, "commit-1")
        .await
        .unwrap();
    assert_eq!(committed_hold.status, "committed");
    let duplicate_commit = db
        .commit_wallet_hold(&hold.id, &settlement.id, "commit-2")
        .await
        .unwrap();
    assert_eq!(duplicate_commit.id, hold.id);
    let commit_transaction = db
        .find_wallet_transaction_by_operation("commit", "commit-1")
        .await
        .unwrap()
        .unwrap();

    let first_charge_refund = db
        .refund_committed_charge(&commit_transaction.id, &user.id, 1_000, "charge-refund-1")
        .await
        .unwrap();
    let duplicate_charge_refund = db
        .refund_committed_charge(&commit_transaction.id, &user.id, 1_000, "charge-refund-1")
        .await
        .unwrap();
    assert_eq!(first_charge_refund.id, duplicate_charge_refund.id);
    db.refund_committed_charge(&commit_transaction.id, &user.id, 3_000, "charge-refund-2")
        .await
        .unwrap();
    assert!(
        db.refund_committed_charge(&commit_transaction.id, &user.id, 1, "charge-refund-3")
            .await
            .is_err()
    );
    let settled = db
        .ensure_settlement_wallet_account(application_id, "CNY")
        .await
        .unwrap();
    assert_eq!(settled.available_minor, 0);

    let transferred = db
        .transfer_wallets(WalletTransfer {
            user_id: &user.id,
            source_wallet_id: &global.id,
            destination_wallet_id: &application_wallet.id,
            currency: "CNY",
            amount_minor: 2_000,
            application_id: Some(application_id),
            idempotency_key: "transfer-1",
        })
        .await
        .unwrap();
    let duplicate_transfer = db
        .transfer_wallets(WalletTransfer {
            user_id: &user.id,
            source_wallet_id: &global.id,
            destination_wallet_id: &application_wallet.id,
            currency: "CNY",
            amount_minor: 2_000,
            application_id: Some(application_id),
            idempotency_key: "transfer-1",
        })
        .await
        .unwrap();
    assert_eq!(transferred.id, duplicate_transfer.id);
    assert!(
        db.transfer_wallets(WalletTransfer {
            user_id: &user.id,
            source_wallet_id: &global.id,
            destination_wallet_id: &application_wallet.id,
            currency: "CNY",
            amount_minor: 9_000,
            application_id: Some(application_id),
            idempotency_key: "transfer-too-much",
        })
        .await
        .is_err()
    );
    db.transfer_wallets(WalletTransfer {
        user_id: &user.id,
        source_wallet_id: &application_wallet.id,
        destination_wallet_id: &global.id,
        currency: "CNY",
        amount_minor: 2_000,
        application_id: Some(application_id),
        idempotency_key: "transfer-2",
    })
    .await
    .unwrap();

    let release_hold = db
        .reserve_wallet_hold(WalletHoldReservation {
            wallet_id: &global.id,
            user_id: &user.id,
            application_id,
            currency: "CNY",
            amount_minor: 500,
            reference: "release-1",
            idempotency_key: "reserve-2",
            expires_at: util::now_ts() + 900,
        })
        .await
        .unwrap();
    db.release_wallet_hold(&release_hold.id, "release-1")
        .await
        .unwrap();
    assert_eq!(
        db.release_wallet_hold(&release_hold.id, "release-2")
            .await
            .unwrap()
            .status,
        "released"
    );

    let order = db
        .insert_payment_order(NewPaymentOrder {
            user_id: user.id.clone(),
            provider_slug: "test-provider".to_string(),
            merchant_order_no: "SGT-test-order-1".to_string(),
            idempotency_key: Some("recharge-test-1".to_string()),
            currency: "CNY".to_string(),
            amount_minor: 5_000,
            subject: "test recharge".to_string(),
            checkout_kind: "redirect".to_string(),
            checkout_value: "https://pay.example.test/order".to_string(),
            expires_at: util::now_ts() + 900,
        })
        .await
        .unwrap();
    assert_eq!(order.idempotency_key.as_deref(), Some("recharge-test-1"));
    assert_eq!(
        db.find_payment_order_by_idempotency_key(&user.id, "test-provider", "recharge-test-1")
            .await
            .unwrap()
            .map(|found| found.id),
        Some(order.id.clone())
    );
    assert!(
        db.mark_payment_order_paid(&order.id, "", util::now_ts())
            .await
            .is_err()
    );
    let paid_order = db
        .mark_payment_order_paid(&order.id, "provider-trade-1", util::now_ts())
        .await
        .unwrap();
    assert_eq!(paid_order.status, "paid");
    assert_eq!(
        db.mark_payment_order_paid(&order.id, "provider-trade-1", util::now_ts())
            .await
            .unwrap()
            .id,
        order.id
    );
    assert!(
        db.mark_payment_order_paid(&order.id, "provider-trade-2", util::now_ts())
            .await
            .is_err()
    );

    let payment_refund = db
        .refund_payment_order(
            &order.id,
            1_000,
            "provider-refund-1",
            None,
            "test refund",
            "payment-refund-1",
        )
        .await
        .unwrap();
    let duplicate_payment_refund = db
        .refund_payment_order(
            &order.id,
            1_000,
            "provider-refund-1",
            None,
            "test refund",
            "payment-refund-1",
        )
        .await
        .unwrap();
    assert_eq!(payment_refund.id, duplicate_payment_refund.id);
    assert!(
        db.refund_payment_order(
            &order.id,
            5_000,
            "provider-refund-2",
            None,
            "too much",
            "payment-refund-2",
        )
        .await
        .is_err()
    );

    let final_global = db
        .ensure_user_wallet_account(&user.id, "CNY")
        .await
        .unwrap();
    assert_eq!(final_global.available_minor, 14_000);
    assert_eq!(final_global.reserved_minor, 0);

    drop(db);
    let _ = std::fs::remove_file(path);
}
