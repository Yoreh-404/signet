pub(super) fn select_application_billing_settings_sql() -> &'static str {
    "SELECT application_id, accept_signet_balance, wallet_mode, COALESCE(supported_currencies, '[]') AS supported_currencies, mode_locked_at, created_at, updated_at FROM application_billing_settings"
}

pub(super) fn select_wallet_account_sql() -> &'static str {
    "SELECT id, account_kind, user_id, application_id, currency, available_minor, reserved_minor, version, created_at, updated_at FROM wallet_accounts"
}

pub(super) fn select_wallet_hold_sql() -> &'static str {
    "SELECT id, hold_kind, wallet_id, user_id, application_id, currency, amount_minor, status, reference, idempotency_key, expires_at, created_at, updated_at FROM wallet_holds"
}

pub(super) fn select_wallet_transaction_sql() -> &'static str {
    "SELECT id, kind, status, user_id, application_id, currency, amount_minor, source_wallet_id, destination_wallet_id, hold_id, idempotency_key, external_provider, external_order_id, metadata, created_at, updated_at FROM wallet_transactions"
}

pub(super) fn select_payment_order_sql() -> &'static str {
    "SELECT id, user_id, provider_slug, merchant_order_no, idempotency_key, provider_trade_id, currency, amount_minor, subject, status, checkout_kind, checkout_value, expires_at, paid_at, last_error, lease_owner, lease_expires_at, lease_generation, attempt_count, next_retry_at, created_at, updated_at FROM payment_orders"
}

pub(super) fn select_payment_refund_sql() -> &'static str {
    "SELECT id, payment_order_id, amount_minor, status, provider_refund_id, requested_by, reason, COALESCE(idempotency_key, '') AS idempotency_key, created_at, updated_at FROM payment_refunds"
}
