use super::DatabaseKind;

pub(super) fn payment_order_lock_suffix(kind: DatabaseKind) -> &'static str {
    match kind {
        DatabaseKind::Sqlite => "",
        DatabaseKind::Postgres | DatabaseKind::Mysql => " FOR UPDATE",
    }
}

pub(super) fn payment_refund_counts_toward_limit(status: &str) -> bool {
    matches!(status, "pending" | "succeeded")
}

pub(super) fn wallet_account_scope_key(
    account_kind: &str,
    user_id: Option<&str>,
    application_id: Option<&str>,
    currency: &str,
) -> String {
    format!(
        "{account_kind}:{}:{}:{currency}",
        user_id.unwrap_or("-"),
        application_id.unwrap_or("-")
    )
}
