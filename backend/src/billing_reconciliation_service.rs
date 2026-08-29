use super::{
    AppError, AppResult, AppState, PAYMENT_STATUS_CLOSED, PAYMENT_STATUS_CREATING,
    PAYMENT_STATUS_FAILED, PAYMENT_STATUS_PAID, PAYMENT_STATUS_PENDING, PaymentOrderLease,
    PaymentOrderRecord, PaymentProvider, PaymentQueryResult, expired_payment_order_policy,
    normalize_currency, provider_adapter, provider_error_message,
    provider_outcome_unknown_with_reason, reconcile_next_retry_at,
};
use crate::util;
use std::time::Duration;
use tokio::{sync::oneshot, task::JoinHandle, time::Instant};

enum ReconcileAttempt {
    Finalized(Option<Box<PaymentOrderRecord>>),
    Shutdown,
}

fn finalized(order: Option<PaymentOrderRecord>) -> ReconcileAttempt {
    ReconcileAttempt::Finalized(order.map(Box::new))
}

async fn finalize_reconcile_error(
    state: &AppState,
    order: &PaymentOrderRecord,
    fence: &PaymentOrderLease,
    error: AppError,
) -> AppResult<Option<PaymentOrderRecord>> {
    let message = provider_error_message(&error);
    let next_retry_at = reconcile_next_retry_at(
        util::now_ts(),
        order.attempt_count,
        state.settings.billing.reconcile_retry_base_seconds,
        state.settings.billing.reconcile_retry_max_seconds,
    );
    if state
        .db
        .mark_payment_order_reconcile_fenced(&order.id, fence, &message, next_retry_at)
        .await?
        .is_none()
    {
        return Ok(None);
    }
    Err(error)
}

async fn finalize_pending_state(
    state: &AppState,
    order: &PaymentOrderRecord,
    fence: &PaymentOrderLease,
) -> AppResult<Option<PaymentOrderRecord>> {
    let next_retry_at = reconcile_next_retry_at(
        util::now_ts(),
        order.attempt_count,
        state.settings.billing.reconcile_retry_base_seconds,
        state.settings.billing.reconcile_retry_max_seconds,
    );
    state
        .db
        .mark_payment_order_pending_fenced(&order.id, fence, next_retry_at)
        .await
}

async fn finalize_failed_state(
    state: &AppState,
    order_id: &str,
    fence: &PaymentOrderLease,
) -> AppResult<Option<PaymentOrderRecord>> {
    state
        .db
        .mark_payment_order_failed_fenced(
            order_id,
            fence,
            "payment provider reported a terminal unsuccessful state",
        )
        .await
}

async fn finalize_paid_state(
    state: &AppState,
    order: &PaymentOrderRecord,
    fence: &PaymentOrderLease,
    provider_trade_id: &str,
    paid_at: i64,
) -> AppResult<Option<PaymentOrderRecord>> {
    state
        .db
        .mark_payment_order_paid_fenced(&order.id, provider_trade_id, paid_at, fence)
        .await
}

async fn query_provider_with_timeout(
    provider: &dyn PaymentProvider,
    order: &PaymentOrderRecord,
) -> AppResult<PaymentQueryResult> {
    match tokio::time::timeout(Duration::from_secs(15), provider.query_payment(order)).await {
        Ok(result) => result,
        Err(_) => Err(provider_outcome_unknown_with_reason(
            "provider query timed out",
        )),
    }
}

async fn query_provider_until_shutdown(
    provider: &dyn PaymentProvider,
    order: &PaymentOrderRecord,
    stop_rx: Option<&mut oneshot::Receiver<()>>,
) -> Result<Option<PaymentQueryResult>, AppError> {
    let query = query_provider_with_timeout(provider, order);
    if let Some(stop_rx) = stop_rx {
        tokio::select! {
            biased;
            _ = stop_rx => Ok(None),
            result = query => result.map(Some),
        }
    } else {
        query.await.map(Some)
    }
}

async fn finalize_provider_query(
    state: &AppState,
    order: &PaymentOrderRecord,
    fence: &PaymentOrderLease,
    query: PaymentQueryResult,
) -> AppResult<Option<PaymentOrderRecord>> {
    let notification = query.notification;
    let currency = match normalize_currency(&notification.currency) {
        Ok(currency) => currency,
        Err(error) => return finalize_reconcile_error(state, order, fence, error).await,
    };
    if notification.merchant_order_no != order.merchant_order_no
        || currency != order.currency
        || notification.amount_minor != order.amount_minor
    {
        return finalize_reconcile_error(
            state,
            order,
            fence,
            AppError::BadRequest("provider query does not match the payment order".to_string()),
        )
        .await;
    }
    match notification.status.as_str() {
        PAYMENT_STATUS_PAID => {
            if notification.provider_trade_id.trim().is_empty() {
                return finalize_reconcile_error(
                    state,
                    order,
                    fence,
                    provider_outcome_unknown_with_reason(
                        "provider query did not return a provider transaction id",
                    ),
                )
                .await;
            }
            finalize_paid_state(
                state,
                order,
                fence,
                &notification.provider_trade_id,
                notification.paid_at,
            )
            .await
        }
        PAYMENT_STATUS_FAILED | PAYMENT_STATUS_CLOSED => {
            finalize_failed_state(state, &order.id, fence).await
        }
        PAYMENT_STATUS_PENDING if order.expires_at <= util::now_ts() => {
            finalize_reconcile_error(
                state,
                order,
                fence,
                provider_outcome_unknown_with_reason(
                    "provider remains pending after local payment expiry",
                ),
            )
            .await
        }
        PAYMENT_STATUS_PENDING => finalize_pending_state(state, order, fence).await,
        _ => {
            finalize_reconcile_error(
                state,
                order,
                fence,
                provider_outcome_unknown_with_reason(
                    "provider query returned an unsupported payment state",
                ),
            )
            .await
        }
    }
}

/// The single billing command surface for worker, manual, and recovery
/// reconciliation. A caller must first obtain a durable claim; provider
/// results are published only through the matching generation fence.
pub(super) struct BillingCommandService<'a> {
    state: &'a AppState,
}

impl<'a> BillingCommandService<'a> {
    pub(super) fn new(state: &'a AppState) -> Self {
        Self { state }
    }

    pub(super) async fn reconcile_order(
        &self,
        order_id: &str,
        force: bool,
    ) -> AppResult<PaymentOrderRecord> {
        let owner = format!("billing-manual-{}", util::random_token(24));
        let now = util::now_ts();
        let Some(order) = self
            .state
            .db
            .claim_payment_order_for_reconcile(
                order_id,
                &owner,
                now,
                self.state.settings.billing.reconcile_lease_seconds,
                force,
            )
            .await?
        else {
            return self
                .state
                .db
                .find_payment_order(order_id)
                .await?
                .ok_or(AppError::NotFound);
        };
        let fence = payment_order_lease(&order, &owner, now);
        match self.reconcile_claimed(order, fence, None).await? {
            ReconcileAttempt::Finalized(Some(order)) => Ok(*order),
            ReconcileAttempt::Finalized(None) => self
                .state
                .db
                .find_payment_order(order_id)
                .await?
                .ok_or(AppError::NotFound),
            ReconcileAttempt::Shutdown => unreachable!("manual reconciliation has no shutdown"),
        }
    }

    async fn reconcile_claimed(
        &self,
        order: PaymentOrderRecord,
        fence: PaymentOrderLease,
        stop_rx: Option<&mut oneshot::Receiver<()>>,
    ) -> AppResult<ReconcileAttempt> {
        let Some(fence) = self
            .state
            .db
            .renew_payment_order_reconcile_lease(
                &order.id,
                &fence,
                self.state.settings.billing.reconcile_lease_seconds,
            )
            .await?
        else {
            return Ok(finalized(None));
        };
        let provider =
            match provider_adapter::configured_provider(&self.state.settings, &order.provider_slug)
            {
                Ok(provider) => provider,
                Err(error) => {
                    return finalize_reconcile_error(self.state, &order, &fence, error)
                        .await
                        .map(finalized);
                }
            };
        let query = match query_provider_until_shutdown(provider.as_ref(), &order, stop_rx).await {
            Ok(Some(query)) => query,
            Ok(None) => return Ok(ReconcileAttempt::Shutdown),
            Err(error) => {
                return finalize_reconcile_error(self.state, &order, &fence, error)
                    .await
                    .map(finalized);
            }
        };
        finalize_provider_query(self.state, &order, &fence, query)
            .await
            .map(finalized)
    }
}

fn payment_order_lease(
    order: &PaymentOrderRecord,
    owner: &str,
    fallback_now: i64,
) -> PaymentOrderLease {
    PaymentOrderLease {
        owner: owner.to_string(),
        generation: order.lease_generation,
        lease_expires_at: order.lease_expires_at.unwrap_or(fallback_now),
    }
}

/// Handle for the process-local part of the billing scheduler. The work is
/// durably claimed, and shutdown cancels the current provider query before
/// releasing the current and unprocessed claims for immediate recovery.
pub struct BillingReconcileWorker {
    stop_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl BillingReconcileWorker {
    pub async fn stop(mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        let _ = self.task.await;
    }
}

/// Starts the durable reconciliation scheduler. Returning `None` when
/// billing is disabled keeps a disabled deployment completely quiet.
pub fn spawn_reconcile_worker(state: AppState) -> Option<BillingReconcileWorker> {
    if !state.settings.billing.enabled {
        return None;
    }
    let (stop_tx, mut stop_rx) = oneshot::channel();
    let interval = Duration::from_secs(state.settings.billing.reconcile_interval_seconds as u64);
    let owner = format!("billing-reconcile-{}", util::random_token(24));
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval_at(Instant::now() + interval, interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                _ = ticker.tick() => {
                    if let Err(error) = reconcile_claimed_payment_orders(
                        &state,
                        &owner,
                        state.settings.billing.reconcile_batch_size as i64,
                        &mut stop_rx,
                    ).await {
                        tracing::warn!(error = %error, "billing reconciliation sweep failed");
                    }
                }
            }
        }
        tracing::debug!(owner = %owner, "billing reconciliation worker stopped");
    });
    Some(BillingReconcileWorker {
        stop_tx: Some(stop_tx),
        task,
    })
}

async fn reconcile_claimed_payment_orders(
    state: &AppState,
    owner: &str,
    limit: i64,
    stop_rx: &mut oneshot::Receiver<()>,
) -> AppResult<Vec<PaymentOrderRecord>> {
    let now = util::now_ts();
    let claimed = state
        .db
        .claim_payment_orders_for_reconcile(
            owner,
            now,
            state.settings.billing.reconcile_lease_seconds,
            limit,
        )
        .await?;
    if claimed.is_empty() {
        return Ok(Vec::new());
    }
    tracing::debug!(owner = %owner, count = claimed.len(), "billing reconciliation orders claimed");
    let service = BillingCommandService::new(state);
    let mut reconciled = Vec::with_capacity(claimed.len());
    for (index, order) in claimed.iter().enumerate() {
        let fence = payment_order_lease(order, owner, now);
        // `expires_at` belongs to the local checkout and is not a provider
        // outcome. Even an expired `pending`/`reconcile` order must be queried
        // first so a late provider `paid` result still enters the wallet. An
        // expired `creating` row with no checkout is query-only recovery: the
        // worker never creates a second provider intent, and only an explicit
        // provider terminal failure can close it.
        if let Some(policy) = expired_payment_order_policy(
            &order.status,
            &order.checkout_value,
            order.expires_at,
            now,
        ) {
            tracing::debug!(
                order_id = %order.id,
                ?policy,
                "billing reconciliation order is locally expired"
            );
        }
        match service
            .reconcile_claimed(order.clone(), fence.clone(), Some(stop_rx))
            .await
        {
            Ok(ReconcileAttempt::Finalized(Some(updated))) => {
                reconciled.push((*updated).clone());
                tracing::debug!(
                order_id = %updated.id,
                status = %updated.status,
                attempt_count = updated.attempt_count,
                "billing payment order reconciled"
                )
            }
            Ok(ReconcileAttempt::Finalized(None)) => {
                tracing::debug!(
                    order_id = %order.id,
                    "billing payment reconciliation result lost its lease fence"
                );
                if let Some(current) = state.db.find_payment_order(&order.id).await? {
                    reconciled.push(current);
                }
            }
            Ok(ReconcileAttempt::Shutdown) => {
                release_payment_order_claim(state, &order.id, &fence, order.attempt_count, true)
                    .await;
                for remaining in claimed.iter().skip(index + 1) {
                    let remaining_fence = payment_order_lease(remaining, owner, now);
                    release_payment_order_claim(
                        state,
                        &remaining.id,
                        &remaining_fence,
                        remaining.attempt_count,
                        true,
                    )
                    .await;
                }
                break;
            }
            Err(error) => {
                tracing::warn!(
                    order_id = %order.id,
                    error = %error,
                    "billing payment reconciliation attempt did not finalize"
                );
                // If the failure happened before a fenced state transition,
                // release the claim with the same backoff policy. Otherwise a
                // transient DB/provider error unnecessarily holds the row
                // until lease expiry.
                release_payment_order_claim(state, &order.id, &fence, order.attempt_count, false)
                    .await;
                if let Some(current) = state.db.find_payment_order(&order.id).await? {
                    reconciled.push(current);
                }
            }
        }
    }
    Ok(reconciled)
}

async fn release_payment_order_claim(
    state: &AppState,
    order_id: &str,
    fence: &PaymentOrderLease,
    attempt_count: i64,
    immediate: bool,
) {
    let next_retry_at = if immediate {
        Some(util::now_ts())
    } else {
        Some(reconcile_next_retry_at(
            util::now_ts(),
            attempt_count,
            state.settings.billing.reconcile_retry_base_seconds,
            state.settings.billing.reconcile_retry_max_seconds,
        ))
    };
    if let Err(error) = state
        .db
        .release_payment_order_reconcile_lease(order_id, fence, next_retry_at)
        .await
    {
        tracing::warn!(
            order_id = %order_id,
            error = %error,
            "failed to release billing reconciliation lease"
        );
    }
}

async fn wait_for_payment_order_creation(
    state: &AppState,
    order: PaymentOrderRecord,
) -> AppResult<PaymentOrderRecord> {
    let mut current = order;
    // A duplicate request arriving while the creator is inside the provider
    // call waits briefly for the durable state transition.  If the process
    // died, the subsequent query below takes over from the creating row.
    for _ in 0..10 {
        if current.status != PAYMENT_STATUS_CREATING {
            return Ok(current);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        current = state
            .db
            .find_payment_order(&current.id)
            .await?
            .ok_or(AppError::NotFound)?;
    }
    Ok(current)
}

pub(super) async fn recover_recharge_intent(
    state: &AppState,
    order: PaymentOrderRecord,
) -> AppResult<PaymentOrderRecord> {
    let order = wait_for_payment_order_creation(state, order).await?;
    if matches!(
        order.status.as_str(),
        PAYMENT_STATUS_PAID | PAYMENT_STATUS_FAILED | PAYMENT_STATUS_CLOSED
    ) {
        return Ok(order);
    }
    if order.status == PAYMENT_STATUS_PENDING
        && !order.checkout_value.trim().is_empty()
        && order.expires_at > util::now_ts()
    {
        return Ok(order);
    }
    // This is an existing durable intent. It is always queried through the
    // claim/fence command and is never allowed to issue a second provider
    // create, even when the checkout is missing or locally expired.
    let queried = BillingCommandService::new(state)
        .reconcile_order(&order.id, true)
        .await?;
    if matches!(
        queried.status.as_str(),
        PAYMENT_STATUS_PAID | PAYMENT_STATUS_FAILED | PAYMENT_STATUS_CLOSED
    ) {
        return Ok(queried);
    }
    if queried.status == PAYMENT_STATUS_PENDING && !queried.checkout_value.trim().is_empty() {
        return Ok(queried);
    }
    if queried.checkout_value.trim().is_empty() {
        return Err(AppError::BadRequest(
            "payment intent has no persisted provider checkout; reconciliation will continue"
                .to_string(),
        ));
    }
    Err(AppError::BadRequest(
        "payment intent is awaiting provider reconciliation".to_string(),
    ))
}
