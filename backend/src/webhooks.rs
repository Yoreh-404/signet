use crate::{
    db::{AuditEventRecord, AuditWebhookRecord, Db, NewAuditWebhook, UpdateAuditWebhook},
    error::{AppError, AppResult},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{sync::OnceLock, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, MissedTickBehavior},
};
use url::Url;

type HmacSha256 = Hmac<Sha256>;

const MAX_NAME_LEN: usize = 160;
const MAX_URL_LEN: usize = 2048;
const MAX_SECRET_LEN: usize = 512;
const MAX_ACTIONS: usize = 50;
const MAX_ACTION_LEN: usize = 128;
const MIN_TIMEOUT_SECONDS: i32 = 1;
const MAX_TIMEOUT_SECONDS: i32 = 30;
const OUTBOX_BATCH_SIZE: i64 = 100;
const OUTBOX_POLL_INTERVAL: Duration = Duration::from_secs(5);
const OUTBOX_NOTIFY_CAPACITY: usize = 32;

static AUDIT_WEBHOOK_WORKER_NOTIFY: OnceLock<mpsc::Sender<()>> = OnceLock::new();

#[derive(Debug, Clone, Deserialize)]
pub struct AuditWebhookInput {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub clear_secret: bool,
    #[serde(default)]
    pub actions: Vec<String>,
    pub is_active: bool,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: i32,
}

#[derive(Debug, Clone, Serialize)]
struct AuditWebhookPayload {
    r#type: &'static str,
    id: String,
    created_at: i64,
    event: Value,
}

pub fn new_webhook(input: AuditWebhookInput) -> AppResult<NewAuditWebhook> {
    let normalized = normalize_input(input)?;
    Ok(NewAuditWebhook {
        name: normalized.name,
        url: normalized.url,
        secret: normalized.secret.unwrap_or_default(),
        actions: normalized.actions,
        is_active: normalized.is_active,
        timeout_seconds: normalized.timeout_seconds,
    })
}

pub fn update_webhook(input: AuditWebhookInput) -> AppResult<UpdateAuditWebhook> {
    let normalized = normalize_input(input)?;
    Ok(UpdateAuditWebhook {
        name: normalized.name,
        url: normalized.url,
        secret: normalized.secret,
        actions: normalized.actions,
        is_active: normalized.is_active,
        timeout_seconds: normalized.timeout_seconds,
    })
}

/// Handle for the single process-local audit webhook scheduler.
///
/// Delivery itself is durably represented by `audit_webhook_outbox`, so the
/// worker can be stopped and restarted without losing events. The channel is
/// only a bounded wake-up hint; the periodic tick remains the recovery path
/// when a notification is dropped or the process starts with pending rows.
pub struct AuditWebhookWorker {
    stop_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl AuditWebhookWorker {
    pub async fn stop(mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
        let _ = self.task.await;
    }
}

/// Starts the one bounded audit-webhook worker and immediately wakes it so
/// rows left by an earlier process are recovered during startup.
pub fn spawn_audit_webhook_worker(db: Db) -> AuditWebhookWorker {
    let (notify_tx, notify_rx) = mpsc::channel(OUTBOX_NOTIFY_CAPACITY);
    if AUDIT_WEBHOOK_WORKER_NOTIFY.set(notify_tx.clone()).is_err() {
        tracing::warn!("audit webhook worker notifier was already initialized");
    }
    let (stop_tx, stop_rx) = oneshot::channel();
    let task = tokio::spawn(run_audit_webhook_worker(db, notify_rx, stop_rx));
    let _ = notify_tx.try_send(());
    AuditWebhookWorker {
        stop_tx: Some(stop_tx),
        task,
    }
}

/// Wakes the bounded worker after a committed audit transaction. The durable
/// outbox is authoritative, so a full channel is harmless: the next worker
/// tick will find the row. This function retains its old public shape for the
/// existing post-commit call sites, but it never creates a task per event.
pub fn spawn_audit_webhook_delivery(_db: Db, _event: AuditEventRecord) {
    let Some(notify) = AUDIT_WEBHOOK_WORKER_NOTIFY.get() else {
        // Startup always performs a full sweep after initializing the worker.
        // An audit event can legitimately be written before that point (for
        // example during seed), so leave it in the durable outbox.
        return;
    };
    if let Err(error) = notify.try_send(()) {
        if !matches!(error, mpsc::error::TrySendError::Full(_)) {
            tracing::debug!(error = %error, "audit webhook worker is no longer available");
        }
    }
}

async fn run_audit_webhook_worker(
    db: Db,
    mut notify_rx: mpsc::Receiver<()>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let client = reqwest::Client::new();
    let mut ticker =
        tokio::time::interval_at(Instant::now() + OUTBOX_POLL_INTERVAL, OUTBOX_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // The initial notification is sent by spawn_audit_webhook_worker. Keep
    // the loop event driven for fresh writes while retaining periodic
    // recovery for dropped notifications and expired leases.
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            notification = notify_rx.recv() => {
                if notification.is_none() {
                    break;
                }
                if let Err(error) = drain_audit_webhook_outbox(&db, &client).await {
                    tracing::warn!(error = %error, "audit webhook outbox sweep failed");
                }
            }
            _ = ticker.tick() => {
                if let Err(error) = drain_audit_webhook_outbox(&db, &client).await {
                    tracing::warn!(error = %error, "audit webhook outbox sweep failed");
                }
            }
        }
    }
    tracing::debug!("audit webhook worker stopped");
}

async fn drain_audit_webhook_outbox(db: &Db, client: &reqwest::Client) -> AppResult<()> {
    loop {
        let claimed = db.claim_audit_webhook_outbox(OUTBOX_BATCH_SIZE).await?;
        if claimed.is_empty() {
            return Ok(());
        }

        // A single snapshot per claimed batch avoids the old one-query-per-
        // event path while still allowing webhook changes to take effect on
        // the next batch.
        let webhooks = db.list_audit_webhooks().await?;
        for work in claimed {
            let result = match db.find_audit_event(&work.event_id).await? {
                Some(event) => deliver_audit_event(db, client, &event, &webhooks).await,
                None => {
                    tracing::error!(
                        outbox_id = %work.id,
                        event_id = %work.event_id,
                        "audit webhook outbox references a missing audit event"
                    );
                    // The event cannot become deliverable by retrying. Mark
                    // this corrupt row complete so it cannot poison the
                    // queue forever; the log remains operator-visible.
                    Ok(())
                }
            };

            match result {
                Ok(()) => {
                    if !db
                        .complete_audit_webhook_outbox(
                            &work.id,
                            work.lease_owner.as_deref().unwrap_or_default(),
                        )
                        .await?
                    {
                        tracing::debug!(outbox_id = %work.id, "audit webhook outbox completion lost its lease");
                    }
                }
                Err(error) => {
                    if !db
                        .retry_audit_webhook_outbox(
                            &work.id,
                            work.lease_owner.as_deref().unwrap_or_default(),
                            work.attempts,
                            error.to_string(),
                        )
                        .await?
                    {
                        tracing::debug!(outbox_id = %work.id, "audit webhook outbox retry lost its lease");
                    }
                }
            }
        }
    }
}

async fn deliver_audit_event(
    db: &Db,
    client: &reqwest::Client,
    event: &AuditEventRecord,
    webhooks: &[AuditWebhookRecord],
) -> AppResult<()> {
    let matching = webhooks
        .iter()
        .filter(|webhook| webhook.is_active == 1)
        .filter(|webhook| webhook_matches(webhook, &event.action))
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return Ok(());
    }

    let payload = payload_for_event(event);
    let body = serde_json::to_vec(&payload)
        .map_err(|err| AppError::Internal(format!("failed to encode webhook payload: {err}")))?;
    let mut failures = Vec::new();
    for webhook in matching {
        if let Err(error) = deliver_to_webhook(db, client, webhook, event, body.clone()).await {
            failures.push(format!("{}: {error}", webhook.id));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(AppError::Internal(format!(
            "audit webhook delivery failed: {}",
            failures.join("; ")
        )))
    }
}

async fn deliver_to_webhook(
    db: &Db,
    client: &reqwest::Client,
    webhook: &AuditWebhookRecord,
    event: &AuditEventRecord,
    body: Vec<u8>,
) -> Result<(), String> {
    let timeout = webhook
        .timeout_seconds
        .clamp(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS);

    let delivery_id = uuid::Uuid::new_v4().to_string();
    let mut request = client
        .post(&webhook.url)
        .timeout(Duration::from_secs(timeout as u64))
        .header("content-type", "application/json")
        .header("user-agent", "signet-webhook/0.1")
        .header("x-gpt-sso-event-id", event.id.as_str())
        .header("x-gpt-sso-delivery-id", delivery_id);

    if !webhook.secret.is_empty() {
        match sign_body(&webhook.secret, &body) {
            Ok(signature) => {
                request = request.header("x-gpt-sso-signature", format!("sha256={signature}"));
            }
            Err(err) => {
                let error = err.to_string();
                update_delivery_status(db, webhook, None, Some(error.clone())).await;
                return Err(error);
            }
        }
    }

    match request.body(body).send().await {
        Ok(response) => {
            let status = response.status().as_u16() as i32;
            let error = (!response.status().is_success())
                .then(|| format!("HTTP {}", response.status().as_u16()));
            update_delivery_status(db, webhook, Some(status), error.clone()).await;
            match error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
        Err(err) => {
            let error = err.to_string();
            update_delivery_status(db, webhook, None, Some(error.clone())).await;
            Err(error)
        }
    }
}

async fn update_delivery_status(
    db: &Db,
    webhook: &AuditWebhookRecord,
    status_code: Option<i32>,
    error: Option<String>,
) {
    let error = error.map(|value| value.chars().take(512).collect::<String>());
    if let Err(err) = db
        .update_audit_webhook_delivery_status(&webhook.id, status_code, error)
        .await
    {
        tracing::warn!(
            webhook_id = %webhook.id,
            error = %err,
            "failed to update audit webhook status"
        );
    }
}

fn payload_for_event(event: &AuditEventRecord) -> AuditWebhookPayload {
    let details = serde_json::from_str::<Value>(&event.details)
        .unwrap_or_else(|_| Value::String(event.details.clone()));
    AuditWebhookPayload {
        r#type: "audit.event",
        id: event.id.clone(),
        created_at: event.created_at,
        event: json!({
            "id": &event.id,
            "actor_user_id": &event.actor_user_id,
            "actor_client_id": &event.actor_client_id,
            "action": &event.action,
            "target_kind": &event.target_kind,
            "target_id": &event.target_id,
            "outcome": &event.outcome,
            "ip_address": &event.ip_address,
            "user_agent": &event.user_agent,
            "details": details,
            "created_at": event.created_at,
        }),
    }
}

fn webhook_matches(webhook: &AuditWebhookRecord, action: &str) -> bool {
    match webhook.actions() {
        Ok(actions) => action_matches(&actions, action),
        Err(err) => {
            tracing::warn!(webhook_id = %webhook.id, error = %err, "invalid audit webhook action filter");
            false
        }
    }
}

fn action_matches(filters: &[String], action: &str) -> bool {
    if filters.is_empty() {
        return true;
    }
    filters.iter().any(|filter| {
        filter == action
            || filter
                .strip_suffix('*')
                .is_some_and(|prefix| action.starts_with(prefix))
    })
}

fn sign_body(secret: &str, body: &[u8]) -> AppResult<String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|err| AppError::Internal(format!("failed to create webhook HMAC: {err}")))?;
    mac.update(body);
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

fn normalize_input(input: AuditWebhookInput) -> AppResult<AuditWebhookInput> {
    let name = input.name.trim().to_string();
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(AppError::BadRequest(format!(
            "webhook name must be 1-{MAX_NAME_LEN} characters"
        )));
    }
    let url = normalize_webhook_url(&input.url)?;
    let secret = if input.clear_secret {
        Some(String::new())
    } else {
        input
            .secret
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    if secret
        .as_ref()
        .is_some_and(|value| value.len() > MAX_SECRET_LEN)
    {
        return Err(AppError::BadRequest(format!(
            "webhook secret must be {MAX_SECRET_LEN} characters or fewer"
        )));
    }
    let actions = normalize_actions(input.actions)?;
    let timeout_seconds = input
        .timeout_seconds
        .clamp(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS);
    Ok(AuditWebhookInput {
        name,
        url,
        secret,
        clear_secret: input.clear_secret,
        actions,
        is_active: input.is_active,
        timeout_seconds,
    })
}

fn normalize_webhook_url(value: &str) -> AppResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_URL_LEN {
        return Err(AppError::BadRequest(format!(
            "webhook URL must be 1-{MAX_URL_LEN} characters"
        )));
    }
    let url = Url::parse(trimmed)
        .map_err(|err| AppError::BadRequest(format!("invalid webhook URL: {err}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AppError::BadRequest(
            "webhook URL must use http or https".to_string(),
        ));
    }
    if url.fragment().is_some() {
        return Err(AppError::BadRequest(
            "webhook URL cannot contain a fragment".to_string(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(AppError::BadRequest(
            "webhook URL cannot include user info".to_string(),
        ));
    }
    Ok(url.to_string())
}

fn normalize_actions(actions: Vec<String>) -> AppResult<Vec<String>> {
    let mut normalized = actions
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    if normalized.len() > MAX_ACTIONS {
        return Err(AppError::BadRequest(format!(
            "webhook action filter can contain at most {MAX_ACTIONS} entries"
        )));
    }
    for action in &normalized {
        if action.len() > MAX_ACTION_LEN
            || !action
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '*'))
            || (action.contains('*') && !action.ends_with('*'))
        {
            return Err(AppError::BadRequest(format!(
                "invalid webhook action filter: {action}"
            )));
        }
    }
    Ok(normalized)
}

const fn default_timeout_seconds() -> i32 {
    5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_filters_match_exact_prefix_and_empty() {
        assert!(action_matches(&[], "user.create"));
        assert!(action_matches(&["user.create".to_string()], "user.create"));
        assert!(action_matches(&["user.*".to_string()], "user.delete"));
        assert!(!action_matches(&["client.*".to_string()], "user.delete"));
    }

    #[test]
    fn invalid_urls_are_rejected() {
        assert!(normalize_webhook_url("https://example.com/hook").is_ok());
        assert!(normalize_webhook_url("ftp://example.com/hook").is_err());
        assert!(normalize_webhook_url("https://user@example.com/hook").is_err());
        assert!(normalize_webhook_url("https://example.com/hook#fragment").is_err());
    }

    #[test]
    fn invalid_action_filters_are_rejected() {
        assert_eq!(
            normalize_actions(vec!["User.*".to_string(), "user.create".to_string()]).unwrap(),
            vec!["user.*".to_string(), "user.create".to_string()]
        );
        assert!(normalize_actions(vec!["user.*.bad".to_string()]).is_err());
        assert!(normalize_actions(vec!["user create".to_string()]).is_err());
    }
}
