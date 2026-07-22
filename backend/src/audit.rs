use crate::{
    db::{AuditEventRecord, Db},
    error::AppResult,
};
use serde_json::Value;
use std::future::Future;

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub actor_user_id: Option<String>,
    pub actor_client_id: Option<String>,
    pub action: String,
    pub target_kind: String,
    pub target_id: Option<String>,
    pub outcome: AuditOutcome,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: Value,
}

#[derive(Debug, Clone, Copy)]
pub enum AuditOutcome {
    Success,
    Failure,
}

impl AuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            AuditOutcome::Success => "success",
            AuditOutcome::Failure => "failure",
        }
    }
}

pub trait AuditSink {
    fn record_audit_event(&self, event: AuditEvent) -> impl Future<Output = AppResult<()>> + Send;
}

impl AuditSink for Db {
    async fn record_audit_event(&self, event: AuditEvent) -> AppResult<()> {
        self.insert_audit_event(event).await
    }
}

pub fn management_event(
    actor_user_id: impl Into<String>,
    action: impl Into<String>,
    target_kind: impl Into<String>,
    target_id: Option<String>,
    details: Value,
) -> AuditEvent {
    AuditEvent {
        actor_user_id: Some(actor_user_id.into()),
        actor_client_id: None,
        action: action.into(),
        target_kind: target_kind.into(),
        target_id,
        outcome: AuditOutcome::Success,
        ip_address: None,
        user_agent: None,
        details,
    }
}

pub fn oauth_event(
    client_id: impl Into<String>,
    action: impl Into<String>,
    outcome: AuditOutcome,
    details: Value,
) -> AuditEvent {
    AuditEvent {
        actor_user_id: None,
        actor_client_id: Some(client_id.into()),
        action: action.into(),
        target_kind: "oauth".to_string(),
        target_id: None,
        outcome,
        ip_address: None,
        user_agent: None,
        details,
    }
}

pub fn public_events(records: Vec<AuditEventRecord>) -> Vec<AuditEventRecord> {
    records
}
