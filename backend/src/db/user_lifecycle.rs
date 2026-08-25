//! Atomic administrative account lifecycle operations.
//!
//! The HTTP layer decides who may request a transition.  This module owns the
//! aggregate write: every selected account is validated against the same
//! state snapshot, dependent authentication rows are cleared in one
//! transaction, and one audit event is committed with the state change.

use super::*;
use crate::config::DatabaseKind;
use diesel::{
    Connection, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

const MAX_USER_LIFECYCLE_BATCH: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserLifecycleBatchAction {
    Enable,
    Disable,
    Archive,
    Delete,
    ResetMfa,
}

impl UserLifecycleBatchAction {
    pub fn parse(value: &str) -> AppResult<Self> {
        match value.trim() {
            "enable" => Ok(Self::Enable),
            "disable" => Ok(Self::Disable),
            "archive" => Ok(Self::Archive),
            "delete" => Ok(Self::Delete),
            "reset_mfa" => Ok(Self::ResetMfa),
            other => Err(AppError::BadRequest(format!(
                "unsupported user lifecycle action: {other}"
            ))),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Archive => "archive",
            Self::Delete => "delete",
            Self::ResetMfa => "reset_mfa",
        }
    }
}

fn placeholders(kind: DatabaseKind, start: usize, count: usize) -> String {
    (start..start + count)
        .map(|index| ph(kind, index))
        .collect::<Vec<_>>()
        .join(", ")
}

macro_rules! delete_user_rows {
    ($conn:expr, $kind:expr, $table:expr, $column:expr, $ids:expr) => {{
        let conn = &mut *$conn;
        let ids = $ids;
        let sql = format!(
            "DELETE FROM {} WHERE {} IN ({})",
            $table,
            $column,
            placeholders($kind, 1, ids.len())
        );
        bind_text_list(conn, sql_query(sql), ids)
            .execute(conn)
            .map_err(AppError::from)?;
        Ok::<(), AppError>(())
    }};
}

macro_rules! delete_session_rows {
    ($conn:expr, $kind:expr, $table:expr, $ids:expr) => {{
        let conn = &mut *$conn;
        let ids = $ids;
        let sql = format!(
            "DELETE FROM {} WHERE session_id IN (SELECT id FROM sessions WHERE user_id IN ({}))",
            $table,
            placeholders($kind, 1, ids.len())
        );
        bind_text_list(conn, sql_query(sql), ids)
            .execute(conn)
            .map_err(AppError::from)?;
        Ok::<(), AppError>(())
    }};
}

macro_rules! clear_user_auth_state_for_users {
    ($conn:expr, $kind:expr, $ids:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let ids = $ids;
        for table in ["session_credentials", "browser_context_accounts"] {
            delete_session_rows!(conn, kind, table, ids)?;
        }
        for (table, column) in super::USER_AUTH_STATE_TABLES {
            delete_user_rows!(conn, kind, table, column, ids)?;
        }
        delete_user_rows!(conn, kind, "application_identity_bindings", "user_id", ids)?;
        Ok::<(), AppError>(())
    }};
}

macro_rules! clear_mfa_for_users {
    ($conn:expr, $kind:expr, $ids:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let ids = $ids;
        for table in [
            "mfa_totp_methods",
            "mfa_totp_setups",
            "mfa_recovery_codes",
            "mfa_challenges",
            "passkeys",
            "webauthn_challenges",
        ] {
            delete_user_rows!(conn, kind, table, "user_id", ids)?;
        }
        Ok::<(), AppError>(())
    }};
}

macro_rules! update_lifecycle_state {
    ($conn:expr, $kind:expr, $ids:expr, $is_active:expr, $archived_at:expr, $now:expr $(,)?) => {{
        let conn = &mut *$conn;
        let kind = $kind;
        let ids = $ids;
        let id_count = ids.len();
        if matches!(kind, DatabaseKind::Postgres) {
            let sql = format!(
                "UPDATE users SET is_active = {}, archived_at = {}, updated_at = {} WHERE id IN ({})",
                ph(kind, id_count + 1),
                ph(kind, id_count + 2),
                ph(kind, id_count + 3),
                placeholders(kind, 1, id_count)
            );
            bind_text_list(conn, sql_query(sql), ids)
                .bind::<Integer, _>($is_active)
                .bind::<Nullable<BigInt>, _>($archived_at)
                .bind::<BigInt, _>($now)
                .execute(conn)
                .map_err(AppError::from)?;
        } else {
            // SQLite/MySQL use anonymous `?` parameters, so bind order must
            // follow the textual SET-then-WHERE order. PostgreSQL uses
            // numbered placeholders and is handled above.
            let sql = format!(
                "UPDATE users SET is_active = {}, archived_at = {}, updated_at = {} WHERE id IN ({})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                placeholders(kind, 4, id_count)
            );
            let mut query = sql_query(sql).into_boxed::<_>();
            query = query
                .bind::<Integer, _>($is_active)
                .bind::<Nullable<BigInt>, _>($archived_at)
                .bind::<BigInt, _>($now);
            for id in ids {
                query = query.bind::<Text, _>(id.clone());
            }
            query.execute(conn).map_err(AppError::from)?;
        }
        Ok::<(), AppError>(())
    }};
}

impl Db {
    /// Applies one lifecycle transition to a bounded set of accounts.
    ///
    /// State validation, dependent-row cleanup, account mutation, and audit
    /// insertion share one transaction. This makes a mixed or stale selection
    /// fail without partially processing the batch; the transport mutation
    /// protocol supplies replay protection around the whole command.
    pub async fn apply_user_lifecycle_batch(
        &self,
        actor_user_id: &str,
        user_ids: Vec<String>,
        action: UserLifecycleBatchAction,
    ) -> AppResult<usize> {
        let ids = user_ids
            .into_iter()
            .map(|id| id.trim().to_string())
            .filter(|id| !id.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Err(AppError::BadRequest(
                "at least one user id is required".to_string(),
            ));
        }
        if ids.len() > MAX_USER_LIFECYCLE_BATCH {
            return Err(AppError::BadRequest(format!(
                "user lifecycle batches cannot exceed {MAX_USER_LIFECYCLE_BATCH} accounts"
            )));
        }
        if ids.iter().any(|id| id == actor_user_id) {
            return Err(AppError::BadRequest(
                "administrator cannot change their own account lifecycle".to_string(),
            ));
        }

        let actor_user_id = actor_user_id.to_string();
        let audit_action = format!("user.bulk.{}", action.as_str());
        let audit_event = crate::audit::management_event(
            actor_user_id,
            audit_action,
            "user_bulk",
            None,
            json!({
                "action": action.as_str(),
                "user_ids": ids,
                "count": ids.len(),
            }),
        );
        let now = util::now_ts();
        let webhook_db = self.clone();
        let (count, audit_event) = with_conn!(self, |conn, kind| {
            conn.transaction::<(usize, AuditEventRecord), AppError, _>(|conn| {
                let user_sql = format!(
                    "{} WHERE id IN ({})",
                    select_user_sql(),
                    placeholders(kind, 1, ids.len())
                );
                let users = bind_text_list(conn, sql_query(user_sql), &ids)
                    .load::<UserRecord>(conn)
                    .map_err(AppError::from)?;
                if users.len() != ids.len() {
                    return Err(AppError::NotFound);
                }
                let users = users
                    .into_iter()
                    .map(|user| (user.id.clone(), user))
                    .collect::<BTreeMap<_, _>>();
                for id in &ids {
                    let user = users.get(id).ok_or(AppError::NotFound)?;
                    let valid = match action {
                        UserLifecycleBatchAction::Enable => true,
                        UserLifecycleBatchAction::Disable => {
                            user.archived_at.is_none() && user.is_active == 1
                        }
                        UserLifecycleBatchAction::Archive => {
                            user.archived_at.is_none() && user.is_active == 0
                        }
                        UserLifecycleBatchAction::Delete => user.archived_at.is_some(),
                        UserLifecycleBatchAction::ResetMfa => user.archived_at.is_none(),
                    };
                    if !valid {
                        return Err(AppError::BadRequest(format!(
                            "user {id} is not in a valid state for {}",
                            action.as_str()
                        )));
                    }
                }

                match action {
                    UserLifecycleBatchAction::Enable => {
                        update_lifecycle_state!(conn, kind, &ids, 1, None::<i64>, now)?;
                    }
                    UserLifecycleBatchAction::Disable => {
                        clear_user_auth_state_for_users!(conn, kind, &ids)?;
                        update_lifecycle_state!(conn, kind, &ids, 0, None::<i64>, now)?;
                    }
                    UserLifecycleBatchAction::Archive => {
                        clear_user_auth_state_for_users!(conn, kind, &ids)?;
                        update_lifecycle_state!(conn, kind, &ids, 0, Some(now), now)?;
                    }
                    UserLifecycleBatchAction::Delete => {
                        clear_user_auth_state_for_users!(conn, kind, &ids)?;
                        for table in [
                            "client_grants",
                            "user_roles",
                            "group_members",
                            "organization_members",
                            "application_members",
                            "application_identity_bindings",
                            "mfa_totp_methods",
                            "mfa_totp_setups",
                            "mfa_recovery_codes",
                            "mfa_challenges",
                            "passkeys",
                            "linked_identities",
                            "login_events",
                            "invitation_redemptions",
                            "trial_enrollments",
                        ] {
                            delete_user_rows!(conn, kind, table, "user_id", &ids)?;
                        }
                        let id_count = ids.len();
                        if matches!(kind, DatabaseKind::Postgres) {
                            let sql = format!(
                                "UPDATE invitations SET is_active = 0, updated_at = {} WHERE authorized_user_id IN ({}) AND code_type = {} AND login_code_level = {}",
                                ph(kind, id_count + 1),
                                placeholders(kind, 1, id_count),
                                ph(kind, id_count + 2),
                                ph(kind, id_count + 3)
                            );
                            bind_text_list(conn, sql_query(sql), &ids)
                                .bind::<BigInt, _>(now)
                                .bind::<Text, _>(
                                    super::AuthorizationCodeType::Login.as_str(),
                                )
                                .bind::<Text, _>(super::LoginCodeLevel::AccountRecovery.as_str())
                                .execute(conn)
                                .map_err(AppError::from)?;
                        } else {
                            let sql = format!(
                                "UPDATE invitations SET is_active = 0, updated_at = {} WHERE authorized_user_id IN ({}) AND code_type = {} AND login_code_level = {}",
                                ph(kind, 1),
                                placeholders(kind, 2, id_count),
                                ph(kind, id_count + 2),
                                ph(kind, id_count + 3)
                            );
                            let mut query = sql_query(sql).into_boxed::<_>();
                            query = query.bind::<BigInt, _>(now);
                            for id in &ids {
                                query = query.bind::<Text, _>(id.clone());
                            }
                            query = query
                                .bind::<Text, _>(super::AuthorizationCodeType::Login.as_str())
                                .bind::<Text, _>(super::LoginCodeLevel::AccountRecovery.as_str());
                            query.execute(conn).map_err(AppError::from)?;
                        }
                        delete_user_rows!(conn, kind, "users", "id", &ids)?;
                    }
                    UserLifecycleBatchAction::ResetMfa => {
                        clear_mfa_for_users!(conn, kind, &ids)?;
                    }
                }
                let audit_event = insert_audit_event_on_conn!(conn, kind, audit_event)?;
                Ok((ids.len(), audit_event))
            })
        })?;
        crate::webhooks::spawn_audit_webhook_delivery(webhook_db, audit_event);
        Ok(count)
    }
}
