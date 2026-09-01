use super::{UserInput, normalize_required_text};
use crate::organizations::OrganizationEmailPolicy;
use crate::{
    AppState,
    access::{Authorizer, Permission},
    audit::{self, AuditSink},
    db::{NewBulkProvisionedUser, NewUser},
    error::{AppError, AppResult},
    organizations, util,
};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;
use csv::ReaderBuilder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub(super) const BULK_IMPORT_MAX_BYTES: usize = 1_048_576;
pub(super) const BULK_IMPORT_MAX_ROWS: usize = 1_000;
pub(super) const BULK_IMPORT_HEADERS: [&str; 6] = [
    "email",
    "username",
    "display_name",
    "organization_slug",
    "organization_role",
    "is_active",
];

#[derive(Debug, Deserialize, Default)]
pub(super) struct BulkImportQuery {
    #[serde(default)]
    pub(super) dry_run: bool,
}

#[derive(Debug, Serialize)]
pub(super) struct BulkImportResponse {
    dry_run: bool,
    atomic: bool,
    committed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    batch_error: Option<String>,
    summary: BulkImportSummary,
    rows: Vec<BulkImportRowResponse>,
}

#[derive(Debug, Serialize)]
pub(super) struct BulkImportSummary {
    total: usize,
    created: usize,
    would_create: usize,
    invalid: usize,
    not_committed: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct BulkImportRowResponse {
    /// The physical CSV line, where the header is line 1.
    row: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    /// `created`, `would_create`, `invalid`, or `not_committed`.
    pub(super) outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct BulkImportCandidate {
    result_index: usize,
    email: String,
    username: String,
    display_name: Option<String>,
    pub(super) organization_slug: Option<String>,
    pub(super) organization_role: Option<String>,
    organization_id: Option<String>,
    pub(super) is_active: bool,
}

#[derive(Debug)]
pub(super) struct ParsedBulkImport {
    pub(super) rows: Vec<BulkImportRowResponse>,
    pub(super) candidates: Vec<BulkImportCandidate>,
    pub(super) has_organization_assignments: bool,
}

#[derive(Debug)]
pub(super) struct NormalizedUserInput {
    pub(super) email: String,
    pub(super) username: String,
    pub(super) display_name: Option<String>,
    pub(super) phone: Option<String>,
    pub(super) password: Option<String>,
    pub(super) is_admin: bool,
    pub(super) is_active: bool,
}

pub(super) fn normalize_user_input(input: UserInput) -> AppResult<NormalizedUserInput> {
    Ok(NormalizedUserInput {
        email: normalize_required_email(input.email)?,
        username: normalize_required_text(input.username, "username")?,
        display_name: super::normalize_optional_text(input.display_name),
        phone: super::normalize_optional_text(input.phone),
        password: super::normalize_optional_text(input.password),
        is_admin: input.is_admin,
        is_active: input.is_active,
    })
}

pub(super) fn normalize_required_email(value: String) -> AppResult<String> {
    let email = value.trim().to_ascii_lowercase();
    if !email.contains('@') || email.ends_with('@') {
        return Err(AppError::BadRequest("email is invalid".to_string()));
    }
    Ok(email)
}

/// Import new enterprise accounts from a CSV document.
///
/// The endpoint is intentionally insert-only.  A dry run performs the same
/// validation and collision checks as a commit, while a commit creates all
/// users and organization memberships in one database transaction.
pub(super) async fn import_users_csv(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<BulkImportQuery>,
    csv_document: String,
) -> AppResult<Response> {
    let current = super::require_user_manager(&state, &jar).await?;
    if csv_document.len() > BULK_IMPORT_MAX_BYTES {
        return Err(AppError::BadRequest(format!(
            "CSV import exceeds the {} byte limit",
            BULK_IMPORT_MAX_BYTES
        )));
    }

    let mut batch = match parse_bulk_import_csv(&csv_document) {
        Ok(batch) => batch,
        Err(message) => {
            record_bulk_import_audit(
                &state,
                &current.user.id,
                query.dry_run,
                false,
                &[],
                Some(&message),
            )
            .await?;
            return Err(AppError::BadRequest(message));
        }
    };

    // A user manager may create unassigned accounts, but assigning an
    // organization owner/admin/member is organization administration too.
    if batch.has_organization_assignments {
        state
            .db
            .require_permission(&current.user, Permission::OrganizationsManage)
            .await?;
    }

    validate_bulk_import_duplicates(&mut batch);
    validate_bulk_import_existing_identities(&state, &mut batch).await?;
    validate_bulk_import_organizations(&state, &mut batch).await?;

    if bulk_import_has_invalid_rows(&batch.rows) {
        mark_bulk_import_not_committed(&mut batch.rows);
        let batch_error = "the CSV contains invalid rows; no accounts were imported";
        record_bulk_import_audit(
            &state,
            &current.user.id,
            query.dry_run,
            false,
            &batch.rows,
            Some(batch_error),
        )
        .await?;
        return Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(bulk_import_response(
                query.dry_run,
                false,
                Some(batch_error.to_string()),
                batch.rows,
            )),
        )
            .into_response());
    }

    if query.dry_run {
        record_bulk_import_audit(&state, &current.user.id, true, false, &batch.rows, None).await?;
        return Ok(Json(bulk_import_response(true, false, None, batch.rows)).into_response());
    }

    // Imported accounts have a cryptographically random, undisclosed initial
    // password.  The same per-batch hash is safe because its plaintext is not
    // returned, logged, or retained; it also avoids an expensive Argon2 run
    // for every CSV row.  Administrators can subsequently use the ordinary
    // password-reset/activation path for each account.
    let initial_password_hash =
        util::hash_password(&format!("BulkProvisioned-{}9!", util::random_token(48)))?;
    let users = batch
        .candidates
        .iter()
        .filter(|candidate| batch.rows[candidate.result_index].outcome == "would_create")
        .map(|candidate| NewBulkProvisionedUser {
            user: NewUser {
                email: candidate.email.clone(),
                username: candidate.username.clone(),
                display_name: candidate.display_name.clone(),
                phone: None,
                password_hash: initial_password_hash.clone(),
                email_verified_at: Some(util::now_ts()),
                phone_verified_at: None,
                is_admin: false,
                is_active: candidate.is_active,
                archived_at: None,
            },
            organization_id: candidate.organization_id.clone(),
            organization_role: candidate.organization_role.clone(),
        })
        .collect::<Vec<_>>();

    let created = match state.db.insert_bulk_provisioned_users(users).await {
        Ok(users) => users,
        Err(error)
            if matches!(
                &error,
                AppError::BadRequest(_) | AppError::Forbidden | AppError::NotFound
            ) =>
        {
            // The preflight passed, so a validation failure here means the
            // database changed between preflight and the transaction.  The DB
            // method rolls the entire transaction back.
            mark_bulk_import_not_committed(&mut batch.rows);
            let batch_error =
                "the directory changed while this batch was committing; no accounts were imported";
            record_bulk_import_audit(
                &state,
                &current.user.id,
                false,
                false,
                &batch.rows,
                Some(batch_error),
            )
            .await?;
            return Ok((
                StatusCode::CONFLICT,
                Json(bulk_import_response(
                    false,
                    false,
                    Some(batch_error.to_string()),
                    batch.rows,
                )),
            )
                .into_response());
        }
        Err(error) => return Err(error),
    };

    for (candidate, user) in batch.candidates.iter().zip(created) {
        let row = &mut batch.rows[candidate.result_index];
        row.outcome = "created".to_string();
        row.user_id = Some(user.id);
    }
    record_bulk_import_audit(&state, &current.user.id, false, true, &batch.rows, None).await?;
    Ok(Json(bulk_import_response(false, true, None, batch.rows)).into_response())
}

pub(super) fn parse_bulk_import_csv(csv_document: &str) -> Result<ParsedBulkImport, String> {
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .trim(csv::Trim::All)
        .from_reader(csv_document.as_bytes());
    let header_positions = bulk_import_header_positions(
        &reader
            .headers()
            .map_err(|error| format!("CSV header is invalid: {error}"))?
            .clone(),
    )?;

    let mut rows = Vec::new();
    let mut candidates = Vec::new();
    let mut has_organization_assignments = false;
    for (index, record) in reader.records().enumerate() {
        if index >= BULK_IMPORT_MAX_ROWS {
            return Err(format!(
                "CSV import exceeds the {BULK_IMPORT_MAX_ROWS} row limit"
            ));
        }
        let record = record.map_err(|error| format!("CSV row is invalid: {error}"))?;
        let row = record
            .position()
            .map(|position| position.line() as usize)
            .unwrap_or(index + 2);
        let result_index = rows.len();
        let email_raw = bulk_import_csv_value(&record, &header_positions, "email");
        let username_raw = bulk_import_csv_value(&record, &header_positions, "username");
        rows.push(BulkImportRowResponse {
            row,
            email: (!email_raw.is_empty()).then(|| email_raw.to_string()),
            username: (!username_raw.is_empty()).then(|| username_raw.to_string()),
            outcome: "would_create".to_string(),
            user_id: None,
            error: None,
        });

        if record.len() != BULK_IMPORT_HEADERS.len() {
            mark_bulk_import_row_invalid(
                &mut rows,
                result_index,
                format!(
                    "expected {} columns but found {}",
                    BULK_IMPORT_HEADERS.len(),
                    record.len()
                ),
            );
            continue;
        }

        let email = match normalize_required_email(email_raw.to_string()) {
            Ok(value) => {
                rows[result_index].email = Some(value.clone());
                Some(value)
            }
            Err(error) => {
                mark_bulk_import_row_invalid(&mut rows, result_index, error.to_string());
                None
            }
        };
        let username = match normalize_required_text(username_raw.to_string(), "username") {
            Ok(value) => {
                rows[result_index].username = Some(value.clone());
                Some(value)
            }
            Err(error) => {
                mark_bulk_import_row_invalid(&mut rows, result_index, error.to_string());
                None
            }
        };
        let display_name = super::normalize_optional_text(
            (!bulk_import_csv_value(&record, &header_positions, "display_name").is_empty()).then(
                || bulk_import_csv_value(&record, &header_positions, "display_name").to_string(),
            ),
        );
        let organization_slug_raw =
            bulk_import_csv_value(&record, &header_positions, "organization_slug");
        let organization_role_raw =
            bulk_import_csv_value(&record, &header_positions, "organization_role");
        if !organization_slug_raw.is_empty() {
            has_organization_assignments = true;
        }
        let organization_slug = if organization_slug_raw.is_empty() {
            None
        } else {
            match organizations::normalize_slug(organization_slug_raw) {
                Ok(value) => Some(value),
                Err(error) => {
                    mark_bulk_import_row_invalid(&mut rows, result_index, error.to_string());
                    None
                }
            }
        };
        let organization_role = if organization_role_raw.is_empty() {
            None
        } else {
            match organizations::normalize_role(organization_role_raw) {
                Ok(value) => Some(value),
                Err(error) => {
                    mark_bulk_import_row_invalid(&mut rows, result_index, error.to_string());
                    None
                }
            }
        };
        match (&organization_slug, &organization_role) {
            (Some(_), None) => mark_bulk_import_row_invalid(
                &mut rows,
                result_index,
                "organization_role is required when organization_slug is set",
            ),
            (None, Some(_)) => mark_bulk_import_row_invalid(
                &mut rows,
                result_index,
                "organization_role must be empty when organization_slug is empty",
            ),
            _ => {}
        }
        let is_active = match parse_bulk_import_is_active(bulk_import_csv_value(
            &record,
            &header_positions,
            "is_active",
        )) {
            Ok(value) => Some(value),
            Err(message) => {
                mark_bulk_import_row_invalid(&mut rows, result_index, message);
                None
            }
        };

        if let (Some(email), Some(username), Some(is_active)) = (email, username, is_active)
            && rows[result_index].outcome != "invalid"
        {
            candidates.push(BulkImportCandidate {
                result_index,
                email,
                username,
                display_name,
                organization_slug,
                organization_role,
                organization_id: None,
                is_active,
            });
        }
    }

    if rows.is_empty() {
        return Err("CSV import must contain at least one data row".to_string());
    }
    Ok(ParsedBulkImport {
        rows,
        candidates,
        has_organization_assignments,
    })
}

pub(super) fn bulk_import_header_positions(
    headers: &csv::StringRecord,
) -> Result<HashMap<String, usize>, String> {
    let mut positions = HashMap::with_capacity(headers.len());
    for (index, value) in headers.iter().enumerate() {
        let value = if index == 0 {
            value.strip_prefix('\u{feff}').unwrap_or(value)
        } else {
            value
        };
        let value = value.trim().to_ascii_lowercase();
        if !BULK_IMPORT_HEADERS.contains(&value.as_str()) {
            return Err(format!("unexpected CSV column: {value}"));
        }
        if positions.insert(value.clone(), index).is_some() {
            return Err(format!("CSV column appears more than once: {value}"));
        }
    }
    for required in BULK_IMPORT_HEADERS {
        if !positions.contains_key(required) {
            return Err(format!("CSV column is required: {required}"));
        }
    }
    if headers.len() != BULK_IMPORT_HEADERS.len() {
        return Err("CSV header must contain exactly the supported columns".to_string());
    }
    Ok(positions)
}

fn bulk_import_csv_value<'a>(
    record: &'a csv::StringRecord,
    header_positions: &HashMap<String, usize>,
    field: &str,
) -> &'a str {
    record
        .get(*header_positions.get(field).expect("validated CSV header"))
        .unwrap_or_default()
        .trim()
}

pub(super) fn parse_bulk_import_is_active(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err("is_active must be true or false".to_string()),
    }
}

pub(super) fn mark_bulk_import_row_invalid(
    rows: &mut [BulkImportRowResponse],
    index: usize,
    message: impl Into<String>,
) {
    let row = &mut rows[index];
    let message = message.into();
    row.outcome = "invalid".to_string();
    match &mut row.error {
        Some(existing) if !existing.contains(&message) => {
            existing.push_str("; ");
            existing.push_str(&message);
        }
        Some(_) => {}
        None => row.error = Some(message),
    }
}

pub(super) fn validate_bulk_import_duplicates(batch: &mut ParsedBulkImport) {
    let mut email_rows = HashMap::<String, usize>::with_capacity(batch.candidates.len());
    let mut username_rows = HashMap::<String, usize>::with_capacity(batch.candidates.len());
    for candidate in &batch.candidates {
        if let Some(first_index) =
            email_rows.insert(candidate.email.clone(), candidate.result_index)
            && first_index != candidate.result_index
        {
            let first_row = batch.rows[first_index].row;
            let duplicate_row = batch.rows[candidate.result_index].row;
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                first_index,
                format!("email duplicates CSV row {duplicate_row}"),
            );
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                candidate.result_index,
                format!("email duplicates CSV row {first_row}"),
            );
        }
        if let Some(first_index) =
            username_rows.insert(candidate.username.clone(), candidate.result_index)
            && first_index != candidate.result_index
        {
            let first_row = batch.rows[first_index].row;
            let duplicate_row = batch.rows[candidate.result_index].row;
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                first_index,
                format!("username duplicates CSV row {duplicate_row}"),
            );
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                candidate.result_index,
                format!("username duplicates CSV row {first_row}"),
            );
        }
    }
}

async fn validate_bulk_import_existing_identities(
    state: &AppState,
    batch: &mut ParsedBulkImport,
) -> AppResult<()> {
    let candidates = batch
        .candidates
        .iter()
        .filter(|candidate| batch.rows[candidate.result_index].outcome != "invalid")
        .cloned()
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Ok(());
    }
    let emails = candidates
        .iter()
        .map(|candidate| candidate.email.clone())
        .collect::<Vec<_>>();
    let usernames = candidates
        .iter()
        .map(|candidate| candidate.username.clone())
        .collect::<Vec<_>>();
    let (existing_emails, existing_usernames) = state
        .db
        .find_existing_user_identities(&emails, &usernames)
        .await?;
    for candidate in candidates {
        if existing_emails.contains(&candidate.email) {
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                candidate.result_index,
                "email already belongs to an existing account",
            );
        }
        if existing_usernames.contains(&candidate.username) {
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                candidate.result_index,
                "username already belongs to an existing account",
            );
        }
    }
    Ok(())
}

async fn validate_bulk_import_organizations(
    state: &AppState,
    batch: &mut ParsedBulkImport,
) -> AppResult<()> {
    let organizations_by_slug = state
        .db
        .list_organizations()
        .await?
        .into_iter()
        .map(|organization| (organization.slug.clone(), organization))
        .collect::<HashMap<_, _>>();
    for candidate_index in 0..batch.candidates.len() {
        let (result_index, organization_slug, email) = {
            let candidate = &batch.candidates[candidate_index];
            (
                candidate.result_index,
                candidate.organization_slug.clone(),
                candidate.email.clone(),
            )
        };
        if batch.rows[result_index].outcome == "invalid" {
            continue;
        }
        let Some(slug) = organization_slug.as_deref() else {
            continue;
        };
        let Some(organization) = organizations_by_slug.get(slug) else {
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                result_index,
                "organization_slug does not reference an existing organization",
            );
            continue;
        };
        if organization.is_active != 1 {
            mark_bulk_import_row_invalid(&mut batch.rows, result_index, "organization is inactive");
            continue;
        }
        if !organization.allows_email(&email)? {
            mark_bulk_import_row_invalid(
                &mut batch.rows,
                result_index,
                "email is not allowed by the organization policy",
            );
            continue;
        }
        batch.candidates[candidate_index].organization_id = Some(organization.id.clone());
    }
    Ok(())
}

pub(super) fn bulk_import_has_invalid_rows(rows: &[BulkImportRowResponse]) -> bool {
    rows.iter().any(|row| row.outcome == "invalid")
}

pub(super) fn mark_bulk_import_not_committed(rows: &mut [BulkImportRowResponse]) {
    for row in rows {
        if row.outcome == "would_create" {
            row.outcome = "not_committed".to_string();
        }
    }
}

pub(super) fn bulk_import_summary(rows: &[BulkImportRowResponse]) -> BulkImportSummary {
    let mut summary = BulkImportSummary {
        total: rows.len(),
        created: 0,
        would_create: 0,
        invalid: 0,
        not_committed: 0,
    };
    for row in rows {
        match row.outcome.as_str() {
            "created" => summary.created += 1,
            "would_create" => summary.would_create += 1,
            "invalid" => summary.invalid += 1,
            "not_committed" => summary.not_committed += 1,
            _ => {}
        }
    }
    summary
}

pub(super) fn bulk_import_response(
    dry_run: bool,
    committed: bool,
    batch_error: Option<String>,
    rows: Vec<BulkImportRowResponse>,
) -> BulkImportResponse {
    BulkImportResponse {
        dry_run,
        atomic: true,
        committed,
        batch_error,
        summary: bulk_import_summary(&rows),
        rows,
    }
}

pub(super) async fn record_bulk_import_audit(
    state: &AppState,
    actor_user_id: &str,
    dry_run: bool,
    committed: bool,
    rows: &[BulkImportRowResponse],
    batch_error: Option<&str>,
) -> AppResult<()> {
    let summary = bulk_import_summary(rows);
    let outcome = if committed || (dry_run && batch_error.is_none()) {
        audit::AuditOutcome::Success
    } else {
        audit::AuditOutcome::Failure
    };
    let action = if dry_run && batch_error.is_none() {
        "user.bulk_import.dry_run"
    } else if committed {
        "user.bulk_import"
    } else {
        "user.bulk_import.rejected"
    };
    state
        .db
        .record_audit_event(audit::AuditEvent {
            actor_user_id: Some(actor_user_id.to_string()),
            actor_client_id: None,
            action: action.to_string(),
            target_kind: "user_bulk_import".to_string(),
            target_id: None,
            outcome,
            ip_address: None,
            user_agent: None,
            details: serde_json::json!({
                "dry_run": dry_run,
                "committed": committed,
                "total": summary.total,
                "created": summary.created,
                "would_create": summary.would_create,
                "invalid": summary.invalid,
                "not_committed": summary.not_committed,
                "error": batch_error,
            }),
        })
        .await
}
