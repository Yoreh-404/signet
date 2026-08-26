//! User account persistence operations.

use super::*;

use super::{
    AppError, AppResult, CountRow, Db, NewBulkProvisionedUser, NewUser, OrganizationRecord,
    UserIdentityCandidate, UserRecord, UserRegistrationSource, UserUpdate, bind_text_list,
    count_all_users_sql, count_user_identity_conflicts_sql, insert_user_sql, ph,
    select_organization_sql, select_user_sql,
};
use crate::util;
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};
use std::collections::{BTreeMap, BTreeSet};

impl Db {
    pub async fn insert_user(&self, user: NewUser) -> AppResult<UserRecord> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let identity = UserIdentityCandidate::insert(&user);
        with_conn!(self, |conn, kind| {
            conn.transaction::<UserRecord, AppError, _>(|conn| {
                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "user email or username already exists"
                )?;
                sql_query(insert_user_sql(kind, UserRegistrationSource::Local))
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(user.email)
                    .bind::<Text, _>(user.username)
                    .bind::<Nullable<Text>, _>(user.display_name)
                    .bind::<Nullable<Text>, _>(user.phone)
                    .bind::<Text, _>(user.password_hash)
                    .bind::<Nullable<BigInt>, _>(user.email_verified_at)
                    .bind::<Nullable<BigInt>, _>(user.phone_verified_at)
                    .bind::<Integer, _>(i32::from(user.is_admin))
                    .bind::<Integer, _>(i32::from(user.is_active))
                    .bind::<Nullable<BigInt>, _>(user.archived_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    /// Inserts a complete enterprise-provisioning batch in one transaction.
    ///
    /// The method validates the identity availability and the optional
    /// organization membership inside the transaction as well as at the API
    /// preflight layer.  The second check makes a concurrent account creation
    /// fail closed: no partial users or memberships can remain from a batch.
    pub async fn insert_bulk_provisioned_users(
        &self,
        users: Vec<NewBulkProvisionedUser>,
    ) -> AppResult<Vec<UserRecord>> {
        if users.is_empty() {
            return Ok(Vec::new());
        }

        let entries = users
            .into_iter()
            .map(|entry| (uuid::Uuid::new_v4().to_string(), entry))
            .collect::<Vec<_>>();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<Vec<UserRecord>, AppError, _>(|conn| {
                let organization_ids = entries
                    .iter()
                    .filter_map(|(_, entry)| entry.organization_id.clone())
                    .collect::<BTreeSet<_>>();
                let organizations = if organization_ids.is_empty() {
                    BTreeMap::new()
                } else {
                    let organization_ids = organization_ids.into_iter().collect::<Vec<_>>();
                    let placeholders = (1..=organization_ids.len())
                        .map(|index| ph(kind, index))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let organization_sql = format!(
                        "{} WHERE id IN ({placeholders})",
                        select_organization_sql()
                    );
                    bind_text_list(conn, sql_query(organization_sql), &organization_ids)
                        .load::<OrganizationRecord>(conn)
                        .map_err(AppError::from)?
                        .into_iter()
                        .map(|organization| (organization.id.clone(), organization))
                        .collect::<BTreeMap<_, _>>()
                };
                let mut inserted = Vec::with_capacity(entries.len());
                for (id, entry) in &entries {
                    if entry.user.is_admin {
                        return Err(AppError::BadRequest(
                            "bulk provisioning cannot create administrators".to_string(),
                        ));
                    }
                    if entry.user.archived_at.is_some() {
                        return Err(AppError::BadRequest(
                            "bulk provisioning cannot create archived accounts".to_string(),
                        ));
                    }

                    let identity = UserIdentityCandidate::insert(&entry.user);
                    ensure_user_identity_available!(
                        conn,
                        kind,
                        identity,
                        "user email or username already exists"
                    )?;

                    let membership = match (
                        entry.organization_id.as_deref(),
                        entry.organization_role.as_deref(),
                    ) {
                        (None, None) => None,
                        (Some(_), None) => {
                            return Err(AppError::BadRequest(
                                "organization membership role is required".to_string(),
                            ));
                        }
                        (None, Some(_)) => {
                            return Err(AppError::BadRequest(
                                "organization membership requires an organization".to_string(),
                            ));
                        }
                        (Some(organization_id), Some(role)) => {
                            let role = crate::organizations::normalize_role(role)?;
                            let organization = organizations.get(organization_id).ok_or_else(|| {
                                AppError::BadRequest(
                                    "organization does not reference an existing organization"
                                        .to_string(),
                                )
                            })?;
                            if organization.is_active != 1 {
                                return Err(AppError::BadRequest(
                                    "organization is inactive".to_string(),
                                ));
                            }
                            if !organization.allows_email(&entry.user.email)? {
                                return Err(AppError::BadRequest(
                                    "email is not allowed by the organization policy".to_string(),
                                ));
                            }
                            Some((organization.id.clone(), role))
                        }
                    };

                    sql_query(insert_user_sql(kind, UserRegistrationSource::Local))
                        .bind::<Text, _>(id)
                        .bind::<Text, _>(&entry.user.email)
                        .bind::<Text, _>(&entry.user.username)
                        .bind::<Nullable<Text>, _>(entry.user.display_name.clone())
                        .bind::<Nullable<Text>, _>(entry.user.phone.clone())
                        .bind::<Text, _>(&entry.user.password_hash)
                        .bind::<Nullable<BigInt>, _>(entry.user.email_verified_at)
                        .bind::<Nullable<BigInt>, _>(entry.user.phone_verified_at)
                        .bind::<Integer, _>(i32::from(entry.user.is_admin))
                        .bind::<Integer, _>(i32::from(entry.user.is_active))
                        .bind::<Nullable<BigInt>, _>(entry.user.archived_at)
                        .bind::<Nullable<BigInt>, _>(None::<i64>)
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<Nullable<Text>, _>(None::<String>)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(|error| match error {
                            diesel::result::Error::DatabaseError(
                                diesel::result::DatabaseErrorKind::UniqueViolation,
                                _,
                            ) => AppError::BadRequest(
                                "user email or username already exists".to_string(),
                            ),
                            other => AppError::from(other),
                        })?;

                    if let Some((organization_id, role)) = membership {
                        let sql = format!(
                            "INSERT INTO organization_members (organization_id, user_id, role, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                            ph(kind, 1),
                            ph(kind, 2),
                            ph(kind, 3),
                            ph(kind, 4),
                            ph(kind, 5)
                        );
                        sql_query(sql)
                            .bind::<Text, _>(organization_id)
                            .bind::<Text, _>(id)
                            .bind::<Text, _>(role)
                            .bind::<BigInt, _>(now)
                            .bind::<BigInt, _>(now)
                            .execute(conn)
                            .map_err(AppError::from)?;
                    }

                    let sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                    inserted.push(
                        sql_query(sql)
                            .bind::<Text, _>(id)
                            .get_result::<UserRecord>(conn)
                            .map_err(AppError::from)?,
                    );
                }
                Ok(inserted)
            })
        })
    }

    pub async fn insert_registered_user(
        &self,
        user: NewUser,
        expected_first_user: bool,
        verification_claims: Vec<VerificationCodeClaim>,
    ) -> AppResult<UserRecord> {
        if !verification_claims.is_empty() {
            self.verify_verification_claims(verification_claims.clone())
                .await?;
        }

        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let identity = UserIdentityCandidate::insert(&user);
        with_conn!(self, |conn, kind| {
            conn.transaction::<UserRecord, AppError, _>(|conn| {
                ensure_first_user_registration_still_first!(conn, expected_first_user)?;
                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "user email or username already exists"
                )?;

                let mut verification_code_ids = Vec::with_capacity(verification_claims.len());
                for claim in &verification_claims {
                    let code_hash = util::token_hash(&claim.code);
                    let record = latest_verification_code!(conn, kind, claim).ok_or_else(|| {
                        AppError::BadRequest("verification code is missing".to_string())
                    })?;
                    match record.verify_hash(&code_hash, now)? {
                        VerificationCodeDecision::Accepted(id) => verification_code_ids.push(id),
                        VerificationCodeDecision::RejectedAttempt(_) => {
                            return Err(AppError::BadRequest(
                                "verification code is invalid".to_string(),
                            ));
                        }
                    }
                }

                sql_query(insert_user_sql(kind, UserRegistrationSource::Local))
                    .bind::<Text, _>(&id)
                    .bind::<Text, _>(user.email)
                    .bind::<Text, _>(user.username)
                    .bind::<Nullable<Text>, _>(user.display_name)
                    .bind::<Nullable<Text>, _>(user.phone)
                    .bind::<Text, _>(user.password_hash)
                    .bind::<Nullable<BigInt>, _>(user.email_verified_at)
                    .bind::<Nullable<BigInt>, _>(user.phone_verified_at)
                    .bind::<Integer, _>(i32::from(user.is_admin))
                    .bind::<Integer, _>(i32::from(user.is_active))
                    .bind::<Nullable<BigInt>, _>(user.archived_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                for verification_code_id in &verification_code_ids {
                    let affected =
                        mark_verification_code_consumed!(conn, kind, now, verification_code_id);
                    if affected == 0 {
                        return Err(AppError::BadRequest(
                            "verification code is missing".to_string(),
                        ));
                    }
                }

                let sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn update_user(&self, update: UserUpdate<'_>) -> AppResult<UserRecord> {
        let UserUpdate {
            id,
            email,
            username,
            display_name,
            phone,
            is_admin,
            is_active,
        } = update;
        let id = id.to_string();
        let now = util::now_ts();
        let identity = UserIdentityCandidate::update(&id, email.clone(), username.clone());
        with_conn!(self, |conn, kind| {
            conn.transaction::<UserRecord, AppError, _>(|conn| {
                let current_sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                let current = sql_query(current_sql)
                    .bind::<Text, _>(&id)
                    .get_result::<UserRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::NotFound)?;
                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "user email or username already exists"
                )?;
                if !is_active {
                    clear_user_auth_state_for_conn!(conn, kind, &id)?;
                }
                let email_changed = current.email != email;
                let phone_changed = current.phone != phone;
                if !is_active {
                    clear_user_application_identity_bindings_for_conn!(conn, kind, &id)?;
                } else {
                    if email_changed {
                        clear_user_application_identity_factor_bindings_for_conn!(
                            conn,
                            kind,
                            &id,
                            crate::applications::FACTOR_EMAIL
                        )?;
                    }
                    if phone_changed {
                        clear_user_application_identity_factor_bindings_for_conn!(
                            conn,
                            kind,
                            &id,
                            crate::applications::FACTOR_PHONE
                        )?;
                    }
                }
                let sql = format!(
                    "UPDATE users SET email = {}, username = {}, display_name = {}, phone = {}, email_verified_at = {}, phone_verified_at = {}, is_admin = {}, is_active = {}, updated_at = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9),
                    ph(kind, 10)
                );
                sql_query(sql)
                    .bind::<Text, _>(&email)
                    .bind::<Text, _>(&username)
                    .bind::<Nullable<Text>, _>(display_name)
                    .bind::<Nullable<Text>, _>(&phone)
                    .bind::<Nullable<BigInt>, _>(
                        (!email_changed).then_some(current.email_verified_at).flatten(),
                    )
                    .bind::<Nullable<BigInt>, _>(
                        (!phone_changed).then_some(current.phone_verified_at).flatten(),
                    )
                    .bind::<Integer, _>(i32::from(is_admin))
                    .bind::<Integer, _>(i32::from(is_active))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }
}
