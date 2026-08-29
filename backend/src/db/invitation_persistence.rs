use super::{
    AccountRecoveryCodeRedemption, AdminLoginCodeRedemptionInput, AppError, AppResult,
    ApplicationRecord, AuthorizationCodeType, CountRow, DatabaseKind, Db, InvitationRecord,
    InvitationRedemptionRecord, InvitationUpdate, LoginCodeLevel, NewInvitation,
    NewTrialEnrollmentUser, NewUser, OidcLoginGrantRecord, OidcLoginGrantRedemption,
    OrganizationRecord, TrialEnrollmentCodeRedemption, TrialEnrollmentRecord,
    UserIdentityCandidate, UserRecord, UserRegistrationSource, VerificationCodeClaim,
    VerificationCodeDecision, VerificationCodeRecord, VerificationCodeVerifier, blocking,
    count_user_identity_conflicts_sql, ensure_invitation_redeemable, insert_user_sql, ph,
    redeem_account_recovery_invitation_update_sql, redeem_invitation_update_sql,
    redeem_trial_enrollment_invitation_update_sql, select_application_sql, select_invitation_sql,
    select_organization_sql, select_trial_enrollment_sql, select_user_sql,
};
use crate::{organizations::OrganizationEmailPolicy, util};
use diesel::{
    Connection, OptionalExtension, RunQueryDsl, sql_query,
    sql_types::{BigInt, Integer, Nullable, Text},
};
impl Db {
    pub async fn list_invitations(&self) -> AppResult<Vec<InvitationRecord>> {
        with_conn!(self, |conn, _kind| {
            let sql = format!("{} ORDER BY created_at DESC", select_invitation_sql());
            sql_query(sql)
                .load::<InvitationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn find_invitation_by_id(&self, id: &str) -> AppResult<Option<InvitationRecord>> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!("{} WHERE id = {}", select_invitation_sql(), ph(kind, 1));
            sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<InvitationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn list_invitation_redemptions(&self) -> AppResult<Vec<InvitationRedemptionRecord>> {
        with_conn!(self, |conn, _kind| {
            sql_query(
                "SELECT invitation_redemptions.id, invitation_redemptions.invitation_id, invitation_redemptions.user_id, users.email AS user_email, users.username AS user_username, invitation_redemptions.redeemed_at FROM invitation_redemptions LEFT JOIN users ON users.id = invitation_redemptions.user_id ORDER BY invitation_redemptions.redeemed_at DESC",
            )
            .load::<InvitationRedemptionRecord>(&mut conn)
            .map_err(AppError::from)
        })
    }

    /// Lists one bounded, keyset-paginated page of redemptions for a single
    /// authorization code.  Keeping this separate from `list_invitations`
    /// prevents a frequently-used code from making the management list grow
    /// without bound.
    pub async fn list_invitation_redemptions_for_invitation(
        &self,
        invitation_id: &str,
        before: Option<(i64, String)>,
        limit: i32,
    ) -> AppResult<Vec<InvitationRedemptionRecord>> {
        let invitation_id = invitation_id.to_string();
        with_conn!(self, |conn, kind| {
            if let Some((redeemed_at, redemption_id)) = before {
                let sql = format!(
                    "SELECT invitation_redemptions.id, invitation_redemptions.invitation_id, invitation_redemptions.user_id, users.email AS user_email, users.username AS user_username, invitation_redemptions.redeemed_at FROM invitation_redemptions LEFT JOIN users ON users.id = invitation_redemptions.user_id WHERE invitation_redemptions.invitation_id = {} AND (invitation_redemptions.redeemed_at < {} OR (invitation_redemptions.redeemed_at = {} AND invitation_redemptions.id < {})) ORDER BY invitation_redemptions.redeemed_at DESC, invitation_redemptions.id DESC LIMIT {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                );
                sql_query(sql)
                    .bind::<Text, _>(invitation_id)
                    .bind::<BigInt, _>(redeemed_at)
                    .bind::<BigInt, _>(redeemed_at)
                    .bind::<Text, _>(redemption_id)
                    .bind::<Integer, _>(limit)
                    .load::<InvitationRedemptionRecord>(&mut conn)
                    .map_err(AppError::from)
            } else {
                let sql = format!(
                    "SELECT invitation_redemptions.id, invitation_redemptions.invitation_id, invitation_redemptions.user_id, users.email AS user_email, users.username AS user_username, invitation_redemptions.redeemed_at FROM invitation_redemptions LEFT JOIN users ON users.id = invitation_redemptions.user_id WHERE invitation_redemptions.invitation_id = {} ORDER BY invitation_redemptions.redeemed_at DESC, invitation_redemptions.id DESC LIMIT {}",
                    ph(kind, 1),
                    ph(kind, 2),
                );
                sql_query(sql)
                    .bind::<Text, _>(invitation_id)
                    .bind::<Integer, _>(limit)
                    .load::<InvitationRedemptionRecord>(&mut conn)
                    .map_err(AppError::from)
            }
        })
    }

    pub async fn insert_invitation(
        &self,
        invitation: NewInvitation,
    ) -> AppResult<(InvitationRecord, String)> {
        let code = format!(
            "{}-{}",
            match invitation.code_type {
                AuthorizationCodeType::Registration => "REG",
                AuthorizationCodeType::Login => "LOGIN",
            },
            util::random_token(18)
        );
        self.insert_invitation_with_secret(invitation, code, None, None)
            .await
    }

    /// Inserts a code whose complete value can later be revealed to an
    /// authorized manager.  The caller supplies an encrypted form produced by
    /// the server; neither the plaintext code nor its ciphertext is included
    /// in public invitation responses.
    pub async fn insert_invitation_with_reveal_secret(
        &self,
        invitation: NewInvitation,
        code: String,
        code_reveal_key_id: String,
        code_reveal_ciphertext: String,
    ) -> AppResult<(InvitationRecord, String)> {
        self.insert_invitation_with_secret(
            invitation,
            code,
            Some(code_reveal_key_id),
            Some(code_reveal_ciphertext),
        )
        .await
    }

    async fn insert_invitation_with_secret(
        &self,
        invitation: NewInvitation,
        code: String,
        code_reveal_key_id: Option<String>,
        code_reveal_ciphertext: Option<String>,
    ) -> AppResult<(InvitationRecord, String)> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        let code_hash = util::token_hash(&code);
        let code_prefix = code.chars().take(12).collect::<String>();
        let allowed_client_ids = util::to_json(&invitation.allowed_client_ids)?;
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "INSERT INTO invitations (id, code_hash, code_prefix, code_reveal_key_id, code_reveal_ciphertext, code_type, login_code_level, allowed_client_ids, organization_id, organization_role, description, authorized_email, authorized_username, authorized_user_id, authorized_display_name, expires_at, max_uses, uses_count, is_active, created_by, created_at, updated_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3),
                ph(kind, 4),
                ph(kind, 5),
                ph(kind, 6),
                ph(kind, 7),
                ph(kind, 8),
                ph(kind, 9),
                ph(kind, 10),
                ph(kind, 11),
                ph(kind, 12),
                ph(kind, 13),
                ph(kind, 14),
                ph(kind, 15),
                ph(kind, 16),
                ph(kind, 17),
                ph(kind, 18),
                ph(kind, 19),
                ph(kind, 20),
                ph(kind, 21),
                ph(kind, 22)
            );
            sql_query(sql)
                .bind::<Text, _>(&id)
                .bind::<Text, _>(code_hash)
                .bind::<Text, _>(code_prefix)
                .bind::<Nullable<Text>, _>(code_reveal_key_id)
                .bind::<Nullable<Text>, _>(code_reveal_ciphertext)
                .bind::<Text, _>(invitation.code_type.as_str())
                .bind::<Text, _>(invitation.login_code_level.as_str())
                .bind::<Nullable<Text>, _>(Some(allowed_client_ids))
                .bind::<Nullable<Text>, _>(invitation.organization_id)
                .bind::<Nullable<Text>, _>(invitation.organization_role)
                .bind::<Nullable<Text>, _>(invitation.description)
                .bind::<Nullable<Text>, _>(invitation.authorized_email)
                .bind::<Nullable<Text>, _>(invitation.authorized_username)
                .bind::<Nullable<Text>, _>(invitation.authorized_user_id)
                .bind::<Nullable<Text>, _>(invitation.authorized_display_name)
                .bind::<Nullable<BigInt>, _>(invitation.expires_at)
                .bind::<Nullable<Integer>, _>(invitation.max_uses)
                .bind::<Integer, _>(0)
                .bind::<Integer, _>(i32::from(invitation.is_active))
                .bind::<Nullable<Text>, _>(invitation.created_by)
                .bind::<BigInt, _>(now)
                .bind::<BigInt, _>(now)
                .execute(&mut conn)
                .map_err(AppError::from)?;
            let sql = format!("{} WHERE id = {}", select_invitation_sql(), ph(kind, 1));
            let record = sql_query(sql)
                .bind::<Text, _>(id)
                .get_result::<InvitationRecord>(&mut conn)
                .map_err(AppError::from)?;
            Ok((record, code))
        })
    }

    pub async fn update_invitation(
        &self,
        update: InvitationUpdate<'_>,
    ) -> AppResult<InvitationRecord> {
        let InvitationUpdate {
            id,
            description,
            authorized_email,
            authorized_username,
            authorized_display_name,
            expires_at,
            max_uses,
            is_active,
        } = update;
        let id = id.to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<InvitationRecord, AppError, _>(|conn| {
                let sql = format!(
                    "UPDATE invitations SET description = {}, authorized_email = {}, authorized_username = {}, authorized_display_name = {}, expires_at = {}, max_uses = {}, is_active = {}, updated_at = {} WHERE id = {}",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9)
                );
                sql_query(sql)
                    .bind::<Nullable<Text>, _>(description)
                    .bind::<Nullable<Text>, _>(authorized_email)
                    .bind::<Nullable<Text>, _>(authorized_username)
                    .bind::<Nullable<Text>, _>(authorized_display_name)
                    .bind::<Nullable<BigInt>, _>(expires_at)
                    .bind::<Nullable<Integer>, _>(max_uses)
                    .bind::<Integer, _>(i32::from(is_active))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if !is_active {
                    let revoke_sql = format!(
                        "DELETE FROM oidc_login_grants WHERE invitation_id = {}",
                        ph(kind, 1)
                    );
                    sql_query(revoke_sql)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                    revoke_trial_enrollment_auth_state_for_invitation!(conn, kind, &id);
                    let revoke_trial_sql = format!(
                        "UPDATE trial_enrollments SET revoked_at = {} WHERE invitation_id = {} AND revoked_at IS NULL",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    sql_query(revoke_trial_sql)
                        .bind::<BigInt, _>(now)
                        .bind::<Text, _>(&id)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }
                let sql = format!("{} WHERE id = {}", select_invitation_sql(), ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .get_result::<InvitationRecord>(conn)
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn delete_invitation(&self, id: &str) -> AppResult<()> {
        let id = id.to_string();
        with_conn!(self, |conn, kind| {
            conn.transaction::<(), AppError, _>(|conn| {
                let mapping_sql = format!(
                    "DELETE FROM application_enrollment_codes WHERE invitation_id = {}",
                    ph(kind, 1)
                );
                sql_query(mapping_sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!(
                    "DELETE FROM oidc_login_grants WHERE invitation_id = {}",
                    ph(kind, 1)
                );
                sql_query(sql)
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                revoke_trial_enrollment_auth_state_for_invitation!(conn, kind, &id);
                let revoke_trial_sql = format!(
                    "UPDATE trial_enrollments SET revoked_at = {} WHERE invitation_id = {} AND revoked_at IS NULL",
                    ph(kind, 1),
                    ph(kind, 2)
                );
                sql_query(revoke_trial_sql)
                    .bind::<BigInt, _>(util::now_ts())
                    .bind::<Text, _>(&id)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let sql = format!("DELETE FROM invitations WHERE id = {}", ph(kind, 1));
                sql_query(sql)
                    .bind::<Text, _>(id)
                    .execute(conn)
                    .map(|_| ())
                    .map_err(AppError::from)
            })
        })
    }

    pub async fn find_invitation_by_code(&self, code: &str) -> AppResult<InvitationRecord> {
        let code_hash = util::token_hash(code);
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE code_hash = {}",
                select_invitation_sql(),
                ph(kind, 1)
            );
            let record = sql_query(sql)
                .bind::<Text, _>(code_hash)
                .get_result::<InvitationRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)?
                .ok_or_else(|| AppError::BadRequest("authorization code is invalid".to_string()))?;
            ensure_invitation_redeemable(&record, now)?;
            Ok(record)
        })
    }

    /// Lists the normal-account invitations owned by one enterprise. Trial
    /// application enrollment codes deliberately use a separate mapping and
    /// remain visible only from their application editor.
    pub async fn list_organization_registration_invitations(
        &self,
        organization_id: &str,
    ) -> AppResult<Vec<InvitationRecord>> {
        let organization_id = organization_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE organization_id = {} AND code_type = {} ORDER BY created_at DESC",
                select_invitation_sql(),
                ph(kind, 1),
                ph(kind, 2)
            );
            sql_query(sql)
                .bind::<Text, _>(organization_id)
                .bind::<Text, _>(AuthorizationCodeType::Registration.as_str())
                .load::<InvitationRecord>(&mut conn)
                .map_err(AppError::from)
        })
    }

    pub async fn organization_registration_invitation_belongs_to(
        &self,
        organization_id: &str,
        invitation_id: &str,
    ) -> AppResult<bool> {
        let organization_id = organization_id.to_string();
        let invitation_id = invitation_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM invitations WHERE id = {} AND organization_id = {} AND code_type = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(invitation_id)
                .bind::<Text, _>(organization_id)
                .bind::<Text, _>(AuthorizationCodeType::Registration.as_str())
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count > 0)
                .map_err(AppError::from)
        })
    }

    pub async fn redeem_registration_code_for_new_user(
        &self,
        code: &str,
        user: NewUser,
        verification_claims: Vec<VerificationCodeClaim>,
    ) -> AppResult<UserRecord> {
        if !verification_claims.is_empty() {
            self.verify_verification_claims(verification_claims.clone())
                .await?;
        }

        let user_id = uuid::Uuid::new_v4().to_string();
        let redemption_id = uuid::Uuid::new_v4().to_string();
        let code_hash = util::token_hash(code);
        let now = util::now_ts();
        let identity = UserIdentityCandidate::insert(&user);
        with_conn!(self, |conn, kind| {
            conn.transaction::<UserRecord, AppError, _>(|conn| {
                let invitation_sql = format!(
                    "{} WHERE code_hash = {}",
                    select_invitation_sql(),
                    ph(kind, 1)
                );
                let invitation = sql_query(invitation_sql)
                    .bind::<Text, _>(&code_hash)
                    .get_result::<InvitationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or_else(|| {
                        AppError::BadRequest("registration authorization code is invalid".to_string())
                    })?;
                if invitation.authorization_code_type()?
                    != AuthorizationCodeType::Registration
                {
                    return Err(AppError::BadRequest(
                        "authorization code cannot be used for registration".to_string(),
                    ));
                }
                ensure_invitation_redeemable(&invitation, now)?;
                if invitation
                    .authorized_email
                    .as_deref()
                    .is_some_and(|value| value != user.email.as_str())
                    || invitation
                        .authorized_username
                        .as_deref()
                        .is_some_and(|value| value != user.username.as_str())
                {
                    return Err(AppError::BadRequest(
                        "registration details do not match the authorization code".to_string(),
                    ));
                }
                let organization_membership = match (
                    invitation
                        .organization_id
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty()),
                    invitation
                        .organization_role
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty()),
                ) {
                    (None, None) => None,
                    (Some(organization_id), Some(role)) => {
                        let role = crate::organizations::normalize_role(role).map_err(|_| {
                            AppError::BadRequest(
                                "registration authorization code has an invalid organization role"
                                    .to_string(),
                            )
                        })?;
                        let organization_sql = format!(
                            "{} WHERE id = {}",
                            select_organization_sql(),
                            ph(kind, 1)
                        );
                        let organization = sql_query(organization_sql)
                            .bind::<Text, _>(organization_id)
                            .get_result::<OrganizationRecord>(conn)
                            .optional()
                            .map_err(AppError::from)?
                            .filter(|organization| organization.is_active == 1)
                            .ok_or_else(|| {
                                AppError::BadRequest(
                                    "registration authorization code organization is unavailable"
                                        .to_string(),
                                )
                            })?;
                        if !organization.allows_email(&user.email)? {
                            return Err(AppError::BadRequest(
                                "email is not allowed by the organization policy".to_string(),
                            ));
                        }
                        Some((organization.id, role))
                    }
                    _ => {
                        return Err(AppError::BadRequest(
                            "registration authorization code has incomplete organization metadata"
                                .to_string(),
                        ));
                    }
                };
                // A normal application enrollment code is still a standard
                // registration invitation: it creates a reusable Signet
                // account and enterprise membership. The mapping adds the
                // app-specific admission edge, and must be checked in this
                // redemption transaction so a disabled or reconfigured app
                // cannot be entered through a previously-issued code.
                let enrollment_application = {
                    let sql = format!(
                        "{} WHERE id IN (SELECT application_id FROM application_enrollment_codes WHERE invitation_id = {})",
                        select_application_sql(),
                        ph(kind, 1)
                    );
                    sql_query(sql)
                        .bind::<Text, _>(&invitation.id)
                        .get_result::<ApplicationRecord>(conn)
                        .optional()
                        .map_err(AppError::from)?
                };
                if let Some(application) = enrollment_application {
                    if application.is_active != 1
                        || application.registration_mode
                            != crate::applications::REGISTRATION_INVITATION
                    {
                        return Err(AppError::BadRequest(
                            "application enrollment is no longer available".to_string(),
                        ));
                    }
                    if organization_membership
                        .as_ref()
                        .is_none_or(|(organization_id, _)| {
                            organization_id != &application.organization_id
                        })
                    {
                        return Err(AppError::BadRequest(
                            "application enrollment code organization is unavailable".to_string(),
                        ));
                    }
                }
                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "registration authorization code cannot be used for an existing account"
                )?;

                let mut verification_code_ids = Vec::with_capacity(verification_claims.len());
                for claim in &verification_claims {
                    let verification_hash = util::token_hash(&claim.code);
                    let record = latest_verification_code!(conn, kind, claim).ok_or_else(|| {
                        AppError::BadRequest("verification code is missing".to_string())
                    })?;
                    match record.verify_hash(&verification_hash, now)? {
                        VerificationCodeDecision::Accepted(id) => verification_code_ids.push(id),
                        VerificationCodeDecision::RejectedAttempt(_) => {
                            return Err(AppError::BadRequest(
                                "verification code is invalid".to_string(),
                            ));
                        }
                    }
                }

                let update_sql = redeem_invitation_update_sql(kind);
                let affected = sql_query(update_sql)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(AuthorizationCodeType::Registration.as_str())
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::BadRequest(
                        "registration authorization code is exhausted or no longer valid"
                            .to_string(),
                    ));
                }

                sql_query(insert_user_sql(
                    kind,
                    UserRegistrationSource::AuthorizationCode,
                ))
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&user.email)
                    .bind::<Text, _>(&user.username)
                    .bind::<Nullable<Text>, _>(user.display_name.clone())
                    .bind::<Nullable<Text>, _>(user.phone.clone())
                    .bind::<Text, _>(&user.password_hash)
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

                if let Some((organization_id, role)) = organization_membership {
                    let membership_sql = format!(
                        "INSERT INTO organization_members (organization_id, user_id, role, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                        ph(kind, 1),
                        ph(kind, 2),
                        ph(kind, 3),
                        ph(kind, 4),
                        ph(kind, 5)
                    );
                    sql_query(membership_sql)
                        .bind::<Text, _>(organization_id)
                        .bind::<Text, _>(&user_id)
                        .bind::<Text, _>(role)
                        .bind::<BigInt, _>(now)
                        .bind::<BigInt, _>(now)
                        .execute(conn)
                        .map_err(AppError::from)?;
                }

                for verification_code_id in &verification_code_ids {
                    let affected =
                        mark_verification_code_consumed!(conn, kind, now, verification_code_id);
                    if affected == 0 {
                        return Err(AppError::BadRequest(
                            "verification code is missing".to_string(),
                        ));
                    }
                }

                let select_user_sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                let user = sql_query(select_user_sql)
                    .bind::<Text, _>(&user_id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)?;

                let insert_redemption_sql = format!(
                    "INSERT INTO invitation_redemptions (id, invitation_id, user_id, redeemed_at) VALUES ({}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(insert_redemption_sql)
                    .bind::<Text, _>(redemption_id)
                    .bind::<Text, _>(invitation.id)
                    .bind::<Text, _>(&user_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                Ok(user)
            })
        })
    }

    /// Atomically turns an active trial-enrollment code into one brand-new,
    /// restricted account.  Existing identities are never selected or reused:
    /// the code is an enrollment capability, not proof of ownership of an
    /// account name or email address.
    pub async fn redeem_trial_enrollment_code_for_new_user(
        &self,
        code: &str,
        user: NewTrialEnrollmentUser,
    ) -> AppResult<TrialEnrollmentCodeRedemption> {
        let user_id = uuid::Uuid::new_v4().to_string();
        let redemption_id = uuid::Uuid::new_v4().to_string();
        let code_hash = util::token_hash(code);
        let now = util::now_ts();
        let identity = UserIdentityCandidate {
            email: user.email.clone(),
            username: user.username.clone(),
            exclude_user_id: None,
        };
        with_conn!(self, |conn, kind| {
            conn.transaction::<TrialEnrollmentCodeRedemption, AppError, _>(|conn| {
                let invitation_sql = format!(
                    "{} WHERE code_hash = {}",
                    select_invitation_sql(),
                    ph(kind, 1)
                );
                let invitation = sql_query(invitation_sql)
                    .bind::<Text, _>(&code_hash)
                    .get_result::<InvitationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                if invitation.authorization_code_type()? != AuthorizationCodeType::Login
                    || invitation.login_code_level()? != LoginCodeLevel::TrialEnrollment
                    || ensure_invitation_redeemable(&invitation, now).is_err()
                    || invitation.expires_at.is_some_and(|expires_at| expires_at <= now)
                {
                    return Err(AppError::Unauthorized);
                }

                let organization_id = invitation
                    .organization_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or(AppError::Unauthorized)?
                    .to_string();
                let organization_role = invitation
                    .organization_role
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or(AppError::Unauthorized)?;
                let organization_role = crate::organizations::normalize_role(organization_role)
                    .map_err(|_| AppError::Unauthorized)?;
                let allowed_client_ids = invitation.allowed_client_ids()?;
                if allowed_client_ids.is_empty() {
                    return Err(AppError::Unauthorized);
                }

                // An application-owned enrollment capability follows the
                // application's live policy. A policy change can therefore
                // stop new admissions without invalidating sessions that
                // were already issued to legitimate members.
                let mapping_sql = format!(
                    "SELECT COUNT(*) AS count FROM application_enrollment_codes WHERE invitation_id = {}",
                    ph(kind, 1)
                );
                let application_code_count = sql_query(mapping_sql)
                    .bind::<Text, _>(&invitation.id)
                    .get_result::<CountRow>(conn)
                    .map_err(AppError::from)?
                    .count;
                if application_code_count > 0 {
                    let active_application_sql = format!(
                        "SELECT COUNT(*) AS count FROM application_enrollment_codes INNER JOIN applications ON applications.id = application_enrollment_codes.application_id WHERE application_enrollment_codes.invitation_id = {} AND applications.is_active = 1 AND applications.registration_mode = {}",
                        ph(kind, 1),
                        ph(kind, 2)
                    );
                    if sql_query(active_application_sql)
                        .bind::<Text, _>(&invitation.id)
                        .bind::<Text, _>(crate::applications::REGISTRATION_INVITATION)
                        .get_result::<CountRow>(conn)
                        .map_err(AppError::from)?
                        .count
                        == 0
                    {
                        return Err(AppError::Unauthorized);
                    }
                }

                let organization_sql = format!(
                    "{} WHERE id = {}",
                    select_organization_sql(),
                    ph(kind, 1)
                );
                let organization = sql_query(organization_sql)
                    .bind::<Text, _>(&organization_id)
                    .get_result::<OrganizationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .filter(|organization| organization.is_active == 1)
                    .ok_or(AppError::Unauthorized)?;
                if !organization.allows_email(&user.email)? {
                    return Err(AppError::Unauthorized);
                }

                ensure_user_identity_available!(
                    conn,
                    kind,
                    identity,
                    "trial enrollment authorization code cannot be used for an existing account"
                )?;

                let affected = sql_query(redeem_trial_enrollment_invitation_update_sql(kind))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                    .bind::<Text, _>(LoginCodeLevel::TrialEnrollment.as_str())
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }

                sql_query(insert_user_sql(
                    kind,
                    UserRegistrationSource::AuthorizationCode,
                ))
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&user.email)
                    .bind::<Text, _>(&user.username)
                    .bind::<Nullable<Text>, _>(user.display_name.clone())
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Text, _>(&user.password_hash)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Integer, _>(0)
                    .bind::<Integer, _>(1)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<Nullable<Text>, _>(None::<String>)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let membership_sql = format!(
                    "INSERT INTO organization_members (organization_id, user_id, role, created_at, updated_at) VALUES ({}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5)
                );
                sql_query(membership_sql)
                    .bind::<Text, _>(&organization_id)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&organization_role)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let enrollment_sql = format!(
                    "INSERT INTO trial_enrollments (user_id, invitation_id, organization_id, organization_role, allowed_client_ids, expires_at, revoked_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8)
                );
                sql_query(enrollment_sql)
                    .bind::<Text, _>(&user_id)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(&organization_id)
                    .bind::<Text, _>(&organization_role)
                    .bind::<Text, _>(util::to_json(&allowed_client_ids)?)
                    .bind::<Nullable<BigInt>, _>(invitation.expires_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let redemption_sql = format!(
                    "INSERT INTO invitation_redemptions (id, invitation_id, user_id, redeemed_at) VALUES ({}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(redemption_sql)
                    .bind::<Text, _>(redemption_id)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(&user_id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let user_sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                let user = sql_query(user_sql)
                    .bind::<Text, _>(&user_id)
                    .get_result::<UserRecord>(conn)
                    .map_err(AppError::from)?;
                Ok(TrialEnrollmentCodeRedemption {
                    invitation_id: invitation.id,
                    user,
                    code_expires_at: invitation.expires_at,
                    organization_id,
                })
            })
        })
    }

    pub async fn find_trial_enrollment_for_user(
        &self,
        user_id: &str,
    ) -> AppResult<Option<TrialEnrollmentRecord>> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "{} WHERE user_id = {}",
                select_trial_enrollment_sql(),
                ph(kind, 1)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .get_result::<TrialEnrollmentRecord>(&mut conn)
                .optional()
                .map_err(AppError::from)
        })
    }

    pub async fn find_active_trial_enrollment_for_user(
        &self,
        user_id: &str,
    ) -> AppResult<Option<TrialEnrollmentRecord>> {
        Ok(self
            .find_trial_enrollment_for_user(user_id)
            .await?
            .filter(|enrollment| enrollment.is_active_at(util::now_ts())))
    }

    pub async fn redeem_account_recovery_code(
        &self,
        code: &str,
        user_id: &str,
        email: &str,
    ) -> AppResult<AccountRecoveryCodeRedemption> {
        let code_hash = util::token_hash(code);
        let user_id = user_id.to_string();
        let email = email.to_string();
        let redemption_id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<AccountRecoveryCodeRedemption, AppError, _>(|conn| {
                let invitation_sql = format!(
                    "{} WHERE code_hash = {}",
                    select_invitation_sql(),
                    ph(kind, 1)
                );
                let invitation = sql_query(invitation_sql)
                    .bind::<Text, _>(&code_hash)
                    .get_result::<InvitationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                if invitation.authorization_code_type()?
                    != AuthorizationCodeType::Login
                    || invitation.login_code_level()? != LoginCodeLevel::AccountRecovery
                    || ensure_invitation_redeemable(&invitation, now).is_err()
                {
                    return Err(AppError::Unauthorized);
                }
                let _bound_username = invitation
                    .authorized_username
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or(AppError::Unauthorized)?;
                let authorized_user_id = invitation
                    .authorized_user_id
                    .as_deref()
                    .ok_or(AppError::Unauthorized)?;
                let user_sql = format!("{} WHERE id = {}", select_user_sql(), ph(kind, 1));
                let user = sql_query(user_sql)
                    .bind::<Text, _>(authorized_user_id)
                    .get_result::<UserRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                if user.id != user_id
                    || user.email != email
                    || user.is_active != 1
                    || user.archived_at.is_some()
                {
                    return Err(AppError::Unauthorized);
                }

                let affected = sql_query(redeem_account_recovery_invitation_update_sql(kind))
                    .bind::<Text, _>(&user.id)
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                    .bind::<Text, _>(LoginCodeLevel::AccountRecovery.as_str())
                    .bind::<Text, _>(&user.id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected == 0 {
                    return Err(AppError::Unauthorized);
                }

                let insert_redemption_sql = format!(
                    "INSERT INTO invitation_redemptions (id, invitation_id, user_id, redeemed_at) VALUES ({}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(insert_redemption_sql)
                    .bind::<Text, _>(redemption_id)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(&user.id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                Ok(AccountRecoveryCodeRedemption {
                    invitation_id: invitation.id,
                    user,
                    code_expires_at: invitation.expires_at,
                })
            })
        })
    }

    pub(crate) async fn redeem_admin_login_code_for_oidc_grant(
        &self,
        input: AdminLoginCodeRedemptionInput<'_>,
    ) -> AppResult<OidcLoginGrantRedemption> {
        if input.ttl_seconds <= 0
            || input.trusted_client_id.trim().is_empty()
            || input.interaction_request_hash.trim().is_empty()
            || input.credential_hash.trim().is_empty()
        {
            return Err(AppError::Unauthorized);
        }
        let code_hash = util::token_hash(input.code);
        let user_id = input.user_id.to_string();
        let email = input.email.to_string();
        let trusted_client_id = input.trusted_client_id.to_string();
        let interaction_request_hash = input.interaction_request_hash.to_string();
        let credential_hash = input.credential_hash.to_string();
        let redemption_id = uuid::Uuid::new_v4().to_string();
        let now = util::now_ts();
        with_conn!(self, |conn, kind| {
            conn.transaction::<OidcLoginGrantRedemption, AppError, _>(|conn| {
                let invitation_sql = format!(
                    "{} WHERE code_hash = {}",
                    select_invitation_sql(),
                    ph(kind, 1)
                );
                let invitation = sql_query(invitation_sql)
                    .bind::<Text, _>(&code_hash)
                    .get_result::<InvitationRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .ok_or(AppError::Unauthorized)?;
                if invitation.authorization_code_type()? != AuthorizationCodeType::Login
                    || invitation.login_code_level()? != LoginCodeLevel::AdminUniversal
                    || ensure_invitation_redeemable(&invitation, now).is_err()
                    || !invitation
                        .allowed_client_ids()?
                        .iter()
                        .any(|value| value == &trusted_client_id)
                {
                    return Err(AppError::Unauthorized);
                }

                let user_sql = format!(
                    "{} WHERE id = {}",
                    select_user_sql(),
                    ph(kind, 1)
                );
                let user = sql_query(user_sql)
                    .bind::<Text, _>(&user_id)
                    .get_result::<UserRecord>(conn)
                    .optional()
                    .map_err(AppError::from)?
                    .filter(|user| {
                        user.id == user_id
                            && user.email == email
                            && user.is_active == 1
                            && user.archived_at.is_none()
                    })
                    .ok_or(AppError::Unauthorized)?;

                let affected = sql_query(redeem_invitation_update_sql(kind))
                    .bind::<BigInt, _>(now)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                if affected != 1 {
                    return Err(AppError::Unauthorized);
                }

                let insert_redemption_sql = format!(
                    "INSERT INTO invitation_redemptions (id, invitation_id, user_id, redeemed_at) VALUES ({}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4)
                );
                sql_query(insert_redemption_sql)
                    .bind::<Text, _>(redemption_id)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(&user.id)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;

                let cleanup_sql = format!(
                    "DELETE FROM oidc_login_grants WHERE expires_at < {} OR consumed_at IS NOT NULL",
                    ph(kind, 1)
                );
                sql_query(cleanup_sql)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(AppError::from)?;
                let expires_at = invitation
                    .expires_at
                    .unwrap_or(i64::MAX)
                    .min(now.saturating_add(input.ttl_seconds));
                if expires_at <= now {
                    return Err(AppError::Unauthorized);
                }
                let insert_grant_sql = format!(
                    "INSERT INTO oidc_login_grants (credential_hash, invitation_id, user_id, client_id, interaction_request_hash, auth_time, expires_at, consumed_at, created_at) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
                    ph(kind, 1),
                    ph(kind, 2),
                    ph(kind, 3),
                    ph(kind, 4),
                    ph(kind, 5),
                    ph(kind, 6),
                    ph(kind, 7),
                    ph(kind, 8),
                    ph(kind, 9)
                );
                sql_query(insert_grant_sql)
                    .bind::<Text, _>(&credential_hash)
                    .bind::<Text, _>(&invitation.id)
                    .bind::<Text, _>(&user.id)
                    .bind::<Text, _>(&trusted_client_id)
                    .bind::<Text, _>(&interaction_request_hash)
                    .bind::<BigInt, _>(now)
                    .bind::<BigInt, _>(expires_at)
                    .bind::<Nullable<BigInt>, _>(None::<i64>)
                    .bind::<BigInt, _>(now)
                    .execute(conn)
                    .map_err(|_| AppError::Unauthorized)?;
                let grant = OidcLoginGrantRecord {
                    credential_hash,
                    invitation_id: invitation.id.clone(),
                    user_id: user.id.clone(),
                    client_id: trusted_client_id,
                    interaction_request_hash,
                    auth_time: now,
                    expires_at,
                    consumed_at: None,
                    created_at: now,
                };
                Ok(OidcLoginGrantRedemption {
                    invitation_id: invitation.id,
                    user,
                    grant,
                })
            })
        })
    }

    pub async fn user_has_invitation_redemption(&self, user_id: &str) -> AppResult<bool> {
        let user_id = user_id.to_string();
        with_conn!(self, |conn, kind| {
            let sql = format!(
                "SELECT COUNT(*) AS count FROM invitation_redemptions INNER JOIN invitations ON invitations.id = invitation_redemptions.invitation_id WHERE invitation_redemptions.user_id = {} AND invitations.code_type = {} AND invitations.login_code_level = {}",
                ph(kind, 1),
                ph(kind, 2),
                ph(kind, 3)
            );
            sql_query(sql)
                .bind::<Text, _>(user_id)
                .bind::<Text, _>(AuthorizationCodeType::Login.as_str())
                .bind::<Text, _>(LoginCodeLevel::AccountRecovery.as_str())
                .get_result::<CountRow>(&mut conn)
                .map(|row| row.count > 0)
                .map_err(AppError::from)
        })
    }
}
