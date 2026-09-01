use super::*;

pub(crate) async fn organization_response(
    state: &AppState,
    organization: OrganizationRecord,
) -> AppResult<OrganizationResponse> {
    let member_count = state
        .db
        .count_organization_members(&organization.id)
        .await?;
    organization_response_with_member_count(organization, member_count)
}

pub(crate) fn organization_response_with_member_count(
    organization: OrganizationRecord,
    member_count: i64,
) -> AppResult<OrganizationResponse> {
    Ok(OrganizationResponse {
        id: organization.id,
        slug: organization.slug,
        name: organization.name,
        kind: organization.kind,
        description: organization.description,
        allowed_email_domains: security_policy::normalize_email_domain_rules(util::from_json::<
            Vec<String>,
        >(
            &organization.allowed_email_domains,
        )?)?,
        is_active: organization.is_active == 1,
        member_count,
        created_at: organization.created_at,
        updated_at: organization.updated_at,
    })
}

pub(crate) fn organization_member_response(
    member: OrganizationMemberWithUserRecord,
) -> OrganizationMemberResponse {
    OrganizationMemberResponse {
        organization_id: member.organization_id,
        user_id: member.user_id,
        role: member.role,
        email: member.email,
        username: member.username,
        display_name: member.display_name,
        is_active: member.is_active == 1,
        archived_at: member.archived_at,
        created_at: member.membership_created_at,
        updated_at: member.membership_updated_at,
    }
}

pub(crate) fn organization_input_to_new(input: OrganizationInput) -> AppResult<NewOrganization> {
    Ok(NewOrganization {
        slug: organizations::normalize_slug(&input.slug)?,
        name: organizations::normalize_name(&input.name)?,
        kind: organizations::ORGANIZATION_KIND_TENANT.to_string(),
        description: normalize_optional_text(input.description),
        allowed_email_domains: security_policy::normalize_email_domain_rules(
            input.allowed_email_domains,
        )?,
        is_active: input.is_active,
    })
}

pub(crate) async fn organization_members_input(
    state: &AppState,
    input: OrganizationMembersInput,
) -> AppResult<Vec<OrganizationMemberInput>> {
    let mut email_selectors = Vec::new();
    for member in &input.members {
        if member
            .user_id
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
            && let Some(email) = member
                .email
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
        {
            email_selectors.push(email.to_string());
        }
    }
    let user_ids_by_email = state.db.find_user_ids_by_emails(&email_selectors).await?;
    let mut members = Vec::with_capacity(input.members.len());
    for member in input.members {
        let user_id = member.user_id.unwrap_or_default().trim().to_string();
        let email = member.email.unwrap_or_default().trim().to_string();
        let user_id = match (user_id.is_empty(), email.is_empty()) {
            (false, true) => user_id,
            (true, false) => user_ids_by_email.get(&email).cloned().ok_or_else(|| {
                AppError::BadRequest("no account found for member email".to_string())
            })?,
            _ => {
                return Err(AppError::BadRequest(
                    "organization member must provide exactly one of user_id or email".to_string(),
                ));
            }
        };
        members.push(OrganizationMemberInput {
            user_id,
            role: organizations::normalize_role(&member.role)?,
        });
    }
    Ok(members)
}

pub(crate) async fn list_organizations(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<OrganizationResponse>>> {
    require_organization_reader(&state, &jar).await?;
    let (member_counts, organizations) = tokio::try_join!(
        state.db.list_organization_member_counts(),
        state.db.list_organizations(),
    )?;
    let mut response = Vec::new();
    for organization in organizations {
        let member_count = member_counts
            .get(&organization.id)
            .copied()
            .unwrap_or_default();
        response.push(organization_response_with_member_count(
            organization,
            member_count,
        )?);
    }
    Ok(Json(response))
}

pub(crate) async fn list_organization_options(
    State(state): State<AppState>,
    jar: CookieJar,
) -> AppResult<Json<Vec<OrganizationOptionResponse>>> {
    require_organization_option_reader(&state, &jar).await?;
    Ok(Json(
        state
            .db
            .list_organizations()
            .await?
            .into_iter()
            .map(|organization| OrganizationOptionResponse {
                id: organization.id,
                slug: organization.slug,
                name: organization.name,
                kind: organization.kind,
                is_active: organization.is_active == 1,
            })
            .collect(),
    ))
}

pub(crate) async fn create_organization(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(payload): Json<OrganizationInput>,
) -> AppResult<Json<OrganizationResponse>> {
    let current = require_organization_manager(&state, &jar).await?;
    let organization_input = organization_input_to_new(payload)?;
    let organization = state
        .db
        .insert_organization_with_audit(
            organization_input.clone(),
            audit::management_event(
                current.user.id,
                "organization.create",
                "organization",
                None,
                serde_json::json!({
                    "slug": organization_input.slug,
                    "name": organization_input.name
                }),
            ),
        )
        .await?;
    Ok(Json(organization_response(&state, organization).await?))
}

pub(crate) async fn update_organization(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<OrganizationInput>,
) -> AppResult<Json<OrganizationResponse>> {
    let current = require_organization_manager(&state, &jar).await?;
    let organization_input = organization_input_to_new(payload)?;
    let organization = state
        .db
        .update_organization_with_audit(
            &id,
            organization_input.clone(),
            audit::management_event(
                current.user.id,
                "organization.update",
                "organization",
                Some(id.clone()),
                serde_json::json!({
                    "slug": organization_input.slug,
                    "name": organization_input.name
                }),
            ),
        )
        .await?;
    Ok(Json(organization_response(&state, organization).await?))
}

pub(crate) async fn delete_organization(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let current = require_organization_manager(&state, &jar).await?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    state
        .db
        .delete_organization_with_audit(
            &id,
            audit::management_event(
                current.user.id,
                "organization.delete",
                "organization",
                Some(id.clone()),
                serde_json::json!({ "slug": organization.slug, "name": organization.name }),
            ),
        )
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub(crate) async fn list_organization_members(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<OrganizationMemberResponse>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    Ok(Json(
        state
            .db
            .list_organization_members(&id)
            .await?
            .into_iter()
            .map(organization_member_response)
            .collect(),
    ))
}

/// Adds a known Signet account to one enterprise without exposing the global
/// user directory. Tenant administrators may use an email address; platform
/// administrators can retain the stable-ID workflow used by the old console.
pub(crate) async fn upsert_organization_member(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<OrganizationMemberPayload>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    let member = organization_members_input(
        &state,
        OrganizationMembersInput {
            members: vec![payload],
        },
    )
    .await?
    .pop()
    .ok_or_else(|| AppError::BadRequest("organization member is required".to_string()))?;
    ensure_assignable_user_ids(
        &state,
        &BTreeSet::from([member.user_id.clone()]),
        &BTreeSet::new(),
        "organizations",
    )
    .await?;
    state
        .db
        .upsert_organization_member(&id, &member.user_id, &member.role)
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.member.upsert",
            "organization",
            Some(id),
            serde_json::json!({ "user_id": member.user_id, "role": member.role }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Creates a one-time registration capability for a specific email address.
/// Unlike application trial enrollment, this produces a normal Signet account
/// and grants it membership in the enterprise on successful registration.
/// Existing accounts continue to be added through the member-by-email action.
pub(crate) async fn list_organization_member_invitations(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<PublicInvitation>>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    Ok(Json(
        state
            .db
            .list_organization_registration_invitations(&organization.id)
            .await?
            .into_iter()
            .map(InvitationRecord::public)
            .collect::<AppResult<Vec<_>>>()?,
    ))
}

pub(crate) async fn create_organization_member_invitation(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<OrganizationMemberInvitationInput>,
) -> AppResult<Json<OrganizationMemberInvitationCreateResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    if organization.is_active != 1 {
        return Err(AppError::BadRequest(
            "cannot invite members to a disabled organization".to_string(),
        ));
    }
    if payload.expires_at <= util::now_ts() {
        return Err(AppError::BadRequest(
            "organization member invitations require a future expiry".to_string(),
        ));
    }
    let email = normalize_optional_email(Some(payload.email))?.ok_or_else(|| {
        AppError::BadRequest("organization member invitation email is required".to_string())
    })?;
    if !organization.allows_email(&email)? {
        return Err(AppError::BadRequest(
            "email is not allowed by the organization policy".to_string(),
        ));
    }
    let organization_role = organizations::normalize_role(&payload.organization_role)?;
    let code = format!("ORG-{}", util::random_token(18));
    let signing_key = state
        .db
        .list_signing_keys()
        .await?
        .into_iter()
        .find(|key| key.is_active == 1)
        .ok_or_else(|| {
            AppError::Configuration(
                "an active signing key is required to create a revealable organization invitation"
                    .to_string(),
            )
        })?;
    let ciphertext =
        util::encrypt_authorization_code_for_reveal(&signing_key.private_key_pem, &code)?;
    let (invitation, code) = state
        .db
        .insert_invitation_with_reveal_secret(
            NewInvitation {
                code_type: AuthorizationCodeType::Registration,
                login_code_level: LoginCodeLevel::AccountRecovery,
                allowed_client_ids: Vec::new(),
                organization_id: Some(organization.id.clone()),
                organization_role: Some(organization_role.clone()),
                description: normalize_optional_text(payload.description),
                authorized_email: Some(email.clone()),
                authorized_username: None,
                authorized_user_id: None,
                authorized_display_name: normalize_optional_text(payload.display_name),
                expires_at: Some(payload.expires_at),
                max_uses: Some(1),
                is_active: payload.is_active,
                created_by: Some(current.user.id.clone()),
            },
            code,
            signing_key.kid,
            ciphertext,
        )
        .await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.member_invitation.create",
            "organization",
            Some(organization.id.clone()),
            serde_json::json!({
                "invitation_id": invitation.id,
                "email": email,
                "organization_role": organization_role,
            }),
        ))
        .await?;
    Ok(Json(OrganizationMemberInvitationCreateResponse {
        invitation: invitation.public()?,
        code,
    }))
}

pub(crate) async fn delete_organization_member_invitation(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((id, invitation_id)): Path<(String, String)>,
) -> AppResult<Json<serde_json::Value>> {
    let current = auth::require_current_user(&state, &jar).await?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    if !state
        .db
        .organization_registration_invitation_belongs_to(&organization.id, &invitation_id)
        .await?
    {
        return Err(AppError::NotFound);
    }
    state.db.delete_invitation(&invitation_id).await?;
    state
        .db
        .record_audit_event(audit::management_event(
            current.user.id,
            "organization.member_invitation.delete",
            "organization",
            Some(organization.id),
            serde_json::json!({ "invitation_id": invitation_id }),
        ))
        .await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

pub(crate) async fn update_organization_members(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<String>,
    Json(payload): Json<OrganizationMembersInput>,
) -> AppResult<Json<OrganizationResponse>> {
    let current = auth::require_current_user(&state, &jar).await?;
    auth::ensure_current_account_mutable(&current)?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    require_organization_manager_for(&state, &current, &organization.id).await?;
    // Signet is the platform-control tenant. Its roster may be managed only
    // by a global organization administrator, never merely by a membership
    // role within the system tenant.
    // Resolve email selectors only after the organization boundary and
    // manager permission have been established. This prevents an unauthorized
    // caller from using "unknown member email" as an account-existence oracle.
    let members = organization_members_input(&state, payload).await?;
    ensure_organization_members_editable(&state, &id, &members).await?;
    state
        .db
        .replace_organization_members_with_audit(
            &id,
            members.clone(),
            audit::management_event(
                current.user.id,
                "organization.members.update",
                "organization",
                Some(id.clone()),
                serde_json::json!({
                    "members": members
                        .iter()
                        .map(|member| serde_json::json!({
                            "user_id": member.user_id,
                            "role": member.role
                        }))
                        .collect::<Vec<_>>()
                }),
            ),
        )
        .await?;
    let organization = state
        .db
        .find_organization_by_id(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(organization_response(&state, organization).await?))
}
