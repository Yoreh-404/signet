pub(crate) fn select_application_sql() -> &'static str {
    "SELECT id, organization_id, slug, name, description, access_mode, registration_mode, account_selection_mode, COALESCE(unique_identity_factors, '[]') AS unique_identity_factors, is_active, created_at, updated_at FROM applications"
}

pub(crate) fn select_application_member_sql() -> &'static str {
    "SELECT application_id, user_id, role, is_active, created_at, updated_at FROM application_members"
}

pub(crate) fn select_application_client_binding_sql() -> &'static str {
    "SELECT application_id, client_db_id, protocol, authorization_profile_id, auth_domain_id, is_active, created_at, updated_at FROM application_client_bindings"
}

pub(crate) fn select_application_identity_binding_sql() -> &'static str {
    "SELECT application_id, factor_type, factor_digest, user_id, created_at, updated_at FROM application_identity_bindings"
}

pub(crate) fn select_application_module_sql() -> &'static str {
    "SELECT application_id, module_key, config_json, is_enabled, created_at, updated_at FROM application_modules"
}

pub(crate) fn select_application_authorization_profile_sql() -> &'static str {
    "SELECT id, application_id, profile_key, connection_kind, connection_id, source_mode, remote_version, remote_digest, sync_status, last_synced_at, last_error, created_at, updated_at FROM application_authorization_profiles"
}

pub(crate) fn select_application_discovery_sql() -> &'static str {
    "SELECT application_id, management_mode, website_url, fetch_secret_ciphertext, signing_public_jwks, last_verified_revision, last_verified_version, last_verified_digest, last_verified_expires_at, sync_status, last_fetched_at, last_success_at, last_error, snapshot_json, operator_disabled, created_at, updated_at, lease_owner, lease_expires_at, lease_generation FROM application_discovery"
}

pub(crate) fn select_application_permission_definition_sql() -> &'static str {
    "SELECT profile_id, permission_key, label, description, source, is_active, created_at, updated_at FROM application_permission_definitions"
}

pub(crate) fn select_application_profile_role_sql() -> &'static str {
    "SELECT id, profile_id, role_key, name, description, permissions, source, is_default, is_active, created_at, updated_at FROM application_profile_roles"
}

pub(crate) fn select_application_profile_permission_override_sql() -> &'static str {
    "SELECT profile_id, user_id, permission, effect FROM application_profile_permission_overrides"
}

pub(crate) fn select_application_jwt_client_sql() -> &'static str {
    "SELECT id, application_id, client_id, client_type, is_active, created_at, updated_at FROM application_jwt_clients"
}

pub(crate) fn select_application_jwt_secret_sql() -> &'static str {
    "SELECT id, jwt_client_id, secret_hash, created_at, expires_at, revoked_at FROM application_jwt_client_secrets"
}

pub(crate) fn select_application_saml_interaction_sql() -> &'static str {
    "SELECT handle_hash, application_id, request_id, sp_entity_id, acs_url, relay_state, response_binding, expires_at, created_at FROM application_saml_interactions"
}

pub(crate) fn select_application_saml_session_sql() -> &'static str {
    "SELECT session_index_hash, application_id, user_id, signet_session_id, name_id_hash, expires_at, created_at FROM application_saml_sessions"
}

pub(crate) fn select_application_cas_ticket_sql() -> &'static str {
    "SELECT ticket_hash, application_id, ticket_type, service, user_id, parent_ticket_hash, pgt_iou, expires_at, consumed_at, revoked_at, created_at FROM application_cas_tickets"
}

pub(crate) fn select_application_scim_token_sql() -> &'static str {
    "SELECT id, application_id, token_prefix, token_hash, scopes, expires_at, revoked_at, last_used_at, created_at FROM application_scim_tokens"
}
