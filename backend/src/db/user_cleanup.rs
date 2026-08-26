pub(super) const USER_AUTH_STATE_TABLES: &[(&str, &str)] = &[
    ("sessions", "user_id"),
    ("authorization_codes", "user_id"),
    ("oidc_login_grants", "user_id"),
    ("refresh_tokens", "user_id"),
    ("device_authorizations", "authorized_user_id"),
    ("webauthn_challenges", "user_id"),
];

pub(super) const USER_PERMANENT_DEPENDENT_TABLES: &[&str] = &[
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
];
