export type Locale = "zh-CN" | "en-US";
export type AuthMode = "login" | "register" | "reset";
export type LoginMethod = "password" | "authorization_code";
export type AuthorizationCodeType = "registration" | "login";
export type LoginAuthorizationCodeLevel = "account_recovery" | "trial_enrollment" | "admin_universal";
/** Public, server-authoritative enrollment guidance for a code just entered by a user. */
export type AuthorizationCodeInspectionMode = "registration" | "trial_enrollment" | "sign_in_only" | "unavailable";
export type AuthorizationCodeEmailRequirement = "required" | "must_match_code" | "new_identity";
export type AuthorizationCodeInspection = {
  mode: AuthorizationCodeInspectionMode;
  email_requirement?: AuthorizationCodeEmailRequirement;
};
export type OrganizationMemberRole = "owner" | "admin" | "member";
export type SessionKind = "standard" | "temporary_authorization_code" | "trial_enrollment";
/** How the account itself was first provisioned, independent of its lifecycle. */
export type UserRegistrationSource = "local" | "authorization_code";

export type User = {
  id: string;
  email: string;
  username: string;
  display_name: string | null;
  phone: string | null;
  email_verified_at: number | null;
  phone_verified_at: number | null;
  is_admin: boolean;
  is_active: boolean;
  archived_at: number | null;
  registration_source: UserRegistrationSource;
  last_login_at: number | null;
  last_login_ip: string | null;
  last_oidc_client_id: string | null;
  last_login_method: string | null;
  created_at: number;
  updated_at: number;
  session_kind?: SessionKind;
  /**
   * Present for a restricted login-code session. Keeping the provenance
   * separate from `session_kind` lets the UI explain trial enrollment without
   * mistaking an account-recovery session for a trial account.
   */
  login_code_level?: LoginAuthorizationCodeLevel | null;
  permissions?: string[];
};

export type LoginEvent = {
  id: string;
  user_id: string;
  login_at: number;
  ip_address: string | null;
  user_agent: string | null;
  method: string;
  oidc_client_id: string | null;
  external_provider: string | null;
};

export type AuditEvent = {
  id: string;
  actor_user_id: string | null;
  actor_client_id: string | null;
  action: string;
  target_kind: string;
  target_id: string | null;
  outcome: string;
  ip_address: string | null;
  user_agent: string | null;
  details: string;
  created_at: number;
};

export type AuditWebhook = {
  id: string;
  name: string;
  url: string;
  has_secret: boolean;
  actions: string[];
  is_active: boolean;
  timeout_seconds: number;
  last_delivered_at: number | null;
  last_status_code: number | null;
  last_error: string | null;
  created_at: number;
  updated_at: number;
};

export type Role = {
  id: string;
  name: string;
  description: string | null;
  is_system: number;
  permissions: string[];
  created_at: number;
  updated_at: number;
};

export type AccessGroup = {
  id: string;
  name: string;
  description: string | null;
  roles?: Role[];
  members?: User[];
  created_at: number;
  updated_at: number;
};

export type OrganizationMember = {
  organization_id: string;
  user_id: string;
  role: string;
  email: string;
  username: string;
  display_name: string | null;
  is_active: boolean;
  archived_at: number | null;
  created_at: number;
  updated_at: number;
};

export type Organization = {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  allowed_email_domains: string[];
  is_active: boolean;
  member_count: number;
  created_at: number;
  updated_at: number;
};

export type OrganizationOption = Pick<Organization, "id" | "slug" | "name" | "is_active">;

export type UserOrganization = {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  is_active: number;
  role: string;
  membership_created_at: number;
  membership_updated_at: number;
};

export type PermissionInfo = {
  key: string;
  category: string;
  label: string;
};

export type UserAccess = {
  direct_roles: Role[];
  groups: AccessGroup[];
  effective_permissions: string[];
};

export type SessionLoginResponse = {
  mode?: "session";
  user: User | null;
  mfa_required: boolean;
  mfa_challenge_id: string | null;
  recovery_available: boolean;
  captcha_required: boolean;
  captcha_challenge_id: string | null;
  captcha_prompt: string | null;
  captcha_expires_at: number | null;
};

export type OidcContinuationLoginResponse = {
  mode: "oidc_continuation";
  continue_to: string;
};

export type LoginResponse = SessionLoginResponse | OidcContinuationLoginResponse;

export type BrowserAccount = {
  account_ref: string;
  user: User;
  session_kind: SessionKind;
  current: boolean;
  /** Successful sign-in time for this browser-context session. */
  last_login_at: number;
  last_selected_at: number | null;
};

export type BrowserAccountsContext = {
  accounts: BrowserAccount[];
  client_name?: string | null;
  client_logo_uri?: string | null;
  login_hint?: string | null;
  reauthentication_required?: boolean;
};

export type BrowserAccountSelectionResponse = {
  continue_to: string;
};

export type BrowserAccountActivationResponse = {
  continue_to: string;
};

export type BrowserAccountAddResponse = {
  login_url: string;
};

export type MfaStatus = {
  enabled: boolean;
  totp_enabled: boolean;
  recovery_codes_remaining: number;
  recovery_codes_total: number;
};

export type TotpSetup = {
  setup_id: string;
  secret: string;
  otpauth_uri: string;
  expires_at: number;
};

export type MfaConfirmResponse = {
  status: MfaStatus;
  recovery_codes: string[];
};

export type Passkey = {
  id: string;
  name: string;
  credential_id: string;
  last_used_at: number | null;
  created_at: number;
  updated_at: number;
};

export type WebauthnCreationPublicKeyJson = Omit<PublicKeyCredentialCreationOptions, "challenge" | "excludeCredentials" | "user"> & {
  challenge: string;
  excludeCredentials?: Array<Omit<PublicKeyCredentialDescriptor, "id"> & { id: string }>;
  user: Omit<PublicKeyCredentialUserEntity, "id"> & { id: string };
};

export type WebauthnCreationResponseJson = {
  publicKey: WebauthnCreationPublicKeyJson;
};

export type WebauthnRequestPublicKeyJson = Omit<PublicKeyCredentialRequestOptions, "allowCredentials" | "challenge"> & {
  allowCredentials?: Array<Omit<PublicKeyCredentialDescriptor, "id"> & { id: string }>;
  challenge: string;
};

export type WebauthnRequestResponseJson = {
  publicKey: WebauthnRequestPublicKeyJson;
  mediation?: CredentialMediationRequirement;
};

export type PasskeyRegistrationStart = {
  challenge_id: string;
  public_key: WebauthnCreationResponseJson;
  expires_at: number;
};

export type PasskeyAuthenticationStart = {
  challenge_id: string;
  public_key: WebauthnRequestResponseJson;
  expires_at: number;
};

export type SecurityPolicy = {
  id: string;
  password_min_length: number;
  password_require_uppercase: number;
  password_require_lowercase: number;
  password_require_digit: number;
  password_require_symbol: number;
  password_reject_user_info: number;
  login_lockout_enabled: number;
  max_failed_login_attempts: number;
  failure_window_seconds: number;
  lockout_seconds: number;
  trusted_ip_cidrs: string[];
  require_mfa_outside_trusted_networks: boolean;
  allowed_ip_cidrs: string[];
  blocked_ip_cidrs: string[];
  allowed_email_domains: string[];
  blocked_email_domains: string[];
  captcha_enabled: boolean;
  captcha_after_failed_attempts: number;
  captcha_ttl_seconds: number;
  updated_at: number;
};

export type SigningKey = {
  id: string;
  kid: string;
  is_active: boolean;
  created_at: number;
  activated_at: number | null;
  retired_at: number | null;
};

export type MyConsent = {
  client_id: string;
  client_name: string | null;
  granted_scopes: string[];
  granted_at: number;
  updated_at: number;
};

export type MySession = {
  id: string;
  current: boolean;
  ip_address: string | null;
  user_agent: string | null;
  login_method: string | null;
  expires_at: number;
  created_at: number;
};

export type LinkedIdentity = {
  id: string;
  user_id: string;
  provider_slug: string;
  external_subject: string;
  external_email: string | null;
  created_at: number;
  updated_at: number;
};

export type UserDetail = {
  user: User;
  login_events: LoginEvent[];
  linked_identities: LinkedIdentity[];
  organizations: UserOrganization[];
};

export type Client = {
  id: string;
  client_id: string;
  client_name: string;
  logo_uri: string;
  organization_id: string | null;
  organization_slug: string | null;
  organization_name: string | null;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  scopes: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  require_pkce: boolean;
  require_mfa: boolean;
  require_pushed_authorization_requests: boolean;
  require_s256_pkce: boolean;
  require_confidential_client: boolean;
  require_dpop: boolean;
  require_account_selection: boolean;
  trust_email_verified: boolean;
  authorization_details_types: string[];
  subject_type: string;
  sector_identifier_uri: string;
  jwks_uri: string;
  jwks: string;
  backchannel_logout_uri: string;
  backchannel_logout_session_required: boolean;
  frontchannel_logout_uri: string;
  frontchannel_logout_session_required: boolean;
  service_account_enabled: boolean;
  service_account_permissions: string[];
  is_active: boolean;
  claim_mappers: ClientClaimMapper[];
  created_at: number;
  updated_at: number;
};

export type LogoutFrame = {
  client_id: string;
  uri: string;
};

export type LogoutResponse = {
  ok: boolean;
  frontchannel_logout_frames?: LogoutFrame[];
};

export type ClientClaimMapper = {
  id: string;
  claim_name: string;
  source: string;
  source_value: string;
  value_type: string;
  include_in_id_token: boolean;
  include_in_access_token: boolean;
  include_in_userinfo: boolean;
  is_active: boolean;
  sort_order: number;
  created_at: number;
  updated_at: number;
};

export type IapApplication = {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  external_host: string;
  path_prefix: string;
  required_organization_id: string | null;
  required_organization_roles: string[];
  required_permissions: string[];
  is_active: boolean;
  created_at: number;
  updated_at: number;
};

export type ClientClaimMapperForm = {
  claim_name: string;
  source: string;
  source_value: string;
  value_type: string;
  include_in_id_token: boolean;
  include_in_access_token: boolean;
  include_in_userinfo: boolean;
  is_active: boolean;
  sort_order: number;
};

export type Invitation = {
  id: string;
  /** Server-authoritative: legacy hash-only codes cannot be reconstructed. */
  can_reveal: boolean;
  code_type: AuthorizationCodeType;
  login_code_level?: LoginAuthorizationCodeLevel | null;
  allowed_client_ids?: string[];
  organization_id?: string | null;
  organization_role?: OrganizationMemberRole | null;
  code_prefix: string;
  description: string | null;
  authorized_email: string | null;
  authorized_username: string | null;
  authorized_display_name: string | null;
  expires_at: number | null;
  max_uses: number | null;
  uses_count: number;
  is_active: boolean;
  created_by: string | null;
  created_at: number;
  updated_at: number;
};

export type InvitationRedemption = {
  id: string;
  user_id: string;
  user_email: string | null;
  user_username: string | null;
  redeemed_at: number;
};

export type InvitationRedemptionsPage = {
  redemptions: InvitationRedemption[];
  next_cursor: string | null;
};

export type BulkUserImportOutcome = "created" | "would_create" | "invalid" | "not_committed";

export type BulkUserImportRow = {
  row: number;
  email?: string | null;
  username?: string | null;
  outcome: BulkUserImportOutcome;
  user_id?: string | null;
  error?: string | null;
};

export type BulkUserImportResult = {
  dry_run: boolean;
  atomic: boolean;
  committed: boolean;
  summary: {
    total: number;
    created: number;
    would_create: number;
    invalid: number;
  };
  rows: BulkUserImportRow[];
};

export type QuickLink = {
  id: string;
  label: string;
  url: string;
  icon: string;
  is_active: boolean;
};

export type LoginSettings = {
  brand_logo_url: string;
  email_domains: string[];
  quick_links: QuickLink[];
  updated_at: number;
};

export type LoginSettingsDraft = {
  brand_logo_url: string;
  email_domains: string;
  quick_links: QuickLink[];
};

export type RegistrationSettings = {
  allow_password_registration: boolean;
  require_email_verification: boolean;
  require_phone_verification: boolean;
  allow_external_oidc_registration: boolean;
  require_invitation: boolean;
  first_user_direct_admin: boolean;
  default_user_active: boolean;
};

export type ExternalProvider = {
  id: string;
  slug: string;
  display_name: string;
  organization_id: string | null;
  issuer: string;
  client_id: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  redirect_path: string;
  scopes: string[];
  email_domains: string[];
  is_active: boolean;
  allow_login: boolean;
  allow_registration: boolean;
  created_at: number;
  updated_at: number;
};

export type ExternalProviderSummary = {
  slug: string;
  display_name: string;
  start_url: string;
  email_domains: string[];
  allow_login: boolean;
  allow_registration: boolean;
};

export type ExternalProviderTemplate = {
  id: string;
  slug: string;
  display_name: string;
  issuer: string;
  scopes: string[];
};

export type ExternalProviderDiscovery = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  scopes: string[];
};

export type LdapProvider = {
  id: string;
  slug: string;
  display_name: string;
  url: string;
  starttls: boolean;
  bind_dn: string;
  has_bind_password: boolean;
  base_dn: string;
  user_filter: string;
  user_id_attribute: string;
  email_attribute: string;
  username_attribute: string;
  display_name_attribute: string;
  phone_attribute: string;
  is_active: boolean;
  allow_login: boolean;
  allow_registration: boolean;
  created_at: number;
  updated_at: number;
};

export type Bootstrap = {
  has_users: boolean;
  issuer: string;
  registration: RegistrationSettings;
  login: LoginSettings;
  default_locale: string;
  supported_locales: string[];
  external_oidc_providers: ExternalProviderSummary[];
  ldap_providers: Array<{ slug: string; display_name: string }>;
};

export type Overview = {
  users: number;
  active_users: number;
  clients: number;
  active_clients: number;
  issuer: string;
  database_kind: string;
};

export type SettingsSummary = Record<string, string | number | boolean | string[]>;

export type RuntimeSettings = {
  public_base_url: string;
  issuer: string;
  trust_proxy_headers: boolean;
  effective_public_base_url: string;
  effective_issuer: string;
  updated_at: number;
};

export type Tab = "account" | "overview" | "users" | "clients" | "iap" | "organizations" | "invitations" | "registration" | "providers" | "portal" | "security" | "settings";
export type UserFilter = "live" | "active" | "disabled" | "archived" | "authorization_code" | "all";
export type Theme = "light" | "dark";

export type PendingConfirmation = {
  title: string;
  description: string;
  action: () => Promise<void> | void;
};
