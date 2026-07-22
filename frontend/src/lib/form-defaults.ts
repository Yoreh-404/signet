import type {
  AuthorizationCodeType,
  ClientClaimMapperForm,
  LoginAuthorizationCodeLevel,
  OrganizationMemberRole
} from "../types";

export const DEFAULT_LOGIN_EMAIL = "admin@example.com";

export const emptyUserForm = {
  id: "",
  email: "",
  username: "",
  display_name: "",
  phone: "",
  password: "",
  is_admin: false,
  is_active: true
};

export const emptyRegisterForm = {
  username: "",
  display_name: "",
  phone: "",
  password: "",
  email_code: "",
  phone_code: "",
  authorization_code: ""
};

export const emptyAuthorizationCodeLoginForm = {
  email: "",
  authorization_code: ""
};

export const emptyPasswordResetForm = {
  code: "",
  password: ""
};

export const emptyClientForm = {
  id: "",
  client_id: "",
  client_name: "",
  logo_uri: "",
  organization_id: "",
  client_secret: "",
  redirect_uris: "http://localhost:3000/callback",
  post_logout_redirect_uris: "http://localhost:3000/",
  scopes: "openid profile email offline_access",
  grant_types: "authorization_code refresh_token",
  response_types: "code",
  token_endpoint_auth_method: "client_secret_basic",
  require_pkce: false,
  require_mfa: false,
  require_pushed_authorization_requests: false,
  require_s256_pkce: false,
  require_confidential_client: false,
  require_dpop: false,
  require_account_selection: false,
  trust_email_verified: false,
  authorization_details_types: "",
  subject_type: "public",
  sector_identifier_uri: "",
  jwks_uri: "",
  jwks: "",
  backchannel_logout_uri: "",
  backchannel_logout_session_required: false,
  frontchannel_logout_uri: "",
  frontchannel_logout_session_required: false,
  service_account_enabled: false,
  service_account_permissions: "",
  is_active: true,
  claim_mappers: [] as ClientClaimMapperForm[]
};

export const emptyIapApplicationForm = {
  id: "",
  slug: "",
  name: "",
  description: "",
  external_host: "",
  path_prefix: "/",
  required_organization_id: "",
  required_organization_roles: [] as string[],
  required_permissions: "",
  is_active: true
};

export function emptyClaimMapperForm(sortOrder: number): ClientClaimMapperForm {
  return {
    claim_name: "",
    source: "user_field",
    source_value: "username",
    value_type: "string",
    include_in_id_token: true,
    include_in_access_token: false,
    include_in_userinfo: true,
    is_active: true,
    sort_order: sortOrder
  };
}

export const emptyInvitationForm = {
  id: "",
  code_type: "registration" as AuthorizationCodeType,
  login_code_level: "account_recovery" as LoginAuthorizationCodeLevel,
  allowed_client_ids: [] as string[],
  organization_id: "",
  organization_role: "member" as OrganizationMemberRole,
  description: "",
  authorized_email: "",
  authorized_username: "",
  authorized_display_name: "",
  expires_at: "",
  max_uses: "",
  is_active: true
};

export const emptyQuickLinkForm = {
  id: "",
  label: "",
  url: "",
  icon: "link",
  is_active: true
};

export const emptyRoleForm = {
  id: "",
  name: "",
  description: "",
  permissions: [] as string[]
};

export const emptyGroupForm = {
  id: "",
  name: "",
  description: "",
  role_ids: [] as string[],
  user_ids: [] as string[]
};

export const emptyOrganizationForm = {
  id: "",
  slug: "",
  name: "",
  description: "",
  allowed_email_domains: "",
  is_active: true
};

export const emptyProviderForm = {
  id: "",
  slug: "",
  display_name: "",
  organization_id: "",
  issuer: "",
  client_id: "",
  client_secret: "",
  clear_client_secret: false,
  authorization_endpoint: "",
  token_endpoint: "",
  userinfo_endpoint: "",
  redirect_path: "/api/register/oidc/example/callback",
  scopes: "openid profile email",
  email_domains: "",
  is_active: false,
  allow_login: true,
  allow_registration: true
};

export const emptyLdapProviderForm = {
  id: "",
  slug: "",
  display_name: "",
  url: "ldap://ldap.example.com",
  starttls: true,
  bind_dn: "",
  bind_password: "",
  clear_bind_password: false,
  base_dn: "dc=example,dc=com",
  user_filter: "(&(|(mail={login})(uid={login})(sAMAccountName={login}))(objectClass=person))",
  user_id_attribute: "dn",
  email_attribute: "mail",
  username_attribute: "uid",
  display_name_attribute: "cn",
  phone_attribute: "telephoneNumber",
  is_active: false,
  allow_login: true,
  allow_registration: true
};

export const emptyAuditWebhookForm = {
  id: "",
  name: "",
  url: "",
  secret: "",
  clear_secret: false,
  actions: "",
  is_active: true,
  timeout_seconds: 5
};

export function createQuickLinkId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `link-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}
