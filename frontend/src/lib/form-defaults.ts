import type {
  AuthorizationCodeType,
  LoginAuthorizationCodeLevel,
  OrganizationMemberRole
} from "../types";

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

const applicationFormDefaults = {
  id: "",
  slug: "",
  name: "",
  website_url: "",
  description: "",
  account_selection_mode: "optional" as "optional" | "required",
  unique_identity_factors: [] as Array<"email" | "phone">,
  is_active: true
};

export function createEmptyApplicationForm(): typeof applicationFormDefaults {
  return {
    ...applicationFormDefaults,
    unique_identity_factors: []
  };
}

export const emptyApplicationForm = createEmptyApplicationForm();

const invitationFormDefaults = {
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

export function createEmptyInvitationForm(): typeof invitationFormDefaults {
  return {
    ...invitationFormDefaults,
    allowed_client_ids: []
  };
}

export const emptyInvitationForm = createEmptyInvitationForm();

export const emptyQuickLinkForm = {
  id: "",
  label: "",
  url: "",
  is_active: true
};

const roleFormDefaults = {
  id: "",
  name: "",
  description: "",
  permissions: [] as string[]
};

export function createEmptyRoleForm(): typeof roleFormDefaults {
  return {
    ...roleFormDefaults,
    permissions: []
  };
}

export const emptyRoleForm = createEmptyRoleForm();

const groupFormDefaults = {
  id: "",
  name: "",
  description: "",
  role_ids: [] as string[],
  user_ids: [] as string[]
};

export function createEmptyGroupForm(): typeof groupFormDefaults {
  return {
    ...groupFormDefaults,
    role_ids: [],
    user_ids: []
  };
}

export const emptyGroupForm = createEmptyGroupForm();

export const emptyOrganizationForm = {
  id: "",
  slug: "",
  name: "",
  description: "",
  allowed_email_domains: "",
  is_active: true
};

export const emptyEnterpriseForm = {
  slug: "",
  name: "",
  description: "",
  allowed_email_domains: ""
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
  organization_id: "",
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
