import type {
  AdminExternalProviderMutation,
  AdminLdapProviderMutation
} from "../../lib/api/admin";
import { normalizeDomain } from "../../lib/auth-flow";
import { joinList, splitList, toDatetimeLocalValue } from "../../lib/formatters";
import {
  emptyInvitationForm,
  emptyLdapProviderForm,
  emptyProviderForm,
  emptyUserForm
} from "../../lib/form-defaults";
import type { ExternalProvider, Invitation, LdapProvider, User } from "../../types";

export function toUserEditorForm(user: User): typeof emptyUserForm {
  return {
    id: user.id,
    email: user.email,
    username: user.username,
    display_name: user.display_name ?? "",
    phone: user.phone ?? "",
    password: "",
    is_admin: user.is_admin,
    is_active: user.is_active
  };
}

export function toInvitationForm(invitation: Invitation): typeof emptyInvitationForm {
  return {
    id: invitation.id,
    code_type: invitation.code_type,
    login_code_level: invitation.login_code_level ?? "account_recovery",
    allowed_client_ids: invitation.allowed_client_ids ?? [],
    organization_id: invitation.organization_id ?? "",
    organization_role: invitation.organization_role ?? "member",
    description: invitation.description ?? "",
    authorized_email: invitation.authorized_email ?? "",
    authorized_username: invitation.authorized_username ?? "",
    authorized_display_name: invitation.authorized_display_name ?? "",
    expires_at: toDatetimeLocalValue(invitation.expires_at),
    max_uses: invitation.max_uses ? String(invitation.max_uses) : "",
    is_active: invitation.is_active
  };
}

export function toExternalOidcProviderForm(
  provider: ExternalProvider
): typeof emptyProviderForm {
  return {
    id: provider.id,
    slug: provider.slug,
    display_name: provider.display_name,
    organization_id: provider.organization_id ?? "",
    issuer: provider.issuer,
    client_id: provider.client_id,
    client_secret: "",
    clear_client_secret: false,
    authorization_endpoint: provider.authorization_endpoint,
    token_endpoint: provider.token_endpoint,
    userinfo_endpoint: provider.userinfo_endpoint,
    redirect_path: provider.redirect_path,
    scopes: joinList(provider.scopes),
    email_domains: joinList(provider.email_domains),
    is_active: provider.is_active,
    allow_login: provider.allow_login,
    allow_registration: provider.allow_registration
  };
}

export function toLdapProviderForm(provider: LdapProvider): typeof emptyLdapProviderForm {
  return {
    id: provider.id,
    slug: provider.slug,
    display_name: provider.display_name,
    organization_id: provider.organization_id ?? "",
    url: provider.url,
    starttls: provider.starttls,
    bind_dn: provider.bind_dn,
    bind_password: "",
    clear_bind_password: false,
    base_dn: provider.base_dn,
    user_filter: provider.user_filter,
    user_id_attribute: provider.user_id_attribute,
    email_attribute: provider.email_attribute,
    username_attribute: provider.username_attribute,
    display_name_attribute: provider.display_name_attribute,
    phone_attribute: provider.phone_attribute,
    is_active: provider.is_active,
    allow_login: provider.allow_login,
    allow_registration: provider.allow_registration
  };
}

export function toExternalOidcProviderPayload(
  form: typeof emptyProviderForm
): AdminExternalProviderMutation {
  return {
    slug: form.slug,
    display_name: form.display_name,
    organization_id: form.organization_id || null,
    issuer: form.issuer,
    client_id: form.client_id,
    client_secret: form.client_secret,
    clear_client_secret: form.clear_client_secret,
    authorization_endpoint: form.authorization_endpoint,
    token_endpoint: form.token_endpoint,
    userinfo_endpoint: form.userinfo_endpoint,
    redirect_path: form.redirect_path,
    scopes: splitList(form.scopes),
    email_domains: splitList(form.email_domains).map(normalizeDomain),
    is_active: form.is_active,
    allow_login: form.allow_login,
    allow_registration: form.allow_registration
  };
}

export function toLdapProviderPayload(
  form: typeof emptyLdapProviderForm
): AdminLdapProviderMutation {
  return {
    slug: form.slug,
    display_name: form.display_name,
    organization_id: form.organization_id || null,
    url: form.url,
    starttls: form.starttls,
    bind_dn: form.bind_dn,
    bind_password: form.bind_password || null,
    clear_bind_password: form.clear_bind_password,
    base_dn: form.base_dn,
    user_filter: form.user_filter,
    user_id_attribute: form.user_id_attribute,
    email_attribute: form.email_attribute,
    username_attribute: form.username_attribute,
    display_name_attribute: form.display_name_attribute,
    phone_attribute: form.phone_attribute,
    is_active: form.is_active,
    allow_login: form.allow_login,
    allow_registration: form.allow_registration
  };
}
