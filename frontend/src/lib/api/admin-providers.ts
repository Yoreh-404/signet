import {
  arrayResponse,
  objectResponse,
  readCached,
  writeJson
} from "./transport";
import { appendPathSegment } from "./path-helpers";
import type { AdminCachedReadOptions, AdminMutationOptions } from "./admin-shared";
import type {
  ExternalProvider,
  ExternalProviderDiscovery,
  ExternalProviderTemplate,
  LdapProvider
} from "../../types";

const ADMIN_PATH = "/api/admin";

export type AdminExternalProviderMutation = {
  slug: string;
  display_name: string;
  organization_id: string | null;
  issuer: string;
  client_id: string;
  client_secret: string;
  clear_client_secret: boolean;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  redirect_path: string;
  scopes: string[];
  email_domains: string[];
  is_active: boolean;
  allow_login: boolean;
  allow_registration: boolean;
};

export type AdminLdapProviderMutation = {
  slug: string;
  display_name: string;
  organization_id: string | null;
  url: string;
  starttls: boolean;
  bind_dn: string;
  bind_password: string | null;
  clear_bind_password: boolean;
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
};

export function adminExternalOidcProvidersPath(): string {
  return `${ADMIN_PATH}/external-oidc-providers`;
}

export function adminExternalOidcProviderTemplatesPath(): string {
  return `${ADMIN_PATH}/external-oidc-provider-templates`;
}

export function adminExternalOidcProviderDiscoveryPath(): string {
  return `${ADMIN_PATH}/external-oidc-provider-discovery`;
}

export function adminLdapProvidersPath(): string {
  return `${ADMIN_PATH}/ldap-providers`;
}

export function adminExternalOidcProviderPath(providerId: string): string {
  return appendPathSegment(adminExternalOidcProvidersPath(), providerId);
}

export function adminLdapProviderPath(providerId: string): string {
  return appendPathSegment(adminLdapProvidersPath(), providerId);
}
export function listAdminExternalOidcProviders(options?: AdminCachedReadOptions): Promise<ExternalProvider[]> {
  return readCached<ExternalProvider[]>(adminExternalOidcProvidersPath(), options, arrayResponse);
}

export function discoverAdminExternalOidcProvider(
  issuer: string,
  options?: AdminMutationOptions
): Promise<ExternalProviderDiscovery> {
  return writeJson<ExternalProviderDiscovery, { issuer: string }>(
    adminExternalOidcProviderDiscoveryPath(),
    "POST",
    { issuer },
    options,
    objectResponse
  );
}

export function createAdminExternalOidcProvider(
  provider: AdminExternalProviderMutation,
  options?: AdminMutationOptions
): Promise<ExternalProvider> {
  return writeJson<ExternalProvider, AdminExternalProviderMutation>(
    adminExternalOidcProvidersPath(),
    "POST",
    provider,
    options,
    objectResponse
  );
}

export function updateAdminExternalOidcProvider(
  providerId: string,
  provider: AdminExternalProviderMutation,
  options?: AdminMutationOptions
): Promise<ExternalProvider> {
  return writeJson<ExternalProvider, AdminExternalProviderMutation>(
    adminExternalOidcProviderPath(providerId),
    "PUT",
    provider,
    options,
    objectResponse
  );
}

export function deleteAdminExternalOidcProvider(providerId: string, options?: AdminMutationOptions): Promise<unknown> {
  return writeJson<unknown, undefined>(adminExternalOidcProviderPath(providerId), "DELETE", undefined, options);
}

export function listAdminExternalOidcProviderTemplates(
  options?: AdminCachedReadOptions
): Promise<ExternalProviderTemplate[]> {
  return readCached<ExternalProviderTemplate[]>(adminExternalOidcProviderTemplatesPath(), options, arrayResponse);
}

export function listAdminLdapProviders(options?: AdminCachedReadOptions): Promise<LdapProvider[]> {
  return readCached<LdapProvider[]>(adminLdapProvidersPath(), options, arrayResponse);
}

export function createAdminLdapProvider(
  provider: AdminLdapProviderMutation,
  options?: AdminMutationOptions
): Promise<LdapProvider> {
  return writeJson<LdapProvider, AdminLdapProviderMutation>(adminLdapProvidersPath(), "POST", provider, options, objectResponse);
}

export function updateAdminLdapProvider(
  providerId: string,
  provider: AdminLdapProviderMutation,
  options?: AdminMutationOptions
): Promise<LdapProvider> {
  return writeJson<LdapProvider, AdminLdapProviderMutation>(adminLdapProviderPath(providerId), "PUT", provider, options, objectResponse);
}

export function deleteAdminLdapProvider(providerId: string, options?: AdminMutationOptions): Promise<unknown> {
  return writeJson<unknown, undefined>(adminLdapProviderPath(providerId), "DELETE", undefined, options);
}
