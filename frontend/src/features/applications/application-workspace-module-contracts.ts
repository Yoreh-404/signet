import type { TenantApplication } from "../../types";
import { record } from "./application-module-values";

export const APPLICATION_AUTHORIZATION_DIRTY_SOURCE = "applications.authorization";
export const APPLICATION_DIRECTORY_SYNC_DIRTY_SOURCE = "applications.directory-sync";
export const APPLICATION_OIDC_CLIENTS_DIRTY_SOURCE = "applications.oidc-clients";
export const APPLICATION_PROTOCOLS_DIRTY_SOURCE = "applications.protocols";

export function applicationProtocolsConfig(application: TenantApplication): Record<string, unknown> {
  const module = (application.modules ?? []).find((item) => item.module_key === "protocols");
  const oidcClientIds = application.client_bindings.reduce<string[]>((clientIds, binding) => {
    if (binding.protocol === "oidc") clientIds.push(binding.id);
    return clientIds;
  }, []);
  return {
    oauth2_oidc: {
      enabled: oidcClientIds.length > 0,
      client_ids: oidcClientIds
    },
    saml2: {
      enabled: false,
      entity_id: "",
      acs_url: "",
      slo_url: "",
      name_id_claim: "email",
      name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      require_signed_requests: false,
      want_assertions_signed: false,
      require_signed_logout: true,
      want_logout_responses_signed: true,
      sp_metadata_xml: "",
      sp_signing_certificate: ""
    },
    cas: {
      enabled: false,
      service_urls: [],
      proxy_callback_urls: [],
      allow_proxy: false,
      ticket_ttl_seconds: 300,
      pgt_ttl_seconds: 300
    },
    jwt: {
      enabled: false,
      client_id: application.slug,
      client_type: "public",
      redirect_uris: [],
      audience: "",
      token_ttl_seconds: 3600
    },
    ...record(module?.config)
  };
}

export function applicationDirectorySyncConfig(application: TenantApplication): Record<string, unknown> {
  const module = (application.modules ?? []).find((item) => item.module_key === "directory_sync");
  return {
    enabled: false,
    ldap_provider_ids: [],
    user_sync_filter: "",
    group_base_dn: "",
    group_filter: "(objectClass=group)",
    group_id_attribute: "dn",
    group_name_attribute: "cn",
    group_member_attribute: "member",
    reactivate_users: true,
    max_entries: 100000,
    deprovision_action: "remove_membership",
    scim_enabled: false,
    scim_audience: "",
    sync_groups: true,
    ...record(module?.config)
  };
}
