import { useMemo } from "react";
import { matchesSearch } from "../../lib/collection-utils";
import type {
  AccessGroup,
  AuditEvent,
  AuditWebhook,
  ExternalProvider,
  Invitation,
  LdapProvider,
  Organization,
  Role,
  TenantApplication
} from "../../types";

export type AdminSearchCollections = {
  organizations: Organization[];
  applications: TenantApplication[];
  invitations: Invitation[];
  providers: ExternalProvider[];
  ldapProviders: LdapProvider[];
  roles: Role[];
  groups: AccessGroup[];
  auditWebhooks: AuditWebhook[];
  auditEvents: AuditEvent[];
};

export function useAdminSearchProjections(
  searchQuery: string,
  collections: AdminSearchCollections
) {
  const normalizedQuery = searchQuery.trim().toLocaleLowerCase();
  const {
    organizations,
    applications,
    invitations,
    providers,
    ldapProviders,
    roles,
    groups,
    auditWebhooks,
    auditEvents
  } = collections;

  return useMemo(() => ({
    filteredOrganizations: organizations.filter((item) => matchesSearch(
      normalizedQuery,
      item.name,
      item.slug,
      item.description,
      item.allowed_email_domains.join(" ")
    )),
    filteredApplications: applications.filter((item) => matchesSearch(
      normalizedQuery,
      item.name,
      item.slug,
      item.description
    )),
    filteredInvitations: invitations.filter((item) => matchesSearch(
      normalizedQuery,
      item.code_type,
      item.login_code_level,
      item.allowed_client_ids?.join(" "),
      item.organization_id,
      item.organization_role,
      item.code_prefix,
      item.description,
      item.authorized_email,
      item.authorized_username
    )),
    filteredProviders: providers.filter((item) => matchesSearch(
      normalizedQuery,
      item.display_name,
      item.slug,
      item.issuer,
      item.email_domains.join(" ")
    )),
    filteredLdapProviders: ldapProviders.filter((item) => matchesSearch(
      normalizedQuery,
      item.display_name,
      item.slug,
      item.url,
      item.base_dn
    )),
    filteredRoles: roles.filter((item) => matchesSearch(
      normalizedQuery,
      item.name,
      item.description,
      item.permissions.join(" ")
    )),
    filteredGroups: groups.filter((item) => matchesSearch(
      normalizedQuery,
      item.name,
      item.description
    )),
    filteredAuditWebhooks: auditWebhooks.filter((item) => matchesSearch(
      normalizedQuery,
      item.name,
      item.url,
      item.actions.join(" "),
      item.last_error
    )),
    filteredAuditEvents: auditEvents.filter((item) => matchesSearch(
      normalizedQuery,
      item.action,
      item.target_kind,
      item.target_id,
      item.actor_user_id,
      item.actor_client_id,
      item.details
    ))
  }), [
    applications,
    auditEvents,
    auditWebhooks,
    groups,
    invitations,
    ldapProviders,
    normalizedQuery,
    organizations,
    providers,
    roles
  ]);
}
