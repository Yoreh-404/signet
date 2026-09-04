import {
  arrayResponse,
  objectResponse,
  readCached,
  writeJson
} from "./transport";
import { appendPathSegment } from "./path-helpers";
import type { AdminCachedReadOptions, AdminMutationOptions } from "./admin-shared";
import type {
  Invitation,
  Organization,
  OrganizationMember,
  OrganizationMemberInvitationCreateResponse,
  OrganizationOption
} from "../../types";

const ADMIN_PATH = "/api/admin";

export type AdminOrganizationMutation = {
  slug: string;
  name: string;
  description: string | null;
  allowed_email_domains: string[];
  is_active: boolean;
};

export type AdminOrganizationMemberCreate = {
  email: string;
  role: string;
};

export type AdminOrganizationMembersReplace = {
  members: Array<{ user_id: string; role: string }>;
};

export type AdminOrganizationInvitationMutation = {
  email: string;
  display_name: string | null;
  description: string | null;
  expires_at: number;
  organization_role: string;
  is_active: boolean;
};

export function adminOrganizationOptionsPath(): string {
  return `${ADMIN_PATH}/organization-options`;
}

export function adminOrganizationsPath(): string {
  return `${ADMIN_PATH}/organizations`;
}

export function adminOrganizationPath(organizationId: string): string {
  return appendPathSegment(adminOrganizationsPath(), organizationId);
}

export function adminOrganizationMembersPath(organizationId: string): string {
  return `${adminOrganizationPath(organizationId)}/members`;
}

export function adminOrganizationMemberInvitationsPath(organizationId: string): string {
  return `${adminOrganizationPath(organizationId)}/member-invitations`;
}

export function createAdminOrganization(
  organization: AdminOrganizationMutation,
  options?: AdminMutationOptions
): Promise<Organization> {
  return writeJson<Organization, AdminOrganizationMutation>(
    adminOrganizationsPath(),
    "POST",
    organization,
    options,
    objectResponse
  );
}

export function updateAdminOrganization(
  organizationId: string,
  organization: AdminOrganizationMutation,
  options?: AdminMutationOptions
): Promise<Organization> {
  return writeJson<Organization, AdminOrganizationMutation>(
    adminOrganizationPath(organizationId),
    "PUT",
    organization,
    options,
    objectResponse
  );
}

export function deleteAdminOrganization(organizationId: string, options?: AdminMutationOptions): Promise<unknown> {
  return writeJson<unknown, undefined>(adminOrganizationPath(organizationId), "DELETE", undefined, options);
}

export function addAdminOrganizationMember(
  organizationId: string,
  member: AdminOrganizationMemberCreate,
  options?: AdminMutationOptions
): Promise<unknown> {
  return writeJson<unknown, AdminOrganizationMemberCreate>(
    adminOrganizationMembersPath(organizationId),
    "POST",
    member,
    options
  );
}

export function replaceAdminOrganizationMembers(
  organizationId: string,
  members: AdminOrganizationMembersReplace,
  options?: AdminMutationOptions
): Promise<unknown> {
  return writeJson<unknown, AdminOrganizationMembersReplace>(
    adminOrganizationMembersPath(organizationId),
    "PUT",
    members,
    options
  );
}

export function createAdminOrganizationInvitation(
  organizationId: string,
  invitation: AdminOrganizationInvitationMutation,
  options?: AdminMutationOptions
): Promise<OrganizationMemberInvitationCreateResponse> {
  return writeJson<OrganizationMemberInvitationCreateResponse, AdminOrganizationInvitationMutation>(
    adminOrganizationMemberInvitationsPath(organizationId),
    "POST",
    invitation,
    options,
    objectResponse
  );
}

export function deleteAdminOrganizationInvitation(
  organizationId: string,
  invitationId: string,
  options?: AdminMutationOptions
): Promise<unknown> {
  return writeJson<unknown, undefined>(
    appendPathSegment(adminOrganizationMemberInvitationsPath(organizationId), invitationId),
    "DELETE",
    undefined,
    options
  );
}
export function listAdminOrganizationOptions(options?: AdminCachedReadOptions): Promise<OrganizationOption[]> {
  return readCached<OrganizationOption[]>(adminOrganizationOptionsPath(), options, arrayResponse);
}

export function listAdminOrganizations(options?: AdminCachedReadOptions): Promise<Organization[]> {
  return readCached<Organization[]>(adminOrganizationsPath(), options, arrayResponse);
}

export function listAdminOrganizationMembers(
  organizationId: string,
  options?: AdminCachedReadOptions
): Promise<OrganizationMember[]> {
  return readCached<OrganizationMember[]>(adminOrganizationMembersPath(organizationId), options, arrayResponse);
}

export function listAdminOrganizationMemberInvitations(
  organizationId: string,
  options?: AdminCachedReadOptions
): Promise<Invitation[]> {
  return readCached<Invitation[]>(adminOrganizationMemberInvitationsPath(organizationId), options, arrayResponse);
}
