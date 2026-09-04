import type { Client, Invitation, OrganizationOption } from "../../types";
import { ignoreForbiddenRead, type AdminReadQueryContext } from "./admin-read-query";

export type AdminInvitationsLoaderOptions = AdminReadQueryContext & {
  canManageAuthorizationCodes: boolean;
};

const AUTHORIZATION_CODES_API = "/api/admin/authorization-codes";

export async function loadAdminInvitations({
  loadCached,
  updateReadModel,
  canManageAuthorizationCodes
}: AdminInvitationsLoaderOptions): Promise<void> {
  if (!canManageAuthorizationCodes) return;

  await Promise.all([
    loadCached<Invitation[]>(AUTHORIZATION_CODES_API, (next) => updateReadModel("invitations", next)),
    loadCached<Client[]>("/api/admin/clients", (next) => updateReadModel("clients", next)).catch(ignoreForbiddenRead),
    loadCached<OrganizationOption[]>(
      "/api/admin/organization-options",
      (next) => updateReadModel("organizationOptions", next)
    ).catch(ignoreForbiddenRead)
  ]);
}
