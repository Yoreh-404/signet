import { useState, type Dispatch, type SetStateAction } from "react";

import * as applicationAuthorizationApi from "../../lib/api/application-authorization";
import type { ApplicationProfileRole } from "../../lib/api/application-authorization";
import type { ApplicationAuthorizationCopy } from "./application-authorization-copy";
import {
  applicationRoleDraft,
  applicationRolePayload,
  newApplicationRoleDraft,
  togglePermission,
  type ApplicationRoleDraft,
} from "./application-authorization-role-policy";
import type { ApplicationWorkspaceRequestApi } from "./use-application-workspace-request-context";

export function useApplicationAuthorizationRoles({
  applicationId,
  selectedProfileId,
  applicationRoles,
  copy,
  requestContext,
  setApplicationRoles,
}: {
  applicationId: string;
  selectedProfileId: string;
  applicationRoles: ApplicationProfileRole[];
  copy: Pick<ApplicationAuthorizationCopy, "saveFailed" | "saved" | "deleteRole" | "defaultRoleDeleteHint">;
  requestContext: ApplicationWorkspaceRequestApi;
  setApplicationRoles: Dispatch<SetStateAction<ApplicationProfileRole[]>>;
}) {
  const [roleDraft, setRoleDraft] = useState<ApplicationRoleDraft | null>(null);
  const [roleSaving, setRoleSaving] = useState(false);
  const [roleFeedback, setRoleFeedback] = useState("");

  function startRole(role?: ApplicationProfileRole) {
    setRoleFeedback("");
    setRoleDraft(role ? applicationRoleDraft(role) : newApplicationRoleDraft(applicationRoles));
  }

  function updateRole(next: Partial<ApplicationRoleDraft>) {
    setRoleDraft((current) => (current ? { ...current, ...next } : current));
  }

  function toggleRolePermission(permission: string) {
    if (!roleDraft) return;
    updateRole({ permissions: togglePermission(roleDraft.permissions, permission) });
  }

  async function saveRole() {
    if (!selectedProfileId || !roleDraft) return;
    const request = requestContext.beginRequest(`authorization:role:${roleDraft.id ?? "new"}`, {
      kind: "mutation",
      payloadFingerprint: JSON.stringify(roleDraft),
    });
    if (!request) return;
    const name = roleDraft.name.trim();
    const roleKey = roleDraft.role_key.trim();
    if (!name || !roleKey) {
      setRoleFeedback(copy.saveFailed);
      requestContext.finishRequest(request, false);
      return;
    }
    setRoleSaving(true);
    setRoleFeedback("");
    let committed = false;
    try {
      const payload = applicationRolePayload(roleDraft);
      if (roleDraft.id) {
        await applicationAuthorizationApi.updateApplicationProfileRole(
          applicationId,
          selectedProfileId,
          roleDraft.id,
          payload,
          requestContext.requestOptions(request),
        );
      } else {
        await applicationAuthorizationApi.createApplicationProfileRole(
          applicationId,
          selectedProfileId,
          payload,
          requestContext.requestOptions(request),
        );
      }
      const roles = await applicationAuthorizationApi.listApplicationProfileRoles(
        applicationId,
        selectedProfileId,
        requestContext.requestOptions(request),
      );
      if (!requestContext.isCurrent(request)) return;
      setApplicationRoles(roles);
      setRoleDraft(null);
      setRoleFeedback(copy.saved);
      committed = true;
    } catch {
      if (requestContext.isCurrent(request)) setRoleFeedback(copy.saveFailed);
    } finally {
      if (requestContext.isCurrent(request)) setRoleSaving(false);
      requestContext.finishRequest(request, committed);
    }
  }

  async function deleteRole(role: ApplicationProfileRole) {
    if (!selectedProfileId || role.is_default) {
      setRoleFeedback(copy.defaultRoleDeleteHint);
      return;
    }
    if (!window.confirm(`${copy.deleteRole}: ${role.name}?`)) return;
    const request = requestContext.beginRequest(`authorization:role:${role.id}:delete`, {
      kind: "mutation",
    });
    if (!request) return;
    setRoleSaving(true);
    setRoleFeedback("");
    let committed = false;
    try {
      await applicationAuthorizationApi.deleteApplicationProfileRole(
        applicationId,
        selectedProfileId,
        role.id,
        requestContext.requestOptions(request),
      );
      if (!requestContext.isCurrent(request)) return;
      setApplicationRoles((current) => current.filter((item) => item.id !== role.id));
      if (roleDraft?.id === role.id) setRoleDraft(null);
      setRoleFeedback(copy.saved);
      committed = true;
    } catch {
      if (requestContext.isCurrent(request)) setRoleFeedback(copy.saveFailed);
    } finally {
      if (requestContext.isCurrent(request)) setRoleSaving(false);
      requestContext.finishRequest(request, committed);
    }
  }

  return {
    roleDraft,
    setRoleDraft,
    roleSaving,
    roleFeedback,
    startRole,
    updateRole,
    toggleRolePermission,
    saveRole,
    deleteRole,
  };
}
