import type { ApplicationProfileRole } from "../../lib/api/application-authorization";

export type ApplicationRoleDraft = {
  id: string | null;
  role_key: string;
  name: string;
  description: string;
  permissions: string[];
  is_default: boolean;
  is_active: boolean;
  source: string;
};

export function applicationRoleDraft(role: ApplicationProfileRole): ApplicationRoleDraft {
  return {
    id: role.id,
    role_key: role.role_key,
    name: role.name,
    description: role.description ?? "",
    permissions: [...role.permissions],
    is_default: role.is_default,
    is_active: role.is_active,
    source: role.source,
  };
}

export function newApplicationRoleDraft(roles: ApplicationProfileRole[]): ApplicationRoleDraft {
  return {
    id: null,
    role_key: "",
    name: "",
    description: "",
    permissions: [],
    is_default: !roles.some((role) => role.is_default && role.is_active),
    is_active: true,
    source: "manual",
  };
}

export function normalizedPermissionList(values: readonly string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)));
}

export function togglePermission(values: readonly string[], permission: string): string[] {
  return normalizedPermissionList(
    values.includes(permission)
      ? values.filter((value) => value !== permission)
      : [...values, permission],
  );
}

export function applicationRolePayload(draft: ApplicationRoleDraft) {
  return {
    role_key: draft.role_key.trim(),
    name: draft.name.trim(),
    description: draft.description.trim() || null,
    permissions: normalizedPermissionList(draft.permissions),
    is_default: draft.is_default,
    is_active: draft.is_active,
  };
}
