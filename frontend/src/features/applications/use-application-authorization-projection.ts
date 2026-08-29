import { useMemo } from "react";

import type {
  ApplicationAuthorizationProfile,
  ApplicationAuthorizationSubjects,
  ApplicationPermissionDefinition,
  ApplicationPermissionOverride,
} from "../../lib/api/application-authorization";
import type { ApplicationRoleDraft } from "./application-authorization-role-policy";

export function useApplicationAuthorizationProjection({
  authorizationProfiles,
  selectedProfileId,
  applicationPermissionCatalog,
  roleDraft,
  userRoleIds,
  groupRoleIds,
  organizationRoleIds,
  userPermissionOverrides,
  authorizationSubjects,
}: {
  authorizationProfiles: ApplicationAuthorizationProfile[];
  selectedProfileId: string;
  applicationPermissionCatalog: ApplicationPermissionDefinition[];
  roleDraft: ApplicationRoleDraft | null;
  userRoleIds: string[];
  groupRoleIds: string[];
  organizationRoleIds: Record<string, string[]>;
  userPermissionOverrides: ApplicationPermissionOverride[];
  authorizationSubjects: ApplicationAuthorizationSubjects | null;
}) {
  const selectedAuthorizationProfile = useMemo(
    () =>
      authorizationProfiles.find((profile) => profile.id === selectedProfileId) ??
      null,
    [authorizationProfiles, selectedProfileId],
  );
  const knownPermissions = useMemo(
    () => new Set(applicationPermissionCatalog.map((permission) => permission.key)),
    [applicationPermissionCatalog],
  );
  const roleDraftPermissionSet = useMemo(
    () => new Set(roleDraft?.permissions ?? []),
    [roleDraft?.permissions],
  );
  const userRoleIdSet = useMemo(() => new Set(userRoleIds), [userRoleIds]);
  const groupRoleIdSet = useMemo(() => new Set(groupRoleIds), [groupRoleIds]);
  const organizationRoleIdSets = useMemo(
    () =>
      new Map(
        Object.entries(organizationRoleIds).map(([key, ids]) => [
          key,
          new Set(ids),
        ]),
      ),
    [organizationRoleIds],
  );
  const permissionOverridesByKey = useMemo(
    () =>
      new Map(
        userPermissionOverrides.map((override) => [
          override.permission,
          override.effect,
        ]),
      ),
    [userPermissionOverrides],
  );
  const customRolePermissions = useMemo(
    () =>
      roleDraft?.permissions.filter(
        (permission) => !knownPermissions.has(permission),
      ) ?? [],
    [knownPermissions, roleDraft?.permissions],
  );
  const customOverrideLines = useMemo(
    () => userPermissionOverrides.reduce<string[]>((lines, override) => {
      if (!knownPermissions.has(override.permission)) {
        lines.push(`${override.effect}:${override.permission}`);
      }
      return lines;
    }, []).join("\n"),
    [knownPermissions, userPermissionOverrides],
  );

  return {
    selectedAuthorizationProfile,
    knownPermissions,
    roleDraftPermissionSet,
    userRoleIdSet,
    groupRoleIdSet,
    organizationRoleIdSets,
    permissionOverridesByKey,
    customRolePermissions,
    customOverrideLines,
    authorizationUsers: authorizationSubjects?.users ?? [],
    authorizationGroups: authorizationSubjects?.groups ?? [],
  };
}
