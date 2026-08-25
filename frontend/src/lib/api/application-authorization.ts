import { applicationPath } from "./applications";
import {
  arrayResponse,
  objectResponse,
  pathSegment,
  readCached,
  writeJson
} from "./transport";
import type {
  ApiMutationOptions,
  ApiOkResponse,
  CachedReadOptions
} from "./transport";
import { ApiDecodeError, expectArray, expectRecord, expectString } from "./validation";
import type {
  ApplicationAuthorizationPreview,
  ApplicationAuthorizationProfile,
  ApplicationAuthorizationSubjects,
  ApplicationPermissionDefinition,
  ApplicationPermissionOverride,
  ApplicationProfileRole,
  PermissionInfo
} from "../../types";

export type {
  ApplicationAuthorizationPreview,
  ApplicationAuthorizationProfile,
  ApplicationAuthorizationSubjects,
  ApplicationPermissionDefinition,
  ApplicationPermissionOverride,
  ApplicationProfileRole,
  PermissionInfo
} from "../../types";

export function applicationAuthorizationPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/authorization`;
}

export function applicationAuthorizationCatalogPath(applicationId: string): string {
  return `${applicationAuthorizationPath(applicationId)}/catalog`;
}

export function applicationAuthorizationSubjectsPath(applicationId: string): string {
  return `${applicationAuthorizationPath(applicationId)}/subjects`;
}

export function applicationAuthorizationProfilesPath(applicationId: string): string {
  return `${applicationAuthorizationPath(applicationId)}/profiles`;
}

export function applicationAuthorizationProfilePath(applicationId: string, profileId: string): string {
  return `${applicationAuthorizationProfilesPath(applicationId)}/${pathSegment(profileId)}`;
}

export function applicationAuthorizationProfileBindingsPath(applicationId: string, profileId: string): string {
  return `${applicationAuthorizationProfilePath(applicationId, profileId)}/bindings`;
}

export function applicationAuthorizationProfileCatalogPath(applicationId: string, profileId: string): string {
  return `${applicationAuthorizationProfilePath(applicationId, profileId)}/catalog`;
}

export function applicationAuthorizationProfileRolesPath(applicationId: string, profileId: string): string {
  return `${applicationAuthorizationProfilePath(applicationId, profileId)}/roles`;
}

export function applicationAuthorizationProfileRolePath(
  applicationId: string,
  profileId: string,
  roleId: string
): string {
  return `${applicationAuthorizationProfileRolesPath(applicationId, profileId)}/${pathSegment(roleId)}`;
}

export function applicationAuthorizationProfilePreviewPath(
  applicationId: string,
  profileId: string,
  userId: string
): string {
  return `${applicationAuthorizationProfilePath(applicationId, profileId)}/${pathSegment(userId)}`;
}

export type ApplicationProfileRoleInput = {
  role_key: string;
  name: string;
  description?: string | null;
  permissions?: string[];
  is_active?: boolean;
  is_default?: boolean;
};

export type ApplicationOrganizationRoleBindings = Record<string, string[]>;

/** Direct payload accepted by the profile-wide bindings PUT endpoint. */
export type ApplicationAuthorizationBindingsInput = {
  user_id: string | null;
  group_id: string | null;
  user_role_ids: string[];
  user_permission_overrides: ApplicationPermissionOverride[];
  group_role_ids: string[];
  organization_role_bindings: ApplicationOrganizationRoleBindings;
};

export type ApplicationAuthorizationUserBinding = {
  user_role_ids: string[];
  user_permission_overrides: ApplicationPermissionOverride[];
};

/** Full representation returned by the profile-wide bindings GET/PUT APIs. */
export type ApplicationAuthorizationBindingsSnapshot = {
  application_id: string;
  profile_id: string;
  user_bindings: Record<string, ApplicationAuthorizationUserBinding>;
  group_bindings: Record<string, string[]>;
  organization_role_bindings: ApplicationOrganizationRoleBindings;
};

export type ApplicationAuthorizationBindingsResponse = ApplicationAuthorizationBindingsSnapshot;

/** Existing consumers may use this name for the aggregate response. */
export type ApplicationAuthorizationBindings = ApplicationAuthorizationBindingsSnapshot;

function stringList(value: unknown, label: string): string[] {
  return expectArray<unknown>(value, label).map((item, index) => expectString(item, `${label}[${index}]`));
}

function permissionOverrides(value: unknown, label: string): ApplicationPermissionOverride[] {
  return expectArray<unknown>(value, label).map((item, index) => {
    const override = expectRecord<Record<string, unknown>>(item, `${label}[${index}]`);
    const effect = expectString(override.effect, `${label}[${index}].effect`);
    if (effect !== "allow" && effect !== "deny") {
      throw new ApiDecodeError(`${label}[${index}].effect must be allow or deny`);
    }
    return {
      permission: expectString(override.permission, `${label}[${index}].permission`),
      effect
    };
  });
}

function stringListRecord(value: unknown, label: string): Record<string, string[]> {
  const record = expectRecord<Record<string, unknown>>(value, label);
  return Object.fromEntries(
    Object.entries(record).map(([key, roleIds]) => [key, stringList(roleIds, `${label}.${key}`)])
  );
}

function authorizationBindingsSnapshotResponse(
  value: unknown,
  label = "application authorization bindings"
): ApplicationAuthorizationBindingsSnapshot {
  const response = expectRecord<Record<string, unknown>>(value, label);
  const rawUserBindings = expectRecord<Record<string, unknown>>(
    response.user_bindings,
    `${label}.user_bindings`
  );
  const userBindings = Object.fromEntries(
    Object.entries(rawUserBindings).map(([userId, rawBinding]) => {
      const binding = expectRecord<Record<string, unknown>>(
        rawBinding,
        `${label}.user_bindings.${userId}`
      );
      return [userId, {
        user_role_ids: stringList(binding.user_role_ids, `${label}.user_bindings.${userId}.user_role_ids`),
        user_permission_overrides: permissionOverrides(
          binding.user_permission_overrides,
          `${label}.user_bindings.${userId}.user_permission_overrides`
        )
      }];
    })
  );
  return {
    application_id: expectString(response.application_id, `${label}.application_id`),
    profile_id: expectString(response.profile_id, `${label}.profile_id`),
    user_bindings: userBindings,
    group_bindings: stringListRecord(response.group_bindings, `${label}.group_bindings`),
    organization_role_bindings: stringListRecord(
      response.organization_role_bindings,
      `${label}.organization_role_bindings`
    )
  };
}

export function listApplicationPermissionCatalog(
  applicationId: string,
  options?: CachedReadOptions
): Promise<PermissionInfo[]> {
  return readCached<PermissionInfo[]>(applicationAuthorizationCatalogPath(applicationId), options, arrayResponse);
}

export function listApplicationAuthorizationSubjects(
  applicationId: string,
  options?: CachedReadOptions
): Promise<ApplicationAuthorizationSubjects> {
  return readCached<ApplicationAuthorizationSubjects>(
    applicationAuthorizationSubjectsPath(applicationId),
    options,
    objectResponse
  );
}

export function listApplicationAuthorizationProfiles(
  applicationId: string,
  options?: CachedReadOptions
): Promise<ApplicationAuthorizationProfile[]> {
  return readCached<ApplicationAuthorizationProfile[]>(
    applicationAuthorizationProfilesPath(applicationId),
    options,
    arrayResponse
  );
}

export function getApplicationAuthorizationProfile(
  applicationId: string,
  profileId: string,
  options?: CachedReadOptions
): Promise<ApplicationAuthorizationProfile> {
  return readCached<ApplicationAuthorizationProfile>(
    applicationAuthorizationProfilePath(applicationId, profileId),
    options,
    objectResponse
  );
}

export function listApplicationAuthorizationBindings(
  applicationId: string,
  profileId: string,
  options?: CachedReadOptions
): Promise<ApplicationAuthorizationBindingsSnapshot> {
  return readCached<ApplicationAuthorizationBindingsSnapshot>(
    applicationAuthorizationProfileBindingsPath(applicationId, profileId),
    options,
    authorizationBindingsSnapshotResponse
  );
}

export function updateApplicationAuthorizationBindings(
  applicationId: string,
  profileId: string,
  input: ApplicationAuthorizationBindingsInput,
  options?: ApiMutationOptions
): Promise<ApplicationAuthorizationBindingsSnapshot> {
  return writeJson<ApplicationAuthorizationBindingsSnapshot, ApplicationAuthorizationBindingsInput>(
    applicationAuthorizationProfileBindingsPath(applicationId, profileId),
    "PUT",
    input,
    options,
    authorizationBindingsSnapshotResponse
  );
}

export function listApplicationProfilePermissionCatalog(
  applicationId: string,
  profileId: string,
  options?: CachedReadOptions
): Promise<ApplicationPermissionDefinition[]> {
  return readCached<ApplicationPermissionDefinition[]>(
    applicationAuthorizationProfileCatalogPath(applicationId, profileId),
    options,
    arrayResponse
  );
}

export function listApplicationProfileRoles(
  applicationId: string,
  profileId: string,
  options?: CachedReadOptions
): Promise<ApplicationProfileRole[]> {
  return readCached<ApplicationProfileRole[]>(
    applicationAuthorizationProfileRolesPath(applicationId, profileId),
    options,
    arrayResponse
  );
}

export function createApplicationProfileRole(
  applicationId: string,
  profileId: string,
  input: ApplicationProfileRoleInput,
  options?: ApiMutationOptions
): Promise<ApplicationProfileRole> {
  return writeJson<ApplicationProfileRole, ApplicationProfileRoleInput>(
    applicationAuthorizationProfileRolesPath(applicationId, profileId),
    "POST",
    input,
    options
  );
}

export function updateApplicationProfileRole(
  applicationId: string,
  profileId: string,
  roleId: string,
  input: ApplicationProfileRoleInput,
  options?: ApiMutationOptions
): Promise<ApplicationProfileRole> {
  return writeJson<ApplicationProfileRole, ApplicationProfileRoleInput>(
    applicationAuthorizationProfileRolePath(applicationId, profileId, roleId),
    "PUT",
    input,
    options
  );
}

export function deleteApplicationProfileRole(
  applicationId: string,
  profileId: string,
  roleId: string,
  options?: ApiMutationOptions
): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(
    applicationAuthorizationProfileRolePath(applicationId, profileId, roleId),
    "DELETE",
    undefined,
    options
  );
}

export function getApplicationProfileAuthorizationPreview(
  applicationId: string,
  profileId: string,
  userId: string,
  options?: CachedReadOptions
): Promise<ApplicationAuthorizationPreview> {
  return readCached<ApplicationAuthorizationPreview>(
    applicationAuthorizationProfilePreviewPath(applicationId, profileId, userId),
    options,
    objectResponse
  );
}
