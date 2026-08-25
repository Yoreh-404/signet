import * as applicationAuthorizationApi from "../../lib/api/application-authorization";
import type {
  ApplicationAuthorizationBindingsInput,
  ApplicationAuthorizationBindingsSnapshot,
  ApplicationPermissionOverride
} from "../../lib/api/application-authorization";

/** The one canonical scope edited by the authorization workspace. */
export type AuthorizationBindingScope = {
  applicationId: string;
  profileId: string;
  userId: string | null;
  groupId: string | null;
  organizationRoles: string[];
};

export type AuthorizationBindingDraft = {
  userRoleIds: string[];
  userPermissionOverrides: ApplicationPermissionOverride[];
  groupRoleIds: string[];
  organizationRoleIds: Record<string, string[]>;
};

export type AuthorizationBindingSnapshot = AuthorizationBindingDraft;

export type AuthorizationBindingRequestOptions = {
  signal?: AbortSignal;
  idempotencyKey?: string;
};

export type AuthorizationBindingReadOptions = {
  signal?: AbortSignal;
  force?: boolean;
  key?: string;
  minRevalidateMs?: number;
};

/**
 * Authorization bindings are an aggregate. There is intentionally no
 * per-edge gateway: four independent writes cannot preserve the profile
 * invariant and create needless request/cache state in the browser.
 */
export type AuthorizationBindingsGateway = {
  listBindings: (
    applicationId: string,
    profileId: string,
    options?: AuthorizationBindingReadOptions
  ) => Promise<ApplicationAuthorizationBindingsSnapshot>;
  updateBindings: (
    applicationId: string,
    profileId: string,
    input: ApplicationAuthorizationBindingsInput,
    options?: AuthorizationBindingRequestOptions
  ) => Promise<ApplicationAuthorizationBindingsSnapshot>;
};

export type AuthorizationBindingsSaveResult =
  | { kind: "saved" }
  | { kind: "reconciled"; snapshot: AuthorizationBindingSnapshot }
  | { kind: "failed" }
  | { kind: "stale" };

const defaultGateway: AuthorizationBindingsGateway = {
  listBindings: applicationAuthorizationApi.listApplicationAuthorizationBindings,
  updateBindings: applicationAuthorizationApi.updateApplicationAuthorizationBindings
};

function snapshotFromAggregate(
  scope: AuthorizationBindingScope,
  value: ApplicationAuthorizationBindingsSnapshot
): AuthorizationBindingSnapshot {
  const userBinding = scope.userId ? value.user_bindings[scope.userId] : undefined;
  return {
    userRoleIds: [...(userBinding?.user_role_ids ?? [])],
    userPermissionOverrides: (userBinding?.user_permission_overrides ?? []).map((override) => ({ ...override })),
    groupRoleIds: scope.groupId ? [...(value.group_bindings[scope.groupId] ?? [])] : [],
    organizationRoleIds: Object.fromEntries(
      Object.entries(value.organization_role_bindings).map(([role, roleIds]) => [role, [...roleIds]])
    )
  };
}

function aggregateInput(
  scope: AuthorizationBindingScope,
  draft: AuthorizationBindingDraft
): ApplicationAuthorizationBindingsInput {
  return {
    user_id: scope.userId,
    group_id: scope.groupId,
    user_role_ids: [...draft.userRoleIds],
    user_permission_overrides: draft.userPermissionOverrides.map((override) => ({ ...override })),
    group_role_ids: [...draft.groupRoleIds],
    organization_role_bindings: Object.fromEntries(
      scope.organizationRoles.map((role) => [role, [...(draft.organizationRoleIds[role] ?? [])]])
    )
  };
}

export async function reconcileAuthorizationBindings(
  scope: AuthorizationBindingScope,
  isCurrent: () => boolean,
  gateway: AuthorizationBindingsGateway = defaultGateway,
  options: AuthorizationBindingReadOptions = {}
): Promise<AuthorizationBindingSnapshot | null> {
  const aggregate = await gateway.listBindings(
    scope.applicationId,
    scope.profileId,
    { ...options, force: true }
  );
  if (!isCurrent()) return null;
  return snapshotFromAggregate(scope, aggregate);
}

export async function persistAuthorizationBindings(
  scope: AuthorizationBindingScope,
  draft: AuthorizationBindingDraft,
  isCurrent: () => boolean,
  gateway: AuthorizationBindingsGateway = defaultGateway,
  options: AuthorizationBindingRequestOptions = {}
): Promise<AuthorizationBindingsSaveResult> {
  if (!isCurrent()) return { kind: "stale" };
  try {
    await gateway.updateBindings(
      scope.applicationId,
      scope.profileId,
      aggregateInput(scope, draft),
      options
    );
    return isCurrent() ? { kind: "saved" } : { kind: "stale" };
  } catch {
    if (!isCurrent()) return { kind: "stale" };
    try {
      const snapshot = await reconcileAuthorizationBindings(scope, isCurrent, gateway, options);
      return snapshot ? { kind: "reconciled", snapshot } : { kind: "stale" };
    } catch {
      return { kind: "failed" };
    }
  }
}
