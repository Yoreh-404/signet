import { Circle, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import * as applicationApi from "../../lib/api/applications";
import * as applicationAuthorizationApi from "../../lib/api/application-authorization";
import { stableDomainEqual } from "../admin/stable-domain-comparator";
import type {
  DirtyNavigationController,
  DirtyNavigationSourceHandle,
} from "../navigation/useDirtyNavigation";
import type { ApplicationModule, TenantApplication } from "../../types";
import type {
  ApplicationAuthorizationPreview,
  ApplicationAuthorizationProfile,
  ApplicationAuthorizationSubjects,
  ApplicationPermissionDefinition,
  ApplicationPermissionOverride,
  ApplicationProfileRole,
} from "../../lib/api/application-authorization";
import {
  persistAuthorizationBindings,
  reconcileAuthorizationBindings,
  type AuthorizationBindingSnapshot,
  type AuthorizationBindingScope,
} from "./authorization-bindings-service";
import type {
  ApplicationRequestGuard,
  ApplicationRequestToken,
} from "./application-request-guard";
import { record, stringList } from "./application-module-values";
import { ApplicationAuthorizationBindingsSection } from "./ApplicationAuthorizationBindingsSection";
import {
  ApplicationAuthorizationRoleSection,
  type ApplicationRoleDraft,
} from "./ApplicationAuthorizationRoleSection";
import {
  Input,
  ModuleHeader,
  ModuleSave,
} from "./components/ApplicationModulePrimitives";

export const APPLICATION_AUTHORIZATION_DIRTY_SOURCE =
  "applications.authorization";

export type ApplicationAuthorizationCopy = {
  permissions: string;
  save: string;
  saving: string;
  saved: string;
  saveFailed: string;
  active: string;
  disabled: string;
  notConfigured: string;
  noModuleConfig: string;
  unsavedChanges: string;
  discardChanges: string;
  authorizationHint: string;
  authorizationProfile: string;
  authorizationProfileHint: string;
  noAuthorizationProfile: string;
  setupNextHint: string;
  profileManual: string;
  profileNoDefinition: string;
  permissionTree: string;
  roleKey: string;
  inheritEnterpriseHint: string;
  defaultRole: string;
  customRoles: string;
  customRolesHint: string;
  claims: string;
  claimsHint: string;
  roleName: string;
  roleDescription: string;
  rolePermissions: string;
  rolePermissionsHint: string;
  customPermissions: string;
  customPermissionsHint: string;
  activeRole: string;
  editRole: string;
  deleteRole: string;
  noApplicationRoles: string;
  defaultRoleDeleteHint: string;
  addRole: string;
  removeRole: string;
  loginBoundaryNote: string;
  userRoleBindings: string;
  userRoleBindingsHint: string;
  selectUser: string;
  noAuthorizationUsers: string;
  groupRoleBindings: string;
  groupRoleBindingsHint: string;
  selectGroup: string;
  noAuthorizationGroups: string;
  enterpriseRoleMappings: string;
  enterpriseRoleMappingsHint: string;
  permissionOverrides: string;
  permissionOverridesHint: string;
  inheritPermission: string;
  allowPermission: string;
  denyPermission: string;
  customOverrides: string;
  customOverridesHint: string;
  saveBindings: string;
  authorizationPreview: string;
  authorizationPreviewHint: string;
  runPreview: string;
  previewEmpty: string;
  previewAllowed: string;
  previewDenied: string;
  previewRoles: string;
  previewPermissions: string;
  previewGroups: string;
  previewPolicyVersion: string;
};

export type ApplicationAuthorizationModuleProps = {
  application: TenantApplication;
  authorizationConfig: Record<string, unknown>;
  canManage: boolean;
  copy: ApplicationAuthorizationCopy;
  requestGuard: ApplicationRequestGuard;
  dirtyNavigation: Pick<
    DirtyNavigationController,
    "getSnapshot" | "registerSource"
  >;
  onApplicationModuleChanged: (
    applicationId: string,
    module: ApplicationModule,
  ) => void;
  hasUnsavedChanges: () => boolean;
  onDiscardChanges: () => void;
  onRequestConfirmation?: (
    action: () => Promise<void> | void,
    title: string,
    description: string,
  ) => void;
};

function applicationRoleDraft(
  role: ApplicationProfileRole,
): ApplicationRoleDraft {
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

function normalizedPermissionList(values: string[]): string[] {
  return Array.from(
    new Set(values.map((value) => value.trim()).filter(Boolean)),
  );
}

export function ApplicationAuthorizationModule({
  application,
  authorizationConfig,
  canManage,
  copy,
  requestGuard,
  dirtyNavigation,
  onApplicationModuleChanged,
  hasUnsavedChanges,
  onDiscardChanges,
  onRequestConfirmation,
}: ApplicationAuthorizationModuleProps) {
  const [draftConfig, setDraftConfig] =
    useState<Record<string, unknown>>(authorizationConfig);
  const [savedConfig, setSavedConfig] =
    useState<Record<string, unknown>>(authorizationConfig);
  const [authorizationProfiles, setAuthorizationProfiles] = useState<
    ApplicationAuthorizationProfile[]
  >([]);
  const [selectedAuthorizationProfileId, setSelectedAuthorizationProfileId] =
    useState("");
  const [applicationRoles, setApplicationRoles] = useState<
    ApplicationProfileRole[]
  >([]);
  const [applicationPermissionCatalog, setApplicationPermissionCatalog] =
    useState<ApplicationPermissionDefinition[]>([]);
  const [roleDraft, setRoleDraft] = useState<ApplicationRoleDraft | null>(null);
  const [roleSaving, setRoleSaving] = useState(false);
  const [roleFeedback, setRoleFeedback] = useState("");
  const [authorizationSubjects, setAuthorizationSubjects] =
    useState<ApplicationAuthorizationSubjects | null>(null);
  const [selectedAuthorizationUserId, setSelectedAuthorizationUserId] =
    useState("");
  const [selectedAuthorizationGroupId, setSelectedAuthorizationGroupId] =
    useState("");
  const [userRoleIds, setUserRoleIds] = useState<string[]>([]);
  const [groupRoleIds, setGroupRoleIds] = useState<string[]>([]);
  const [organizationRoleIds, setOrganizationRoleIds] = useState<
    Record<string, string[]>
  >({});
  const [userPermissionOverrides, setUserPermissionOverrides] = useState<
    ApplicationPermissionOverride[]
  >([]);
  const [authorizationPreview, setAuthorizationPreview] =
    useState<ApplicationAuthorizationPreview | null>(null);
  const [authorizationLoading, setAuthorizationLoading] = useState(false);
  const [authorizationSaving, setAuthorizationSaving] = useState(false);
  const [authorizationFeedback, setAuthorizationFeedback] = useState("");
  const [authorizationBindingsDirty, setAuthorizationBindingsDirty] =
    useState(false);
  const [moduleSaving, setModuleSaving] = useState(false);
  const [moduleFeedback, setModuleFeedback] = useState("");
  const dirtySourceRef = useRef<DirtyNavigationSourceHandle | null>(null);

  const selectedAuthorizationProfile =
    authorizationProfiles.find(
      (profile) => profile.id === selectedAuthorizationProfileId,
    ) ?? null;
  const knownPermissions = useMemo(
    () =>
      new Set(applicationPermissionCatalog.map((permission) => permission.key)),
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

  function requestOptions(token: ApplicationRequestToken) {
    return {
      signal: token.signal,
      ...(token.idempotencyKey ? { idempotencyKey: token.idempotencyKey } : {}),
    };
  }

  function isCurrentApplicationRequest(
    token: ApplicationRequestToken,
  ): boolean {
    return requestGuard.isCurrent(token);
  }

  function hasUnsavedAuthorizationChanges(): boolean {
    return (
      authorizationBindingsDirty ||
      roleDraft !== null ||
      !stableDomainEqual(draftConfig, savedConfig)
    );
  }

  useEffect(() => {
    const source = dirtyNavigation.registerSource(
      APPLICATION_AUTHORIZATION_DIRTY_SOURCE,
    );
    dirtySourceRef.current = source;
    return () => {
      source.unregister();
      if (dirtySourceRef.current === source) dirtySourceRef.current = null;
    };
  }, [dirtyNavigation.registerSource]);

  useEffect(() => {
    dirtySourceRef.current?.setDirty(hasUnsavedAuthorizationChanges());
  }, [authorizationBindingsDirty, draftConfig, roleDraft, savedConfig]);

  useEffect(() => {
    const request = requestGuard.begin(application.id, {
      scope: "authorization:subjects",
      kind: "read",
    });
    if (!request) return;
    setAuthorizationBindingsDirty(false);
    void Promise.all([
      applicationAuthorizationApi.listApplicationAuthorizationProfiles(
        application.id,
        requestOptions(request),
      ),
      applicationAuthorizationApi.listApplicationAuthorizationSubjects(
        application.id,
        requestOptions(request),
      ),
    ])
      .then(([profiles, subjects]) => {
        if (!isCurrentApplicationRequest(request)) return;
        setAuthorizationProfiles(profiles);
        setSelectedAuthorizationProfileId((current) =>
          current && profiles.some((profile) => profile.id === current)
            ? current
            : (profiles[0]?.id ?? ""),
        );
        setAuthorizationSubjects(subjects);
        setSelectedAuthorizationUserId(subjects.users[0]?.user_id ?? "");
        setSelectedAuthorizationGroupId(subjects.groups[0]?.id ?? "");
      })
      .catch(() => {
        if (!isCurrentApplicationRequest(request)) return;
        setAuthorizationProfiles([]);
        setSelectedAuthorizationProfileId("");
        setApplicationRoles([]);
        setApplicationPermissionCatalog([]);
        setAuthorizationSubjects(null);
      });
    return () => requestGuard.finish(request, false);
  }, [application, requestGuard]);

  useEffect(() => {
    if (!selectedAuthorizationProfileId) {
      setApplicationRoles([]);
      setApplicationPermissionCatalog([]);
      return;
    }
    const request = requestGuard.begin(application.id, {
      scope: `authorization:profile:${selectedAuthorizationProfileId}`,
      kind: "read",
    });
    if (!request) return;
    void Promise.all([
      applicationAuthorizationApi.listApplicationProfileRoles(
        application.id,
        selectedAuthorizationProfileId,
        requestOptions(request),
      ),
      applicationAuthorizationApi.listApplicationProfilePermissionCatalog(
        application.id,
        selectedAuthorizationProfileId,
        requestOptions(request),
      ),
    ])
      .then(([roles, catalog]) => {
        if (!isCurrentApplicationRequest(request)) return;
        setApplicationRoles(roles);
        setApplicationPermissionCatalog(catalog);
      })
      .catch(() => {
        if (!isCurrentApplicationRequest(request)) return;
        setApplicationRoles([]);
        setApplicationPermissionCatalog([]);
        setAuthorizationFeedback(copy.saveFailed);
      });
    return () => requestGuard.finish(request, false);
  }, [
    application,
    copy.saveFailed,
    requestGuard,
    selectedAuthorizationProfileId,
  ]);

  useEffect(() => {
    const organizationRoles = authorizationSubjects?.organization_roles ?? [];
    if (!selectedAuthorizationProfileId) {
      setUserRoleIds([]);
      setUserPermissionOverrides([]);
      setGroupRoleIds([]);
      setOrganizationRoleIds({});
      setAuthorizationLoading(false);
      return;
    }
    const request = requestGuard.begin(application.id, {
      scope: `authorization:bindings:${selectedAuthorizationProfileId}:${selectedAuthorizationUserId}:${selectedAuthorizationGroupId}`,
      kind: "read",
    });
    if (!request) return;
    setAuthorizationLoading(true);
    const scope: AuthorizationBindingScope = {
      applicationId: application.id,
      profileId: selectedAuthorizationProfileId,
      userId: selectedAuthorizationUserId || null,
      groupId: selectedAuthorizationGroupId || null,
      organizationRoles,
    };
    void reconcileAuthorizationBindings(
      scope,
      () => isCurrentApplicationRequest(request),
      undefined,
      { signal: request.signal },
    )
      .then((snapshot) => {
        if (!snapshot || !isCurrentApplicationRequest(request)) return;
        setUserRoleIds(snapshot.userRoleIds);
        setUserPermissionOverrides(snapshot.userPermissionOverrides);
        setGroupRoleIds(snapshot.groupRoleIds);
        setOrganizationRoleIds(
          Object.fromEntries(
            organizationRoles.map((role) => [
              role,
              [...(snapshot.organizationRoleIds[role] ?? [])],
            ]),
          ),
        );
        setAuthorizationPreview(null);
      })
      .catch(() => {
        // Keep the previous binding state visible on an authorization or
        // server error. An error response is not an empty assignment set.
        if (isCurrentApplicationRequest(request))
          setAuthorizationFeedback(copy.saveFailed);
      })
      .finally(() => {
        if (isCurrentApplicationRequest(request))
          setAuthorizationLoading(false);
      });
    return () => requestGuard.finish(request, false);
  }, [
    application,
    authorizationSubjects,
    copy.saveFailed,
    requestGuard,
    selectedAuthorizationGroupId,
    selectedAuthorizationProfileId,
    selectedAuthorizationUserId,
  ]);

  function resetAuthorizationDrafts() {
    setDraftConfig(savedConfig);
    setRoleDraft(null);
    setAuthorizationBindingsDirty(false);
    setUserRoleIds([]);
    setGroupRoleIds([]);
    setOrganizationRoleIds({});
    setUserPermissionOverrides([]);
    setAuthorizationPreview(null);
    setAuthorizationFeedback("");
  }

  function selectAuthorizationUser(nextId: string) {
    if (nextId === selectedAuthorizationUserId) return;
    const commit = () => {
      resetAuthorizationDrafts();
      onDiscardChanges();
      setSelectedAuthorizationUserId(nextId);
    };
    if (!hasUnsavedChanges()) {
      commit();
      return;
    }
    if (onRequestConfirmation) {
      onRequestConfirmation(commit, copy.unsavedChanges, copy.discardChanges);
    } else if (
      window.confirm(`${copy.unsavedChanges}\n${copy.discardChanges}?`)
    ) {
      commit();
    }
  }

  function selectAuthorizationGroup(nextId: string) {
    if (nextId === selectedAuthorizationGroupId) return;
    const commit = () => {
      resetAuthorizationDrafts();
      onDiscardChanges();
      setSelectedAuthorizationGroupId(nextId);
    };
    if (!hasUnsavedChanges()) {
      commit();
      return;
    }
    if (onRequestConfirmation) {
      onRequestConfirmation(commit, copy.unsavedChanges, copy.discardChanges);
    } else if (
      window.confirm(`${copy.unsavedChanges}\n${copy.discardChanges}?`)
    ) {
      commit();
    }
  }

  function selectAuthorizationProfile(nextId: string) {
    if (nextId === selectedAuthorizationProfileId) return;
    const commit = () => {
      resetAuthorizationDrafts();
      onDiscardChanges();
      setSelectedAuthorizationProfileId(nextId);
    };
    if (!hasUnsavedChanges()) {
      commit();
      return;
    }
    if (onRequestConfirmation) {
      onRequestConfirmation(commit, copy.unsavedChanges, copy.discardChanges);
    } else if (
      window.confirm(`${copy.unsavedChanges}\n${copy.discardChanges}?`)
    ) {
      commit();
    }
  }

  function startApplicationRole(role?: ApplicationProfileRole) {
    setRoleFeedback("");
    if (role) {
      setRoleDraft(applicationRoleDraft(role));
      return;
    }
    setRoleDraft({
      id: null,
      role_key: "",
      name: "",
      description: "",
      permissions: [],
      is_default: !applicationRoles.some(
        (item) => item.is_default && item.is_active,
      ),
      is_active: true,
      source: "manual",
    });
  }

  function updateRoleDraft(next: Partial<ApplicationRoleDraft>) {
    setRoleDraft((current) => (current ? { ...current, ...next } : current));
  }

  function toggleRolePermission(permission: string) {
    if (!roleDraft) return;
    const permissions = roleDraft.permissions.includes(permission)
      ? roleDraft.permissions.filter((item) => item !== permission)
      : [...roleDraft.permissions, permission];
    updateRoleDraft({ permissions: normalizedPermissionList(permissions) });
  }

  async function saveApplicationRole() {
    if (!selectedAuthorizationProfileId || !roleDraft) return;
    const request = requestGuard.begin(application.id, {
      scope: `authorization:role:${roleDraft.id ?? "new"}`,
      kind: "mutation",
      payloadFingerprint: JSON.stringify(roleDraft),
    });
    if (!request) return;
    const name = roleDraft.name.trim();
    const roleKey = roleDraft.role_key.trim();
    if (!name || !roleKey) {
      setRoleFeedback(copy.saveFailed);
      requestGuard.finish(request, false);
      return;
    }
    setRoleSaving(true);
    setRoleFeedback("");
    let committed = false;
    try {
      const payload = {
        role_key: roleKey,
        name,
        description: roleDraft.description.trim() || null,
        permissions: normalizedPermissionList(roleDraft.permissions),
        is_default: roleDraft.is_default,
        is_active: roleDraft.is_active,
      };
      if (roleDraft.id) {
        await applicationAuthorizationApi.updateApplicationProfileRole(
          application.id,
          selectedAuthorizationProfileId,
          roleDraft.id,
          payload,
          requestOptions(request),
        );
      } else {
        await applicationAuthorizationApi.createApplicationProfileRole(
          application.id,
          selectedAuthorizationProfileId,
          payload,
          requestOptions(request),
        );
      }
      const roles =
        await applicationAuthorizationApi.listApplicationProfileRoles(
          application.id,
          selectedAuthorizationProfileId,
          requestOptions(request),
        );
      if (!isCurrentApplicationRequest(request)) return;
      setApplicationRoles(roles);
      setRoleDraft(null);
      setRoleFeedback(copy.saved);
      committed = true;
    } catch {
      if (isCurrentApplicationRequest(request))
        setRoleFeedback(copy.saveFailed);
    } finally {
      if (isCurrentApplicationRequest(request)) setRoleSaving(false);
      requestGuard.finish(request, committed);
    }
  }

  async function deleteApplicationRole(role: ApplicationProfileRole) {
    if (!selectedAuthorizationProfileId || role.is_default) {
      setRoleFeedback(copy.defaultRoleDeleteHint);
      return;
    }
    if (!window.confirm(`${copy.deleteRole}: ${role.name}?`)) return;
    const request = requestGuard.begin(application.id, {
      scope: `authorization:role:${role.id}:delete`,
      kind: "mutation",
    });
    if (!request) return;
    setRoleSaving(true);
    setRoleFeedback("");
    let committed = false;
    try {
      await applicationAuthorizationApi.deleteApplicationProfileRole(
        application.id,
        selectedAuthorizationProfileId,
        role.id,
        requestOptions(request),
      );
      if (!isCurrentApplicationRequest(request)) return;
      setApplicationRoles((current) =>
        current.filter((item) => item.id !== role.id),
      );
      if (roleDraft?.id === role.id) setRoleDraft(null);
      setRoleFeedback(copy.saved);
      committed = true;
    } catch {
      if (isCurrentApplicationRequest(request))
        setRoleFeedback(copy.saveFailed);
    } finally {
      if (isCurrentApplicationRequest(request)) setRoleSaving(false);
      requestGuard.finish(request, committed);
    }
  }

  function toggleRoleId(roleIds: string[], roleId: string): string[] {
    return roleIds.includes(roleId)
      ? roleIds.filter((item) => item !== roleId)
      : [...roleIds, roleId];
  }

  function updateUserRoleIds(
    next: string[] | ((current: string[]) => string[]),
  ) {
    setUserRoleIds(next);
    setAuthorizationBindingsDirty(true);
  }

  function updateGroupRoleIds(
    next: string[] | ((current: string[]) => string[]),
  ) {
    setGroupRoleIds(next);
    setAuthorizationBindingsDirty(true);
  }

  function updateOrganizationRoleIds(
    next:
      | Record<string, string[]>
      | ((current: Record<string, string[]>) => Record<string, string[]>),
  ) {
    setOrganizationRoleIds(next);
    setAuthorizationBindingsDirty(true);
  }

  function updateUserPermissionOverrides(
    next:
      | ApplicationPermissionOverride[]
      | ((
          current: ApplicationPermissionOverride[],
        ) => ApplicationPermissionOverride[]),
  ) {
    setUserPermissionOverrides(next);
    setAuthorizationBindingsDirty(true);
  }

  function updatePermissionOverride(
    permission: string,
    effect: "" | "allow" | "deny",
  ) {
    updateUserPermissionOverrides((current) => {
      const withoutPermission = current.filter(
        (item) => item.permission !== permission,
      );
      if (!effect) return withoutPermission;
      return [...withoutPermission, { permission, effect }];
    });
    setAuthorizationPreview(null);
  }

  function updateCustomPermissionOverrides(value: string) {
    const standard = userPermissionOverrides.filter((item) =>
      knownPermissions.has(item.permission),
    );
    const custom = value
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const separator = line.indexOf(":");
        const effect =
          separator > 0 ? line.slice(0, separator).trim() : "allow";
        const permission = (
          separator > 0 ? line.slice(separator + 1) : line
        ).trim();
        return effect === "deny" && permission
          ? { permission, effect: "deny" as const }
          : permission
            ? { permission, effect: "allow" as const }
            : null;
      })
      .filter((item): item is ApplicationPermissionOverride => item !== null);
    updateUserPermissionOverrides([...standard, ...custom]);
    setAuthorizationPreview(null);
  }

  function applyAuthorizationBindingSnapshot(
    snapshot: AuthorizationBindingSnapshot,
  ) {
    setUserRoleIds(snapshot.userRoleIds);
    setUserPermissionOverrides(snapshot.userPermissionOverrides);
    setGroupRoleIds(snapshot.groupRoleIds);
    setOrganizationRoleIds(snapshot.organizationRoleIds);
    setAuthorizationBindingsDirty(false);
    setAuthorizationPreview(null);
  }

  async function saveAuthorizationBindings() {
    if (!selectedAuthorizationProfileId) return;
    const request = requestGuard.begin(application.id, {
      scope: "authorization:bindings",
      kind: "mutation",
      payloadFingerprint: JSON.stringify({
        profileId: selectedAuthorizationProfileId,
        userId: selectedAuthorizationUserId,
        groupId: selectedAuthorizationGroupId,
        userRoleIds,
        userPermissionOverrides,
        groupRoleIds,
        organizationRoleIds,
      }),
    });
    if (!request) return;
    setAuthorizationSaving(true);
    setAuthorizationFeedback("");
    let committed = false;
    try {
      const scope: AuthorizationBindingScope = {
        applicationId: application.id,
        profileId: selectedAuthorizationProfileId,
        userId: selectedAuthorizationUserId || null,
        groupId: selectedAuthorizationGroupId || null,
        organizationRoles: authorizationSubjects?.organization_roles ?? [],
      };
      const result = await persistAuthorizationBindings(
        scope,
        {
          userRoleIds,
          userPermissionOverrides,
          groupRoleIds,
          organizationRoleIds,
        },
        () => isCurrentApplicationRequest(request),
        undefined,
        requestOptions(request),
      );
      if (result.kind === "stale") return;
      if (result.kind === "reconciled")
        applyAuthorizationBindingSnapshot(result.snapshot);
      if (result.kind === "saved") {
        setAuthorizationBindingsDirty(false);
        setAuthorizationPreview(null);
        setAuthorizationFeedback(copy.saved);
        committed = true;
      } else {
        setAuthorizationFeedback(copy.saveFailed);
      }
    } catch {
      if (isCurrentApplicationRequest(request))
        setAuthorizationFeedback(copy.saveFailed);
    } finally {
      if (isCurrentApplicationRequest(request)) setAuthorizationSaving(false);
      requestGuard.finish(request, committed);
    }
  }

  async function runAuthorizationPreview() {
    if (!selectedAuthorizationProfileId || !selectedAuthorizationUserId) return;
    const request = requestGuard.begin(application.id, {
      scope: "authorization:preview",
      kind: "read",
    });
    if (!request) return;
    setAuthorizationLoading(true);
    setAuthorizationFeedback("");
    try {
      const preview =
        await applicationAuthorizationApi.getApplicationProfileAuthorizationPreview(
          application.id,
          selectedAuthorizationProfileId,
          selectedAuthorizationUserId,
          requestOptions(request),
        );
      if (!isCurrentApplicationRequest(request)) return;
      setAuthorizationPreview(preview);
    } catch {
      if (isCurrentApplicationRequest(request)) {
        setAuthorizationFeedback(copy.saveFailed);
        setAuthorizationPreview(null);
      }
    } finally {
      if (isCurrentApplicationRequest(request)) setAuthorizationLoading(false);
      requestGuard.finish(request, false);
    }
  }

  async function reloadAuthorizationModule(
    request: ApplicationRequestToken,
  ): Promise<ApplicationModule | null> {
    const modules = await applicationApi.listApplicationModules(
      application.id,
      {
        force: true,
        ...requestOptions(request),
      },
    );
    if (!isCurrentApplicationRequest(request)) return null;
    const module = modules.find((item) => item.module_key === "authorization");
    if (module) onApplicationModuleChanged(application.id, module);
    return module ?? null;
  }

  async function saveAuthorizationModule() {
    if (!canManage) return;
    const request = requestGuard.begin(application.id, {
      scope: "module:authorization",
      kind: "mutation",
      payloadFingerprint: JSON.stringify(draftConfig),
    });
    if (!request) return;
    setModuleSaving(true);
    setModuleFeedback("");
    let moduleWritten = false;
    let committed = false;
    try {
      const module = await applicationApi.updateApplicationModule(
        application.id,
        "authorization",
        {
          config: draftConfig,
          is_enabled: true,
        },
        requestOptions(request),
      );
      moduleWritten = true;
      if (!isCurrentApplicationRequest(request)) return;
      setDraftConfig(module.config);
      setSavedConfig(module.config);
      onApplicationModuleChanged(application.id, module);
      setModuleFeedback(copy.saved);
      committed = true;
    } catch {
      if (isCurrentApplicationRequest(request)) {
        try {
          const reloaded = await reloadAuthorizationModule(request);
          if (reloaded && moduleWritten) {
            setDraftConfig(reloaded.config);
            setSavedConfig(reloaded.config);
          }
        } catch {
          // Keep the draft when the reconciliation read also fails. The
          // dirty state gives the user a safe retry path for an unknown write outcome.
        }
        if (isCurrentApplicationRequest(request))
          setModuleFeedback(copy.saveFailed);
      }
    } finally {
      if (isCurrentApplicationRequest(request)) setModuleSaving(false);
      requestGuard.finish(request, committed);
    }
  }

  const config = draftConfig;
  const claims = stringList(config.claims);
  const customRolePermissions = roleDraft
    ? roleDraft.permissions.filter(
        (permission) => !knownPermissions.has(permission),
      )
    : [];
  const authorizationUsers = authorizationSubjects?.users ?? [];
  const authorizationGroups = authorizationSubjects?.groups ?? [];
  const customOverrideLines = userPermissionOverrides
    .filter((override) => !knownPermissions.has(override.permission))
    .map((override) => `${override.effect}:${override.permission}`)
    .join("\n");

  return (
    <div className="application-module-content">
      <ModuleHeader
        icon={<ShieldCheck size={19} />}
        title={copy.permissions}
        description={copy.authorizationHint}
      />
      {authorizationProfiles.length === 0 ? (
        <div className="module-setting-card authorization-empty-profile">
          <strong>{copy.noAuthorizationProfile}</strong>
          <p className="muted">{copy.setupNextHint}</p>
        </div>
      ) : (
        <div className="module-setting-card">
          <div className="authorization-profile-panel">
            <div className="subsection-heading">
              <div>
                <strong>{copy.authorizationProfile}</strong>
                <p className="muted">{copy.authorizationProfileHint}</p>
              </div>
              <span>{authorizationProfiles.length}</span>
            </div>
            <label className="application-input">
              <span>{copy.authorizationProfile}</span>
              <select
                value={selectedAuthorizationProfileId}
                onChange={(event) =>
                  selectAuthorizationProfile(event.target.value)
                }
              >
                {authorizationProfiles.map((profile) => (
                  <option value={profile.id} key={profile.id}>
                    {profile.profile_key}
                  </option>
                ))}
              </select>
            </label>
            {selectedAuthorizationProfile && (
              <>
                <div className="authorization-profile-mode-row">
                  <span className="application-role-badge default">
                    {copy.profileManual}
                  </span>
                  <span className="muted">
                    {selectedAuthorizationProfile.sync_status}
                  </span>
                </div>
                {selectedAuthorizationProfile.last_error && (
                  <p className="module-save-error" role="alert">
                    {selectedAuthorizationProfile.last_error}
                  </p>
                )}
                {selectedAuthorizationProfile.source_mode === "manual" && (
                  <p className="module-note">
                    <Circle size={11} />
                    {copy.profileNoDefinition}
                  </p>
                )}
              </>
            )}
          </div>
          <div className="module-divider" />
          <p className="module-note">
            <Circle size={11} />
            {copy.loginBoundaryNote}
          </p>
          <div className="module-divider" />
          <ApplicationAuthorizationRoleSection
            canManage={canManage}
            copy={copy}
            applicationRoles={applicationRoles}
            applicationPermissionCatalog={applicationPermissionCatalog}
            roleDraft={roleDraft}
            roleDraftPermissionSet={roleDraftPermissionSet}
            customRolePermissions={customRolePermissions}
            roleSaving={roleSaving}
            roleFeedback={roleFeedback}
            onStartRole={startApplicationRole}
            onDeleteRole={(role) => void deleteApplicationRole(role)}
            onUpdateRole={updateRoleDraft}
            onTogglePermission={toggleRolePermission}
            onClearRole={() => setRoleDraft(null)}
            onSaveRole={() => void saveApplicationRole()}
            normalizedPermissionList={normalizedPermissionList}
          />
          <div className="module-divider" />
          <ApplicationAuthorizationBindingsSection
            copy={copy}
            canManage={canManage}
            applicationRoles={applicationRoles}
            applicationPermissionCatalog={applicationPermissionCatalog}
            authorizationSubjects={authorizationSubjects}
            selectedAuthorizationUserId={selectedAuthorizationUserId}
            selectedAuthorizationGroupId={selectedAuthorizationGroupId}
            userRoleIdSet={userRoleIdSet}
            groupRoleIdSet={groupRoleIdSet}
            organizationRoleIdSets={organizationRoleIdSets}
            userPermissionOverrides={userPermissionOverrides}
            permissionOverridesByKey={permissionOverridesByKey}
            customOverrideLines={customOverrideLines}
            authorizationLoading={authorizationLoading}
            authorizationSaving={authorizationSaving}
            authorizationFeedback={authorizationFeedback}
            authorizationPreview={authorizationPreview}
            authorizationUsers={authorizationUsers}
            authorizationGroups={authorizationGroups}
            onSelectUser={selectAuthorizationUser}
            onSelectGroup={selectAuthorizationGroup}
            onUpdateUserRoles={updateUserRoleIds}
            onUpdateGroupRoles={updateGroupRoleIds}
            onUpdateOrganizationRoles={updateOrganizationRoleIds}
            onUpdatePermissionOverride={updatePermissionOverride}
            onUpdateCustomOverrides={updateCustomPermissionOverrides}
            onSave={() => void saveAuthorizationBindings()}
            onPreview={() => void runAuthorizationPreview()}
            toggleRoleId={toggleRoleId}
          />
          <div className="module-divider" />
          <p className="module-note">{copy.loginBoundaryNote}</p>
          <Input
            label={copy.claims}
            hint={copy.claimsHint}
            value={claims.join("\n")}
            textarea
            onChange={(value) =>
              setDraftConfig({
                ...config,
                claims: value
                  .split(/\r?\n/)
                  .map((item) => item.trim())
                  .filter(Boolean),
              })
            }
          />
        </div>
      )}
      <ModuleSave
        saving={moduleSaving}
        feedback={moduleFeedback}
        copy={copy}
        onSave={() => void saveAuthorizationModule()}
      />
    </div>
  );
}
