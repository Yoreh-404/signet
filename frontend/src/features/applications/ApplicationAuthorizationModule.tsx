import {
  ArrowRight,
  ChevronRight,
  Circle,
  Eye,
  Pencil,
  Plus,
  ShieldCheck,
  Trash2
} from "lucide-react";
import type { ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import * as applicationApi from "../../lib/api/applications";
import * as applicationAuthorizationApi from "../../lib/api/application-authorization";
import { stableDomainEqual } from "../admin/stable-domain-comparator";
import type {
  DirtyNavigationController,
  DirtyNavigationSourceHandle
} from "../navigation/useDirtyNavigation";
import type {
  ApplicationModule,
  TenantApplication
} from "../../types";
import type {
  ApplicationAuthorizationPreview,
  ApplicationAuthorizationProfile,
  ApplicationAuthorizationSubjects,
  ApplicationPermissionDefinition,
  ApplicationPermissionOverride,
  ApplicationProfileRole
} from "../../lib/api/application-authorization";
import {
  persistAuthorizationBindings,
  reconcileAuthorizationBindings,
  type AuthorizationBindingSnapshot,
  type AuthorizationBindingScope
} from "./authorization-bindings-service";
import type {
  ApplicationRequestGuard,
  ApplicationRequestToken
} from "./application-request-guard";
import { record, stringList } from "./application-module-values";
import { Input, ModuleHeader, ModuleSave, Toggle } from "./components/ApplicationModulePrimitives";

export const APPLICATION_AUTHORIZATION_DIRTY_SOURCE = "applications.authorization";

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

type ApplicationRoleDraft = {
  id: string | null;
  role_key: string;
  name: string;
  description: string;
  permissions: string[];
  is_default: boolean;
  is_active: boolean;
  source: string;
};

type PermissionTreeNode = {
  label: string;
  children: Map<string, PermissionTreeNode>;
  definition?: ApplicationPermissionDefinition;
};

export type ApplicationAuthorizationModuleProps = {
  application: TenantApplication;
  authorizationConfig: Record<string, unknown>;
  canManage: boolean;
  copy: ApplicationAuthorizationCopy;
  requestGuard: ApplicationRequestGuard;
  dirtyNavigation: Pick<DirtyNavigationController, "getSnapshot" | "registerSource">;
  onApplicationModuleChanged: (applicationId: string, module: ApplicationModule) => void;
  hasUnsavedChanges: () => boolean;
  onDiscardChanges: () => void;
  onRequestConfirmation?: (
    action: () => Promise<void> | void,
    title: string,
    description: string
  ) => void;
};

function applicationRoleDraft(role: ApplicationProfileRole): ApplicationRoleDraft {
  return {
    id: role.id,
    role_key: role.role_key,
    name: role.name,
    description: role.description ?? "",
    permissions: [...role.permissions],
    is_default: role.is_default,
    is_active: role.is_active,
    source: role.source
  };
}

function normalizedPermissionList(values: string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)));
}

function permissionTree(definitions: ApplicationPermissionDefinition[]): PermissionTreeNode[] {
  const root: PermissionTreeNode = { label: "", children: new Map() };
  for (const definition of definitions.filter((item) => item.is_active)) {
    const segments = definition.key.split(":");
    let current = root;
    segments.forEach((segment, index) => {
      let next = current.children.get(segment);
      if (!next) {
        next = { label: segment, children: new Map() };
        current.children.set(segment, next);
      }
      if (index === segments.length - 1) next.definition = definition;
      current = next;
    });
  }
  return Array.from(root.children.values()).sort((left, right) => left.label.localeCompare(right.label));
}

function PermissionTree({
  definitions,
  renderLeaf
}: {
  definitions: ApplicationPermissionDefinition[];
  renderLeaf: (definition: ApplicationPermissionDefinition) => ReactNode;
}) {
  function renderNode(node: PermissionTreeNode, depth: number): ReactNode {
    const children = Array.from(node.children.values()).sort((left, right) => left.label.localeCompare(right.label));
    return (
      <div className="permission-tree-node" key={`${node.definition?.key ?? node.label}-${depth}`}>
        {node.definition && renderLeaf(node.definition)}
        {!node.definition && <div className="permission-tree-branch"><ChevronRight size={13} /><strong>{node.label}</strong></div>}
        {children.length > 0 && <div className="permission-tree-children">{children.map((child) => renderNode(child, depth + 1))}</div>}
      </div>
    );
  }

  const nodes = useMemo(() => permissionTree(definitions), [definitions]);
  return <div className="permission-tree">{nodes.length > 0 ? nodes.map((node) => renderNode(node, 0)) : <p className="muted">{"—"}</p>}</div>;
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
  onRequestConfirmation
}: ApplicationAuthorizationModuleProps) {
  const [draftConfig, setDraftConfig] = useState<Record<string, unknown>>(authorizationConfig);
  const [savedConfig, setSavedConfig] = useState<Record<string, unknown>>(authorizationConfig);
  const [authorizationProfiles, setAuthorizationProfiles] = useState<ApplicationAuthorizationProfile[]>([]);
  const [selectedAuthorizationProfileId, setSelectedAuthorizationProfileId] = useState("");
  const [applicationRoles, setApplicationRoles] = useState<ApplicationProfileRole[]>([]);
  const [applicationPermissionCatalog, setApplicationPermissionCatalog] = useState<ApplicationPermissionDefinition[]>([]);
  const [roleDraft, setRoleDraft] = useState<ApplicationRoleDraft | null>(null);
  const [roleSaving, setRoleSaving] = useState(false);
  const [roleFeedback, setRoleFeedback] = useState("");
  const [authorizationSubjects, setAuthorizationSubjects] = useState<ApplicationAuthorizationSubjects | null>(null);
  const [selectedAuthorizationUserId, setSelectedAuthorizationUserId] = useState("");
  const [selectedAuthorizationGroupId, setSelectedAuthorizationGroupId] = useState("");
  const [userRoleIds, setUserRoleIds] = useState<string[]>([]);
  const [groupRoleIds, setGroupRoleIds] = useState<string[]>([]);
  const [organizationRoleIds, setOrganizationRoleIds] = useState<Record<string, string[]>>({});
  const [userPermissionOverrides, setUserPermissionOverrides] = useState<ApplicationPermissionOverride[]>([]);
  const [authorizationPreview, setAuthorizationPreview] = useState<ApplicationAuthorizationPreview | null>(null);
  const [authorizationLoading, setAuthorizationLoading] = useState(false);
  const [authorizationSaving, setAuthorizationSaving] = useState(false);
  const [authorizationFeedback, setAuthorizationFeedback] = useState("");
  const [authorizationBindingsDirty, setAuthorizationBindingsDirty] = useState(false);
  const [moduleSaving, setModuleSaving] = useState(false);
  const [moduleFeedback, setModuleFeedback] = useState("");
  const dirtySourceRef = useRef<DirtyNavigationSourceHandle | null>(null);

  const selectedAuthorizationProfile = authorizationProfiles.find((profile) => profile.id === selectedAuthorizationProfileId) ?? null;
  const knownPermissions = useMemo(
    () => new Set(applicationPermissionCatalog.map((permission) => permission.key)),
    [applicationPermissionCatalog]
  );
  const roleDraftPermissionSet = useMemo(
    () => new Set(roleDraft?.permissions ?? []),
    [roleDraft?.permissions]
  );
  const userRoleIdSet = useMemo(() => new Set(userRoleIds), [userRoleIds]);
  const groupRoleIdSet = useMemo(() => new Set(groupRoleIds), [groupRoleIds]);
  const organizationRoleIdSets = useMemo(
    () => new Map(Object.entries(organizationRoleIds).map(([key, ids]) => [key, new Set(ids)])),
    [organizationRoleIds]
  );
  const permissionOverridesByKey = useMemo(
    () => new Map(userPermissionOverrides.map((override) => [override.permission, override.effect])),
    [userPermissionOverrides]
  );

  function requestOptions(token: ApplicationRequestToken) {
    return {
      signal: token.signal,
      ...(token.idempotencyKey ? { idempotencyKey: token.idempotencyKey } : {})
    };
  }

  function isCurrentApplicationRequest(token: ApplicationRequestToken): boolean {
    return requestGuard.isCurrent(token);
  }

  function hasUnsavedAuthorizationChanges(): boolean {
    return authorizationBindingsDirty
      || roleDraft !== null
      || !stableDomainEqual(draftConfig, savedConfig);
  }

  useEffect(() => {
    const source = dirtyNavigation.registerSource(APPLICATION_AUTHORIZATION_DIRTY_SOURCE);
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
      kind: "read"
    });
    if (!request) return;
    setAuthorizationBindingsDirty(false);
    void Promise.all([
      applicationAuthorizationApi.listApplicationAuthorizationProfiles(application.id, requestOptions(request)),
      applicationAuthorizationApi.listApplicationAuthorizationSubjects(application.id, requestOptions(request))
    ])
      .then(([profiles, subjects]) => {
        if (!isCurrentApplicationRequest(request)) return;
        setAuthorizationProfiles(profiles);
        setSelectedAuthorizationProfileId((current) => current && profiles.some((profile) => profile.id === current)
          ? current
          : profiles[0]?.id ?? "");
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
      kind: "read"
    });
    if (!request) return;
    void Promise.all([
      applicationAuthorizationApi.listApplicationProfileRoles(application.id, selectedAuthorizationProfileId, requestOptions(request)),
      applicationAuthorizationApi.listApplicationProfilePermissionCatalog(application.id, selectedAuthorizationProfileId, requestOptions(request))
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
  }, [application, copy.saveFailed, requestGuard, selectedAuthorizationProfileId]);

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
      kind: "read"
    });
    if (!request) return;
    setAuthorizationLoading(true);
    const scope: AuthorizationBindingScope = {
      applicationId: application.id,
      profileId: selectedAuthorizationProfileId,
      userId: selectedAuthorizationUserId || null,
      groupId: selectedAuthorizationGroupId || null,
      organizationRoles
    };
    void reconcileAuthorizationBindings(
      scope,
      () => isCurrentApplicationRequest(request),
      undefined,
      { signal: request.signal }
    )
      .then((snapshot) => {
        if (!snapshot || !isCurrentApplicationRequest(request)) return;
        setUserRoleIds(snapshot.userRoleIds);
        setUserPermissionOverrides(snapshot.userPermissionOverrides);
        setGroupRoleIds(snapshot.groupRoleIds);
        setOrganizationRoleIds(Object.fromEntries(
          organizationRoles.map((role) => [role, [...(snapshot.organizationRoleIds[role] ?? [])]])
        ));
        setAuthorizationPreview(null);
      })
      .catch(() => {
        // Keep the previous binding state visible on an authorization or
        // server error. An error response is not an empty assignment set.
        if (isCurrentApplicationRequest(request)) setAuthorizationFeedback(copy.saveFailed);
      })
      .finally(() => {
        if (isCurrentApplicationRequest(request)) setAuthorizationLoading(false);
      });
    return () => requestGuard.finish(request, false);
  }, [application, authorizationSubjects, copy.saveFailed, requestGuard, selectedAuthorizationGroupId, selectedAuthorizationProfileId, selectedAuthorizationUserId]);

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
    } else if (window.confirm(`${copy.unsavedChanges}\n${copy.discardChanges}?`)) {
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
    } else if (window.confirm(`${copy.unsavedChanges}\n${copy.discardChanges}?`)) {
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
    } else if (window.confirm(`${copy.unsavedChanges}\n${copy.discardChanges}?`)) {
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
      is_default: !applicationRoles.some((item) => item.is_default && item.is_active),
      is_active: true,
      source: "manual"
    });
  }

  function updateRoleDraft(next: Partial<ApplicationRoleDraft>) {
    setRoleDraft((current) => current ? { ...current, ...next } : current);
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
      payloadFingerprint: JSON.stringify(roleDraft)
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
        is_active: roleDraft.is_active
      };
      if (roleDraft.id) {
        await applicationAuthorizationApi.updateApplicationProfileRole(
          application.id,
          selectedAuthorizationProfileId,
          roleDraft.id,
          payload,
          requestOptions(request)
        );
      } else {
        await applicationAuthorizationApi.createApplicationProfileRole(
          application.id,
          selectedAuthorizationProfileId,
          payload,
          requestOptions(request)
        );
      }
      const roles = await applicationAuthorizationApi.listApplicationProfileRoles(application.id, selectedAuthorizationProfileId, requestOptions(request));
      if (!isCurrentApplicationRequest(request)) return;
      setApplicationRoles(roles);
      setRoleDraft(null);
      setRoleFeedback(copy.saved);
      committed = true;
    } catch {
      if (isCurrentApplicationRequest(request)) setRoleFeedback(copy.saveFailed);
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
      kind: "mutation"
    });
    if (!request) return;
    setRoleSaving(true);
    setRoleFeedback("");
    let committed = false;
    try {
      await applicationAuthorizationApi.deleteApplicationProfileRole(application.id, selectedAuthorizationProfileId, role.id, requestOptions(request));
      if (!isCurrentApplicationRequest(request)) return;
      setApplicationRoles((current) => current.filter((item) => item.id !== role.id));
      if (roleDraft?.id === role.id) setRoleDraft(null);
      setRoleFeedback(copy.saved);
      committed = true;
    } catch {
      if (isCurrentApplicationRequest(request)) setRoleFeedback(copy.saveFailed);
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

  function updateUserRoleIds(next: string[] | ((current: string[]) => string[])) {
    setUserRoleIds(next);
    setAuthorizationBindingsDirty(true);
  }

  function updateGroupRoleIds(next: string[] | ((current: string[]) => string[])) {
    setGroupRoleIds(next);
    setAuthorizationBindingsDirty(true);
  }

  function updateOrganizationRoleIds(
    next: Record<string, string[]> | ((current: Record<string, string[]>) => Record<string, string[]>)
  ) {
    setOrganizationRoleIds(next);
    setAuthorizationBindingsDirty(true);
  }

  function updateUserPermissionOverrides(
    next: ApplicationPermissionOverride[]
      | ((current: ApplicationPermissionOverride[]) => ApplicationPermissionOverride[])
  ) {
    setUserPermissionOverrides(next);
    setAuthorizationBindingsDirty(true);
  }

  function updatePermissionOverride(permission: string, effect: "" | "allow" | "deny") {
    updateUserPermissionOverrides((current) => {
      const withoutPermission = current.filter((item) => item.permission !== permission);
      if (!effect) return withoutPermission;
      return [...withoutPermission, { permission, effect }];
    });
    setAuthorizationPreview(null);
  }

  function updateCustomPermissionOverrides(value: string) {
    const standard = userPermissionOverrides.filter((item) => knownPermissions.has(item.permission));
    const custom = value
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const separator = line.indexOf(":");
        const effect = separator > 0 ? line.slice(0, separator).trim() : "allow";
        const permission = (separator > 0 ? line.slice(separator + 1) : line).trim();
        return effect === "deny" && permission ? { permission, effect: "deny" as const } : permission ? { permission, effect: "allow" as const } : null;
      })
      .filter((item): item is ApplicationPermissionOverride => item !== null);
    updateUserPermissionOverrides([...standard, ...custom]);
    setAuthorizationPreview(null);
  }

  function applyAuthorizationBindingSnapshot(snapshot: AuthorizationBindingSnapshot) {
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
        organizationRoleIds
      })
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
        organizationRoles: authorizationSubjects?.organization_roles ?? []
      };
      const result = await persistAuthorizationBindings(
        scope,
        {
          userRoleIds,
          userPermissionOverrides,
          groupRoleIds,
          organizationRoleIds
        },
        () => isCurrentApplicationRequest(request),
        undefined,
        requestOptions(request)
      );
      if (result.kind === "stale") return;
      if (result.kind === "reconciled") applyAuthorizationBindingSnapshot(result.snapshot);
      if (result.kind === "saved") {
        setAuthorizationBindingsDirty(false);
        setAuthorizationPreview(null);
        setAuthorizationFeedback(copy.saved);
        committed = true;
      } else {
        setAuthorizationFeedback(copy.saveFailed);
      }
    } catch {
      if (isCurrentApplicationRequest(request)) setAuthorizationFeedback(copy.saveFailed);
    } finally {
      if (isCurrentApplicationRequest(request)) setAuthorizationSaving(false);
      requestGuard.finish(request, committed);
    }
  }

  async function runAuthorizationPreview() {
    if (!selectedAuthorizationProfileId || !selectedAuthorizationUserId) return;
    const request = requestGuard.begin(application.id, { scope: "authorization:preview", kind: "read" });
    if (!request) return;
    setAuthorizationLoading(true);
    setAuthorizationFeedback("");
    try {
      const preview = await applicationAuthorizationApi.getApplicationProfileAuthorizationPreview(
        application.id,
        selectedAuthorizationProfileId,
        selectedAuthorizationUserId,
        requestOptions(request)
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

  async function reloadAuthorizationModule(request: ApplicationRequestToken): Promise<ApplicationModule | null> {
    const modules = await applicationApi.listApplicationModules(application.id, {
      force: true,
      ...requestOptions(request)
    });
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
      payloadFingerprint: JSON.stringify(draftConfig)
    });
    if (!request) return;
    setModuleSaving(true);
    setModuleFeedback("");
    let moduleWritten = false;
    let committed = false;
    try {
      const module = await applicationApi.updateApplicationModule(application.id, "authorization", {
        config: draftConfig,
        is_enabled: true
      }, requestOptions(request));
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
        if (isCurrentApplicationRequest(request)) setModuleFeedback(copy.saveFailed);
      }
    } finally {
      if (isCurrentApplicationRequest(request)) setModuleSaving(false);
      requestGuard.finish(request, committed);
    }
  }

  const config = draftConfig;
  const claims = stringList(config.claims);
  const customRolePermissions = roleDraft
    ? roleDraft.permissions.filter((permission) => !knownPermissions.has(permission))
    : [];
  const authorizationUsers = authorizationSubjects?.users ?? [];
  const authorizationGroups = authorizationSubjects?.groups ?? [];
  const customOverrideLines = userPermissionOverrides
    .filter((override) => !knownPermissions.has(override.permission))
    .map((override) => `${override.effect}:${override.permission}`)
    .join("\n");

  return (
    <div className="application-module-content">
      <ModuleHeader icon={<ShieldCheck size={19} />} title={copy.permissions} description={copy.authorizationHint} />
      {authorizationProfiles.length === 0 ? (
        <div className="module-setting-card authorization-empty-profile">
          <strong>{copy.noAuthorizationProfile}</strong>
          <p className="muted">{copy.setupNextHint}</p>
        </div>
      ) : <div className="module-setting-card">
        <div className="authorization-profile-panel">
          <div className="subsection-heading">
            <div><strong>{copy.authorizationProfile}</strong><p className="muted">{copy.authorizationProfileHint}</p></div>
            <span>{authorizationProfiles.length}</span>
          </div>
          <label className="application-input">
            <span>{copy.authorizationProfile}</span>
            <select value={selectedAuthorizationProfileId} onChange={(event) => selectAuthorizationProfile(event.target.value)}>
              {authorizationProfiles.map((profile) => <option value={profile.id} key={profile.id}>{profile.profile_key}</option>)}
            </select>
          </label>
          {selectedAuthorizationProfile && <>
            <div className="authorization-profile-mode-row">
              <span className="application-role-badge default">{copy.profileManual}</span>
              <span className="muted">{selectedAuthorizationProfile.sync_status}</span>
            </div>
            {selectedAuthorizationProfile.last_error && <p className="module-save-error" role="alert">{selectedAuthorizationProfile.last_error}</p>}
            {selectedAuthorizationProfile.source_mode === "manual" && <p className="module-note"><Circle size={11} />{copy.profileNoDefinition}</p>}
          </>}
        </div>
        <div className="module-divider" />
        <p className="module-note"><Circle size={11} />{copy.loginBoundaryNote}</p>
        <div className="module-divider" />
        <div className="subsection-heading">
          <div><strong>{copy.customRoles}</strong><p className="muted">{copy.customRolesHint}</p></div>
          {canManage && <button type="button" className="secondary-button" onClick={() => startApplicationRole()} disabled={roleSaving}><Plus size={14} />{copy.addRole}</button>}
        </div>
        <div className="application-role-list">
          {applicationRoles.map((role) => (
            <article className={`application-role-record${role.is_active ? "" : " inactive"}`} key={role.id}>
              <div className="application-role-record-main">
                <strong>{role.name}</strong>
                <small><code>{role.role_key}</code> · {role.description || copy.noModuleConfig}</small>
                <div className="application-role-permission-summary">
                  {role.permissions.length > 0
                    ? role.permissions.map((permission) => <span key={permission}>{permission}</span>)
                    : <span>{copy.notConfigured}</span>}
                </div>
              </div>
              <div className="application-role-record-meta">
                {role.is_default && <span className="application-role-badge default">{copy.defaultRole}</span>}
                <span className="application-role-badge">{role.is_active ? copy.active : copy.disabled}</span>
              </div>
              {canManage && <div className="application-role-record-actions">
                <button type="button" className="secondary-button" onClick={() => startApplicationRole(role)} disabled={roleSaving}><Pencil size={13} />{copy.editRole}</button>
                <button type="button" className="text-danger-button" onClick={() => void deleteApplicationRole(role)} disabled={roleSaving || role.is_default} title={role.is_default ? copy.defaultRoleDeleteHint : copy.deleteRole}><Trash2 size={13} />{copy.deleteRole}</button>
              </div>}
            </article>
          ))}
          {applicationRoles.length === 0 && <p className="muted">{copy.noApplicationRoles}</p>}
        </div>
        {roleDraft && (
          <div className="application-role-editor">
            <div className="subsection-heading"><strong>{roleDraft.id ? copy.editRole : copy.addRole}</strong><span>{roleDraft.id ?? copy.notConfigured}</span></div>
            <div className="form-grid-2 compact-form-grid">
              <Input label={copy.roleKey} value={roleDraft.role_key} disabled={roleDraft.source === "manifest" || !!roleDraft.id} onChange={(value) => updateRoleDraft({ role_key: value })} />
              <Input label={copy.roleName} value={roleDraft.name} onChange={(value) => updateRoleDraft({ name: value })} />
              <Input label={copy.roleDescription} value={roleDraft.description} onChange={(value) => updateRoleDraft({ description: value })} />
            </div>
            <Toggle label={copy.activeRole} checked={roleDraft.is_active} onChange={(value) => updateRoleDraft({ is_active: value, is_default: value ? roleDraft.is_default : false })} />
            <Toggle label={copy.defaultRole} hint={copy.inheritEnterpriseHint} checked={roleDraft.is_default} disabled={!roleDraft.is_active} onChange={(value) => updateRoleDraft({ is_default: value })} />
            <div className="module-divider" />
            <div><strong>{copy.rolePermissions}</strong><p className="muted">{copy.rolePermissionsHint}</p></div>
            {applicationPermissionCatalog.length > 0 && <>
              <span className="application-permission-label">{copy.permissionTree}</span>
              <PermissionTree
                definitions={applicationPermissionCatalog}
                renderLeaf={(permission) => <label className="application-choice permission-tree-choice" key={permission.key}>
                  <input type="checkbox" checked={roleDraftPermissionSet.has(permission.key)} onChange={() => toggleRolePermission(permission.key)} />
                  <span><strong>{permission.label}</strong><small><code>{permission.key}</code>{permission.description ? ` · ${permission.description}` : ""}</small></span>
                </label>}
              />
            </>}
            <Input
              label={copy.customPermissions}
              hint={copy.customPermissionsHint}
              value={customRolePermissions.join("\n")}
              textarea
              onChange={(value) => updateRoleDraft({ permissions: normalizedPermissionList([
                ...roleDraft.permissions.filter((permission) => knownPermissions.has(permission)),
                ...value.split(/\r?\n/)
              ]) })}
            />
            <div className="application-role-editor-actions">
              <button type="button" className="secondary-button" onClick={() => setRoleDraft(null)} disabled={roleSaving}>{copy.removeRole}</button>
              <button type="button" className="primary-action" onClick={() => void saveApplicationRole()} disabled={roleSaving || !roleDraft.name.trim() || !roleDraft.role_key.trim()}>{roleSaving ? copy.saving : copy.save}<ArrowRight size={15} /></button>
            </div>
          </div>
        )}
        {roleFeedback && <p className={roleFeedback === copy.saveFailed || roleFeedback === copy.defaultRoleDeleteHint ? "module-save-error" : "module-save-feedback"} role="status">{roleFeedback}</p>}
        <div className="module-divider" />
        <div className="authorization-subsection">
          <div className="subsection-heading"><div><strong>{copy.userRoleBindings}</strong><p className="muted">{copy.userRoleBindingsHint}</p></div><span>{authorizationUsers.length}</span></div>
          {authorizationUsers.length > 0 ? <>
            <label className="application-input"><span>{copy.selectUser}</span><select value={selectedAuthorizationUserId} disabled={authorizationLoading} onChange={(event) => selectAuthorizationUser(event.target.value)}>
              {authorizationUsers.map((user) => <option value={user.user_id} key={user.user_id}>{user.email} · {user.display_name || user.username}</option>)}
            </select></label>
            <div className="application-permission-grid">
              {applicationRoles.filter((role) => role.is_active || userRoleIdSet.has(role.id)).map((role) => (
                <label className="application-choice" key={role.id}>
                  <input type="checkbox" checked={userRoleIdSet.has(role.id)} onChange={() => updateUserRoleIds((current) => toggleRoleId(current, role.id))} disabled={authorizationSaving} />
                  <span><strong>{role.name}</strong><small>{role.description || copy.noModuleConfig}</small></span>
                </label>
              ))}
              {applicationRoles.length === 0 && <p className="muted">{copy.noApplicationRoles}</p>}
            </div>
          </> : <p className="muted">{copy.noAuthorizationUsers}</p>}
        </div>
        <div className="authorization-subsection">
          <div className="subsection-heading"><div><strong>{copy.groupRoleBindings}</strong><p className="muted">{copy.groupRoleBindingsHint}</p></div><span>{authorizationGroups.length}</span></div>
          {authorizationGroups.length > 0 ? <>
            <label className="application-input"><span>{copy.selectGroup}</span><select value={selectedAuthorizationGroupId} disabled={authorizationLoading} onChange={(event) => selectAuthorizationGroup(event.target.value)}>
              {authorizationGroups.map((group) => <option value={group.id} key={group.id}>{group.name}</option>)}
            </select></label>
            <div className="application-permission-grid">
              {applicationRoles.filter((role) => role.is_active || groupRoleIdSet.has(role.id)).map((role) => (
                <label className="application-choice" key={role.id}>
                  <input type="checkbox" checked={groupRoleIdSet.has(role.id)} onChange={() => updateGroupRoleIds((current) => toggleRoleId(current, role.id))} disabled={authorizationSaving} />
                  <span><strong>{role.name}</strong><small>{role.description || copy.noModuleConfig}</small></span>
                </label>
              ))}
              {applicationRoles.length === 0 && <p className="muted">{copy.noApplicationRoles}</p>}
            </div>
          </> : <p className="muted">{copy.noAuthorizationGroups}</p>}
        </div>
        <div className="authorization-subsection">
          <div className="subsection-heading"><div><strong>{copy.enterpriseRoleMappings}</strong><p className="muted">{copy.enterpriseRoleMappingsHint}</p></div><span>{authorizationSubjects?.organization_roles.length ?? 0}</span></div>
          <div className="authorization-mapping-list">
            {(authorizationSubjects?.organization_roles ?? []).map((organizationRole) => (
              <div className="authorization-mapping-row" key={organizationRole}>
                <strong>{organizationRole}</strong>
                <div className="application-role-chip-list">
                  {applicationRoles.filter((role) => role.is_active || organizationRoleIdSets.get(organizationRole)?.has(role.id)).map((role) => (
                    <label className="application-choice" key={role.id}>
                      <input type="checkbox" checked={organizationRoleIdSets.get(organizationRole)?.has(role.id) ?? false} onChange={() => updateOrganizationRoleIds((current) => ({ ...current, [organizationRole]: toggleRoleId(current[organizationRole] ?? [], role.id) }))} disabled={authorizationSaving} />
                      <span><strong>{role.name}</strong><small>{role.description || copy.noModuleConfig}</small></span>
                    </label>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="authorization-subsection">
          <div className="subsection-heading"><div><strong>{copy.permissionOverrides}</strong><p className="muted">{copy.permissionOverridesHint}</p></div><span>{selectedAuthorizationUserId ? userPermissionOverrides.length : 0}</span></div>
          {selectedAuthorizationUserId ? <>
            <PermissionTree
              definitions={applicationPermissionCatalog}
              renderLeaf={(permission) => {
                const effect = permissionOverridesByKey.get(permission.key) ?? "";
                return <label className="application-input permission-tree-override" key={permission.key}><span>{permission.label}<small><code>{permission.key}</code></small></span><select value={effect} disabled={authorizationSaving} onChange={(event) => updatePermissionOverride(permission.key, event.target.value as "" | "allow" | "deny")}><option value="">{copy.inheritPermission}</option><option value="allow">{copy.allowPermission}</option><option value="deny">{copy.denyPermission}</option></select></label>;
              }}
            />
            <Input label={copy.customOverrides} hint={copy.customOverridesHint} value={customOverrideLines} textarea onChange={updateCustomPermissionOverrides} />
          </> : <p className="muted">{copy.noAuthorizationUsers}</p>}
        </div>
        <div className="application-role-editor-actions">
          <span className="module-save-feedback" role="status">{authorizationFeedback}</span>
          {canManage && <button type="button" className="primary-action" onClick={() => void saveAuthorizationBindings()} disabled={authorizationSaving || authorizationLoading}>{authorizationSaving ? copy.saving : copy.saveBindings}<ArrowRight size={15} /></button>}
        </div>
        <div className="module-divider" />
        <div className="authorization-subsection">
          <div className="subsection-heading"><div><strong>{copy.authorizationPreview}</strong><p className="muted">{copy.authorizationPreviewHint}</p></div><button type="button" className="secondary-button" onClick={() => void runAuthorizationPreview()} disabled={!selectedAuthorizationUserId || authorizationLoading}><Eye size={14} />{authorizationLoading ? copy.saving : copy.runPreview}</button></div>
          {authorizationPreview ? <div className="authorization-preview" role="status">
            <strong className={authorizationPreview.decision.allowed ? "preview-allowed" : "preview-denied"}>{authorizationPreview.decision.allowed ? copy.previewAllowed : copy.previewDenied}</strong>
            <div className="authorization-preview-grid"><div><span>{copy.previewRoles}</span><strong>{authorizationPreview.entitlements?.roles.join(" · ") || "-"}</strong></div><div><span>{copy.previewPermissions}</span><strong>{authorizationPreview.entitlements?.permissions.join(" · ") || "-"}</strong></div><div><span>{copy.previewGroups}</span><strong>{authorizationPreview.entitlements?.groups.join(" · ") || "-"}</strong></div><div><span>{copy.previewPolicyVersion}</span><code>{authorizationPreview.decision.policy_version}</code></div></div>
          </div> : <p className="muted">{copy.previewEmpty}</p>}
        </div>
        <div className="module-divider" />
        <p className="module-note">{copy.loginBoundaryNote}</p>
        <Input label={copy.claims} hint={copy.claimsHint} value={claims.join("\n")} textarea onChange={(value) => setDraftConfig({ ...config, claims: value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean) })} />
      </div>}
      <ModuleSave saving={moduleSaving} feedback={moduleFeedback} copy={copy} onSave={() => void saveAuthorizationModule()} />
    </div>
  );
}
