import { Circle, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState } from "react";
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
  ApplicationPermissionOverride,
  ApplicationProfileRole,
} from "../../lib/api/application-authorization";
import type { ApplicationRequestToken } from "./application-request-guard";
import { persistApplicationModule } from "./application-module-persistence";
import { record, stringList, toggleString } from "./application-module-values";
import { normalizedPermissionList } from "./application-authorization-role-policy";
import { useApplicationWorkspaceRequestContext } from "./use-application-workspace-request-context";
import { useApplicationAuthorizationData } from "./use-application-authorization-data";
import { useApplicationAuthorizationRoles } from "./use-application-authorization-roles";
import { useApplicationAuthorizationActions } from "./use-application-authorization-actions";
import { useApplicationAuthorizationProjection } from "./use-application-authorization-projection";
import { useApplicationAuthorizationSelection } from "./use-application-authorization-selection";
import type { ApplicationAuthorizationCopy } from "./application-authorization-copy";
import { ApplicationAuthorizationBindingsSection } from "./ApplicationAuthorizationBindingsSection";
import { ApplicationAuthorizationRoleSection } from "./ApplicationAuthorizationRoleSection";
import {
  Input,
  ModuleHeader,
  ModuleSave,
} from "./components/ApplicationModulePrimitives";

import { APPLICATION_AUTHORIZATION_DIRTY_SOURCE } from "./application-workspace-module-contracts";
export { APPLICATION_AUTHORIZATION_DIRTY_SOURCE } from "./application-workspace-module-contracts";

export type ApplicationAuthorizationModuleProps = {
  application: TenantApplication;
  authorizationConfig: Record<string, unknown>;
  canManage: boolean;
  copy: ApplicationAuthorizationCopy;
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

export function ApplicationAuthorizationModule({
  application,
  authorizationConfig,
  canManage,
  copy,
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
  const [moduleSaving, setModuleSaving] = useState(false);
  const [moduleFeedback, setModuleFeedback] = useState("");
  const dirtySourceRef = useRef<DirtyNavigationSourceHandle | null>(null);
  const requestContext = useApplicationWorkspaceRequestContext();
  const { beginRequest, isCurrent, finishRequest } = requestContext;
  const authorizationData = useApplicationAuthorizationData({
    applicationId: application.id,
    saveFailed: copy.saveFailed,
    requestContext,
  });
  const {
    authorizationProfiles,
    setAuthorizationProfiles,
    selectedAuthorizationProfileId,
    setSelectedAuthorizationProfileId,
    applicationRoles,
    setApplicationRoles,
    applicationPermissionCatalog,
    setApplicationPermissionCatalog,
    authorizationSubjects,
    setAuthorizationSubjects,
    selectedAuthorizationUserId,
    setSelectedAuthorizationUserId,
    selectedAuthorizationGroupId,
    setSelectedAuthorizationGroupId,
    bindings: authorizationBindings,
  } = authorizationData;
  const {
    userRoleIds,
    groupRoleIds,
    organizationRoleIds,
    userPermissionOverrides,
    authorizationPreview,
    setAuthorizationPreview,
    authorizationLoading,
    setAuthorizationLoading,
    authorizationFeedback,
    setAuthorizationFeedback,
    authorizationBindingsDirty,
    setAuthorizationBindingsDirty,
    applyAuthorizationBindingSnapshot,
    resetAuthorizationBindings,
    updateUserRoleIds,
    updateGroupRoleIds,
    updateOrganizationRoleIds,
    updateUserPermissionOverrides,
  } = authorizationBindings;
  const {
    roleDraft,
    setRoleDraft,
    roleSaving,
    roleFeedback,
    startRole,
    updateRole,
    toggleRolePermission,
    saveRole,
    deleteRole,
  } = useApplicationAuthorizationRoles({
    applicationId: application.id,
    selectedProfileId: selectedAuthorizationProfileId,
    applicationRoles,
    copy,
    requestContext,
    setApplicationRoles,
  });
  const {
    authorizationSaving,
    saveAuthorizationBindings,
    runAuthorizationPreview,
  } = useApplicationAuthorizationActions({
    applicationId: application.id,
    profileId: selectedAuthorizationProfileId,
    userId: selectedAuthorizationUserId,
    groupId: selectedAuthorizationGroupId,
    organizationRoles: authorizationSubjects?.organization_roles ?? [],
    draft: {
      userRoleIds,
      userPermissionOverrides,
      groupRoleIds,
      organizationRoleIds,
    },
    copy,
    requestContext,
    bindingEffects: {
      applySnapshot: applyAuthorizationBindingSnapshot,
      setDirty: setAuthorizationBindingsDirty,
      setFeedback: setAuthorizationFeedback,
      setPreview: setAuthorizationPreview,
      setLoading: setAuthorizationLoading,
    },
  });

  const {
    selectedAuthorizationProfile,
    knownPermissions,
    roleDraftPermissionSet,
    userRoleIdSet,
    groupRoleIdSet,
    organizationRoleIdSets,
    permissionOverridesByKey,
    customRolePermissions,
    customOverrideLines,
    authorizationUsers,
    authorizationGroups,
  } = useApplicationAuthorizationProjection({
    authorizationProfiles,
    selectedProfileId: selectedAuthorizationProfileId,
    applicationPermissionCatalog,
    roleDraft,
    userRoleIds,
    groupRoleIds,
    organizationRoleIds,
    userPermissionOverrides,
    authorizationSubjects,
  });

  function isCurrentApplicationRequest(
    token: ApplicationRequestToken,
  ): boolean {
    return isCurrent(token);
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

  function resetAuthorizationDrafts() {
    setDraftConfig(savedConfig);
    setRoleDraft(null);
    resetAuthorizationBindings();
    setAuthorizationFeedback("");
  }
  const {
    selectAuthorizationProfile,
    selectAuthorizationUser,
    selectAuthorizationGroup,
  } = useApplicationAuthorizationSelection({
    selectedProfileId: selectedAuthorizationProfileId,
    selectedUserId: selectedAuthorizationUserId,
    selectedGroupId: selectedAuthorizationGroupId,
    hasUnsavedChanges,
    resetDrafts: resetAuthorizationDrafts,
    onDiscardChanges,
    onRequestConfirmation,
    unsavedChangesCopy: copy.unsavedChanges,
    discardChangesCopy: copy.discardChanges,
    setProfileId: setSelectedAuthorizationProfileId,
    setUserId: setSelectedAuthorizationUserId,
    setGroupId: setSelectedAuthorizationGroupId,
  });

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
  }

  async function saveAuthorizationModule() {
    if (!canManage) return;
    const request = beginRequest("module:authorization", {
      kind: "mutation",
      payloadFingerprint: JSON.stringify(draftConfig),
    });
    if (!request) return;
    setModuleSaving(true);
    setModuleFeedback("");
    let committed = false;
    try {
      const result = await persistApplicationModule(application.id, "authorization", {
        config: draftConfig,
        is_enabled: true,
      }, request, isCurrentApplicationRequest);
      if (result.stale) return;
      if (result.module) {
        setDraftConfig(result.module.config);
        setSavedConfig(result.module.config);
        onApplicationModuleChanged(application.id, result.module);
      }
      setModuleFeedback(result.committed ? copy.saved : copy.saveFailed);
      committed = result.committed;
    } finally {
      if (isCurrentApplicationRequest(request)) setModuleSaving(false);
      finishRequest(request, committed);
    }
  }

  const config = draftConfig;
  const claims = stringList(config.claims);
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
            knownPermissionKeys={knownPermissions}
            roleDraft={roleDraft}
            roleDraftPermissionSet={roleDraftPermissionSet}
            customRolePermissions={customRolePermissions}
            roleSaving={roleSaving}
            roleFeedback={roleFeedback}
            onStartRole={startRole}
            onDeleteRole={(role) => void deleteRole(role)}
            onUpdateRole={updateRole}
            onTogglePermission={toggleRolePermission}
            onClearRole={() => setRoleDraft(null)}
            onSaveRole={() => void saveRole()}
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
            toggleRoleId={toggleString}
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
