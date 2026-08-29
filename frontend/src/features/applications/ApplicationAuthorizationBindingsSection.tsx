import { ArrowRight, Eye } from "lucide-react";
import type {
  ApplicationAuthorizationPreview,
  ApplicationAuthorizationSubjects,
  ApplicationPermissionDefinition,
  ApplicationPermissionOverride,
  ApplicationProfileRole,
} from "../../lib/api/application-authorization";
import type { ApplicationAuthorizationCopy } from "./application-authorization-copy";
import {
  PermissionDefinitionDetails,
  PermissionTree,
} from "./ApplicationPermissionTree";
import { Input } from "./components/ApplicationModulePrimitives";

type ApplicationAuthorizationBindingsSectionProps = {
  copy: ApplicationAuthorizationCopy;
  canManage: boolean;
  applicationRoles: ApplicationProfileRole[];
  applicationPermissionCatalog: ApplicationPermissionDefinition[];
  authorizationSubjects: ApplicationAuthorizationSubjects | null;
  selectedAuthorizationUserId: string;
  selectedAuthorizationGroupId: string;
  userRoleIdSet: Set<string>;
  groupRoleIdSet: Set<string>;
  organizationRoleIdSets: Map<string, Set<string>>;
  userPermissionOverrides: ApplicationPermissionOverride[];
  permissionOverridesByKey: Map<string, "allow" | "deny">;
  customOverrideLines: string;
  authorizationLoading: boolean;
  authorizationSaving: boolean;
  authorizationFeedback: string;
  authorizationPreview: ApplicationAuthorizationPreview | null;
  authorizationUsers: ApplicationAuthorizationSubjects["users"];
  authorizationGroups: ApplicationAuthorizationSubjects["groups"];
  onSelectUser: (id: string) => void;
  onSelectGroup: (id: string) => void;
  onUpdateUserRoles: (
    next: string[] | ((current: string[]) => string[]),
  ) => void;
  onUpdateGroupRoles: (
    next: string[] | ((current: string[]) => string[]),
  ) => void;
  onUpdateOrganizationRoles: (
    next:
      | Record<string, string[]>
      | ((current: Record<string, string[]>) => Record<string, string[]>),
  ) => void;
  onUpdatePermissionOverride: (
    permission: string,
    effect: "" | "allow" | "deny",
  ) => void;
  onUpdateCustomOverrides: (value: string) => void;
  onSave: () => void;
  onPreview: () => void;
  toggleRoleId: (roleIds: string[], roleId: string) => string[];
};

export function ApplicationAuthorizationBindingsSection({
  copy,
  canManage,
  applicationRoles,
  applicationPermissionCatalog,
  authorizationSubjects,
  selectedAuthorizationUserId,
  selectedAuthorizationGroupId,
  userRoleIdSet,
  groupRoleIdSet,
  organizationRoleIdSets,
  userPermissionOverrides,
  permissionOverridesByKey,
  customOverrideLines,
  authorizationLoading,
  authorizationSaving,
  authorizationFeedback,
  authorizationPreview,
  authorizationUsers,
  authorizationGroups,
  onSelectUser,
  onSelectGroup,
  onUpdateUserRoles,
  onUpdateGroupRoles,
  onUpdateOrganizationRoles,
  onUpdatePermissionOverride,
  onUpdateCustomOverrides,
  onSave,
  onPreview,
  toggleRoleId,
}: ApplicationAuthorizationBindingsSectionProps) {
  const activeRoles = (selectedIds: Set<string>) =>
    applicationRoles.filter(
      (role) => role.is_active || selectedIds.has(role.id),
    );

  return (
    <>
      <div className="authorization-subsection">
        <div className="subsection-heading">
          <div>
            <strong>{copy.userRoleBindings}</strong>
            <p className="muted">{copy.userRoleBindingsHint}</p>
          </div>
          <span>{authorizationUsers.length}</span>
        </div>
        {authorizationUsers.length > 0 ? (
          <>
            <label className="application-input">
              <span>{copy.selectUser}</span>
              <select
                value={selectedAuthorizationUserId}
                disabled={authorizationLoading}
                onChange={(event) => onSelectUser(event.target.value)}
              >
                {authorizationUsers.map((user) => (
                  <option value={user.user_id} key={user.user_id}>
                    {user.email} · {user.display_name || user.username}
                  </option>
                ))}
              </select>
            </label>
            <div className="application-permission-grid">
              {activeRoles(userRoleIdSet).map((role) => (
                <label className="application-choice" key={role.id}>
                  <input
                    type="checkbox"
                    checked={userRoleIdSet.has(role.id)}
                    onChange={() =>
                      onUpdateUserRoles((current) =>
                        toggleRoleId(current, role.id),
                      )
                    }
                    disabled={authorizationSaving}
                  />
                  <span>
                    <strong>{role.name}</strong>
                    <small>{role.description || copy.noModuleConfig}</small>
                  </span>
                </label>
              ))}
              {applicationRoles.length === 0 && (
                <p className="muted">{copy.noApplicationRoles}</p>
              )}
            </div>
          </>
        ) : (
          <p className="muted">{copy.noAuthorizationUsers}</p>
        )}
      </div>
      <div className="authorization-subsection">
        <div className="subsection-heading">
          <div>
            <strong>{copy.groupRoleBindings}</strong>
            <p className="muted">{copy.groupRoleBindingsHint}</p>
          </div>
          <span>{authorizationGroups.length}</span>
        </div>
        {authorizationGroups.length > 0 ? (
          <>
            <label className="application-input">
              <span>{copy.selectGroup}</span>
              <select
                value={selectedAuthorizationGroupId}
                disabled={authorizationLoading}
                onChange={(event) => onSelectGroup(event.target.value)}
              >
                {authorizationGroups.map((group) => (
                  <option value={group.id} key={group.id}>
                    {group.name}
                  </option>
                ))}
              </select>
            </label>
            <div className="application-permission-grid">
              {activeRoles(groupRoleIdSet).map((role) => (
                <label className="application-choice" key={role.id}>
                  <input
                    type="checkbox"
                    checked={groupRoleIdSet.has(role.id)}
                    onChange={() =>
                      onUpdateGroupRoles((current) =>
                        toggleRoleId(current, role.id),
                      )
                    }
                    disabled={authorizationSaving}
                  />
                  <span>
                    <strong>{role.name}</strong>
                    <small>{role.description || copy.noModuleConfig}</small>
                  </span>
                </label>
              ))}
              {applicationRoles.length === 0 && (
                <p className="muted">{copy.noApplicationRoles}</p>
              )}
            </div>
          </>
        ) : (
          <p className="muted">{copy.noAuthorizationGroups}</p>
        )}
      </div>
      <div className="authorization-subsection">
        <div className="subsection-heading">
          <div>
            <strong>{copy.enterpriseRoleMappings}</strong>
            <p className="muted">{copy.enterpriseRoleMappingsHint}</p>
          </div>
          <span>{authorizationSubjects?.organization_roles.length ?? 0}</span>
        </div>
        <div className="authorization-mapping-list">
          {(authorizationSubjects?.organization_roles ?? []).map(
            (organizationRole) => (
              <div className="authorization-mapping-row" key={organizationRole}>
                <strong>{organizationRole}</strong>
                <div className="application-role-chip-list">
                  {applicationRoles
                    .filter(
                      (role) =>
                        role.is_active ||
                        organizationRoleIdSets
                          .get(organizationRole)
                          ?.has(role.id),
                    )
                    .map((role) => (
                      <label className="application-choice" key={role.id}>
                        <input
                          type="checkbox"
                          checked={
                            organizationRoleIdSets
                              .get(organizationRole)
                              ?.has(role.id) ?? false
                          }
                          onChange={() =>
                            onUpdateOrganizationRoles((current) => ({
                              ...current,
                              [organizationRole]: toggleRoleId(
                                current[organizationRole] ?? [],
                                role.id,
                              ),
                            }))
                          }
                          disabled={authorizationSaving}
                        />
                        <span>
                          <strong>{role.name}</strong>
                          <small>
                            {role.description || copy.noModuleConfig}
                          </small>
                        </span>
                      </label>
                    ))}
                </div>
              </div>
            ),
          )}
        </div>
      </div>
      <div className="authorization-subsection">
        <div className="subsection-heading">
          <div>
            <strong>{copy.permissionOverrides}</strong>
            <p className="muted">{copy.permissionOverridesHint}</p>
          </div>
          <span>
            {selectedAuthorizationUserId ? userPermissionOverrides.length : 0}
          </span>
        </div>
        {selectedAuthorizationUserId ? (
          <>
            <PermissionTree
              definitions={applicationPermissionCatalog}
              renderLeaf={(permission) => {
                const effect =
                  permissionOverridesByKey.get(permission.key) ?? "";
                return (
                  <label
                    className="application-input permission-tree-override"
                    key={permission.key}
                  >
                    <PermissionDefinitionDetails permission={permission} />
                    <select
                      value={effect}
                      disabled={authorizationSaving}
                      onChange={(event) =>
                        onUpdatePermissionOverride(
                          permission.key,
                          event.target.value as "" | "allow" | "deny",
                        )
                      }
                    >
                      <option value="">{copy.inheritPermission}</option>
                      <option value="allow">{copy.allowPermission}</option>
                      <option value="deny">{copy.denyPermission}</option>
                    </select>
                  </label>
                );
              }}
            />
            <Input
              label={copy.customOverrides}
              hint={copy.customOverridesHint}
              value={customOverrideLines}
              textarea
              onChange={onUpdateCustomOverrides}
            />
          </>
        ) : (
          <p className="muted">{copy.noAuthorizationUsers}</p>
        )}
      </div>
      <div className="application-role-editor-actions">
        <span className="module-save-feedback" role="status">
          {authorizationFeedback}
        </span>
        {canManage && (
          <button
            type="button"
            className="primary-action"
            onClick={onSave}
            disabled={authorizationSaving || authorizationLoading}
          >
            {authorizationSaving ? copy.saving : copy.saveBindings}
            <ArrowRight size={15} />
          </button>
        )}
      </div>
      <div className="module-divider" />
      <div className="authorization-subsection">
        <div className="subsection-heading">
          <div>
            <strong>{copy.authorizationPreview}</strong>
            <p className="muted">{copy.authorizationPreviewHint}</p>
          </div>
          <button
            type="button"
            className="secondary-button"
            onClick={onPreview}
            disabled={!selectedAuthorizationUserId || authorizationLoading}
          >
            <Eye size={14} />
            {authorizationLoading ? copy.saving : copy.runPreview}
          </button>
        </div>
        {authorizationPreview ? (
          <div className="authorization-preview" role="status">
            <strong
              className={
                authorizationPreview.decision.allowed
                  ? "preview-allowed"
                  : "preview-denied"
              }
            >
              {authorizationPreview.decision.allowed
                ? copy.previewAllowed
                : copy.previewDenied}
            </strong>
            <div className="authorization-preview-grid">
              <div>
                <span>{copy.previewRoles}</span>
                <strong>
                  {authorizationPreview.entitlements?.roles.join(" · ") || "-"}
                </strong>
              </div>
              <div>
                <span>{copy.previewPermissions}</span>
                <strong>
                  {authorizationPreview.entitlements?.permissions.join(" · ") ||
                    "-"}
                </strong>
              </div>
              <div>
                <span>{copy.previewGroups}</span>
                <strong>
                  {authorizationPreview.entitlements?.groups.join(" · ") || "-"}
                </strong>
              </div>
              <div>
                <span>{copy.previewPolicyVersion}</span>
                <code>{authorizationPreview.decision.policy_version}</code>
              </div>
            </div>
          </div>
        ) : (
          <p className="muted">{copy.previewEmpty}</p>
        )}
      </div>
    </>
  );
}
