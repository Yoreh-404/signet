import { ArrowRight, Pencil, Plus, Trash2 } from "lucide-react";
import type {
  ApplicationPermissionDefinition,
  ApplicationProfileRole,
} from "../../lib/api/application-authorization";
import type { ApplicationAuthorizationCopy } from "./ApplicationAuthorizationModule";
import {
  PermissionDefinitionDetails,
  PermissionTree,
} from "./ApplicationPermissionTree";
import { Input, Toggle } from "./components/ApplicationModulePrimitives";

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

type ApplicationAuthorizationRoleSectionProps = {
  canManage: boolean;
  copy: ApplicationAuthorizationCopy;
  applicationRoles: ApplicationProfileRole[];
  applicationPermissionCatalog: ApplicationPermissionDefinition[];
  roleDraft: ApplicationRoleDraft | null;
  roleDraftPermissionSet: Set<string>;
  customRolePermissions: string[];
  roleSaving: boolean;
  roleFeedback: string;
  onStartRole: (role?: ApplicationProfileRole) => void;
  onDeleteRole: (role: ApplicationProfileRole) => void;
  onUpdateRole: (next: Partial<ApplicationRoleDraft>) => void;
  onTogglePermission: (permission: string) => void;
  onClearRole: () => void;
  onSaveRole: () => void;
  normalizedPermissionList: (values: string[]) => string[];
};

export function ApplicationAuthorizationRoleSection({
  canManage,
  copy,
  applicationRoles,
  applicationPermissionCatalog,
  roleDraft,
  roleDraftPermissionSet,
  customRolePermissions,
  roleSaving,
  roleFeedback,
  onStartRole,
  onDeleteRole,
  onUpdateRole,
  onTogglePermission,
  onClearRole,
  onSaveRole,
  normalizedPermissionList,
}: ApplicationAuthorizationRoleSectionProps) {
  return (
    <>
      <div className="subsection-heading">
        <div>
          <strong>{copy.customRoles}</strong>
          <p className="muted">{copy.customRolesHint}</p>
        </div>
        {canManage && (
          <button
            type="button"
            className="secondary-button"
            onClick={() => onStartRole()}
            disabled={roleSaving}
          >
            <Plus size={14} />
            {copy.addRole}
          </button>
        )}
      </div>
      <div className="application-role-list">
        {applicationRoles.map((role) => (
          <article
            className={`application-role-record${role.is_active ? "" : " inactive"}`}
            key={role.id}
          >
            <div className="application-role-record-main">
              <strong>{role.name}</strong>
              <small>
                <code>{role.role_key}</code> ·{" "}
                {role.description || copy.noModuleConfig}
              </small>
              <div className="application-role-permission-summary">
                {role.permissions.length > 0 ? (
                  role.permissions.map((permission) => (
                    <span key={permission}>{permission}</span>
                  ))
                ) : (
                  <span>{copy.notConfigured}</span>
                )}
              </div>
            </div>
            <div className="application-role-record-meta">
              {role.is_default && (
                <span className="application-role-badge default">
                  {copy.defaultRole}
                </span>
              )}
              <span className="application-role-badge">
                {role.is_active ? copy.active : copy.disabled}
              </span>
            </div>
            {canManage && (
              <div className="application-role-record-actions">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => onStartRole(role)}
                  disabled={roleSaving}
                >
                  <Pencil size={13} />
                  {copy.editRole}
                </button>
                <button
                  type="button"
                  className="text-danger-button"
                  onClick={() => void onDeleteRole(role)}
                  disabled={roleSaving || role.is_default}
                  title={
                    role.is_default
                      ? copy.defaultRoleDeleteHint
                      : copy.deleteRole
                  }
                >
                  <Trash2 size={13} />
                  {copy.deleteRole}
                </button>
              </div>
            )}
          </article>
        ))}
        {applicationRoles.length === 0 && (
          <p className="muted">{copy.noApplicationRoles}</p>
        )}
      </div>
      {roleDraft && (
        <div className="application-role-editor">
          <div className="subsection-heading">
            <strong>{roleDraft.id ? copy.editRole : copy.addRole}</strong>
            <span>{roleDraft.id ?? copy.notConfigured}</span>
          </div>
          <div className="form-grid-2 compact-form-grid">
            <Input
              label={copy.roleKey}
              value={roleDraft.role_key}
              disabled={roleDraft.source === "manifest" || !!roleDraft.id}
              onChange={(value) => onUpdateRole({ role_key: value })}
            />
            <Input
              label={copy.roleName}
              value={roleDraft.name}
              onChange={(value) => onUpdateRole({ name: value })}
            />
            <Input
              label={copy.roleDescription}
              value={roleDraft.description}
              onChange={(value) => onUpdateRole({ description: value })}
            />
          </div>
          <Toggle
            label={copy.activeRole}
            checked={roleDraft.is_active}
            onChange={(value) =>
              onUpdateRole({
                is_active: value,
                is_default: value ? roleDraft.is_default : false,
              })
            }
          />
          <Toggle
            label={copy.defaultRole}
            hint={copy.inheritEnterpriseHint}
            checked={roleDraft.is_default}
            disabled={!roleDraft.is_active}
            onChange={(value) => onUpdateRole({ is_default: value })}
          />
          <div className="module-divider" />
          <div>
            <strong>{copy.rolePermissions}</strong>
            <p className="muted">{copy.rolePermissionsHint}</p>
          </div>
          {applicationPermissionCatalog.length > 0 && (
            <>
              <span className="application-permission-label">
                {copy.permissionTree}
              </span>
              <PermissionTree
                definitions={applicationPermissionCatalog}
                renderLeaf={(permission) => (
                  <label
                    className="application-choice permission-tree-choice"
                    key={permission.key}
                  >
                    <input
                      type="checkbox"
                      checked={roleDraftPermissionSet.has(permission.key)}
                      onChange={() => onTogglePermission(permission.key)}
                    />
                    <PermissionDefinitionDetails
                      permission={permission}
                      description={permission.description}
                      emphasizeLabel
                    />
                  </label>
                )}
              />
            </>
          )}
          <Input
            label={copy.customPermissions}
            hint={copy.customPermissionsHint}
            value={customRolePermissions.join("\n")}
            textarea
            onChange={(value) =>
              onUpdateRole({
                permissions: normalizedPermissionList([
                  ...roleDraft.permissions.filter((permission) =>
                    applicationPermissionCatalog.some(
                      (item) => item.key === permission,
                    ),
                  ),
                  ...value.split(/\r?\n/),
                ]),
              })
            }
          />
          <div className="application-role-editor-actions">
            <button
              type="button"
              className="secondary-button"
              onClick={onClearRole}
              disabled={roleSaving}
            >
              {copy.removeRole}
            </button>
            <button
              type="button"
              className="primary-action"
              onClick={onSaveRole}
              disabled={
                roleSaving ||
                !roleDraft.name.trim() ||
                !roleDraft.role_key.trim()
              }
            >
              {roleSaving ? copy.saving : copy.save}
              <ArrowRight size={15} />
            </button>
          </div>
        </div>
      )}
      {roleFeedback && (
        <p
          className={
            roleFeedback === copy.saveFailed ||
            roleFeedback === copy.defaultRoleDeleteHint
              ? "module-save-error"
              : "module-save-feedback"
          }
          role="status"
        >
          {roleFeedback}
        </p>
      )}
    </>
  );
}
