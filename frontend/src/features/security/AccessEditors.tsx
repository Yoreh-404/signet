import type { FormEvent } from "react";

import {
  Check,
  Field,
  FormActions,
  Modal
} from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { emptyGroupForm, emptyRoleForm } from "../../lib/form-defaults";
import { toggleValue } from "../../lib/collection-utils";
import type {
  AccessGroup,
  PermissionInfo,
  Role,
  UserOption
} from "../../types";

export type RoleEditorForm = typeof emptyRoleForm;
export type GroupEditorForm = typeof emptyGroupForm;

export type AccessEditorsProps = {
  roleOpen: boolean;
  groupOpen: boolean;
  roleForm: RoleEditorForm;
  groupForm: GroupEditorForm;
  permissionCatalog: PermissionInfo[];
  roles: Role[];
  userOptions: UserOption[];
  busy: boolean;
  error: string;
  roleDirty: boolean;
  groupDirty: boolean;
  translate: (key: TranslationKey) => string;
  onRoleChange: (form: RoleEditorForm) => void;
  onGroupChange: (form: GroupEditorForm) => void;
  onRoleSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onGroupSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onClose: () => void;
};

export function AccessEditors({
  roleOpen,
  groupOpen,
  roleForm,
  groupForm,
  permissionCatalog,
  roles,
  userOptions,
  busy,
  error,
  roleDirty,
  groupDirty,
  translate: t,
  onRoleChange,
  onGroupChange,
  onRoleSubmit,
  onGroupSubmit,
  onClose
}: AccessEditorsProps) {
  const selectedRolePermissionKeys = new Set(roleForm.permissions);
  const selectedGroupRoleIds = new Set(groupForm.role_ids);
  const selectedGroupUserIds = new Set(groupForm.user_ids);

  return (
    <>
      {roleOpen && (
        <Modal
          title={roleForm.id ? t("updateRole") : t("createRole")}
          closeLabel={t("close")}
          error={error}
          dismissible={!busy}
          onClose={onClose}
        >
          <form className="panel" onSubmit={onRoleSubmit}>
            <Field label={t("roleName")} value={roleForm.name} onChange={(name) => onRoleChange({ ...roleForm, name })} />
            <Field label={t("description")} value={roleForm.description} onChange={(description) => onRoleChange({ ...roleForm, description })} textarea />
            <label>{t("rolePermissions")}</label>
            <div className="checkbox-grid">
              {permissionCatalog.map((permission) => (
                <Check
                  key={permission.key}
                  label={`${permission.key} · ${permission.category}`}
                  checked={selectedRolePermissionKeys.has(permission.key)}
                  onChange={() => onRoleChange({
                    ...roleForm,
                    permissions: toggleValue(roleForm.permissions, permission.key)
                  })}
                />
              ))}
            </div>
            <FormActions
              submitLabel={roleForm.id ? t("save") : t("create")}
              cancelLabel={t("cancel")}
              onCancel={onClose}
              busy={busy}
              dirty={roleDirty}
              statusLabel={roleDirty ? t("unsavedChanges") : undefined}
              savingLabel={t("saving")}
            />
          </form>
        </Modal>
      )}

      {groupOpen && (
        <Modal
          title={groupForm.id ? t("updateGroup") : t("createGroup")}
          closeLabel={t("close")}
          error={error}
          dismissible={!busy}
          onClose={onClose}
        >
          <form className="panel" onSubmit={onGroupSubmit}>
            <Field label={t("groupName")} value={groupForm.name} onChange={(name) => onGroupChange({ ...groupForm, name })} />
            <Field label={t("description")} value={groupForm.description} onChange={(description) => onGroupChange({ ...groupForm, description })} textarea />
            <label>{t("groupRoles")}</label>
            <div className="checkbox-grid">
              {roles.map((role) => (
                <Check
                  key={role.id}
                  label={role.name}
                  checked={selectedGroupRoleIds.has(role.id)}
                  onChange={() => onGroupChange({
                    ...groupForm,
                    role_ids: toggleValue(groupForm.role_ids, role.id)
                  })}
                />
              ))}
            </div>
            <label>{t("groupMembers")}</label>
            <div className="checkbox-grid tall">
              {userOptions.map((item) => (
                <Check
                  key={item.id}
                  label={`${item.email} · ${item.username}`}
                  checked={selectedGroupUserIds.has(item.id)}
                  onChange={() => onGroupChange({
                    ...groupForm,
                    user_ids: toggleValue(groupForm.user_ids, item.id)
                  })}
                />
              ))}
            </div>
            <FormActions
              submitLabel={groupForm.id ? t("save") : t("create")}
              cancelLabel={t("cancel")}
              onCancel={onClose}
              busy={busy}
              dirty={groupDirty}
              statusLabel={groupDirty ? t("unsavedChanges") : undefined}
              savingLabel={t("saving")}
            />
          </form>
        </Modal>
      )}
    </>
  );
}
