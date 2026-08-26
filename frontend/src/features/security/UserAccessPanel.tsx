import { Save } from "lucide-react";

import { Check, SelectField } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { Role, UserAccess, UserOption } from "../../types";

export type UserAccessPanelProps = {
  userOptions: UserOption[];
  roles: Role[];
  selectedUserId: string;
  userAccess: UserAccess | null;
  busy: boolean;
  translate: (key: TranslationKey) => string;
  onSelectUser: (userId: string) => void;
  onToggleRole: (role: Role) => void;
  onSave: () => void | Promise<void>;
};

export function UserAccessPanel({
  userOptions,
  roles,
  selectedUserId,
  userAccess,
  busy,
  translate: t,
  onSelectUser,
  onToggleRole,
  onSave
}: UserAccessPanelProps) {
  const selectedDirectRoleIds = new Set(userAccess?.direct_roles.map((role) => role.id) ?? []);

  return (
    <section className="panel security-user-access-panel">
      <h3>{t("userAccess")}</h3>
      <SelectField
        label={t("selectUser")}
        value={selectedUserId}
        disabled={busy}
        onChange={onSelectUser}
      >
        <option value="">-</option>
        {userOptions.map((item) => (
          <option key={item.id} value={item.id}>{item.email}</option>
        ))}
      </SelectField>
      {userAccess && (
        <>
          <label>{t("directRoles")}</label>
          <div className="checkbox-grid">
            {roles.map((role) => (
              <Check
                key={role.id}
                label={role.name}
                checked={selectedDirectRoleIds.has(role.id)}
                onChange={() => onToggleRole(role)}
              />
            ))}
          </div>
          <div className="actions">
            <button className="security-action-primary" type="button" onClick={() => void onSave()} disabled={busy}>
              <Save size={14} />{t("save")}
            </button>
          </div>
          <label>{t("groups")}</label>
          <div className="token-list security-access-token-list">
            {userAccess.groups.map((group) => <span key={group.id}>{group.name}</span>)}
          </div>
          <label>{t("effectivePermissions")}</label>
          <div className="token-list security-access-token-list">
            {userAccess.effective_permissions.map((permission) => <span key={permission}>{permission}</span>)}
          </div>
        </>
      )}
    </section>
  );
}
