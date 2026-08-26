import type { Locale, Role } from "../../types";
import type { TranslationKey } from "../../i18n";

export type RoleTableProps = {
  roles: Role[];
  canManage: boolean;
  locale: Locale;
  translate: (key: TranslationKey) => string;
  onEdit: (role: Role) => void;
  onDelete: (role: Role) => void;
};

export function RoleTable({
  roles,
  canManage,
  locale,
  translate: t,
  onEdit,
  onDelete
}: RoleTableProps) {
  return (
    <table lang={locale}>
      <thead>
        <tr>
          <th>{t("role")}</th>
          <th>{t("permissions")}</th>
          <th>{t("status")}</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {roles.map((role) => (
          <tr key={role.id}>
            <td>
              {role.name}
              <br />
              <small>{role.description ?? "-"}</small>
            </td>
            <td>
              <div className="token-list">
                {role.permissions.map((permission) => <span key={permission}>{permission}</span>)}
              </div>
            </td>
            <td>{role.is_system ? t("systemRole") : t("customRole")}</td>
            <td className="actions">
              {canManage && !role.is_system && (
                <button type="button" onClick={() => onEdit(role)}>{t("edit")}</button>
              )}
              {canManage && !role.is_system && (
                <button type="button" onClick={() => onDelete(role)}>{t("delete")}</button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
