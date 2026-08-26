import { EmptyState } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { AccessGroup } from "../../types";

export type GroupTableProps = {
  groups: AccessGroup[];
  loading: boolean;
  searchActive: boolean;
  canManage: boolean;
  translate: (key: TranslationKey) => string;
  onEdit: (group: AccessGroup) => void;
  onDelete: (group: AccessGroup) => void;
};

export function GroupTable({
  groups,
  loading,
  searchActive,
  canManage,
  translate: t,
  onEdit,
  onDelete
}: GroupTableProps) {
  return (
    <>
      <table>
        <thead><tr><th>{t("groups")}</th><th>{t("groupRoles")}</th><th>{t("groupMembers")}</th><th /></tr></thead>
        <tbody>
          {groups.map((group) => (
            <tr key={group.id}>
              <td>{group.name}<br /><small>{group.description ?? "-"}</small></td>
              <td><div className="token-list">{(group.roles ?? []).map((role) => <span key={role.id}>{role.name}</span>)}</div></td>
              <td><div className="token-list">{(group.members ?? []).map((member) => <span key={member.id}>{member.email}</span>)}</div></td>
              <td className="actions">
                {canManage && <button type="button" onClick={() => onEdit(group)}>{t("edit")}</button>}
                {canManage && <button type="button" onClick={() => onDelete(group)}>{t("delete")}</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!loading && groups.length === 0 && <EmptyState title={searchActive ? t("noSearchResults") : t("noData")} />}
    </>
  );
}
