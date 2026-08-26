import {
  Archive,
  Ban,
  KeyRound,
  RotateCcw,
  Trash2
} from "lucide-react";

import { StatusBadge } from "../../components/ui";
import {
  availableUserActions
} from "./user-lifecycle";
import type { TranslationKey } from "../../i18n";
import { formatTime } from "../../lib/formatters";
import type { Locale, User } from "../../types";

export interface UserTableProps {
  users: User[];
  canManageUsers: boolean;
  currentUserId?: string;
  selectedUserIdSet: ReadonlySet<string>;
  allVisibleSelected: boolean;
  busy: boolean;
  locale: Locale;
  translate: (key: TranslationKey) => string;
  onToggleVisibleSelection: (checked: boolean) => void;
  onToggleSelection: (id: string) => void;
  onEditUser: (user: User) => void;
  onShowDetails: (id: string) => void;
  onResetMfa: (id: string) => void | Promise<void>;
  onAdvanceLifecycle: (id: string) => void | Promise<void>;
  onEnableUser: (id: string) => void | Promise<void>;
  onRequestConfirmation: (action: () => void | Promise<void>) => void;
}

export function UserTable({
  users,
  canManageUsers,
  currentUserId,
  selectedUserIdSet,
  allVisibleSelected,
  busy,
  locale,
  translate,
  onToggleVisibleSelection,
  onToggleSelection,
  onEditUser,
  onShowDetails,
  onResetMfa,
  onAdvanceLifecycle,
  onEnableUser,
  onRequestConfirmation
}: UserTableProps) {
  return (
    <table className="user-table">
      <caption className="sr-only">{translate("users")}</caption>
      <thead>
        <tr>
          {canManageUsers && (
            <th className="user-selection-column">
              <input
                type="checkbox"
                aria-label={translate("selectAllUsers")}
                checked={allVisibleSelected}
                onChange={(event) => onToggleVisibleSelection(event.target.checked)}
              />
            </th>
          )}
          <th>{translate("email")}</th>
          <th>{translate("role")}</th>
          <th>{translate("registeredAt")}</th>
          <th>{translate("lastLogin")}</th>
          <th>{translate("status")}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {users.map((item) => {
          const actions = availableUserActions(item, currentUserId);
          return (
            <tr key={item.id}>
              {canManageUsers && (
                <td className="user-selection-column">
                  <input
                    type="checkbox"
                    aria-label={`${translate("email")}: ${item.email}`}
                    checked={selectedUserIdSet.has(item.id)}
                    onChange={() => onToggleSelection(item.id)}
                  />
                </td>
              )}
              <td className="user-summary">{item.email}<br /><small>{item.username}</small></td>
              <td className="user-role">{item.is_admin ? translate("admin") : translate("normalUser")}</td>
              <td className="user-registration">{formatTime(item.created_at, locale)}</td>
              <td className="user-last-login">{formatTime(item.last_login_at, locale)}</td>
              <td className="user-status">
                <div className="user-status-stack">
                  <StatusBadge tone={item.archived_at !== null ? "neutral" : item.is_active ? "success" : "warning"}>
                    {item.archived_at !== null ? translate("archived") : item.is_active ? translate("active") : translate("disabled")}
                  </StatusBadge>
                  {item.registration_source === "authorization_code" && (
                    <StatusBadge tone="info">{translate("authorizationCodeRegistered")}</StatusBadge>
                  )}
                </div>
                {item.archived_at !== null && <><br /><small>{formatTime(item.archived_at, locale)}</small></>}
              </td>
              <td className="actions user-actions">
                {canManageUsers && item.archived_at === null && (
                  <button type="button" onClick={() => onEditUser(item)}>{translate("edit")}</button>
                )}
                <button type="button" onClick={() => onShowDetails(item.id)} disabled={busy}>{translate("details")}</button>
                {canManageUsers && actions.includes("reset_mfa") && (
                  <button type="button" onClick={() => onRequestConfirmation(() => onResetMfa(item.id))}>
                    <KeyRound size={14} />
                    {translate("resetMfa")}
                  </button>
                )}
                {canManageUsers && actions.includes("disable") && (
                  <button type="button" onClick={() => onRequestConfirmation(() => onAdvanceLifecycle(item.id))}>
                    <Ban size={14} />
                    {translate("disable")}
                  </button>
                )}
                {canManageUsers && actions.includes("enable") && (
                  <button type="button" onClick={() => void onEnableUser(item.id)} disabled={busy}>
                    <RotateCcw size={14} />
                    {translate("enable")}
                  </button>
                )}
                {canManageUsers && actions.includes("archive") && (
                  <button type="button" onClick={() => onRequestConfirmation(() => onAdvanceLifecycle(item.id))}>
                    <Archive size={14} />
                    {translate("archive")}
                  </button>
                )}
                {canManageUsers && actions.includes("delete") && (
                  <button type="button" onClick={() => onRequestConfirmation(() => onAdvanceLifecycle(item.id))}>
                    <Trash2 size={14} />
                    {translate("delete")}
                  </button>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
