import { LogOut } from "lucide-react";

import type { TranslationKey } from "../../i18n";
import { formatTime, shortSessionId } from "../../lib/formatters";
import type { Locale, MySession } from "../../types";

export type SessionListPanelProps = {
  locale: Locale;
  sessions: MySession[];
  hasMore: boolean;
  loadingMore: boolean;
  busy: boolean;
  canMutateAccount: boolean;
  translate: (key: TranslationKey) => string;
  onRevokeSession: (id: string) => void | Promise<void>;
  onLoadMore: () => void | Promise<void>;
};

export function SessionListPanel({
  locale,
  sessions,
  hasMore,
  loadingMore,
  busy,
  canMutateAccount,
  translate: t,
  onRevokeSession,
  onLoadMore
}: SessionListPanelProps) {
  return (
    <div className="table-panel">
      <h3>{t("activeSessions")}</h3>
      <table>
        <thead><tr><th>{t("sessionId")}</th><th>{t("device")}</th><th>{t("authMethod")}</th><th>{t("createdAt")}</th><th>{t("expiresAt")}</th><th></th></tr></thead>
        <tbody>
          {sessions.map((session) => (
            <tr key={session.id}>
              <td><code>{shortSessionId(session.id)}</code>{session.current && <><br /><small>{t("currentSession")}</small></>}</td>
              <td><div className="session-device"><strong>{session.ip_address ?? "-"}</strong><small>{session.user_agent ?? "-"}</small></div></td>
              <td>{session.login_method ?? "-"}</td>
              <td>{formatTime(session.created_at, locale)}</td>
              <td>{formatTime(session.expires_at, locale)}</td>
              <td className="actions">
                {canMutateAccount && !session.current && <button type="button" onClick={() => onRevokeSession(session.id)} disabled={busy}><LogOut size={14} />{t("revokeSession")}</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {sessions.length === 0 && <div className="empty">{t("noActiveSessions")}</div>}
      {hasMore && (
        <button type="button" onClick={onLoadMore} disabled={busy || loadingMore}>
          {loadingMore ? t("loading") : t("loadMore")}
        </button>
      )}
    </div>
  );
}
