import type { TranslationKey } from "../../i18n";
import { formatTime } from "../../lib/formatters";
import type { Locale, User } from "../../types";

export type ProfilePanelProps = {
  user: User;
  locale: Locale;
  translate: (key: TranslationKey) => string;
};

export function ProfilePanel({ user, locale, translate: t }: ProfilePanelProps) {
  return (
    <div className="panel">
      <h3>{t("account")}</h3>
      <div className="detail-grid">
        <div className="info-cell"><span>{t("email")}</span><strong>{user.email}</strong></div>
        <div className="info-cell"><span>{t("username")}</span><strong>{user.username}</strong></div>
        <div className="info-cell"><span>{t("displayName")}</span><strong>{user.display_name ?? "-"}</strong></div>
        <div className="info-cell"><span>{t("phone")}</span><strong>{user.phone ?? "-"}</strong></div>
        <div className="info-cell"><span>{t("role")}</span><strong>{user.is_admin ? t("admin") : t("normalUser")}</strong></div>
        <div className="info-cell"><span>{t("status")}</span><strong>{user.archived_at ? t("archived") : user.is_active ? t("active") : t("disabled")}</strong></div>
        <div className="info-cell"><span>{t("registeredAt")}</span><strong>{formatTime(user.created_at, locale)}</strong></div>
        <div className="info-cell"><span>{t("lastLogin")}</span><strong>{formatTime(user.last_login_at, locale)}</strong></div>
        <div className="info-cell"><span>{t("lastIp")}</span><strong>{user.last_login_ip ?? "-"}</strong></div>
        <div className="info-cell"><span>{t("lastClient")}</span><strong>{user.last_oidc_client_id ?? "-"}</strong></div>
      </div>
      {user.archived_at && <p className="muted">{t("archivedReadOnly")}</p>}
    </div>
  );
}
