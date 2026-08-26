import { EmptyState } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import { formatTime } from "../../lib/formatters";
import type { AuditEvent, Locale } from "../../types";

export type AuditEventsPanelProps = {
  events: AuditEvent[];
  loading: boolean;
  searchActive: boolean;
  locale: Locale;
  translate: (key: TranslationKey) => string;
};

export function AuditEventsPanel({
  events,
  loading,
  searchActive,
  locale,
  translate: t
}: AuditEventsPanelProps) {
  return (
    <section className="table-panel security-audit-events-panel">
      <h3>{t("auditEvents")}</h3>
      <table>
        <thead><tr><th>{t("action")}</th><th>{t("actor")}</th><th>{t("target")}</th><th>{t("outcome")}</th><th>{t("registeredAt")}</th></tr></thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td>{event.action}<br /><small>{event.details}</small></td>
              <td>{event.actor_user_id ?? event.actor_client_id ?? "-"}</td>
              <td>{event.target_kind}<br /><small>{event.target_id ?? "-"}</small></td>
              <td>{event.outcome}</td>
              <td>{formatTime(event.created_at, locale)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!loading && events.length === 0 && <EmptyState title={searchActive ? t("noSearchResults") : t("noData")} />}
    </section>
  );
}
