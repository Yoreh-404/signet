import { Activity, Clock3, Globe2, KeyRound, Link2, Monitor } from "lucide-react";

import type { TranslationKey } from "../../i18n";
import type { Locale, UserDetail } from "../../types";
import { formatTime } from "../../lib/formatters";

type UserDetailPanelProps = {
  detail: UserDetail;
  locale: Locale;
  t: (key: TranslationKey) => string;
};

export function UserDetailPanel({ detail, locale, t }: UserDetailPanelProps) {
  return (
    <section className="detail-panel modal-detail-panel">
      <div className="detail-grid">
        <Info label={t("email")} value={`${detail.user.email} · ${detail.user.email_verified_at ? t("verified") : t("unverified")}`} />
        <Info label={t("phone")} value={`${detail.user.phone ?? "-"} · ${detail.user.phone_verified_at ? t("verified") : t("unverified")}`} />
        <Info label={t("status")} value={detail.user.archived_at !== null ? t("archived") : detail.user.is_active ? t("active") : t("disabled")} />
        <Info
          label={t("registrationSource")}
          value={detail.user.registration_source === "authorization_code" ? t("authorizationCodeRegistered") : t("localRegistration")}
        />
        <Info label={t("archivedAt")} value={formatTime(detail.user.archived_at, locale)} />
        <Info label={t("registeredAt")} value={formatTime(detail.user.created_at, locale)} />
        <Info label={t("lastLogin")} value={formatTime(detail.user.last_login_at, locale)} />
        <Info label={t("lastIp")} value={detail.user.last_login_ip ?? "-"} />
        <Info label={t("lastClient")} value={detail.user.last_oidc_client_id ?? "-"} />
        <Info label={t("loginMethod")} value={detail.user.last_login_method ?? "-"} />
      </div>
      {detail.user.archived_at !== null && <p className="muted">{t("archivedReadOnly")}</p>}
      <h4>{t("organizations")}</h4>
      {detail.organizations.length === 0 ? <p className="muted">{t("noData")}</p> : detail.organizations.map((organization) => (
        <div className="event-row" key={organization.id}>
          <strong>{organization.name}</strong>
          <span>{organization.slug} · {organization.role} · {organization.is_active ? t("active") : t("disabled")}</span>
        </div>
      ))}
      <h4>{t("linkedIdentities")}</h4>
      {detail.linked_identities.length === 0 ? <p className="muted">{t("noData")}</p> : detail.linked_identities.map((item) => (
        <div className="event-row" key={item.id}>
          <strong>{item.provider_slug}</strong>
          <span>{item.external_email ?? item.external_subject}</span>
        </div>
      ))}
      <h4>{t("loginEvents")}</h4>
      {detail.login_events.length === 0 ? <p className="muted">{t("noData")}</p> : (
        <ol className="login-event-list">
          {detail.login_events.map((event) => {
            const clientOrProvider = event.oidc_client_id ?? event.external_provider;
            const clientOrProviderLabel = event.oidc_client_id
              ? t("lastClient")
              : t("linkedIdentities");
            return (
              <li className="login-event" key={event.id}>
                <span className="login-event-marker" aria-hidden="true"><Activity size={16} /></span>
                <div className="login-event-content">
                  <div className="login-event-heading">
                    <div className="login-event-method">
                      <KeyRound size={16} aria-hidden="true" />
                      <strong>{event.method || "-"}</strong>
                    </div>
                    <time dateTime={new Date(event.login_at * 1000).toISOString()}>
                      <Clock3 size={15} aria-hidden="true" />
                      <span>{formatTime(event.login_at, locale)}</span>
                    </time>
                  </div>
                  <dl className="login-event-meta">
                    <div>
                      <dt><Globe2 size={14} aria-hidden="true" />{t("lastIp")}</dt>
                      <dd>{event.ip_address ?? "-"}</dd>
                    </div>
                    {clientOrProvider && (
                      <div>
                        <dt><Link2 size={14} aria-hidden="true" />{clientOrProviderLabel}</dt>
                        <dd>{clientOrProvider}</dd>
                      </div>
                    )}
                    {event.user_agent && (
                      <div className="login-event-device" title={event.user_agent}>
                        <dt><Monitor size={14} aria-hidden="true" />{t("userAgent")}</dt>
                        <dd>{event.user_agent}</dd>
                      </div>
                    )}
                  </dl>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="info-cell">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
