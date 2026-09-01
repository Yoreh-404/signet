import { Activity, Building2, ExternalLink, Shield, Users } from "lucide-react";
import { Card, StatusBadge } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { Overview, Tab } from "../../types";

type Translate = (key: TranslationKey) => string;

type AdminOverviewProps = {
  username: string;
  overview: Overview | null;
  issuer: string;
  canReadUsers: boolean;
  canReadOrganizations: boolean;
  canManageSecurity: boolean;
  activeUserCount: number;
  totalUserCount: number;
  activeClientCount: number;
  totalClientCount: number;
  translate: Translate;
  navigateToTab: (tab: Tab) => void;
};

export function AdminOverview({
  username,
  overview,
  issuer,
  canReadUsers,
  canReadOrganizations,
  canManageSecurity,
  activeUserCount,
  totalUserCount,
  activeClientCount,
  totalClientCount,
  translate,
  navigateToTab
}: AdminOverviewProps) {
  const activeUserRate = totalUserCount > 0 ? Math.round((activeUserCount / totalUserCount) * 100) : 0;
  const activeClientRate = totalClientCount > 0 ? Math.round((activeClientCount / totalClientCount) * 100) : 0;

  return (
    <section className="dashboard">
      <article className="welcome-card">
        <div>
          <StatusBadge tone="success"><Activity size={13} />{translate("serviceHealthy")}</StatusBadge>
          <h3>{translate("welcomeBack")}，{username}</h3>
          <p>{translate("overviewIntro")}</p>
        </div>
        <div className="quick-actions" role="group" aria-label={translate("quickActions")}>
          {canReadUsers && <button type="button" onClick={() => navigateToTab("users")}><Users size={16} />{translate("users")}</button>}
          {canManageSecurity && <button type="button" onClick={() => navigateToTab("security")}><Shield size={16} />{translate("security")}</button>}
        </div>
      </article>
      <div className="metrics-grid">
        <Metric label={translate("usersMetric")} value={totalUserCount} detail={`${activeUserCount} ${translate("active")}`} />
        <Metric label={translate("activeRate")} value={`${activeUserRate}%`} detail={`${activeUserCount}/${totalUserCount} ${translate("users")}`} />
        <Metric label={translate("clientsMetric")} value={totalClientCount} detail={`${activeClientCount} ${translate("active")} · ${activeClientRate}%`} />
        <Metric label={translate("database")} value={overview?.database_kind ?? "-"} detail={translate("settings")} />
      </div>
      <div className="overview-bottom-grid">
        <article className="panel overview-status-card">
          <div className="overview-card-heading">
            <div>
              <StatusBadge tone="success"><Activity size={13} />{translate("serviceHealthy")}</StatusBadge>
              <h3>{translate("overviewStatus")}</h3>
            </div>
            <Shield size={22} aria-hidden="true" />
          </div>
          <div className="overview-fact-grid">
            <Info label={translate("issuerLabel")} value={overview?.issuer ?? issuer} />
            <Info label={translate("database")} value={overview?.database_kind ?? "-"} />
            <Info label={translate("usersMetric")} value={`${activeUserCount}/${totalUserCount} ${translate("active")}`} />
            <Info label={translate("clientsMetric")} value={`${activeClientCount}/${totalClientCount} ${translate("active")}`} />
          </div>
        </article>
        <article className="panel overview-workspace-card">
          <div className="overview-card-heading">
            <div>
              <h3>{translate("overviewWorkspace")}</h3>
              <p className="muted">{translate("overviewIntro")}</p>
            </div>
          </div>
          <div className="overview-nav-grid">
            {canReadUsers && <button type="button" onClick={() => navigateToTab("users")}><Users size={17} /><span>{translate("users")}</span><ExternalLink size={14} /></button>}
            {canReadOrganizations && <button type="button" onClick={() => navigateToTab("organizations")}><Building2 size={17} /><span>{translate("organizations")}</span><ExternalLink size={14} /></button>}
            {canManageSecurity && <button type="button" onClick={() => navigateToTab("security")}><Shield size={17} /><span>{translate("security")}</span><ExternalLink size={14} /></button>}
          </div>
        </article>
      </div>
    </section>
  );
}

function Metric({ label, value, detail }: { label: string; value: string | number; detail: string }) {
  const text = String(value);
  const compact = text.length > 12;
  const schemeBoundary = typeof value === "string" && /^https?:\/\//.test(value)
    ? value.indexOf("//") + 2
    : 0;
  return (
    <Card as="article" className="metric">
      <span>{label}</span>
      <strong className={compact ? "metric-compact" : undefined}>
        {schemeBoundary ? <>{text.slice(0, schemeBoundary)}<wbr />{text.slice(schemeBoundary)}</> : value}
      </strong>
      <p>{detail}</p>
    </Card>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return <div className="info-cell"><span>{label}</span><strong>{value}</strong></div>;
}
