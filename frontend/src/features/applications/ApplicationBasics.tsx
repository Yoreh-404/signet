import {
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  Circle,
  Code2,
  Coins,
  Database,
  Globe2,
  KeyRound,
  Pencil,
  Plus,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Trash2
} from "lucide-react";
import type { ReactNode } from "react";
import { useMemo } from "react";

import type {
  ApplicationModuleKey,
  ApplicationSection,
  TenantApplication
} from "../../types";

export type ApplicationBasicsCopy = {
  applications: string;
  websites: string;
  applicationIntro: string;
  createWebsite: string;
  selectWebsite: string;
  noWebsites: string;
  noWebsitesHint: string;
  active: string;
  disabled: string;
  edit: string;
  delete: string;
  overview: string;
  protocols: string;
  identity: string;
  directory: string;
  permissions: string;
  billing: string;
  iapRules: string;
  accessBundle: string;
  accessBundleHint: string;
  identitySources: string;
  sourcesSelected: string;
  syncSources: string;
  protocolCount: string;
  setupNext: string;
  setupNextHint: string;
  configure: string;
};

/**
 * Read-only projection consumed by the application shell.  Business modules
 * own their drafts and mutations; this feature only renders the selected
 * application, its URL projection, and section navigation.
 */
export type ApplicationBasicsReadModel = {
  applications: TenantApplication[];
  selected: TenantApplication | null;
  section: ApplicationSection;
  /** `protocols.website_url` is written only by the App basics editor. */
  websiteUrl: string;
  enabledProtocolCount: number;
  enabledIdentityCount: number;
  enabledSyncCount: number;
  identitySourceCount: number;
  authorizationSummary: string;
  moduleEnabled: Record<ApplicationModuleKey, boolean>;
  billingEnabled: boolean;
  iapRuleCount: number;
};

export type ApplicationBasicsCommands = {
  selectApplication: (applicationId: string) => void;
  openSection: (section: ApplicationSection) => void;
  createApplication: () => void;
  editApplication: (application: TenantApplication) => void;
  deleteApplication: (applicationId: string) => void;
};

export type ApplicationBasicsProps = {
  readModel: ApplicationBasicsReadModel;
  commands: ApplicationBasicsCommands;
  copy: ApplicationBasicsCopy;
  canManage: boolean;
  children?: ReactNode;
};

const MODULE_KEYS: ApplicationModuleKey[] = [
  "protocols",
  "login_adapters",
  "directory_sync",
  "authorization"
];

export function ApplicationBasics({
  readModel,
  commands,
  copy,
  canManage,
  children
}: ApplicationBasicsProps) {
  const {
    applications,
    selected,
    section,
    websiteUrl,
    enabledProtocolCount,
    enabledIdentityCount,
    enabledSyncCount,
    identitySourceCount,
    authorizationSummary,
    moduleEnabled,
    billingEnabled,
    iapRuleCount
  } = readModel;
  const protocolCount = useMemo(
    () => applications.reduce(
      (total, item) => total
        + (item.client_bindings.length > 0 ? 1 : 0)
        + (item.modules ?? []).filter((module) => module.module_key === "protocols" && module.is_enabled).length,
      0
    ),
    [applications]
  );

  if (applications.length === 0) {
    return (
      <section className="application-workspace empty-application-workspace">
        <div className="application-empty-illustration"><Globe2 size={30} /></div>
        <h3>{copy.noWebsites}</h3>
        <p>{copy.noWebsitesHint}</p>
        {canManage && <button type="button" onClick={commands.createApplication}><Plus size={15} />{copy.createWebsite}</button>}
      </section>
    );
  }

  return (
    <section className="application-workspace">
      <div className="application-workspace-heading">
        <div>
          <span className="eyebrow"><Globe2 size={14} />{copy.websites}</span>
          <h3>{copy.applications}</h3>
          <p>{copy.applicationIntro}</p>
        </div>
        {canManage && <button type="button" className="primary-action" onClick={commands.createApplication}><Plus size={15} />{copy.createWebsite}</button>}
      </div>
      <div className="application-stat-strip">
        <div><span>{copy.websites}</span><strong>{applications.length}</strong></div>
        <div><span>{copy.protocols}</span><strong>{protocolCount}</strong></div>
        <div><span>{copy.identitySources}</span><strong>{identitySourceCount}</strong></div>
      </div>
      <div className="application-workspace-layout">
        <aside className="application-picker" aria-label={copy.selectWebsite}>
          <div className="application-picker-heading"><span>{copy.selectWebsite}</span><strong>{applications.length}</strong></div>
          <label className="application-mobile-picker">
            <span className="sr-only">{copy.selectWebsite}</span>
            <select value={selected?.id ?? ""} onChange={(event) => commands.selectApplication(event.target.value)}>
              {applications.map((application) => <option value={application.id} key={application.id}>{application.name} · {application.slug}</option>)}
            </select>
          </label>
          <div className="application-picker-list">
            {applications.map((application) => (
              <button type="button" key={application.id} className={application.id === selected?.id ? "selected" : ""} onClick={() => commands.selectApplication(application.id)}>
                <span className="application-avatar">{Array.from(application.name)[0]?.toUpperCase() ?? "W"}</span>
                <span className="application-picker-copy"><strong>{application.name}</strong><small>{application.slug}</small><em><span className="status-dot" aria-hidden="true" />{application.is_active ? copy.active : copy.disabled}</em></span>
                <ChevronRight size={16} />
              </button>
            ))}
          </div>
        </aside>
        {selected && (
          <div className="application-detail">
            <div className="application-detail-hero">
              <div className="application-hero-identity"><span className="application-hero-avatar"><Globe2 size={25} /></span><div><div className="application-breadcrumb"><span>{copy.websites}</span><ChevronRight size={13} /><span>{selected.slug}</span></div><h4>{selected.name}</h4><p>{selected.description || copy.accessBundleHint}</p>{websiteUrl && <a className="application-website-link" href={websiteUrl} target="_blank" rel="noreferrer"><Globe2 size={12} />{websiteUrl}</a>}</div></div>
              <div className="application-hero-actions">{canManage && <button type="button" className="icon-button" onClick={() => commands.editApplication(selected)} title={copy.edit} aria-label={copy.edit}><Pencil size={16} /></button>}</div>
            </div>
            <nav className="application-detail-tabs" aria-label={copy.accessBundle}>
              {(["overview", ...MODULE_KEYS, "iap", "billing"] as const).map((item) => {
                const label = item === "overview" ? copy.overview : item === "protocols" ? copy.protocols : item === "login_adapters" ? copy.identity : item === "directory_sync" ? copy.directory : item === "authorization" ? copy.permissions : item === "iap" ? copy.iapRules : copy.billing;
                const enabled = item === "billing"
                  ? billingEnabled
                  : item === "iap"
                    ? iapRuleCount > 0
                    : item === "overview"
                      ? false
                      : moduleEnabled[item];
                return <button type="button" className={section === item ? "active" : ""} key={item} onClick={() => commands.openSection(item)} aria-current={section === item ? "page" : undefined}>{item === "billing" ? <Coins size={16} aria-hidden="true" /> : item === "iap" ? <ShieldCheck size={16} aria-hidden="true" /> : <ModuleTabIcon item={item} />}<span>{label}</span>{item !== "overview" && <span className={`tab-status ${enabled ? "on" : ""}`} aria-label={enabled ? copy.active : copy.disabled}>{enabled ? copy.active : copy.disabled}</span>}</button>;
              })}
            </nav>
            {section === "overview" && (
              <div className="application-overview-panel">
                <div className="application-module-grid">
                  <ModuleSummary keyName="protocols" title={copy.protocols} icon={<Code2 size={18} />} enabled={moduleEnabled.protocols} summary={`${enabledProtocolCount} ${copy.protocolCount}`} onClick={() => commands.openSection("protocols")} />
                  <ModuleSummary keyName="login_adapters" title={copy.identity} icon={<KeyRound size={18} />} enabled={moduleEnabled.login_adapters} summary={`${enabledIdentityCount} ${copy.sourcesSelected}`} onClick={() => commands.openSection("login_adapters")} />
                  <ModuleSummary keyName="directory_sync" title={copy.directory} icon={<Database size={18} />} enabled={moduleEnabled.directory_sync} summary={`${enabledSyncCount} ${copy.syncSources}`} onClick={() => commands.openSection("directory_sync")} />
                  <ModuleSummary keyName="authorization" title={copy.permissions} icon={<ShieldCheck size={18} />} enabled={moduleEnabled.authorization} summary={authorizationSummary} onClick={() => commands.openSection("authorization")} />
                </div>
                <div className="application-next-step"><div className="next-step-icon"><SlidersHorizontal size={18} /></div><div><strong>{copy.setupNext}</strong><p>{copy.setupNextHint}</p></div><button type="button" onClick={() => commands.openSection("protocols")}><span>{copy.configure}</span><ArrowRight size={15} /></button></div>
              </div>
            )}
            {section !== "overview" && children}
            {canManage && <div className="application-danger-zone"><button type="button" className="text-danger-button" onClick={() => commands.deleteApplication(selected.id)}><Trash2 size={14} />{copy.delete}</button></div>}
          </div>
        )}
      </div>
    </section>
  );
}

function ModuleTabIcon({ item }: { item: "overview" | ApplicationModuleKey }) {
  if (item === "overview") return <Settings2 size={16} />;
  return <ModuleIcon keyName={item} />;
}

function ModuleIcon({ keyName }: { keyName: ApplicationModuleKey }) {
  if (keyName === "protocols") return <Code2 size={18} />;
  if (keyName === "login_adapters") return <KeyRound size={18} />;
  if (keyName === "directory_sync") return <Database size={18} />;
  return <ShieldCheck size={18} />;
}

function ModuleSummary({
  keyName,
  title,
  icon,
  enabled,
  summary,
  onClick
}: {
  keyName: ApplicationModuleKey;
  title: string;
  icon: ReactNode;
  enabled: boolean;
  summary: string;
  onClick: () => void;
}) {
  return <button type="button" className="application-module-summary" onClick={onClick}><span className={`module-summary-icon module-${keyName}`}>{icon}</span><span className="module-summary-copy"><strong>{title}</strong><small>{summary}</small></span><span className={`module-summary-state ${enabled ? "on" : ""}`}>{enabled ? <CheckCircle2 size={15} /> : <Circle size={15} />}</span><ChevronRight size={15} /></button>;
}
