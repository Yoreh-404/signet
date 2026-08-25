import { KeyRound } from "lucide-react";
import { useMemo } from "react";
import type { ExternalProvider } from "../../types";
import { ModuleHeader, ModuleSave, Toggle } from "./components/ApplicationModulePrimitives";

export type ApplicationLoginAdaptersEditorCopy = {
  loginAdapters: string;
  loginAdaptersHint: string;
  enabled: string;
  active: string;
  disabled: string;
  allowSignetPassword: string;
  noLoginAdapters: string;
  save: string;
  saving: string;
  saveFailed: string;
};

export type ApplicationLoginAdaptersEditorProps = {
  providers: ExternalProvider[];
  organizationId: string;
  enabled: boolean;
  providerIds: string[];
  allowSignetPassword: boolean;
  saving: boolean;
  feedback: string;
  copy: ApplicationLoginAdaptersEditorCopy;
  onEnabledChange: (enabled: boolean) => void;
  onProviderToggle: (providerId: string) => void;
  onAllowSignetPasswordChange: (allowed: boolean) => void;
  onSave: () => void;
};

export function ApplicationLoginAdaptersEditor({
  providers,
  organizationId,
  enabled,
  providerIds,
  allowSignetPassword,
  saving,
  feedback,
  copy,
  onEnabledChange,
  onProviderToggle,
  onAllowSignetPasswordChange,
  onSave
}: ApplicationLoginAdaptersEditorProps) {
  const visibleProviders = providers.filter((provider) => (
    !provider.organization_id || provider.organization_id === organizationId
  ));
  const providerIdSet = useMemo(() => new Set(providerIds), [providerIds]);

  return (
    <div className="application-module-content">
      <ModuleHeader icon={<KeyRound size={19} />} title={copy.loginAdapters} description={copy.loginAdaptersHint} />
      <div className="module-setting-card">
        <Toggle label={copy.enabled} checked={enabled} onChange={onEnabledChange} />
        <div className="application-choice-list">
          {visibleProviders.map((provider) => (
            <label className="application-choice" key={provider.id}>
              <input type="checkbox" checked={providerIdSet.has(provider.id)} onChange={() => onProviderToggle(provider.id)} />
              <span><strong>{provider.display_name}</strong><small>{provider.issuer}</small></span>
              <span className="application-choice-status">{provider.allow_login && provider.is_active ? copy.active : copy.disabled}</span>
            </label>
          ))}
          {providers.length === 0 && <p className="muted">{copy.noLoginAdapters}</p>}
        </div>
        <Toggle label={copy.allowSignetPassword} checked={allowSignetPassword} onChange={onAllowSignetPasswordChange} />
      </div>
      <ModuleSave saving={saving} feedback={feedback} copy={copy} onSave={onSave} />
    </div>
  );
}
