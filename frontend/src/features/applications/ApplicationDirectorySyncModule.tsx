import {
  Copy as CopyIcon,
  Database,
  Plus,
  RefreshCw
} from "lucide-react";
import { useEffect, useState } from "react";

import * as applicationApi from "../../lib/api/applications";
import type { DirtyNavigationController } from "../navigation/useDirtyNavigation";
import type {
  ApplicationDirectorySyncRun,
  ApplicationModule,
  ApplicationScimToken,
  LdapProvider,
  Locale,
  TenantApplication
} from "../../types";
import { persistApplicationModule } from "./application-module-persistence";
import {
  booleanValue,
  record,
  stringList,
  stringValue,
  toggleString
} from "./application-module-values";
import { useApplicationWorkspaceRequestContext } from "./use-application-workspace-request-context";
import { useApplicationModuleDraft } from "./use-application-module-draft";
import {
  Input,
  ModuleHeader,
  ModuleSave,
  Toggle
} from "./components/ApplicationModulePrimitives";

import {
  APPLICATION_DIRECTORY_SYNC_DIRTY_SOURCE,
  applicationDirectorySyncConfig,
} from "./application-workspace-module-contracts";
export { APPLICATION_DIRECTORY_SYNC_DIRTY_SOURCE } from "./application-workspace-module-contracts";

export type ApplicationDirectorySyncCopy = {
  directorySync: string;
  directorySyncHint: string;
  ldapAd: string;
  scim: string;
  scimHint: string;
  scimAudience: string;
  groupSync: string;
  userSyncFilter: string;
  groupBaseDn: string;
  groupFilter: string;
  groupIdAttribute: string;
  groupNameAttribute: string;
  groupMemberAttribute: string;
  reactivateUsers: string;
  maxEntries: string;
  deprovisionAction: string;
  runNow: string;
  syncRunning: string;
  syncCompleted: string;
  syncHistory: string;
  noSyncRuns: string;
  syncSuccess: string;
  syncFailure: string;
  syncSeen: string;
  syncCreated: string;
  syncUpdated: string;
  syncDisabled: string;
  syncCheckpoint: string;
  syncNoCheckpoint: string;
  syncSources: string;
  configured: string;
  notConfigured: string;
  enabled: string;
  scimTokens: string;
  scimTokensHint: string;
  createScimToken: string;
  scimTokenScopes: string;
  scimRead: string;
  scimWrite: string;
  scimTokenExpiry: string;
  scimTokenExpiryHint: string;
  noScimTokens: string;
  tokenExpires: string;
  tokenNeverExpires: string;
  tokenLastUsed: string;
  tokenNeverUsed: string;
  tokenCreated: string;
  copyToken: string;
  copied: string;
  revokeToken: string;
  revokeTokenHint: string;
  revoked: string;
  tokenOnlyOnce: string;
  active: string;
  disabled: string;
  saving: string;
  save: string;
  saveFailed: string;
  saved: string;
};

export type ApplicationDirectorySyncModuleProps = {
  application: TenantApplication;
  ldapProviders: LdapProvider[];
  locale: Locale;
  canManage: boolean;
  copy: ApplicationDirectorySyncCopy;
  dirtyNavigation: Pick<DirtyNavigationController, "registerSource">;
  onDirtyChange?: () => void;
  onReadModelChange?: (applicationId: string, config: Record<string, unknown> | null) => void;
  onApplicationModuleChanged: (applicationId: string, module: ApplicationModule) => void;
  onRequestConfirmation?: (
    action: () => Promise<void> | void,
    title: string,
    description: string
  ) => void;
};

export { applicationDirectorySyncConfig } from "./application-workspace-module-contracts";

function formatScimTokenTime(value: number | null, locale: Locale): string {
  if (value === null) return "";
  return new Date(value * 1000).toLocaleString(locale === "zh-CN" ? "zh-CN" : "en-US");
}

export function ApplicationDirectorySyncModule({
  application,
  ldapProviders,
  locale,
  canManage,
  copy,
  dirtyNavigation,
  onDirtyChange,
  onReadModelChange,
  onApplicationModuleChanged,
  onRequestConfirmation
}: ApplicationDirectorySyncModuleProps) {
  const [scimTokens, setScimTokens] = useState<ApplicationScimToken[]>([]);
  const [scimTokenScopes, setScimTokenScopes] = useState<string[]>(["scim.read", "scim.write"]);
  const [scimTokenExpiry, setScimTokenExpiry] = useState("");
  const [scimTokenSaving, setScimTokenSaving] = useState(false);
  const [createdScimToken, setCreatedScimToken] = useState("");
  const [syncRuns, setSyncRuns] = useState<ApplicationDirectorySyncRun[]>([]);
  const [runningProviderId, setRunningProviderId] = useState<string | null>(null);
  const { beginRequest, isCurrent, finishRequest, requestOptions } = useApplicationWorkspaceRequestContext();
  const {
    config,
    draftConfig,
    setDraftConfig,
    saving,
    setSaving,
    feedback,
    setFeedback
  } = useApplicationModuleDraft({
    application,
    dirtyNavigation,
    dirtySource: APPLICATION_DIRECTORY_SYNC_DIRTY_SOURCE,
    resolveConfig: applicationDirectorySyncConfig,
    onDirtyChange,
    onReadModelChange
  });

  useEffect(() => {
    setScimTokens([]);
    setScimTokenScopes(["scim.read", "scim.write"]);
    setScimTokenExpiry("");
    setCreatedScimToken("");
    setSyncRuns([]);
    setRunningProviderId(null);
    setScimTokenSaving(false);
  }, [application.id]);

  useEffect(() => {
    const request = beginRequest("directory-sync:runs", { kind: "read" });
    if (!request) return;
    void applicationApi.listApplicationDirectorySyncRuns(application.id, requestOptions(request))
      .then((runs) => {
        if (isCurrent(request)) setSyncRuns(runs);
      })
      .catch(() => {
        if (isCurrent(request)) setSyncRuns([]);
      });
    return () => finishRequest(request, false);
  }, [application.id, beginRequest, finishRequest, isCurrent]);

  useEffect(() => {
    const request = beginRequest("directory-sync:scim-tokens", { kind: "read" });
    if (!request) return;
    void applicationApi.listApplicationScimTokens(application.id, requestOptions(request))
      .then((tokens) => {
        if (isCurrent(request)) setScimTokens(tokens);
      })
      .catch(() => {
        if (isCurrent(request)) setScimTokens([]);
      });
    return () => finishRequest(request, false);
  }, [application.id, beginRequest, finishRequest, isCurrent]);

  function updateDraft(next: Record<string, unknown>) {
    setDraftConfig(next);
  }

  function toggleId(id: string) {
    const values = stringList(config.ldap_provider_ids);
    const next = toggleString(values, id);
    updateDraft({ ...config, ldap_provider_ids: next });
  }

  async function saveModule() {
    const nextConfig = draftConfig ?? applicationDirectorySyncConfig(application);
    const request = beginRequest("module:directory_sync", {
      kind: "mutation",
      payloadFingerprint: JSON.stringify(nextConfig)
    });
    if (!request) return;
    setSaving(true);
    setFeedback("");
    let committed = false;
    try {
      const result = await persistApplicationModule(application.id, "directory_sync", {
        config: nextConfig,
        is_enabled: booleanValue(nextConfig.enabled)
      }, request, isCurrent);
      if (result.stale) return;
      if (result.module) onApplicationModuleChanged(application.id, result.module);
      if (result.committed || (result.module && result.moduleWritten)) setDraftConfig(null);
      setFeedback(result.committed ? copy.saved : copy.saveFailed);
      committed = result.committed;
    } finally {
      if (isCurrent(request)) setSaving(false);
      finishRequest(request, committed);
    }
  }

  function toggleScimTokenScope(scope: string) {
    setScimTokenScopes((current) => current.includes(scope)
      ? current.filter((item) => item !== scope)
      : [...current, scope]);
  }

  async function createScimToken() {
    if (scimTokenScopes.length === 0) return;
    const request = beginRequest("directory-sync:scim-token:create", { kind: "mutation" });
    if (!request) return;
    let expiresAt: number | null = null;
    if (scimTokenExpiry) {
      const parsed = Date.parse(scimTokenExpiry);
      if (!Number.isFinite(parsed) || parsed <= Date.now()) {
        setFeedback(copy.saveFailed);
        finishRequest(request, false);
        return;
      }
      expiresAt = Math.floor(parsed / 1000);
    }
    setScimTokenSaving(true);
    setFeedback("");
    let committed = false;
    try {
      const response = await applicationApi.createApplicationScimToken(application.id, {
        scopes: scimTokenScopes,
        expires_at: expiresAt
      }, requestOptions(request));
      if (!isCurrent(request)) return;
      const { token, ...metadata } = response;
      setScimTokens((current) => [metadata, ...current]);
      setCreatedScimToken(token ?? "");
      setScimTokenExpiry("");
      setFeedback(copy.saved);
      committed = true;
    } catch {
      if (isCurrent(request)) setFeedback(copy.saveFailed);
    } finally {
      if (isCurrent(request)) setScimTokenSaving(false);
      finishRequest(request, committed);
    }
  }

  async function revokeScimToken(tokenId: string) {
    const request = beginRequest(`directory-sync:scim-token:${tokenId}:revoke`, { kind: "mutation" });
    if (!request) return;
    setScimTokenSaving(true);
    setFeedback("");
    let committed = false;
    try {
      await applicationApi.revokeApplicationScimToken(application.id, tokenId, requestOptions(request));
      if (!isCurrent(request)) return;
      setScimTokens((current) => current.map((token) => token.id === tokenId
        ? { ...token, revoked_at: Math.floor(Date.now() / 1000) }
        : token));
      if (createdScimToken) setCreatedScimToken("");
      committed = true;
    } catch {
      if (isCurrent(request)) setFeedback(copy.saveFailed);
    } finally {
      if (isCurrent(request)) setScimTokenSaving(false);
      finishRequest(request, committed);
    }
  }

  async function runDirectorySync(providerId: string) {
    if (!canManage) return;
    const request = beginRequest(`directory-sync:${providerId}:run`, { kind: "mutation" });
    if (!request) return;
    setRunningProviderId(providerId);
    setFeedback("");
    let committed = false;
    try {
      const run = await applicationApi.runApplicationDirectorySync(application.id, providerId, requestOptions(request));
      if (!isCurrent(request)) return;
      setSyncRuns((current) => [run, ...current.filter((item) => item.id !== run.id)]);
      setFeedback(copy.syncCompleted);
      committed = true;
    } catch {
      if (!isCurrent(request)) return;
      setFeedback(copy.saveFailed);
      try {
        const runs = await applicationApi.listApplicationDirectorySyncRuns(application.id, requestOptions(request));
        if (!isCurrent(request)) return;
        setSyncRuns(runs);
      } catch {
        // Preserve the original action error when refreshing history fails.
      }
    } finally {
      if (isCurrent(request)) setRunningProviderId(null);
      finishRequest(request, committed);
    }
  }

  async function copyCreatedScimToken() {
    if (!createdScimToken) return;
    try {
      await navigator.clipboard.writeText(createdScimToken);
      setFeedback(copy.copied);
    } catch {
      setFeedback(copy.saveFailed);
    }
  }

  const selectedLdapProviderIds = new Set(stringList(config.ldap_provider_ids));
  const ldapProvidersById = new Map(ldapProviders.map((provider) => [provider.id, provider]));
  const checkpoint = syncRuns.find((run) => run.status === "succeeded" && run.cursor);
  const activeScimTokenCount = scimTokens.filter((token) => !token.revoked_at).length;

  return (
    <div className="application-module-content">
      <ModuleHeader icon={<Database size={19} />} title={copy.directorySync} description={copy.directorySyncHint} />
      <div className="module-setting-card">
        <div className="subsection-heading"><strong>{copy.ldapAd}</strong><span>{selectedLdapProviderIds.size} {copy.syncSources}</span></div>
        <div className="application-choice-list">
          {ldapProviders.map((provider) => (
            <div className="directory-sync-provider-row" key={provider.id}>
              <label className="application-choice">
                <input type="checkbox" checked={selectedLdapProviderIds.has(provider.id)} onChange={() => toggleId(provider.id)} />
                <span><strong>{provider.display_name}</strong><small>{provider.url} · {provider.base_dn}</small></span>
                <span className="application-choice-status">{provider.is_active ? copy.active : copy.disabled}</span>
              </label>
              <button type="button" className="text-button directory-sync-run-button" onClick={() => void runDirectorySync(provider.id)} disabled={!canManage || runningProviderId !== null || !selectedLdapProviderIds.has(provider.id) || !booleanValue(config.enabled)}>
                <RefreshCw size={14} className={runningProviderId === provider.id ? "spin" : undefined} />
                {runningProviderId === provider.id ? copy.syncRunning : copy.runNow}
              </button>
            </div>
          ))}
          {ldapProviders.length === 0 && <p className="muted">{copy.notConfigured}</p>}
        </div>
        <div className="module-divider" />
        <div className="subsection-heading"><strong>{copy.ldapAd} {copy.directorySync}</strong><span>{copy.deprovisionAction}: remove_membership</span></div>
        <div className="form-grid-2 compact-form-grid">
          <Input label={copy.userSyncFilter} hint={locale === "zh-CN" ? "留空则使用 LDAP provider 的用户过滤器，并将登录占位符替换为通配符。" : "Leave blank to derive a wildcard filter from the LDAP provider user filter."} value={stringValue(config.user_sync_filter)} onChange={(value) => updateDraft({ ...config, user_sync_filter: value })} />
          <Input label={copy.groupBaseDn} value={stringValue(config.group_base_dn)} onChange={(value) => updateDraft({ ...config, group_base_dn: value })} />
          <Input label={copy.groupIdAttribute} value={stringValue(config.group_id_attribute, "dn")} onChange={(value) => updateDraft({ ...config, group_id_attribute: value })} />
          <Input label={copy.groupNameAttribute} value={stringValue(config.group_name_attribute, "cn")} onChange={(value) => updateDraft({ ...config, group_name_attribute: value })} />
          <Input label={copy.groupMemberAttribute} value={stringValue(config.group_member_attribute, "member")} onChange={(value) => updateDraft({ ...config, group_member_attribute: value })} />
          <Input label={copy.maxEntries} type="number" value={String(typeof config.max_entries === "number" ? config.max_entries : 100000)} onChange={(value) => updateDraft({ ...config, max_entries: Number(value) || 100000 })} />
        </div>
        <Input label={copy.groupFilter} value={stringValue(config.group_filter, "(objectClass=group)")} onChange={(value) => updateDraft({ ...config, group_filter: value })} />
        <Toggle label={copy.reactivateUsers} checked={booleanValue(config.reactivate_users, true)} onChange={(value) => updateDraft({ ...config, reactivate_users: value })} />
        <label className="application-input"><span>{copy.deprovisionAction}</span><select value={stringValue(config.deprovision_action, "remove_membership")} onChange={(event) => updateDraft({ ...config, deprovision_action: event.target.value })}><option value="remove_membership">remove_membership</option></select></label>
        <div className="module-divider" />
        <div className="subsection-heading"><strong>{copy.scim}</strong><span>{booleanValue(config.scim_enabled) ? copy.configured : copy.notConfigured}</span></div>
        <p className="muted">{copy.scimHint}</p>
        <Toggle label={copy.enabled} checked={booleanValue(config.enabled)} onChange={(value) => updateDraft({ ...config, enabled: value })} />
        <Toggle label={copy.enabled} checked={booleanValue(config.scim_enabled)} onChange={(value) => updateDraft({ ...config, scim_enabled: value })} />
        <div className="form-grid-2 compact-form-grid">
          <Input label={copy.scimAudience} value={stringValue(config.scim_audience)} onChange={(value) => updateDraft({ ...config, scim_audience: value })} />
        </div>
        <Toggle label={copy.groupSync} checked={booleanValue(config.sync_groups, true)} onChange={(value) => updateDraft({ ...config, sync_groups: value })} />
      </div>
      <div className="module-setting-card directory-sync-history">
        <div className="subsection-heading"><div><strong>{copy.syncHistory}</strong><p className="muted">{copy.syncCheckpoint}: {checkpoint?.cursor ? formatScimTokenTime(Number(checkpoint.cursor), locale) : copy.syncNoCheckpoint}</p></div><span>{syncRuns.length}</span></div>
        <div className="directory-sync-run-list">
          {syncRuns.map((run) => {
            const provider = ldapProvidersById.get(run.provider_id);
            const status = run.status === "succeeded" ? copy.syncSuccess : run.status === "failed" ? copy.syncFailure : copy.syncRunning;
            return <div className={`directory-sync-run${run.status === "succeeded" ? " succeeded" : run.status === "failed" ? " failed" : " running"}`} key={run.id}>
              <div className="directory-sync-run-heading"><strong>{provider?.display_name ?? run.provider_id}</strong><span>{status}</span></div>
              <div className="directory-sync-run-meta"><span>{formatScimTokenTime(run.started_at, locale)}</span><span>{copy.syncSeen}: {run.total_seen}</span><span>{copy.syncCreated}: {run.created_count}</span><span>{copy.syncUpdated}: {run.updated_count}</span><span>{copy.syncDisabled}: {run.disabled_count}</span></div>
              {run.error && <small className="directory-sync-run-error">{run.error}</small>}
            </div>;
          })}
          {syncRuns.length === 0 && <p className="muted">{copy.noSyncRuns}</p>}
        </div>
      </div>
      <div className="module-setting-card scim-token-card">
        <div className="subsection-heading"><div><strong>{copy.scimTokens}</strong><p className="muted">{copy.scimTokensHint}</p></div><span>{activeScimTokenCount}</span></div>
        <div className="scim-token-create">
          <strong>{copy.createScimToken}</strong>
          <div className="scim-token-scope-list">
            <label className="application-choice"><input type="checkbox" checked={scimTokenScopes.includes("scim.read")} onChange={() => toggleScimTokenScope("scim.read")} /><span><strong>{copy.scimRead}</strong><small>scim.read</small></span></label>
            <label className="application-choice"><input type="checkbox" checked={scimTokenScopes.includes("scim.write")} onChange={() => toggleScimTokenScope("scim.write")} /><span><strong>{copy.scimWrite}</strong><small>scim.write</small></span></label>
          </div>
          <Input label={copy.scimTokenExpiry} hint={copy.scimTokenExpiryHint} type="datetime-local" value={scimTokenExpiry} onChange={setScimTokenExpiry} />
          <button type="button" className="secondary-button" onClick={() => void createScimToken()} disabled={scimTokenSaving || scimTokenScopes.length === 0 || !booleanValue(config.scim_enabled)}><Plus size={14} />{scimTokenSaving ? copy.saving : copy.createScimToken}</button>
        </div>
        {createdScimToken && <div className="module-secret-value scim-token-reveal"><div><code>{createdScimToken}</code><small>{copy.tokenOnlyOnce}</small></div><button type="button" className="text-button" onClick={() => void copyCreatedScimToken()}><CopyIcon size={14} />{copy.copyToken}</button></div>}
        <div className="scim-token-list">
          {scimTokens.map((token) => (
            <div className={`scim-token-row${token.revoked_at ? " revoked" : ""}`} key={token.id}>
              <div className="scim-token-main"><strong>{token.token_prefix}…</strong><small>{token.scopes.join(" · ")}</small></div>
              <div className="scim-token-meta"><span>{token.revoked_at ? copy.revoked : `${copy.tokenExpires}: ${token.expires_at ? formatScimTokenTime(token.expires_at, locale) : copy.tokenNeverExpires}`}</span><span>{copy.tokenLastUsed}: {token.last_used_at ? formatScimTokenTime(token.last_used_at, locale) : copy.tokenNeverUsed}</span><small>{copy.tokenCreated}: {formatScimTokenTime(token.created_at, locale)}</small></div>
              {!token.revoked_at && <button type="button" className="text-danger-button" onClick={() => onRequestConfirmation ? onRequestConfirmation(() => revokeScimToken(token.id), copy.revokeToken, copy.revokeTokenHint) : void revokeScimToken(token.id)} disabled={scimTokenSaving}>{copy.revokeToken}</button>}
            </div>
          ))}
          {scimTokens.length === 0 && <p className="muted">{copy.noScimTokens}</p>}
        </div>
      </div>
      <ModuleSave saving={saving} feedback={feedback} copy={copy} onSave={() => void saveModule()} />
    </div>
  );
}
