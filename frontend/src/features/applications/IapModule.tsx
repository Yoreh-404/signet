import { ArrowRight, Pencil, Plus, ShieldCheck, Trash2 } from "lucide-react";
import type { FormEvent } from "react";
import { useEffect, useState } from "react";
import * as applicationApi from "../../lib/api/applications";
import type { IapApplication, OrganizationOption } from "../../types";
import { Input, ModuleFeedback, ModuleHeader, Toggle } from "./components/ApplicationModulePrimitives";
import { useApplicationModuleLifecycle } from "./use-application-module-lifecycle";
import { useApplicationWorkspaceRequestContext } from "./use-application-workspace-request-context";
import { toIapRulePayload } from "./form-adapters";

export type IapRuleDraft = {
  id: string;
  slug: string;
  name: string;
  description: string;
  external_host: string;
  path_prefix: string;
  required_organization_id: string;
  required_organization_roles: string[];
  required_permissions: string;
  is_active: boolean;
};

type IapCopy = {
  iapRules: string;
  iapRulesHint: string;
  noIapRules: string;
  createIapRule: string;
  slug: string;
  client: string;
  externalHost: string;
  pathPrefix: string;
  description: string;
  requiredOrganization: string;
  notConfigured: string;
  requiredRoles: string;
  requiredPermissions: string;
  customPermissionsHint: string;
  active: string;
  disabled: string;
  discardChanges: string;
  saving: string;
  save: string;
  edit: string;
  delete: string;
  saved: string;
  saveFailed: string;
  loadFailed: string;
};

function emptyIapRuleDraft(): IapRuleDraft {
  return {
    id: "",
    slug: "",
    name: "",
    description: "",
    external_host: "",
    path_prefix: "/",
    required_organization_id: "",
    required_organization_roles: [],
    required_permissions: "",
    is_active: true
  };
}

function toIapRuleDraft(rule: IapApplication): IapRuleDraft {
  return {
    id: rule.id,
    slug: rule.slug,
    name: rule.name,
    description: rule.description ?? "",
    external_host: rule.external_host,
    path_prefix: rule.path_prefix,
    required_organization_id: rule.required_organization_id ?? "",
    required_organization_roles: rule.required_organization_roles,
    required_permissions: rule.required_permissions.join("\n"),
    is_active: rule.is_active
  };
}

export function IapModule({
  applicationId,
  organizationId,
  organizationOptions,
  canManage,
  copy,
  onDirtyChange,
  onRulesCountChange,
  onRequestConfirmation
}: {
  applicationId: string;
  organizationId: string;
  organizationOptions: OrganizationOption[];
  canManage: boolean;
  copy: IapCopy;
  onDirtyChange: (dirty: boolean) => void;
  onRulesCountChange: (count: number) => void;
  onRequestConfirmation?: (
    action: () => Promise<void> | void,
    title: string,
    description: string
  ) => void;
}) {
  const [rules, setRules] = useState<IapApplication[]>([]);
  const [draft, setDraft] = useState<IapRuleDraft | null>(null);
  const { requestGuard } = useApplicationWorkspaceRequestContext();
  const {
    saving,
    setSaving,
    feedback,
    setFeedback,
    beginRequest,
    isCurrent,
    finishRequest
  } = useApplicationModuleLifecycle({
    applicationId,
    requestGuard,
    onDirtyChange,
    dirty: draft !== null
  });

  useEffect(() => {
    setRules([]);
    setDraft(null);
    setSaving(false);
    setFeedback("");
    onRulesCountChange(0);
    onDirtyChange(false);
  }, [applicationId, onDirtyChange, onRulesCountChange]);

  useEffect(() => {
    const request = beginRequest("iap:rules", { kind: "read" });
    if (!request) return;
    void applicationApi.listApplicationIapRules(applicationId, { signal: request.signal })
      .then((nextRules) => {
        if (!isCurrent(request)) return;
        setRules(nextRules);
        onRulesCountChange(nextRules.length);
      })
      .catch(() => {
        if (!isCurrent(request)) return;
        setRules([]);
        onRulesCountChange(0);
        setFeedback(copy.loadFailed);
      });
    return () => finishRequest(request, false);
  }, [beginRequest, copy.loadFailed, finishRequest, isCurrent, onRulesCountChange]);

  useEffect(() => {
    onRulesCountChange(rules.length);
  }, [onRulesCountChange, rules.length]);

  function openEditor(rule?: IapApplication) {
    setDraft(rule ? toIapRuleDraft(rule) : emptyIapRuleDraft());
    setFeedback("");
  }

  async function saveRule(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!draft || !canManage) return;
    const request = beginRequest(`iap:rule:${draft.id || "new"}`, {
      kind: "mutation",
      payloadFingerprint: JSON.stringify(draft)
    });
    if (!request) return;
    setSaving(true);
    let committed = false;
    try {
      const payload = toIapRulePayload(draft);
      const saved = draft.id
        ? await applicationApi.updateApplicationIapRule(applicationId, draft.id, payload, { signal: request.signal, idempotencyKey: request.idempotencyKey ?? undefined })
        : await applicationApi.createApplicationIapRule(applicationId, payload, { signal: request.signal, idempotencyKey: request.idempotencyKey ?? undefined });
      if (!isCurrent(request)) return;
      setRules((current) => {
        return draft.id
          ? current.map((rule) => rule.id === saved.id ? saved : rule)
          : [saved, ...current];
      });
      setDraft(null);
      setFeedback(copy.saved);
      committed = true;
    } catch {
      if (isCurrent(request)) setFeedback(copy.saveFailed);
    } finally {
      if (isCurrent(request)) setSaving(false);
      finishRequest(request, committed);
    }
  }

  async function deleteRule(rule: IapApplication) {
    const request = beginRequest(`iap:rule:${rule.id}:delete`, { kind: "mutation" });
    if (!request) return;
    setSaving(true);
    let committed = false;
    try {
      await applicationApi.deleteApplicationIapRule(applicationId, rule.id, { signal: request.signal, idempotencyKey: request.idempotencyKey ?? undefined });
      if (!isCurrent(request)) return;
      setRules((current) => {
        return current.filter((item) => item.id !== rule.id);
      });
      setDraft((current) => current?.id === rule.id ? null : current);
      setFeedback(copy.saved);
      committed = true;
    } catch {
      if (isCurrent(request)) setFeedback(copy.saveFailed);
    } finally {
      if (isCurrent(request)) setSaving(false);
      finishRequest(request, committed);
    }
  }

  const currentOrganization = organizationOptions.find((item) => item.id === organizationId);

  return (
    <div className="application-module-content application-iap-editor">
      <ModuleHeader icon={<ShieldCheck size={19} />} title={copy.iapRules} description={copy.iapRulesHint} />
      <ModuleFeedback message={feedback} errorMessages={[copy.saveFailed, copy.loadFailed]} />
      <div className="subsection-heading">
        <strong>{copy.iapRules}</strong>
        <button type="button" className="secondary-button" onClick={() => openEditor()} disabled={!canManage || saving}>
          <Plus size={14} />{copy.createIapRule}
        </button>
      </div>
      {draft && (
        <form className="application-iap-rule-form" onSubmit={saveRule}>
          <div className="form-grid-2 compact-form-grid">
            <Input label={copy.slug} value={draft.slug} required disabled={saving} onChange={(value) => setDraft((current) => current ? { ...current, slug: value } : current)} />
            <Input label={copy.client} value={draft.name} required disabled={saving} onChange={(value) => setDraft((current) => current ? { ...current, name: value } : current)} />
            <Input label={copy.externalHost} value={draft.external_host} required disabled={saving} onChange={(value) => setDraft((current) => current ? { ...current, external_host: value } : current)} />
            <Input label={copy.pathPrefix} value={draft.path_prefix} required disabled={saving} onChange={(value) => setDraft((current) => current ? { ...current, path_prefix: value } : current)} />
          </div>
          <Input label={copy.description} value={draft.description} textarea disabled={saving} onChange={(value) => setDraft((current) => current ? { ...current, description: value } : current)} />
          <label className="application-input">
            <span>{copy.requiredOrganization}</span>
            <select value={draft.required_organization_id} disabled={saving} onChange={(event) => setDraft((current) => current ? { ...current, required_organization_id: event.target.value } : current)}>
              <option value="">{copy.notConfigured}</option>
              {currentOrganization && <option value={currentOrganization.id}>{currentOrganization.name} · {currentOrganization.slug}</option>}
            </select>
          </label>
          <div className="application-input">
            <span>{copy.requiredRoles}</span>
            <div className="application-toggle-grid">
              {["owner", "admin", "member"].map((role) => (
                <Toggle
                  key={role}
                  label={role}
                  checked={draft.required_organization_roles.includes(role)}
                  disabled={saving}
                  onChange={(value) => setDraft((current) => current ? {
                    ...current,
                    required_organization_roles: value
                      ? [...current.required_organization_roles, role]
                      : current.required_organization_roles.filter((item) => item !== role)
                  } : current)}
                />
              ))}
            </div>
          </div>
          <Input label={copy.requiredPermissions} value={draft.required_permissions} textarea hint={copy.customPermissionsHint} disabled={saving} onChange={(value) => setDraft((current) => current ? { ...current, required_permissions: value } : current)} />
          <Toggle label={copy.active} checked={draft.is_active} disabled={saving} onChange={(value) => setDraft((current) => current ? { ...current, is_active: value } : current)} />
          <div className="application-module-actions">
            <button type="button" className="secondary-button" onClick={() => setDraft(null)} disabled={saving}>{copy.discardChanges}</button>
            <button type="submit" className="primary-action" disabled={saving}>{saving ? copy.saving : copy.save}<ArrowRight size={15} /></button>
          </div>
        </form>
      )}
      <div className="application-iap-rule-list">
        {rules.map((rule) => (
          <article className="application-iap-rule-card" key={rule.id}>
            <div><strong>{rule.name}</strong><small><code>{rule.external_host}{rule.path_prefix}</code></small></div>
            <span className={`tab-status ${rule.is_active ? "on" : ""}`}>{rule.is_active ? copy.active : copy.disabled}</span>
            <div className="tag-row"><span>{copy.slug}: {rule.slug}</span>{rule.required_organization_roles.map((role) => <span key={role}>{role}</span>)}{rule.required_permissions.map((permission) => <span key={permission}>{permission}</span>)}</div>
            {canManage && <div className="actions"><button type="button" onClick={() => openEditor(rule)} disabled={saving}><Pencil size={14} />{copy.edit}</button><button type="button" className="text-danger-button" onClick={() => onRequestConfirmation ? onRequestConfirmation(() => deleteRule(rule), copy.delete, copy.iapRulesHint) : void deleteRule(rule)} disabled={saving}><Trash2 size={14} />{copy.delete}</button></div>}
          </article>
        ))}
        {rules.length === 0 && <p className="muted">{copy.noIapRules}</p>}
      </div>
    </div>
  );
}
