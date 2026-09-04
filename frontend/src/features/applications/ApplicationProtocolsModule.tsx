import {
  Circle,
  Code2,
  Globe2,
  LockKeyhole
} from "lucide-react";
import { useEffect, useState } from "react";

import * as applicationApi from "../../lib/api/applications";
import type { DirtyNavigationController } from "../navigation/useDirtyNavigation";
import type {
  ApplicationJwtClient,
  ApplicationModule,
  Client,
  Locale,
  TenantApplication
} from "../../types";
import { persistApplicationProtocols } from "./application-protocols-persistence";
import {
  booleanValue,
  record,
  splitUniqueTrimmed,
  stringList,
  stringValue
} from "./application-module-values";
import { useApplicationWorkspaceRequestContext } from "./use-application-workspace-request-context";
import { useApplicationModuleDraft } from "./use-application-module-draft";
import { ApplicationOidcClients } from "./ApplicationOidcClients";
import {
  Input,
  ModuleHeader,
  ModuleSave,
  ProtocolCard,
  Toggle
} from "./components/ApplicationModulePrimitives";

import {
  APPLICATION_PROTOCOLS_DIRTY_SOURCE,
  applicationProtocolsConfig,
} from "./application-workspace-module-contracts";
export { APPLICATION_PROTOCOLS_DIRTY_SOURCE } from "./application-workspace-module-contracts";

export type ApplicationProtocolsCopy = {
  protocols: string;
  protocolHint: string;
  protocolRuntimeHint: string;
  oauth: string;
  oauthHint: string;
  saml: string;
  samlHint: string;
  cas: string;
  casHint: string;
  jwt: string;
  jwtHint: string;
  oidcClients: string;
  oidcClientHint: string;
  createOidcClient: string;
  clientId: string;
  clientName: string;
  clientSecret: string;
  clientSecretHint: string;
  audience: string;
  redirectUris: string;
  postLogoutUris: string;
  scopes: string;
  grantTypes: string;
  responseTypes: string;
  tokenAuthMethod: string;
  requirePkce: string;
  requireMfa: string;
  active: string;
  disabled: string;
  edit: string;
  noConnections: string;
  discardChanges: string;
  saving: string;
  save: string;
  delete: string;
  loadFailed: string;
  saved: string;
  saveFailed: string;
  entityId: string;
  acsUrl: string;
  sloUrl: string;
  spMetadataXml: string;
  spSigningCertificate: string;
  nameIdClaim: string;
  nameIdFormat: string;
  signedRequests: string;
  signedAssertions: string;
  signedLogout: string;
  signedLogoutResponses: string;
  casServiceUrls: string;
  casProxyCallbacks: string;
  casAllowProxy: string;
  casTicketTtl: string;
  casPgtTtl: string;
  redirect: string;
  tokenTtl: string;
  jwtClientType: string;
  publicClient: string;
  confidentialClient: string;
  rotateSecret: string;
  secretOnlyOnce: string;
  revokeSecrets: string;
  revokeSecretsHint: string;
};

export type ApplicationProtocolsModuleProps = {
  application: TenantApplication;
  canManage: boolean;
  locale: Locale;
  copy: ApplicationProtocolsCopy;
  dirtyNavigation: Pick<DirtyNavigationController, "registerSource">;
  onDirtyChange?: () => void;
  onReadModelChange?: (applicationId: string, config: Record<string, unknown> | null) => void;
  onApplicationModuleChanged: (applicationId: string, module: ApplicationModule) => void;
  onApplicationOidcClientsChanged?: (applicationId: string, clients: Client[]) => void;
  onRequestConfirmation?: (
    action: () => Promise<void> | void,
    title: string,
    description: string
  ) => void;
};

export { applicationProtocolsConfig } from "./application-workspace-module-contracts";

export function ApplicationProtocolsModule({
  application,
  canManage,
  locale,
  copy,
  dirtyNavigation,
  onDirtyChange,
  onReadModelChange,
  onApplicationModuleChanged,
  onApplicationOidcClientsChanged,
  onRequestConfirmation
}: ApplicationProtocolsModuleProps) {
  const [jwtClient, setJwtClient] = useState<ApplicationJwtClient | null>(null);
  const [rotatedSecret, setRotatedSecret] = useState("");
  const [secretSaving, setSecretSaving] = useState(false);
  const {
    requestGuard,
    beginRequest,
    isCurrent,
    finishRequest,
    requestOptions
  } = useApplicationWorkspaceRequestContext();

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
    dirtySource: APPLICATION_PROTOCOLS_DIRTY_SOURCE,
    resolveConfig: applicationProtocolsConfig,
    onDirtyChange,
    onReadModelChange
  });

  useEffect(() => {
    setJwtClient(null);
    setRotatedSecret("");
    setSecretSaving(false);
  }, [application.id]);

  useEffect(() => {
    const request = beginRequest("protocols:jwt-client", { kind: "read" });
    if (!request) return;
    void applicationApi.getApplicationJwtClient(application.id, requestOptions(request))
      .then((client) => {
        if (isCurrent(request)) setJwtClient(client);
      })
      .catch(() => {
        if (isCurrent(request)) setJwtClient(null);
      });
    return () => finishRequest(request, false);
  }, [application.id, beginRequest, finishRequest, isCurrent]);

  function updateProtocol(
    protocol: "oauth2_oidc" | "saml2" | "cas" | "jwt",
    field: string,
    value: string | boolean | number | string[]
  ) {
    const current = draftConfig ?? applicationProtocolsConfig(application);
    const nextProtocol = { ...record(current[protocol]), [field]: value };
    setDraftConfig({ ...current, [protocol]: nextProtocol });
  }

  async function saveModule() {
    const nextConfig = draftConfig ?? applicationProtocolsConfig(application);
    const request = beginRequest("module:protocols", {
      kind: "mutation",
      payloadFingerprint: JSON.stringify(nextConfig)
    });
    if (!request) return;
    setSaving(true);
    setFeedback("");
    let committed = false;
    try {
      const isEnabled = ["oauth2_oidc", "saml2", "cas", "jwt", "iap", "forward_auth"]
        .some((protocol) => booleanValue(record(nextConfig[protocol]).enabled));
      const result = await persistApplicationProtocols(application.id, application.slug, {
        config: nextConfig,
        is_enabled: isEnabled
      }, request, isCurrent);
      if (result.stale) return;
      if (result.jwtClient !== undefined) setJwtClient(result.jwtClient);
      if (result.module) onApplicationModuleChanged(application.id, result.module);
      if (result.committed || (result.module && result.moduleWritten)) setDraftConfig(null);
      setFeedback(result.committed ? copy.saved : copy.saveFailed);
      committed = result.committed;
    } finally {
      if (isCurrent(request)) setSaving(false);
      finishRequest(request, committed);
    }
  }

  async function rotateJwtSecret() {
    if (!jwtClient || jwtClient.client_type !== "confidential") return;
    const request = beginRequest("protocols:jwt-secret:rotate", { kind: "mutation" });
    if (!request) return;
    setSecretSaving(true);
    setFeedback("");
    let committed = false;
    try {
      const response = await applicationApi.rotateApplicationJwtSecret(
        application.id,
        { grace_seconds: 300 },
        requestOptions(request)
      );
      if (!isCurrent(request)) return;
      setRotatedSecret(response.secret);
      const refreshed = await applicationApi.getApplicationJwtClient(application.id, requestOptions(request));
      if (!isCurrent(request)) return;
      setJwtClient(refreshed);
      committed = true;
    } catch {
      if (isCurrent(request)) setFeedback(copy.saveFailed);
    } finally {
      if (isCurrent(request)) setSecretSaving(false);
      finishRequest(request, committed);
    }
  }

  async function revokeJwtSecrets() {
    if (!jwtClient || jwtClient.active_secret_count === 0) return;
    const request = beginRequest("protocols:jwt-secret:revoke", { kind: "mutation" });
    if (!request) return;
    setSecretSaving(true);
    let committed = false;
    try {
      await applicationApi.revokeApplicationJwtSecrets(application.id, requestOptions(request));
      if (!isCurrent(request)) return;
      setRotatedSecret("");
      const refreshed = await applicationApi.getApplicationJwtClient(application.id, requestOptions(request));
      if (!isCurrent(request)) return;
      setJwtClient(refreshed);
      committed = true;
    } catch {
      if (isCurrent(request)) setFeedback(copy.saveFailed);
    } finally {
      if (isCurrent(request)) setSecretSaving(false);
      finishRequest(request, committed);
    }
  }

  const oauth = record(config.oauth2_oidc);
  const saml = record(config.saml2);
  const cas = record(config.cas);
  const jwt = record(config.jwt);

  return (
    <div className="application-module-content">
      <ModuleHeader icon={<Code2 size={19} />} title={copy.protocols} description={copy.protocolHint} />
      <div className="protocol-grid">
        <ProtocolCard
          icon={<Globe2 size={19} />}
          title={copy.oauth}
          description={copy.oauthHint}
          enabled={booleanValue(oauth.enabled, application.client_bindings.some((binding) => binding.protocol === "oidc"))}
          onToggle={(value) => updateProtocol("oauth2_oidc", "enabled", value)}
          tone="brand"
        >
          <ApplicationOidcClients
            application={application}
            canManage={canManage}
            requestGuard={requestGuard}
            dirtyNavigation={dirtyNavigation}
            onClientsChanged={onApplicationOidcClientsChanged}
            onRequestConfirmation={onRequestConfirmation}
            copy={{
              oidcClients: copy.oidcClients,
              oidcClientHint: copy.oidcClientHint,
              createOidcClient: copy.createOidcClient,
              clientId: copy.clientId,
              clientName: copy.clientName,
              clientSecret: copy.clientSecret,
              clientSecretHint: copy.clientSecretHint,
              audience: copy.audience,
              redirectUris: copy.redirectUris,
              postLogoutUris: copy.postLogoutUris,
              scopes: copy.scopes,
              grantTypes: copy.grantTypes,
              responseTypes: copy.responseTypes,
              tokenAuthMethod: copy.tokenAuthMethod,
              requirePkce: copy.requirePkce,
              requireMfa: copy.requireMfa,
              active: copy.active,
              disabled: copy.disabled,
              noConnections: copy.noConnections,
              discardChanges: copy.discardChanges,
              saving: copy.saving,
              save: copy.save,
              delete: copy.delete,
              edit: copy.edit,
              loadFailed: copy.loadFailed,
              saved: copy.saved,
              saveFailed: copy.saveFailed
            }}
          />
        </ProtocolCard>
        <ProtocolCard
          icon={<LockKeyhole size={19} />}
          title={copy.saml}
          description={copy.samlHint}
          enabled={booleanValue(saml.enabled)}
          onToggle={(value) => updateProtocol("saml2", "enabled", value)}
        >
          <div className="form-grid-2 compact-form-grid">
            <Input label={copy.entityId} value={stringValue(saml.entity_id)} onChange={(value) => updateProtocol("saml2", "entity_id", value)} />
            <Input label={copy.acsUrl} value={stringValue(saml.acs_url)} onChange={(value) => updateProtocol("saml2", "acs_url", value)} />
            <Input label={copy.sloUrl} hint={locale === "zh-CN" ? "网站的 SingleLogoutService；填写后 Signet metadata 会广告应用级 SLO endpoint。" : "The website SingleLogoutService. When set, Signet metadata advertises the application SLO endpoint."} value={stringValue(saml.slo_url)} onChange={(value) => updateProtocol("saml2", "slo_url", value)} />
            <Input label={copy.nameIdClaim} value={stringValue(saml.name_id_claim, "email")} onChange={(value) => updateProtocol("saml2", "name_id_claim", value)} />
            <Input label={copy.nameIdFormat} value={stringValue(saml.name_id_format)} onChange={(value) => updateProtocol("saml2", "name_id_format", value)} />
          </div>
          <div className="form-grid-2 compact-form-grid">
            <Input label={copy.spSigningCertificate} value={stringValue(saml.sp_signing_certificate)} onChange={(value) => updateProtocol("saml2", "sp_signing_certificate", value)} textarea />
            <Input label={copy.spMetadataXml} value={stringValue(saml.sp_metadata_xml)} onChange={(value) => updateProtocol("saml2", "sp_metadata_xml", value)} textarea />
          </div>
          <div className="application-toggle-grid">
            <Toggle label={copy.signedRequests} checked={booleanValue(saml.require_signed_requests)} onChange={(value) => updateProtocol("saml2", "require_signed_requests", value)} />
            <Toggle label={copy.signedAssertions} checked={booleanValue(saml.want_assertions_signed)} onChange={(value) => updateProtocol("saml2", "want_assertions_signed", value)} />
            <Toggle label={copy.signedLogout} checked={booleanValue(saml.require_signed_logout, true)} onChange={(value) => updateProtocol("saml2", "require_signed_logout", value)} />
            <Toggle label={copy.signedLogoutResponses} checked={booleanValue(saml.want_logout_responses_signed, true)} onChange={(value) => updateProtocol("saml2", "want_logout_responses_signed", value)} />
          </div>
          <small className="module-note"><Circle size={11} />{copy.protocolRuntimeHint}</small>
        </ProtocolCard>
        <ProtocolCard
          icon={<TicketIcon />}
          title={copy.cas}
          description={copy.casHint}
          enabled={booleanValue(cas.enabled)}
          onToggle={(value) => updateProtocol("cas", "enabled", value)}
        >
          <Input
            label={copy.casServiceUrls}
            hint={locale === "zh-CN" ? "每行一个精确 service URL；生产环境必须使用 HTTPS。旧配置中的 Service Validate URL 会作为兼容值读取。" : "One exact service URL per line; production deployments must use HTTPS. The legacy Service Validate URL is read as a compatibility value."}
            value={stringList(cas.service_urls).join("\n") || stringValue(cas.service_validate_url)}
            textarea
            onChange={(value) => updateProtocol("cas", "service_urls", splitUniqueTrimmed(value))}
          />
          <Input
            label={copy.casProxyCallbacks}
            hint={locale === "zh-CN" ? "启用 PGT/代理票据时，每行一个已登记的回调 URL。" : "When PGT/proxy tickets are enabled, enter one registered callback URL per line."}
            value={stringList(cas.proxy_callback_urls).join("\n")}
            textarea
            onChange={(value) => updateProtocol("cas", "proxy_callback_urls", splitUniqueTrimmed(value))}
          />
          <Toggle label={copy.casAllowProxy} checked={booleanValue(cas.allow_proxy)} onChange={(value) => updateProtocol("cas", "allow_proxy", value)} />
          <div className="form-grid-2 compact-form-grid">
            <Input label={copy.casTicketTtl} type="number" value={String(typeof cas.ticket_ttl_seconds === "number" ? cas.ticket_ttl_seconds : 300)} onChange={(value) => updateProtocol("cas", "ticket_ttl_seconds", Number(value) || 300)} />
            <Input label={copy.casPgtTtl} type="number" value={String(typeof cas.pgt_ttl_seconds === "number" ? cas.pgt_ttl_seconds : 300)} onChange={(value) => updateProtocol("cas", "pgt_ttl_seconds", Number(value) || 300)} />
          </div>
        </ProtocolCard>
        <ProtocolCard
          icon={<Code2 size={19} />}
          title={copy.jwt}
          description={copy.jwtHint}
          enabled={booleanValue(jwt.enabled)}
          onToggle={(value) => updateProtocol("jwt", "enabled", value)}
        >
          <div className="form-grid-2 compact-form-grid">
            <Input label={copy.clientId} value={stringValue(jwt.client_id, application.slug)} onChange={(value) => updateProtocol("jwt", "client_id", value)} />
            <Input label={copy.audience} value={stringValue(jwt.audience)} onChange={(value) => updateProtocol("jwt", "audience", value)} />
            <Input label={copy.tokenTtl} type="number" value={String(typeof jwt.token_ttl_seconds === "number" ? jwt.token_ttl_seconds : 3600)} onChange={(value) => updateProtocol("jwt", "token_ttl_seconds", Number(value) || 3600)} />
            <label className="application-input"><span>{copy.jwtClientType}</span><select value={stringValue(jwt.client_type, "public")} onChange={(event) => updateProtocol("jwt", "client_type", event.target.value)}><option value="public">{copy.publicClient}</option><option value="confidential">{copy.confidentialClient}</option></select></label>
          </div>
          <Input label={copy.redirect} hint={locale === "zh-CN" ? "每行一个精确回调地址；生产环境必须使用 HTTPS。" : "One exact redirect URI per line; production deployments must use HTTPS."} value={stringList(jwt.redirect_uris).join("\n")} textarea onChange={(value) => updateProtocol("jwt", "redirect_uris", splitUniqueTrimmed(value))} />
          {jwtClient?.client_type === "confidential" && <div className="module-secret-panel"><div><strong>{copy.confidentialClient}</strong><small>{jwtClient.active_secret_count} active secret(s)</small></div><div className="module-secret-actions"><button type="button" className="text-button" onClick={() => void rotateJwtSecret()} disabled={secretSaving}>{secretSaving ? copy.saving : copy.rotateSecret}</button><button type="button" className="text-danger-button" onClick={() => onRequestConfirmation ? onRequestConfirmation(() => revokeJwtSecrets(), copy.revokeSecrets, copy.revokeSecretsHint) : void revokeJwtSecrets()} disabled={secretSaving || jwtClient.active_secret_count === 0}>{copy.revokeSecrets}</button></div>{rotatedSecret && <div className="module-secret-value"><code>{rotatedSecret}</code><small>{copy.secretOnlyOnce}</small></div>}</div>}
        </ProtocolCard>
      </div>
      <ModuleSave saving={saving} feedback={feedback} copy={copy} onSave={() => void saveModule()} />
    </div>
  );
}

function TicketIcon() {
  return <span className="ticket-icon" aria-hidden="true">✦</span>;
}
