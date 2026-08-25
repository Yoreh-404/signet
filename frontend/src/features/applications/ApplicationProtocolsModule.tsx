import {
  Circle,
  Code2,
  Globe2,
  LockKeyhole
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

import * as applicationApi from "../../lib/api/applications";
import { stableDomainEqual } from "../admin/stable-domain-comparator";
import type {
  DirtyNavigationController,
  DirtyNavigationSourceHandle
} from "../navigation/useDirtyNavigation";
import type {
  ApplicationJwtClient,
  ApplicationModule,
  Client,
  Locale,
  TenantApplication
} from "../../types";
import type {
  ApplicationRequestGuard,
  ApplicationRequestToken
} from "./application-request-guard";
import {
  booleanValue,
  record,
  stringList,
  stringValue
} from "./application-module-values";
import { ApplicationOidcClients } from "./ApplicationOidcClients";
import {
  Input,
  ModuleHeader,
  ModuleSave,
  ProtocolCard,
  Toggle
} from "./components/ApplicationModulePrimitives";

export const APPLICATION_PROTOCOLS_DIRTY_SOURCE = "applications.protocols";

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
  requestGuard: ApplicationRequestGuard;
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

export function applicationProtocolsConfig(application: TenantApplication): Record<string, unknown> {
  const module = (application.modules ?? []).find((item) => item.module_key === "protocols");
  return {
    oauth2_oidc: {
      enabled: application.client_bindings.some((binding) => binding.protocol === "oidc"),
      client_ids: application.client_bindings
        .filter((binding) => binding.protocol === "oidc")
        .map((binding) => binding.id)
    },
    saml2: {
      enabled: false,
      entity_id: "",
      acs_url: "",
      slo_url: "",
      name_id_claim: "email",
      name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      require_signed_requests: false,
      want_assertions_signed: false,
      require_signed_logout: true,
      want_logout_responses_signed: true,
      sp_metadata_xml: "",
      sp_signing_certificate: ""
    },
    cas: {
      enabled: false,
      service_urls: [],
      proxy_callback_urls: [],
      allow_proxy: false,
      ticket_ttl_seconds: 300,
      pgt_ttl_seconds: 300
    },
    jwt: {
      enabled: false,
      client_id: application.slug,
      client_type: "public",
      redirect_uris: [],
      audience: "",
      token_ttl_seconds: 3600
    },
    ...record(module?.config)
  };
}

function requestOptions(token: ApplicationRequestToken) {
  return {
    signal: token.signal,
    ...(token.idempotencyKey ? { idempotencyKey: token.idempotencyKey } : {})
  };
}

export function ApplicationProtocolsModule({
  application,
  canManage,
  locale,
  copy,
  requestGuard,
  dirtyNavigation,
  onDirtyChange,
  onReadModelChange,
  onApplicationModuleChanged,
  onApplicationOidcClientsChanged,
  onRequestConfirmation
}: ApplicationProtocolsModuleProps) {
  const [draftConfig, setDraftConfig] = useState<Record<string, unknown> | null>(null);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState("");
  const [jwtClient, setJwtClient] = useState<ApplicationJwtClient | null>(null);
  const [rotatedSecret, setRotatedSecret] = useState("");
  const [secretSaving, setSecretSaving] = useState(false);
  const dirtySourceRef = useRef<DirtyNavigationSourceHandle | null>(null);
  const onDirtyChangeRef = useRef(onDirtyChange);
  onDirtyChangeRef.current = onDirtyChange;
  const onReadModelChangeRef = useRef(onReadModelChange);
  onReadModelChangeRef.current = onReadModelChange;

  const config = draftConfig ?? applicationProtocolsConfig(application);

  function isCurrentApplicationRequest(token: ApplicationRequestToken): boolean {
    return requestGuard.isCurrent(token);
  }

  function hasUnsavedChanges(): boolean {
    return draftConfig !== null && !stableDomainEqual(draftConfig, applicationProtocolsConfig(application));
  }

  useEffect(() => {
    const source = dirtyNavigation.registerSource(APPLICATION_PROTOCOLS_DIRTY_SOURCE);
    dirtySourceRef.current = source;
    return () => {
      source.unregister();
      onDirtyChangeRef.current?.();
      onReadModelChangeRef.current?.(application.id, null);
      if (dirtySourceRef.current === source) dirtySourceRef.current = null;
    };
  }, [dirtyNavigation.registerSource]);

  useEffect(() => {
    dirtySourceRef.current?.setDirty(hasUnsavedChanges());
    onDirtyChangeRef.current?.();
  }, [application, draftConfig]);

  useEffect(() => {
    onReadModelChangeRef.current?.(application.id, draftConfig ?? applicationProtocolsConfig(application));
  }, [application, draftConfig]);

  useEffect(() => {
    setDraftConfig(null);
    setFeedback("");
    setJwtClient(null);
    setRotatedSecret("");
    setSaving(false);
    setSecretSaving(false);
  }, [application.id]);

  useEffect(() => {
    const request = requestGuard.begin(application.id, {
      scope: "protocols:jwt-client",
      kind: "read"
    });
    if (!request) return;
    void applicationApi.getApplicationJwtClient(application.id, requestOptions(request))
      .then((client) => {
        if (isCurrentApplicationRequest(request)) setJwtClient(client);
      })
      .catch(() => {
        if (isCurrentApplicationRequest(request)) setJwtClient(null);
      });
    return () => requestGuard.finish(request, false);
  }, [application, requestGuard]);

  function updateProtocol(
    protocol: "oauth2_oidc" | "saml2" | "cas" | "jwt",
    field: string,
    value: string | boolean | number | string[]
  ) {
    const current = draftConfig ?? applicationProtocolsConfig(application);
    const nextProtocol = { ...record(current[protocol]), [field]: value };
    setDraftConfig({ ...current, [protocol]: nextProtocol });
  }

  async function reloadModuleAfterSaveFailure(request: ApplicationRequestToken): Promise<boolean> {
    const modules = await applicationApi.listApplicationModules(application.id, {
      force: true,
      ...requestOptions(request)
    });
    if (!isCurrentApplicationRequest(request)) return false;
    const module = modules.find((item) => item.module_key === "protocols");
    if (!module) return false;
    onApplicationModuleChanged(application.id, module);
    const client = await applicationApi.getApplicationJwtClient(application.id, {
      force: true,
      ...requestOptions(request)
    });
    if (!isCurrentApplicationRequest(request)) return false;
    setJwtClient(client);
    return true;
  }

  async function saveModule() {
    const nextConfig = draftConfig ?? applicationProtocolsConfig(application);
    const request = requestGuard.begin(application.id, {
      scope: "module:protocols",
      kind: "mutation",
      payloadFingerprint: JSON.stringify(nextConfig)
    });
    if (!request) return;
    setSaving(true);
    setFeedback("");
    let moduleWritten = false;
    let committed = false;
    try {
      const isEnabled = ["oauth2_oidc", "saml2", "cas", "jwt", "iap", "forward_auth"]
        .some((protocol) => booleanValue(record(nextConfig[protocol]).enabled));
      const module = await applicationApi.updateApplicationModule(application.id, "protocols", {
        config: nextConfig,
        is_enabled: isEnabled
      }, requestOptions(request));
      moduleWritten = true;
      if (!isCurrentApplicationRequest(request)) return;
      const jwt = record(nextConfig.jwt);
      if (booleanValue(jwt.enabled) && isCurrentApplicationRequest(request)) {
        const configuredClient = await applicationApi.updateApplicationJwtClient(application.id, {
          client_id: stringValue(jwt.client_id, application.slug),
          client_type: stringValue(jwt.client_type, "public") as "public" | "confidential",
          is_active: true
        }, requestOptions(request));
        if (!isCurrentApplicationRequest(request)) return;
        setJwtClient(configuredClient);
      }
      if (!isCurrentApplicationRequest(request)) return;
      onApplicationModuleChanged(application.id, module);
      setDraftConfig(null);
      setFeedback(copy.saved);
      committed = true;
    } catch {
      if (isCurrentApplicationRequest(request)) {
        try {
          const reloaded = await reloadModuleAfterSaveFailure(request);
          if (reloaded && moduleWritten) setDraftConfig(null);
        } catch {
          // Keep the draft when the reconciliation read also fails. The dirty
          // source then gives the user a safe retry path.
        }
        if (isCurrentApplicationRequest(request)) setFeedback(copy.saveFailed);
      }
    } finally {
      if (isCurrentApplicationRequest(request)) setSaving(false);
      requestGuard.finish(request, committed);
    }
  }

  async function rotateJwtSecret() {
    if (!jwtClient || jwtClient.client_type !== "confidential") return;
    const request = requestGuard.begin(application.id, {
      scope: "protocols:jwt-secret:rotate",
      kind: "mutation"
    });
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
      if (!isCurrentApplicationRequest(request)) return;
      setRotatedSecret(response.secret);
      const refreshed = await applicationApi.getApplicationJwtClient(application.id, requestOptions(request));
      if (!isCurrentApplicationRequest(request)) return;
      setJwtClient(refreshed);
      committed = true;
    } catch {
      if (isCurrentApplicationRequest(request)) setFeedback(copy.saveFailed);
    } finally {
      if (isCurrentApplicationRequest(request)) setSecretSaving(false);
      requestGuard.finish(request, committed);
    }
  }

  async function revokeJwtSecrets() {
    if (!jwtClient || jwtClient.active_secret_count === 0) return;
    const request = requestGuard.begin(application.id, {
      scope: "protocols:jwt-secret:revoke",
      kind: "mutation"
    });
    if (!request) return;
    setSecretSaving(true);
    let committed = false;
    try {
      await applicationApi.revokeApplicationJwtSecrets(application.id, requestOptions(request));
      if (!isCurrentApplicationRequest(request)) return;
      setRotatedSecret("");
      const refreshed = await applicationApi.getApplicationJwtClient(application.id, requestOptions(request));
      if (!isCurrentApplicationRequest(request)) return;
      setJwtClient(refreshed);
      committed = true;
    } catch {
      if (isCurrentApplicationRequest(request)) setFeedback(copy.saveFailed);
    } finally {
      if (isCurrentApplicationRequest(request)) setSecretSaving(false);
      requestGuard.finish(request, committed);
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
            onChange={(value) => updateProtocol("cas", "service_urls", value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))}
          />
          <Input
            label={copy.casProxyCallbacks}
            hint={locale === "zh-CN" ? "启用 PGT/代理票据时，每行一个已登记的回调 URL。" : "When PGT/proxy tickets are enabled, enter one registered callback URL per line."}
            value={stringList(cas.proxy_callback_urls).join("\n")}
            textarea
            onChange={(value) => updateProtocol("cas", "proxy_callback_urls", value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))}
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
          <Input label={copy.redirect} hint={locale === "zh-CN" ? "每行一个精确回调地址；生产环境必须使用 HTTPS。" : "One exact redirect URI per line; production deployments must use HTTPS."} value={stringList(jwt.redirect_uris).join("\n")} textarea onChange={(value) => updateProtocol("jwt", "redirect_uris", value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))} />
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
