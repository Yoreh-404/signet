import type { FormEvent } from "react";
import { useEffect, useState } from "react";

import * as applicationApi from "../../lib/api/applications";
import type {
  ApiMutationOptions,
  ApplicationOidcClientInput,
} from "../../lib/api/applications";
import type { Client, TenantApplication } from "../../types";
import type { DirtyNavigationController } from "../navigation/useDirtyNavigation";
import { ModuleFeedback } from "./components/ApplicationModulePrimitives";
import { ApplicationOidcClientEditor } from "./ApplicationOidcClientEditor";
import { ApplicationOidcClientList } from "./ApplicationOidcClientList";
import type {
  ApplicationRequestGuard,
  ApplicationRequestToken,
} from "./application-request-guard";
import { useApplicationModuleLifecycle } from "./use-application-module-lifecycle";

export const APPLICATION_OIDC_CLIENTS_DIRTY_SOURCE =
  "applications.oidc-clients";

export type ApplicationOidcClientsCopy = {
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
};

export type OidcClientDraft = {
  id: string;
  client_id: string;
  client_name: string;
  client_secret: string;
  logo_uri: string;
  organization_id: string;
  redirect_uris: string;
  post_logout_redirect_uris: string;
  scopes: string;
  audience: string;
  grant_types: string;
  response_types: string;
  token_endpoint_auth_method: string;
  require_pkce: boolean;
  require_mfa: boolean;
  require_pushed_authorization_requests: boolean;
  require_s256_pkce: boolean;
  require_confidential_client: boolean;
  require_dpop: boolean;
  require_account_selection: boolean;
  trust_email_verified: boolean;
  authorization_details_types: string;
  subject_type: string;
  sector_identifier_uri: string;
  jwks_uri: string;
  jwks: string;
  backchannel_logout_uri: string;
  backchannel_logout_session_required: boolean;
  frontchannel_logout_uri: string;
  frontchannel_logout_session_required: boolean;
  service_account_enabled: boolean;
  service_account_permissions: string;
  is_active: boolean;
  claim_mappers: Client["claim_mappers"];
};

export type ApplicationOidcClientsProps = {
  application: TenantApplication;
  canManage: boolean;
  copy: ApplicationOidcClientsCopy;
  requestGuard: ApplicationRequestGuard;
  dirtyNavigation: Pick<DirtyNavigationController, "registerSource">;
  onClientsChanged?: (applicationId: string, clients: Client[]) => void;
  onRequestConfirmation?: (
    action: () => Promise<void> | void,
    title: string,
    description: string,
  ) => void;
};

function emptyOidcClientDraft(organizationId: string): OidcClientDraft {
  return {
    id: "",
    client_id: "",
    client_name: "",
    client_secret: "",
    logo_uri: "",
    organization_id: organizationId,
    redirect_uris: "http://localhost:3000/callback",
    post_logout_redirect_uris: "http://localhost:3000/",
    scopes: "openid profile email offline_access",
    audience: "",
    grant_types: "authorization_code refresh_token",
    response_types: "code",
    token_endpoint_auth_method: "client_secret_basic",
    require_pkce: false,
    require_mfa: false,
    require_pushed_authorization_requests: false,
    require_s256_pkce: false,
    require_confidential_client: false,
    require_dpop: false,
    require_account_selection: false,
    trust_email_verified: false,
    authorization_details_types: "",
    subject_type: "public",
    sector_identifier_uri: "",
    jwks_uri: "",
    jwks: "",
    backchannel_logout_uri: "",
    backchannel_logout_session_required: false,
    frontchannel_logout_uri: "",
    frontchannel_logout_session_required: false,
    service_account_enabled: false,
    service_account_permissions: "",
    is_active: true,
    claim_mappers: [],
  };
}

function toOidcClientDraft(
  client: Client,
  organizationId: string,
): OidcClientDraft {
  return {
    id: client.id,
    client_id: client.client_id,
    client_name: client.client_name,
    client_secret: "",
    logo_uri: client.logo_uri,
    organization_id: client.organization_id ?? organizationId,
    redirect_uris: client.redirect_uris.join("\n"),
    post_logout_redirect_uris: client.post_logout_redirect_uris.join("\n"),
    scopes: client.scopes.join(" "),
    audience: client.audience,
    grant_types: client.grant_types.join(" "),
    response_types: client.response_types.join(" "),
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    require_pkce: client.require_pkce,
    require_mfa: client.require_mfa,
    require_pushed_authorization_requests:
      client.require_pushed_authorization_requests,
    require_s256_pkce: client.require_s256_pkce,
    require_confidential_client: client.require_confidential_client,
    require_dpop: client.require_dpop,
    require_account_selection: client.require_account_selection,
    trust_email_verified: client.trust_email_verified,
    authorization_details_types: client.authorization_details_types.join("\n"),
    subject_type: client.subject_type,
    sector_identifier_uri: client.sector_identifier_uri,
    jwks_uri: client.jwks_uri,
    jwks: client.jwks,
    backchannel_logout_uri: client.backchannel_logout_uri,
    backchannel_logout_session_required:
      client.backchannel_logout_session_required,
    frontchannel_logout_uri: client.frontchannel_logout_uri,
    frontchannel_logout_session_required:
      client.frontchannel_logout_session_required,
    service_account_enabled: client.service_account_enabled,
    service_account_permissions: client.service_account_permissions.join("\n"),
    is_active: client.is_active,
    claim_mappers: client.claim_mappers,
  };
}

function tokenList(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function oidcClientPayload(
  draft: OidcClientDraft,
  organizationId: string,
): ApplicationOidcClientInput {
  return {
    client_id: draft.client_id.trim(),
    client_name: draft.client_name.trim(),
    logo_uri: draft.logo_uri.trim(),
    organization_id: organizationId,
    client_secret: draft.client_secret.trim() || null,
    redirect_uris: draft.redirect_uris
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean),
    post_logout_redirect_uris: draft.post_logout_redirect_uris
      .split(/\r?\n/)
      .map((item) => item.trim())
      .filter(Boolean),
    scopes: tokenList(draft.scopes),
    audience: draft.audience.trim() || null,
    grant_types: tokenList(draft.grant_types),
    response_types: tokenList(draft.response_types),
    token_endpoint_auth_method: draft.token_endpoint_auth_method,
    require_pkce: draft.require_pkce,
    require_mfa: draft.require_mfa,
    require_pushed_authorization_requests:
      draft.require_pushed_authorization_requests,
    require_s256_pkce: draft.require_s256_pkce,
    require_confidential_client: draft.require_confidential_client,
    require_dpop: draft.require_dpop,
    require_account_selection: draft.require_account_selection,
    trust_email_verified: draft.trust_email_verified,
    authorization_details_types: tokenList(draft.authorization_details_types),
    subject_type: draft.subject_type,
    sector_identifier_uri: draft.sector_identifier_uri.trim(),
    jwks_uri: draft.jwks_uri.trim(),
    jwks: draft.jwks.trim(),
    backchannel_logout_uri: draft.backchannel_logout_uri.trim(),
    backchannel_logout_session_required:
      draft.backchannel_logout_session_required,
    frontchannel_logout_uri: draft.frontchannel_logout_uri.trim(),
    frontchannel_logout_session_required:
      draft.frontchannel_logout_session_required,
    service_account_enabled: draft.service_account_enabled,
    service_account_permissions: tokenList(draft.service_account_permissions),
    is_active: draft.is_active,
    claim_mappers: draft.claim_mappers.map((mapper, index) => ({
      claim_name: mapper.claim_name,
      source: mapper.source,
      source_value: mapper.source_value,
      value_type: mapper.value_type,
      include_in_id_token: mapper.include_in_id_token,
      include_in_access_token: mapper.include_in_access_token,
      include_in_userinfo: mapper.include_in_userinfo,
      is_active: mapper.is_active,
      sort_order: mapper.sort_order ?? index,
    })),
  };
}

function requestOptions(token: ApplicationRequestToken): ApiMutationOptions {
  return {
    signal: token.signal,
    ...(token.idempotencyKey ? { idempotencyKey: token.idempotencyKey } : {}),
  };
}

export function ApplicationOidcClients({
  application,
  canManage,
  copy,
  requestGuard,
  dirtyNavigation,
  onClientsChanged,
  onRequestConfirmation,
}: ApplicationOidcClientsProps) {
  const [clients, setClients] = useState<Client[]>([]);
  const [draft, setDraft] = useState<OidcClientDraft | null>(null);
  const {
    saving,
    setSaving,
    feedback,
    setFeedback,
    beginRequest,
    isCurrent,
    finishRequest,
  } = useApplicationModuleLifecycle({
    applicationId: application.id,
    dirtySource: APPLICATION_OIDC_CLIENTS_DIRTY_SOURCE,
    dirtyNavigation,
    requestGuard,
    dirty: draft !== null,
  });

  useEffect(() => {
    setClients([]);
    setDraft(null);
    setSaving(false);
    setFeedback("");
    const request = beginRequest("protocols:oidc-clients", {
      kind: "read",
    });
    if (!request) return;
    void applicationApi
      .listApplicationOidcClients(application.id, requestOptions(request))
      .then((nextClients) => {
        if (isCurrent(request)) setClients(nextClients);
      })
      .catch(() => {
        if (!isCurrent(request)) return;
        // Bindings are part of the application read model. Keep this scoped
        // fallback for older servers while the dedicated collection catches
        // up, without allowing an older application response to win.
        setClients(
          application.client_bindings.filter(
            (binding) => binding.protocol === "oidc",
          ),
        );
        setFeedback(copy.loadFailed);
      });
    return () => finishRequest(request, false);
  }, [application, beginRequest, copy.loadFailed, finishRequest, isCurrent]);

  function publishClients(nextClients: Client[]) {
    setClients(nextClients);
    onClientsChanged?.(application.id, nextClients);
  }

  function openEditor(client?: Client) {
    setDraft(
      client
        ? toOidcClientDraft(client, application.organization_id)
        : emptyOidcClientDraft(application.organization_id),
    );
    setFeedback("");
  }

  async function saveClient(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!draft || !canManage) return;
    const request = beginRequest(`protocols:oidc-client:${draft.id || "new"}`, {
      kind: "mutation",
      payloadFingerprint: JSON.stringify(draft),
    });
    if (!request) return;
    setSaving(true);
    setFeedback("");
    let committed = false;
    try {
      const payload = oidcClientPayload(draft, application.organization_id);
      const saved = draft.id
        ? await applicationApi.updateApplicationOidcClient(
            application.id,
            draft.id,
            payload,
            requestOptions(request),
          )
        : await applicationApi.createApplicationOidcClient(
            application.id,
            payload,
            requestOptions(request),
          );
      if (!isCurrent(request)) return;
      const nextClients = draft.id
        ? clients.map((client) => (client.id === saved.id ? saved : client))
        : [saved, ...clients];
      publishClients(nextClients);
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

  async function deleteClient(client: Client) {
    const request = beginRequest(`protocols:oidc-client:${client.id}:delete`, {
      kind: "mutation",
    });
    if (!request) return;
    setSaving(true);
    setFeedback("");
    let committed = false;
    try {
      await applicationApi.deleteApplicationOidcClient(
        application.id,
        client.id,
        requestOptions(request),
      );
      if (!isCurrent(request)) return;
      publishClients(clients.filter((item) => item.id !== client.id));
      if (draft?.id === client.id) setDraft(null);
      setFeedback(copy.saved);
      committed = true;
    } catch {
      if (isCurrent(request)) setFeedback(copy.saveFailed);
    } finally {
      if (isCurrent(request)) setSaving(false);
      finishRequest(request, committed);
    }
  }

  return (
    <div className="application-connection-list application-oidc-manager">
      <ApplicationOidcClientList
        copy={copy}
        canManage={canManage}
        clients={clients}
        saving={saving}
        onCreate={() => openEditor()}
        onEdit={openEditor}
        onDelete={(client) =>
          onRequestConfirmation
            ? onRequestConfirmation(
                () => deleteClient(client),
                copy.delete,
                copy.oidcClientHint,
              )
            : void deleteClient(client)
        }
      >
        {draft && (
          <ApplicationOidcClientEditor
            copy={copy}
            draft={draft}
            saving={saving}
            onChange={(next) =>
              setDraft((current) =>
                current ? { ...current, ...next } : current,
              )
            }
            onDiscard={() => setDraft(null)}
            onSubmit={saveClient}
          />
        )}
        <ModuleFeedback message={feedback} errorMessages={[copy.saveFailed]} />
      </ApplicationOidcClientList>
    </div>
  );
}
