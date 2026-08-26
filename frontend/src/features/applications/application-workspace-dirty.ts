import { APPLICATION_AUTHORIZATION_DIRTY_SOURCE } from "./ApplicationAuthorizationModule";
import { APPLICATION_DIRECTORY_SYNC_DIRTY_SOURCE } from "./ApplicationDirectorySyncModule";
import { APPLICATION_PROTOCOLS_DIRTY_SOURCE } from "./ApplicationProtocolsModule";
import { APPLICATION_OIDC_CLIENTS_DIRTY_SOURCE } from "./ApplicationOidcClients";
import { stableDomainEqual } from "../admin/stable-domain-comparator";

export type ApplicationWorkspaceDrafts = Partial<Record<"login_adapters", Record<string, unknown>>>;

export type ApplicationWorkspaceDirtyStateInput = {
  selected: boolean;
  drafts: ApplicationWorkspaceDrafts;
  billingDirty: boolean;
  iapRuleDirty: boolean;
  sources: Readonly<Record<string, boolean>>;
  moduleConfig: (key: "login_adapters") => Record<string, unknown>;
};

export type ApplicationWorkspaceDirtyState = {
  hasUnsavedDrafts: boolean;
  hasWorkspaceDrafts: boolean;
};

export function getApplicationWorkspaceDirtyState({
  selected,
  drafts,
  billingDirty,
  iapRuleDirty,
  sources,
  moduleConfig
}: ApplicationWorkspaceDirtyStateInput): ApplicationWorkspaceDirtyState {
  const hasLocalDrafts = Object.entries(drafts).some(([key, draft]) => (
    draft !== undefined
    && !stableDomainEqual(draft, moduleConfig(key as "login_adapters"))
  ));
  const hasChildDirtySources = Boolean(
    sources[APPLICATION_OIDC_CLIENTS_DIRTY_SOURCE]
    || sources[APPLICATION_AUTHORIZATION_DIRTY_SOURCE]
    || sources[APPLICATION_PROTOCOLS_DIRTY_SOURCE]
    || sources[APPLICATION_DIRECTORY_SYNC_DIRTY_SOURCE]
  );

  return {
    hasUnsavedDrafts: selected && (hasChildDirtySources || billingDirty || iapRuleDirty || hasLocalDrafts),
    hasWorkspaceDrafts: billingDirty || iapRuleDirty || (selected && hasLocalDrafts)
  };
}
