import { lazy, Suspense } from "react";

import type {
  DirtyNavigationController
} from "../navigation/useDirtyNavigation";
import type {
  ApplicationSection,
  ApplicationModule,
  Client,
  ExternalProvider,
  LdapProvider,
  OrganizationOption,
  TenantApplication,
  Locale
} from "../../types";
import type { ApplicationWorkspaceOverviewProjection } from "./use-application-workspace-overview-projection";
import type { ApplicationWorkspaceCopy } from "./application-workspace-copy";

const ApplicationLoginAdaptersModule = lazy(() =>
  import("./ApplicationLoginAdaptersModule").then(({ ApplicationLoginAdaptersModule }) => ({
    default: ApplicationLoginAdaptersModule,
  })),
);
const ApplicationAuthorizationModule = lazy(() =>
  import("./ApplicationAuthorizationModule").then(({ ApplicationAuthorizationModule }) => ({
    default: ApplicationAuthorizationModule,
  })),
);
const BillingModule = lazy(() =>
  import("./BillingModule").then(({ BillingModule }) => ({ default: BillingModule })),
);
const IapModule = lazy(() =>
  import("./IapModule").then(({ IapModule }) => ({ default: IapModule })),
);
const ApplicationDirectorySyncModule = lazy(() =>
  import("./ApplicationDirectorySyncModule").then(({ ApplicationDirectorySyncModule }) => ({
    default: ApplicationDirectorySyncModule,
  })),
);
const ApplicationProtocolsModule = lazy(() =>
  import("./ApplicationProtocolsModule").then(({ ApplicationProtocolsModule }) => ({
    default: ApplicationProtocolsModule,
  })),
);

type ApplicationWorkspaceModuleContentProps = {
  section: ApplicationSection;
  selected: TenantApplication | null;
  providers: ExternalProvider[];
  ldapProviders: LdapProvider[];
  organizationOptions: OrganizationOption[];
  locale: Locale;
  canManage: boolean;
  copy: ApplicationWorkspaceCopy;
  dirtyNavigation: Pick<DirtyNavigationController, "getSnapshot" | "registerSource">;
  overviewProjection: ApplicationWorkspaceOverviewProjection;
  onLoginAdaptersConfigChange: (config: Record<string, unknown> | null) => void;
  onDirtyChange: () => void;
  onApplicationModuleChanged: (applicationId: string, module: ApplicationModule) => void;
  onApplicationOidcClientsChanged?: (applicationId: string, clients: Client[]) => void;
  onRequestConfirmation?: (
    action: () => Promise<void> | void,
    title: string,
    description: string
  ) => void;
  authorizationConfig: Record<string, unknown>;
  hasUnsavedChanges: () => boolean;
  onDiscardChanges: () => void;
  onIapDirtyChange: (dirty: boolean) => void;
  onBillingDirtyChange: (dirty: boolean) => void;
};

export function ApplicationWorkspaceModuleContent({
  section,
  selected,
  providers,
  ldapProviders,
  organizationOptions,
  locale,
  canManage,
  copy,
  dirtyNavigation,
  overviewProjection,
  onLoginAdaptersConfigChange,
  onDirtyChange,
  onApplicationModuleChanged,
  onApplicationOidcClientsChanged,
  onRequestConfirmation,
  authorizationConfig,
  hasUnsavedChanges,
  onDiscardChanges,
  onIapDirtyChange,
  onBillingDirtyChange
}: ApplicationWorkspaceModuleContentProps) {
  if (!selected) return null;

  if (section === "protocols") {
    return <Suspense fallback={<div className="loading-state">Loading…</div>}>
      <ApplicationProtocolsModule
        key={selected.id}
        application={selected}
        canManage={canManage}
        locale={locale}
        copy={copy}
        dirtyNavigation={dirtyNavigation}
        onDirtyChange={onDirtyChange}
        onReadModelChange={overviewProjection.updateProtocolReadModel}
        onApplicationModuleChanged={onApplicationModuleChanged}
        onApplicationOidcClientsChanged={onApplicationOidcClientsChanged}
        onRequestConfirmation={onRequestConfirmation}
      />
    </Suspense>;
  }

  if (section === "login_adapters") {
    return <Suspense fallback={<div className="loading-state">Loading…</div>}>
      <ApplicationLoginAdaptersModule
        key={selected.id}
        application={selected}
        providers={providers}
        canManage={canManage}
        copy={copy}
        dirtyNavigation={dirtyNavigation}
        onApplicationModuleChanged={onApplicationModuleChanged}
        savedMessage={copy.saved}
        onConfigChange={onLoginAdaptersConfigChange}
      />
    </Suspense>;
  }

  if (section === "directory_sync") {
    return <Suspense fallback={<div className="loading-state">Loading…</div>}>
      <ApplicationDirectorySyncModule
        key={selected.id}
        application={selected}
        ldapProviders={ldapProviders}
        locale={locale}
        canManage={canManage}
        copy={copy}
        dirtyNavigation={dirtyNavigation}
        onDirtyChange={onDirtyChange}
        onReadModelChange={overviewProjection.updateDirectoryReadModel}
        onApplicationModuleChanged={onApplicationModuleChanged}
        onRequestConfirmation={onRequestConfirmation}
      />
    </Suspense>;
  }

  if (section === "authorization") {
    return <Suspense fallback={<div className="loading-state">Loading…</div>}>
      <ApplicationAuthorizationModule
        key={selected.id}
        application={selected}
        authorizationConfig={authorizationConfig}
        canManage={canManage}
        copy={copy}
        dirtyNavigation={dirtyNavigation}
        onApplicationModuleChanged={onApplicationModuleChanged}
        hasUnsavedChanges={hasUnsavedChanges}
        onDiscardChanges={onDiscardChanges}
        onRequestConfirmation={onRequestConfirmation}
      />
    </Suspense>;
  }

  if (section === "iap") {
    return <Suspense fallback={<div className="loading-state">Loading…</div>}>
      <IapModule
        applicationId={selected.id}
        organizationId={selected.organization_id}
        organizationOptions={organizationOptions}
        canManage={canManage}
        copy={copy}
        onDirtyChange={onIapDirtyChange}
        onRulesCountChange={overviewProjection.setIapRuleCount}
        onRequestConfirmation={onRequestConfirmation}
      />
    </Suspense>;
  }

  if (section === "billing") {
    return <Suspense fallback={<div className="loading-state">Loading…</div>}>
      <BillingModule
        applicationId={selected.id}
        canManage={canManage}
        copy={copy}
        onDirtyChange={onBillingDirtyChange}
        onEnabledChange={overviewProjection.setBillingEnabled}
      />
    </Suspense>;
  }

  return null;
}
