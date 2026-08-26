import type { ReactNode } from "react";

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
import type { ApplicationRequestGuard } from "./application-request-guard";
import { ApplicationAuthorizationModule } from "./ApplicationAuthorizationModule";
import { BillingModule } from "./BillingModule";
import { IapModule } from "./IapModule";
import { ApplicationDirectorySyncModule } from "./ApplicationDirectorySyncModule";
import { ApplicationProtocolsModule } from "./ApplicationProtocolsModule";
import type { ApplicationWorkspaceCopy } from "./ApplicationWorkspace";

type ApplicationWorkspaceModuleContentProps = {
  section: ApplicationSection;
  selected: TenantApplication | null;
  providers: ExternalProvider[];
  ldapProviders: LdapProvider[];
  organizationOptions: OrganizationOption[];
  locale: Locale;
  canManage: boolean;
  copy: ApplicationWorkspaceCopy;
  requestGuard: ApplicationRequestGuard;
  dirtyNavigation: Pick<DirtyNavigationController, "getSnapshot" | "registerSource">;
  identityEditor: ReactNode;
  onDirtyChange: () => void;
  onProtocolReadModelChange: (applicationId: string, config: Record<string, unknown> | null) => void;
  onDirectoryReadModelChange: (applicationId: string, config: Record<string, unknown> | null) => void;
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
  onIapRulesCountChange: (count: number) => void;
  onBillingDirtyChange: (dirty: boolean) => void;
  onBillingEnabledChange: (enabled: boolean) => void;
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
  requestGuard,
  dirtyNavigation,
  identityEditor,
  onDirtyChange,
  onProtocolReadModelChange,
  onDirectoryReadModelChange,
  onApplicationModuleChanged,
  onApplicationOidcClientsChanged,
  onRequestConfirmation,
  authorizationConfig,
  hasUnsavedChanges,
  onDiscardChanges,
  onIapDirtyChange,
  onIapRulesCountChange,
  onBillingDirtyChange,
  onBillingEnabledChange
}: ApplicationWorkspaceModuleContentProps) {
  if (!selected) return null;

  if (section === "protocols") {
    return <ApplicationProtocolsModule
      key={selected.id}
      application={selected}
      canManage={canManage}
      locale={locale}
      copy={copy}
      requestGuard={requestGuard}
      dirtyNavigation={dirtyNavigation}
      onDirtyChange={onDirtyChange}
      onReadModelChange={onProtocolReadModelChange}
      onApplicationModuleChanged={onApplicationModuleChanged}
      onApplicationOidcClientsChanged={onApplicationOidcClientsChanged}
      onRequestConfirmation={onRequestConfirmation}
    />;
  }

  if (section === "login_adapters") return identityEditor;

  if (section === "directory_sync") {
    return <ApplicationDirectorySyncModule
      key={selected.id}
      application={selected}
      ldapProviders={ldapProviders}
      locale={locale}
      canManage={canManage}
      copy={copy}
      requestGuard={requestGuard}
      dirtyNavigation={dirtyNavigation}
      onDirtyChange={onDirtyChange}
      onReadModelChange={onDirectoryReadModelChange}
      onApplicationModuleChanged={onApplicationModuleChanged}
      onRequestConfirmation={onRequestConfirmation}
    />;
  }

  if (section === "authorization") {
    return <ApplicationAuthorizationModule
      key={selected.id}
      application={selected}
      authorizationConfig={authorizationConfig}
      canManage={canManage}
      copy={copy}
      requestGuard={requestGuard}
      dirtyNavigation={dirtyNavigation}
      onApplicationModuleChanged={onApplicationModuleChanged}
      hasUnsavedChanges={hasUnsavedChanges}
      onDiscardChanges={onDiscardChanges}
      onRequestConfirmation={onRequestConfirmation}
    />;
  }

  if (section === "iap") {
    return <IapModule
      applicationId={selected.id}
      organizationId={selected.organization_id}
      organizationOptions={organizationOptions}
      canManage={canManage}
      copy={copy}
      requestGuard={requestGuard}
      onDirtyChange={onIapDirtyChange}
      onRulesCountChange={onIapRulesCountChange}
      onRequestConfirmation={onRequestConfirmation}
    />;
  }

  if (section === "billing") {
    return <BillingModule
      applicationId={selected.id}
      canManage={canManage}
      copy={copy}
      requestGuard={requestGuard}
      onDirtyChange={onBillingDirtyChange}
      onEnabledChange={onBillingEnabledChange}
    />;
  }

  return null;
}
