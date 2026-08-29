import { useEffect, useMemo, useState } from "react";
import {
  applicationDirectorySyncConfig,
  applicationProtocolsConfig,
} from "./application-workspace-module-contracts";
import {
  ApplicationBasics,
  type ApplicationBasicsCommands,
} from "./ApplicationBasics";
import { ApplicationWorkspaceModuleContent } from "./ApplicationWorkspaceModuleContent";
import { buildApplicationBasicsReadModel } from "./application-basics-read-model";
import { record } from "./application-module-values";
import { useApplicationModuleState } from "./use-application-module-state";
import { useApplicationWorkspaceNavigation } from "./use-application-workspace-navigation";
import { useApplicationWorkspaceOverviewProjection } from "./use-application-workspace-overview-projection";
import { useApplicationWorkspaceDirtyCoordinator } from "./use-application-workspace-dirty-coordinator";
import { useApplicationWorkspaceSelection } from "./use-application-workspace-selection";
import { APPLICATION_LOGIN_ADAPTERS_DIRTY_SOURCE } from "./application-login-adapters-constants";
import { ApplicationWorkspaceRequestContextProvider } from "./use-application-workspace-request-context";
import {
  EN,
  ZH,
  type ApplicationWorkspaceCopy,
} from "./application-workspace-copy";
export type { ApplicationWorkspaceCopy } from "./application-workspace-copy";
import type {
  DirtyNavigationController
} from "../navigation/useDirtyNavigation";
import type {
  ApplicationSection,
  ApplicationModule,
  ApplicationModuleKey,
  Client,
  ExternalProvider,
  LdapProvider,
  Locale,
  OrganizationOption,
  TenantApplication
} from "../../types";


export function ApplicationWorkspace({
  applications,
  providers,
  ldapProviders,
  organizationOptions,
  locale,
  canManage,
  initialApplicationId,
  initialSection,
  onCreateApplication,
  onEditApplication,
  onDeleteApplication,
  onApplicationModuleChanged,
  onApplicationOidcClientsChanged,
  onNavigationChange,
  dirtyNavigation,
  onRequestConfirmation
}: {
  applications: TenantApplication[];
  providers: ExternalProvider[];
  ldapProviders: LdapProvider[];
  organizationOptions: OrganizationOption[];
  locale: Locale;
  canManage: boolean;
  initialApplicationId?: string | null;
  initialSection?: ApplicationSection | null;
  onCreateApplication: () => void;
  onEditApplication: (application: TenantApplication) => void;
  onDeleteApplication: (id: string) => void;
  onApplicationModuleChanged: (applicationId: string, module: ApplicationModule) => void;
  onApplicationOidcClientsChanged?: (applicationId: string, clients: Client[]) => void;
  onNavigationChange?: (applicationId: string, section: ApplicationSection) => void;
  dirtyNavigation: Pick<DirtyNavigationController, "getSnapshot" | "registerSource">;
  onRequestConfirmation?: (
    action: () => Promise<void> | void,
    title: string,
    description: string
  ) => void;
}) {
  const c = locale === "zh-CN" ? ZH : EN;
  const [loginAdaptersConfig, setLoginAdaptersConfig] = useState<Record<string, unknown> | null>(null);
  const [billingDirty, setBillingDirty] = useState(false);
  const [iapRuleDirty, setIapRuleDirty] = useState(false);
  const {
    selectedId,
    setSelectedId,
    section,
    setSection,
    selected,
    requestGuard,
    invalidateApplicationRequests,
  } = useApplicationWorkspaceSelection({
    applications,
    initialApplicationId,
    initialSection,
  });

  useEffect(() => {
    setLoginAdaptersConfig(null);
    setBillingDirty(false);
    setIapRuleDirty(false);
  }, [selectedId]);

  const { moduleConfig, moduleEnabled } = useApplicationModuleState(selected);
  const overviewProjection = useApplicationWorkspaceOverviewProjection(selectedId);
  const {
    protocolReadModel,
    directoryReadModel,
    billingEnabled,
    iapRuleCount,
    resetProtocolReadModel,
    resetDirectoryReadModel
  } = overviewProjection;

  const {
    getWorkspaceDirtyState,
    resetWorkspaceDrafts,
    syncWorkspaceDirtySource
  } = useApplicationWorkspaceDirtyCoordinator({
    selected: Boolean(selected),
    drafts: {},
    billingDirty,
    iapRuleDirty,
    dirtyNavigation,
    moduleConfig,
    resetDrafts: () => {
      setLoginAdaptersConfig(null);
      setBillingDirty(false);
      setIapRuleDirty(false);
    },
    resetProtocolReadModel,
    resetDirectoryReadModel
  });

  useEffect(() => {
    const nextSection = initialSection ?? "overview";
    if (nextSection === section) return;
    resetWorkspaceDrafts();
    setSection(nextSection);
  }, [initialSection, resetWorkspaceDrafts, section]);

  const { selectApplication, openSection } = useApplicationWorkspaceNavigation({
    selected,
    selectedId,
    section,
    setSelectedId,
    setSection,
    resetWorkspaceDrafts,
    invalidateApplicationRequests,
    clearFeedback: () => undefined,
    hasUnsavedChanges: () => getWorkspaceDirtyState().hasUnsavedDrafts
      || Boolean(dirtyNavigation.getSnapshot().sources[APPLICATION_LOGIN_ADAPTERS_DIRTY_SOURCE]),
    unsavedChanges: c.unsavedChanges,
    discardChanges: c.discardChanges,
    onNavigationChange,
    onRequestConfirmation
  });

  const protocolConfig = useMemo(() => selected
    ? protocolReadModel?.applicationId === selected.id
      ? protocolReadModel.config
      : applicationProtocolsConfig(selected)
    : {}, [protocolReadModel, selected]);
  const loginAdaptersOverviewConfig = useMemo(
    () => record(loginAdaptersConfig ?? moduleConfig("login_adapters")),
    [loginAdaptersConfig, moduleConfig]
  );
  const directoryConfig = useMemo(() => selected
    ? directoryReadModel?.applicationId === selected.id
      ? directoryReadModel.config
      : applicationDirectorySyncConfig(selected)
    : {}, [directoryReadModel, selected]);
  const authorizationConfig = useMemo(
    () => record(selected ? moduleConfig("authorization") : {}),
    [moduleConfig, selected]
  );
  const enabledModules = useMemo(() => ({
    protocols: selected ? moduleEnabled("protocols") : false,
    login_adapters: selected ? moduleEnabled("login_adapters") : false,
    directory_sync: selected ? moduleEnabled("directory_sync") : false,
    authorization: selected ? moduleEnabled("authorization") : false
  }), [moduleEnabled, selected]);
  const readModel = useMemo(() => buildApplicationBasicsReadModel({
    applications,
    selected,
    section,
    protocolConfig,
    loginAdaptersConfig: loginAdaptersOverviewConfig,
    directoryConfig,
    providers,
    ldapProviders,
    authorizationConfig,
    moduleEnabled: enabledModules,
    inheritEnterprise: c.inheritEnterprise,
    notConfigured: c.notConfigured,
    billingEnabled,
    iapRuleCount
  }), [
    applications,
    authorizationConfig,
    billingEnabled,
    c.inheritEnterprise,
    c.notConfigured,
    directoryConfig,
    enabledModules,
    iapRuleCount,
    ldapProviders,
    loginAdaptersOverviewConfig,
    protocolConfig,
    providers,
    section,
    selected
  ]);
  const commands: ApplicationBasicsCommands = useMemo(() => ({
    createApplication: onCreateApplication,
    editApplication: onEditApplication,
    deleteApplication: onDeleteApplication,
    selectApplication,
    openSection
  }), [onCreateApplication, onDeleteApplication, onEditApplication, openSection, selectApplication]);
  return (
    <ApplicationBasics
      readModel={readModel}
      commands={commands}
      copy={c}
      canManage={canManage}
    >
            <ApplicationWorkspaceRequestContextProvider
              applicationId={selected?.id ?? ""}
              requestGuard={requestGuard}
            >
              <ApplicationWorkspaceModuleContent
              section={section}
              selected={selected}
              providers={providers}
              ldapProviders={ldapProviders}
              organizationOptions={organizationOptions}
              locale={locale}
              canManage={canManage}
              copy={c}
              dirtyNavigation={dirtyNavigation}
              overviewProjection={overviewProjection}
              onLoginAdaptersConfigChange={setLoginAdaptersConfig}
              onDirtyChange={syncWorkspaceDirtySource}
              onApplicationModuleChanged={onApplicationModuleChanged}
              onApplicationOidcClientsChanged={onApplicationOidcClientsChanged}
              onRequestConfirmation={onRequestConfirmation}
              authorizationConfig={moduleConfig("authorization")}
              hasUnsavedChanges={() => getWorkspaceDirtyState().hasUnsavedDrafts
                || Boolean(dirtyNavigation.getSnapshot().sources[APPLICATION_LOGIN_ADAPTERS_DIRTY_SOURCE])}
              onDiscardChanges={resetWorkspaceDrafts}
              onIapDirtyChange={setIapRuleDirty}
              onBillingDirtyChange={setBillingDirty}
              />
            </ApplicationWorkspaceRequestContextProvider>
    </ApplicationBasics>
  );
}
