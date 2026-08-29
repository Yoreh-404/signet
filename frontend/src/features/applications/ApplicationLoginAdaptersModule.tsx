import { useEffect, useState } from "react";

import type { DirtyNavigationController } from "../navigation/useDirtyNavigation";
import type { ApplicationModule, ExternalProvider, TenantApplication } from "../../types";
import { ApplicationLoginAdaptersSection } from "./ApplicationLoginAdaptersSection";
import type { ApplicationLoginAdaptersEditorCopy } from "./ApplicationLoginAdaptersEditor";
import { useApplicationLoginAdaptersPersistence } from "./use-application-login-adapters-persistence";
import { useApplicationModuleState } from "./use-application-module-state";
import { stableDomainEqual } from "../admin/stable-domain-comparator";
import { useApplicationWorkspaceRequestContext } from "./use-application-workspace-request-context";
import { useApplicationDirtySource } from "./use-application-dirty-source";
import { APPLICATION_LOGIN_ADAPTERS_DIRTY_SOURCE } from "./application-login-adapters-constants";

type ApplicationLoginAdaptersModuleProps = {
  application: TenantApplication;
  providers: ExternalProvider[];
  canManage: boolean;
  copy: ApplicationLoginAdaptersEditorCopy;
  dirtyNavigation: Pick<DirtyNavigationController, "registerSource">;
  onApplicationModuleChanged: (applicationId: string, module: ApplicationModule) => void;
  savedMessage: string;
  onConfigChange?: (config: Record<string, unknown> | null) => void;
};

export function ApplicationLoginAdaptersModule({
  application,
  providers,
  canManage,
  copy,
  dirtyNavigation,
  onApplicationModuleChanged,
  savedMessage,
  onConfigChange
}: ApplicationLoginAdaptersModuleProps) {
  const { moduleConfig, moduleEnabled } = useApplicationModuleState(application);
  const { requestGuard } = useApplicationWorkspaceRequestContext();
  const [draftConfig, setDraftConfig] = useState<Record<string, unknown> | null>(null);
  const config = draftConfig ?? moduleConfig("login_adapters");
  const hasUnsavedChanges = draftConfig !== null
    && !stableDomainEqual(draftConfig, moduleConfig("login_adapters"));
  useApplicationDirtySource({
    dirtySource: APPLICATION_LOGIN_ADAPTERS_DIRTY_SOURCE,
    dirtyNavigation,
    dirty: hasUnsavedChanges
  });

  const persistence = useApplicationLoginAdaptersPersistence({
    applicationId: application.id,
    config,
    requestGuard,
    onModuleChanged: (module) => onApplicationModuleChanged(application.id, module),
    onDraftCommitted: () => setDraftConfig(null),
    savedMessage,
    saveFailedMessage: copy.saveFailed
  });

  useEffect(() => {
    onConfigChange?.(config);
  }, [config, hasUnsavedChanges, onConfigChange]);

  useEffect(() => () => onConfigChange?.(null), [onConfigChange]);

  return (
    <ApplicationLoginAdaptersSection
      providers={providers}
      organizationId={application.organization_id}
      config={config}
      enabled={moduleEnabled("login_adapters")}
      saving={persistence.saving}
      feedback={persistence.feedback}
      copy={copy}
      onUpdate={setDraftConfig}
      onSave={() => void persistence.save()}
    />
  );
}
