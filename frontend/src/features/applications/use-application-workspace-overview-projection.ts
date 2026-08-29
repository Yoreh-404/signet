import { useCallback, useEffect, useState } from "react";

import {
  useApplicationWorkspaceReadModel,
  type ApplicationWorkspaceReadModel
} from "./use-application-workspace-read-model";

export type ApplicationWorkspaceOverviewProjection = {
  protocolReadModel: ApplicationWorkspaceReadModel | null;
  directoryReadModel: ApplicationWorkspaceReadModel | null;
  billingEnabled: boolean;
  iapRuleCount: number;
  updateProtocolReadModel: (
    applicationId: string,
    config: Record<string, unknown> | null
  ) => void;
  updateDirectoryReadModel: (
    applicationId: string,
    config: Record<string, unknown> | null
  ) => void;
  resetProtocolReadModel: () => void;
  resetDirectoryReadModel: () => void;
  resetReadModels: () => void;
  setBillingEnabled: (enabled: boolean) => void;
  setIapRuleCount: (count: number) => void;
};

export function useApplicationWorkspaceOverviewProjection(
  applicationId: string | null
): ApplicationWorkspaceOverviewProjection {
  const {
    readModel: protocolReadModel,
    updateReadModel: updateProtocolReadModel,
    resetReadModel: resetProtocolReadModel
  } = useApplicationWorkspaceReadModel();
  const {
    readModel: directoryReadModel,
    updateReadModel: updateDirectoryReadModel,
    resetReadModel: resetDirectoryReadModel
  } = useApplicationWorkspaceReadModel();
  const [billingEnabled, setBillingEnabled] = useState(false);
  const [iapRuleCount, setIapRuleCount] = useState(0);

  const resetReadModels = useCallback(() => {
    resetProtocolReadModel();
    resetDirectoryReadModel();
  }, [resetDirectoryReadModel, resetProtocolReadModel]);

  useEffect(() => {
    resetReadModels();
    setBillingEnabled(false);
    setIapRuleCount(0);
  }, [applicationId, resetReadModels]);

  return {
    protocolReadModel,
    directoryReadModel,
    billingEnabled,
    iapRuleCount,
    updateProtocolReadModel,
    updateDirectoryReadModel,
    resetProtocolReadModel,
    resetDirectoryReadModel,
    resetReadModels,
    setBillingEnabled,
    setIapRuleCount
  };
}
