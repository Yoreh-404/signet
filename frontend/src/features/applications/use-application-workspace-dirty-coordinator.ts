import { useCallback, useEffect, useRef } from "react";

import type {
  DirtyNavigationController,
  DirtyNavigationSourceHandle
} from "../navigation/useDirtyNavigation";
import {
  APPLICATION_AUTHORIZATION_DIRTY_SOURCE,
  APPLICATION_DIRECTORY_SYNC_DIRTY_SOURCE,
  APPLICATION_OIDC_CLIENTS_DIRTY_SOURCE,
  APPLICATION_PROTOCOLS_DIRTY_SOURCE,
} from "./application-workspace-module-contracts";
import {
  getApplicationWorkspaceDirtyState,
  type ApplicationWorkspaceDrafts,
  type ApplicationWorkspaceDirtyState
} from "./application-workspace-dirty";

const APPLICATION_WORKSPACE_DIRTY_SOURCE = "applications.workspace";

export type ApplicationWorkspaceDirtyCoordinatorOptions = {
  selected: boolean;
  drafts: ApplicationWorkspaceDrafts;
  billingDirty: boolean;
  iapRuleDirty: boolean;
  dirtyNavigation: Pick<DirtyNavigationController, "getSnapshot" | "registerSource">;
  moduleConfig: (key: "login_adapters") => Record<string, unknown>;
  resetDrafts: () => void;
  resetProtocolReadModel: () => void;
  resetDirectoryReadModel: () => void;
};

export function useApplicationWorkspaceDirtyCoordinator({
  selected,
  drafts,
  billingDirty,
  iapRuleDirty,
  dirtyNavigation,
  moduleConfig,
  resetDrafts,
  resetProtocolReadModel,
  resetDirectoryReadModel
}: ApplicationWorkspaceDirtyCoordinatorOptions) {
  const dirtySourceRef = useRef<DirtyNavigationSourceHandle | null>(null);

  const getWorkspaceDirtyState = useCallback(
    (sources = dirtyNavigation.getSnapshot().sources): ApplicationWorkspaceDirtyState =>
      getApplicationWorkspaceDirtyState({
        selected,
        drafts,
        billingDirty,
        iapRuleDirty,
        sources,
        moduleConfig
      }),
    [billingDirty, dirtyNavigation, drafts, iapRuleDirty, moduleConfig, selected]
  );

  const syncWorkspaceDirtySource = useCallback(() => {
    const sources = dirtyNavigation.getSnapshot().sources;
    const dirtyState = getWorkspaceDirtyState(sources);
    dirtySourceRef.current?.setDirty(
      dirtyState.hasWorkspaceDrafts
      || sources[APPLICATION_OIDC_CLIENTS_DIRTY_SOURCE]
      || sources[APPLICATION_AUTHORIZATION_DIRTY_SOURCE]
      || sources[APPLICATION_PROTOCOLS_DIRTY_SOURCE]
      || sources[APPLICATION_DIRECTORY_SYNC_DIRTY_SOURCE]
    );
  }, [dirtyNavigation, getWorkspaceDirtyState]);

  useEffect(() => {
    const source = dirtyNavigation.registerSource(APPLICATION_WORKSPACE_DIRTY_SOURCE);
    dirtySourceRef.current = source;
    return () => {
      source.unregister();
      if (dirtySourceRef.current === source) dirtySourceRef.current = null;
    };
  }, [dirtyNavigation.registerSource]);

  useEffect(() => {
    syncWorkspaceDirtySource();
  }, [billingDirty, drafts, iapRuleDirty, selected, syncWorkspaceDirtySource]);

  const resetWorkspaceDrafts = useCallback(() => {
    resetDrafts();
    resetProtocolReadModel();
    resetDirectoryReadModel();
  }, [resetDirectoryReadModel, resetDrafts, resetProtocolReadModel]);

  return { getWorkspaceDirtyState, resetWorkspaceDrafts, syncWorkspaceDirtySource };
}
