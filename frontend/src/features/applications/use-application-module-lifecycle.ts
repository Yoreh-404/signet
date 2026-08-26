import { useCallback, useEffect, useRef, useState } from "react";

import type {
  DirtyNavigationController,
  DirtyNavigationSourceHandle
} from "../navigation/useDirtyNavigation";
import type {
  ApplicationRequestBeginOptions,
  ApplicationRequestGuard,
  ApplicationRequestToken
} from "./application-request-guard";

export type ApplicationModuleLifecycleOptions = {
  applicationId: string;
  dirtySource?: string;
  dirtyNavigation?: Pick<DirtyNavigationController, "registerSource">;
  onDirtyChange?: (dirty: boolean) => void;
  requestGuard: ApplicationRequestGuard;
  dirty: boolean;
};

export function useApplicationModuleLifecycle({
  applicationId,
  dirtySource,
  dirtyNavigation,
  onDirtyChange,
  requestGuard,
  dirty
}: ApplicationModuleLifecycleOptions) {
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState("");
  const dirtySourceRef = useRef<DirtyNavigationSourceHandle | null>(null);
  const registerSource = dirtyNavigation?.registerSource;

  useEffect(() => {
    if (!registerSource || !dirtySource) return;
    const source = registerSource(dirtySource);
    dirtySourceRef.current = source;
    return () => {
      source.unregister();
      if (dirtySourceRef.current === source) dirtySourceRef.current = null;
    };
  }, [dirtySource, registerSource]);

  useEffect(() => {
    dirtySourceRef.current?.setDirty(dirty);
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);

  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange]);

  const beginRequest = useCallback(
    (scope: string, options: Omit<ApplicationRequestBeginOptions, "scope"> = {}) =>
      requestGuard.begin(applicationId, { ...options, scope }),
    [applicationId, requestGuard]
  );
  const isCurrent = useCallback(
    (request: ApplicationRequestToken) => requestGuard.isCurrent(request),
    [requestGuard]
  );
  const finishRequest = useCallback(
    (request: ApplicationRequestToken, committed = true) => requestGuard.finish(request, committed),
    [requestGuard]
  );

  return {
    saving,
    setSaving,
    feedback,
    setFeedback,
    beginRequest,
    isCurrent,
    finishRequest
  };
}
