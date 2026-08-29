import { useState } from "react";

import type { DirtyNavigationController } from "../navigation/useDirtyNavigation";
import type { ApplicationRequestGuard } from "./application-request-guard";
import { useApplicationDirtySource } from "./use-application-dirty-source";
import { useApplicationRequestLifecycle } from "./use-application-request-lifecycle";

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
  useApplicationDirtySource({ dirtyNavigation, dirtySource, dirty, onDirtyChange });

  const { beginRequest, isCurrent, finishRequest } = useApplicationRequestLifecycle({
    applicationId,
    requestGuard
  });

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
