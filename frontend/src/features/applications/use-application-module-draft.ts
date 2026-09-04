import { useEffect, useRef, useState } from "react";

import type { TenantApplication } from "../../types";
import type { DirtyNavigationController } from "../navigation/useDirtyNavigation";
import { stableDomainEqual } from "../admin/stable-domain-comparator";
import { useApplicationDirtySource } from "./use-application-dirty-source";

export type ApplicationModuleDraftOptions = {
  application: TenantApplication;
  dirtyNavigation: Pick<DirtyNavigationController, "registerSource">;
  dirtySource: string;
  resolveConfig: (application: TenantApplication) => Record<string, unknown>;
  onDirtyChange?: () => void;
  onReadModelChange?: (applicationId: string, config: Record<string, unknown> | null) => void;
};

export function useApplicationModuleDraft({
  application,
  dirtyNavigation,
  dirtySource,
  resolveConfig,
  onDirtyChange,
  onReadModelChange
}: ApplicationModuleDraftOptions) {
  const [draftConfig, setDraftConfig] = useState<Record<string, unknown> | null>(null);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState("");
  const onReadModelChangeRef = useRef(onReadModelChange);
  onReadModelChangeRef.current = onReadModelChange;

  const baseConfig = resolveConfig(application);
  const config = draftConfig ?? baseConfig;
  const dirty = draftConfig !== null && !stableDomainEqual(draftConfig, baseConfig);

  useApplicationDirtySource({
    dirtyNavigation,
    dirtySource,
    dirty,
    onDirtyChange
  });

  useEffect(() => {
    return () => {
      onReadModelChangeRef.current?.(application.id, null);
    };
  }, [application.id]);

  useEffect(() => {
    onReadModelChangeRef.current?.(application.id, draftConfig ?? resolveConfig(application));
  }, [application, draftConfig, resolveConfig]);

  useEffect(() => {
    setDraftConfig(null);
    setFeedback("");
    setSaving(false);
  }, [application.id]);

  return {
    config,
    draftConfig,
    setDraftConfig,
    saving,
    setSaving,
    feedback,
    setFeedback,
    dirty
  };
}
