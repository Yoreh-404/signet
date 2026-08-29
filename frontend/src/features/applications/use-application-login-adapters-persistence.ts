import { useEffect, useState } from "react";
import type { ApplicationModule } from "../../types";
import type { ApplicationRequestGuard } from "./application-request-guard";
import { persistApplicationModule } from "./application-module-persistence";
import { useApplicationRequestLifecycle } from "./use-application-request-lifecycle";

type ApplicationLoginAdaptersPersistenceOptions = {
  applicationId: string | null;
  config: Record<string, unknown>;
  requestGuard: ApplicationRequestGuard;
  onModuleChanged: (module: ApplicationModule) => void;
  onDraftCommitted: () => void;
  savedMessage: string;
  saveFailedMessage: string;
};

export function useApplicationLoginAdaptersPersistence({
  applicationId,
  config,
  requestGuard,
  onModuleChanged,
  onDraftCommitted,
  savedMessage,
  saveFailedMessage
}: ApplicationLoginAdaptersPersistenceOptions) {
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState("");
  const { beginRequest, isCurrent, finishRequest } = useApplicationRequestLifecycle({
    applicationId: applicationId ?? "",
    requestGuard
  });

  useEffect(() => {
    setSaving(false);
    setFeedback("");
  }, [applicationId]);

  async function save() {
    if (!applicationId) return;
    const request = beginRequest("module:login_adapters", { kind: "mutation" });
    if (!request) return;
    setSaving(true);
    setFeedback("");
    let committed = false;
    try {
      const result = await persistApplicationModule(applicationId, "login_adapters", {
        config,
        is_enabled: typeof config.enabled === "boolean" ? config.enabled : true
      }, request, isCurrent);
      if (result.stale) return;
      if (result.module) onModuleChanged(result.module);
      if (result.committed || (result.module && result.moduleWritten)) onDraftCommitted();
      setFeedback(result.committed ? savedMessage : saveFailedMessage);
      committed = result.committed;
    } finally {
      if (isCurrent(request)) setSaving(false);
      finishRequest(request, committed);
    }
  }

  return { saving, feedback, save, clearFeedback: () => setFeedback("") };
}
