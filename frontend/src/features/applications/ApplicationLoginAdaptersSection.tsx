import type { ExternalProvider } from "../../types";
import {
  ApplicationLoginAdaptersEditor,
  type ApplicationLoginAdaptersEditorCopy
} from "./ApplicationLoginAdaptersEditor";
import { booleanValue, stringList } from "./application-module-values";

type ApplicationLoginAdaptersSectionProps = {
  providers: ExternalProvider[];
  organizationId: string;
  config: Record<string, unknown>;
  enabled: boolean;
  saving: boolean;
  feedback: string;
  copy: ApplicationLoginAdaptersEditorCopy;
  onUpdate: (config: Record<string, unknown>) => void;
  onSave: () => void;
};

export function ApplicationLoginAdaptersSection({
  providers,
  organizationId,
  config,
  enabled,
  saving,
  feedback,
  copy,
  onUpdate,
  onSave
}: ApplicationLoginAdaptersSectionProps) {
  const update = (key: string, value: unknown) => onUpdate({ ...config, [key]: value });
  const providerIds = stringList(config.provider_ids);

  return (
    <ApplicationLoginAdaptersEditor
      providers={providers}
      organizationId={organizationId}
      enabled={booleanValue(config.enabled, enabled)}
      providerIds={providerIds}
      allowSignetPassword={booleanValue(config.allow_signet_password, true)}
      saving={saving}
      feedback={feedback}
      copy={copy}
      onEnabledChange={(value) => update("enabled", value)}
      onProviderToggle={(providerId) => update(
        "provider_ids",
        providerIds.includes(providerId)
          ? providerIds.filter((item) => item !== providerId)
          : [...providerIds, providerId]
      )}
      onAllowSignetPasswordChange={(value) => update("allow_signet_password", value)}
      onSave={onSave}
    />
  );
}
