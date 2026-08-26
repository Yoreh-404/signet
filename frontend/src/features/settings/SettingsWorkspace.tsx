import type { FormEvent } from "react";

import { DiagnosticsPanel } from "./DiagnosticsPanel";
import { RuntimeSettingsPanel } from "./RuntimeSettingsPanel";
import type { TranslationKey } from "../../i18n";
import type { RuntimeSettings, SettingsSummary } from "../../types";

export type SettingsWorkspaceProps = {
  settings: SettingsSummary;
  runtimeSettings: RuntimeSettings;
  busy: boolean;
  dirty: boolean;
  translate: (key: TranslationKey) => string;
  onRuntimeSettingsChange: (value: RuntimeSettings) => void;
  onRuntimeSettingsSubmit: (event: FormEvent<HTMLFormElement>) => void | Promise<void>;
};

export function SettingsWorkspace({
  settings,
  runtimeSettings,
  busy,
  dirty,
  translate,
  onRuntimeSettingsChange,
  onRuntimeSettingsSubmit
}: SettingsWorkspaceProps) {
  return (
    <section className="split wide">
      <RuntimeSettingsPanel
        value={runtimeSettings}
        busy={busy}
        dirty={dirty}
        translate={translate}
        onChange={onRuntimeSettingsChange}
        onSubmit={onRuntimeSettingsSubmit}
      />
      <DiagnosticsPanel settings={settings} runtimeSettings={runtimeSettings} translate={translate} />
    </section>
  );
}
