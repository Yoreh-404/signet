import type { LoginSettingsDraft, Tab } from "../../types";
import {
  loadAdminPortalQuery,
  loadAdminRegistrationQuery,
  loadAdminRuntimeSettingsQuery
} from "./admin-settings-query";
import type { AdminReadQueryContext } from "./admin-read-query";

export type AdminSettingsLoaderOptions = AdminReadQueryContext & {
  tab: Extract<Tab, "registration" | "portal" | "settings">;
  canManageSettings: boolean;
  onLoginSettingsLoaded: (draft: LoginSettingsDraft) => void;
};

export async function loadAdminSettings({
  tab,
  loadCached,
  updateReadModel,
  canManageSettings,
  onLoginSettingsLoaded
}: AdminSettingsLoaderOptions): Promise<void> {
  const options = { loadCached, updateReadModel, canManageSettings, onLoginSettingsLoaded };
  switch (tab) {
    case "registration":
      await loadAdminRegistrationQuery(options);
      return;
    case "portal":
      await loadAdminPortalQuery(options);
      return;
    case "settings":
      await loadAdminRuntimeSettingsQuery(options);
      return;
  }
}
