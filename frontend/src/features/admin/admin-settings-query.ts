import type {
  LoginSettings,
  LoginSettingsDraft,
  RegistrationSettings,
  RuntimeSettings,
  SettingsSummary
} from "../../types";
import type { AdminReadQueryContext } from "./admin-read-query";

export type AdminSettingsQueryOptions = AdminReadQueryContext & {
  canManageSettings: boolean;
  onLoginSettingsLoaded: (draft: LoginSettingsDraft) => void;
};

export async function loadAdminRegistrationQuery({
  loadCached,
  updateReadModel,
  canManageSettings
}: AdminSettingsQueryOptions): Promise<void> {
  if (!canManageSettings) return;

  await loadCached<RegistrationSettings>("/api/admin/registration-settings", (next) => {
    updateReadModel("registrationSettings", next);
    updateReadModel("registrationSettingsBaseline", next);
  });
}

export async function loadAdminPortalQuery({
  loadCached,
  updateReadModel,
  canManageSettings,
  onLoginSettingsLoaded
}: AdminSettingsQueryOptions): Promise<void> {
  if (!canManageSettings) return;

  await loadCached<LoginSettings>("/api/admin/login-settings", (next) => {
    updateReadModel("loginSettings", next);
    const draft: LoginSettingsDraft = {
      brand_logo_url: next.brand_logo_url,
      email_domains: next.email_domains.join("\n"),
      quick_links: next.quick_links
    };
    onLoginSettingsLoaded(draft);
    updateReadModel("loginSettingsBaseline", draft);
  });
}

export async function loadAdminRuntimeSettingsQuery({
  loadCached,
  updateReadModel,
  canManageSettings
}: AdminSettingsQueryOptions): Promise<void> {
  if (!canManageSettings) return;

  await Promise.all([
    loadCached<RuntimeSettings>("/api/admin/runtime-settings", (next) => {
      updateReadModel("runtimeSettings", next);
      updateReadModel("runtimeSettingsBaseline", next);
    }),
    loadCached<SettingsSummary>("/api/admin/settings", (next) => updateReadModel("settings", next))
  ]);
}
