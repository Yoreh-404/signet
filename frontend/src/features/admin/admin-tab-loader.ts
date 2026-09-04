import type { LoginSettingsDraft, Tab } from "../../types";
import { loadAdminApplicationsQuery } from "./admin-applications-query";
import { loadAdminOrganizationsQuery } from "./admin-organizations-query";
import { loadAdminProvidersQuery } from "./admin-providers-query";
import { loadAdminSecurityQuery } from "./admin-security-query";
import type { AdminReadQueryContext } from "./admin-read-query";
import { loadAdminInvitations } from "./admin-invitations-loader";
import { loadAdminOverview } from "./admin-overview-loader";
import { loadAdminSettings } from "./admin-settings-loader";
import { loadAdminUsers } from "./admin-users-loader";

export type AdminTabLoaderOptions = AdminReadQueryContext & {
  targetTab: Tab;
  canReadUsers: boolean;
  canManageActiveOrganization: boolean;
  canReadOrganizations: boolean;
  canManageOrganizations: boolean;
  canManageAuthorizationCodes: boolean;
  canManageSettings: boolean;
  canManagePlatformProviders: boolean;
  canManageProviders: boolean;
  canManageSecurity: boolean;
  canReadAudit: boolean;
  onLoginSettingsLoaded: (draft: LoginSettingsDraft) => void;
};

export async function loadAdminTab({ targetTab, onLoginSettingsLoaded, ...options }: AdminTabLoaderOptions): Promise<void> {
  switch (targetTab) {
    case "overview":
      await loadAdminOverview(options);
      return;
    case "users":
      await loadAdminUsers(options);
      return;
    case "applications":
      await loadAdminApplicationsQuery(options);
      return;
    case "organizations":
      await loadAdminOrganizationsQuery(options);
      return;
    case "invitations":
      await loadAdminInvitations(options);
      return;
    case "registration":
    case "portal":
    case "settings":
      await loadAdminSettings({ ...options, tab: targetTab, onLoginSettingsLoaded });
      return;
    case "providers":
      if (!options.canManageProviders) return;
      await loadAdminProvidersQuery(options);
      return;
    case "security":
      await loadAdminSecurityQuery(options);
      return;
    case "billing":
    case "account":
      return;
  }
}
