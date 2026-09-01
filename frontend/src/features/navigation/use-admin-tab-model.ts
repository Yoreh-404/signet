import { AtSign, Building2, Coins, Link2, Settings, Shield, Ticket, UserRound, Users } from "lucide-react";
import { useMemo } from "react";
import type { TranslationKey } from "../../i18n";
import type { Locale, User } from "../../types";
import { buildAdminNavigationGroups, type AdminNavigationGroup, type AdminNavigationTab } from "./admin-navigation-groups";

type Translate = (key: TranslationKey) => string;

export type AdminTabModelOptions = {
  locale: Locale;
  translate: Translate;
  user: User | null;
  isRestrictedLoginCodeSession: boolean;
  canAdmin: boolean;
  hasGlobalConsolePermission: boolean;
  canReadUsers: boolean;
  canManageActiveOrganization: boolean;
  canReadOrganizations: boolean;
  canManageAuthorizationCodes: boolean;
  canManageSettings: boolean;
  canManageProviders: boolean;
  canManageSecurity: boolean;
  canReadAudit: boolean;
};

export type AdminTabModel = {
  tabs: AdminNavigationTab[];
  navigationGroups: AdminNavigationGroup[];
};

export function useAdminTabModel({
  locale,
  translate,
  user,
  isRestrictedLoginCodeSession,
  canAdmin,
  hasGlobalConsolePermission,
  canReadUsers,
  canManageActiveOrganization,
  canReadOrganizations,
  canManageAuthorizationCodes,
  canManageSettings,
  canManageProviders,
  canManageSecurity,
  canReadAudit
}: AdminTabModelOptions): AdminTabModel {
  const tabs = useMemo<AdminNavigationTab[]>(() => {
    const accountTab = { id: "account" as const, label: translate("account"), icon: UserRound };
    const billingTab = user && !isRestrictedLoginCodeSession
      ? { id: "billing" as const, label: translate("billing"), icon: Coins }
      : null;
    const adminTabs = [
      hasGlobalConsolePermission ? { id: "overview" as const, label: translate("overview"), icon: Shield } : null,
      canReadUsers ? { id: "users" as const, label: translate("users"), icon: Users } : null,
      canManageActiveOrganization ? { id: "applications" as const, label: translate("applications"), icon: Building2 } : null,
      canReadOrganizations ? { id: "organizations" as const, label: translate("organizations"), icon: Building2 } : null,
      canManageAuthorizationCodes ? { id: "invitations" as const, label: translate("invitations"), icon: Ticket } : null,
      canManageSettings ? { id: "registration" as const, label: translate("registration"), icon: UserRound } : null,
      canManageProviders ? { id: "providers" as const, label: translate("providers"), icon: Link2 } : null,
      canManageSettings ? { id: "portal" as const, label: translate("portal"), icon: AtSign } : null,
      canManageSecurity || canReadAudit ? { id: "security" as const, label: translate("security"), icon: Shield } : null,
      canManageSettings ? { id: "settings" as const, label: translate("settings"), icon: Settings } : null
    ].filter((item): item is NonNullable<typeof item> => Boolean(item));
    return canAdmin
      ? [accountTab, ...(billingTab ? [billingTab] : []), ...adminTabs]
      : [accountTab, ...(billingTab ? [billingTab] : [])];
  }, [
    canAdmin,
    canManageActiveOrganization,
    canManageAuthorizationCodes,
    canManageProviders,
    canManageSecurity,
    canManageSettings,
    canReadAudit,
    canReadOrganizations,
    canReadUsers,
    hasGlobalConsolePermission,
    isRestrictedLoginCodeSession,
    locale,
    translate,
    user
  ]);

  const navigationGroups = useMemo(
    () => buildAdminNavigationGroups(tabs, translate),
    [locale, tabs, translate]
  );

  return {
    tabs,
    navigationGroups
  };
}
