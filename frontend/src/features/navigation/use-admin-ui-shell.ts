import { useCallback, useEffect, useMemo, useRef, useState, type Dispatch, type RefObject, type SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import type { AuthMode, Locale, Tab, Theme, User } from "../../types";
import { initialTheme } from "../../lib/navigation";
import { useDocumentPreferences } from "../preferences/use-document-preferences";
import { useMobileSidebarFocusTrap } from "./use-mobile-sidebar-focus-trap";
import {
  useAdminTabModel,
  type AdminTabModel,
  type AdminTabModelOptions
} from "./use-admin-tab-model";
import type { AdminSidebarNavigationGroup } from "./AdminSidebar";
import type { AdminHeaderNavigationGroup, AdminHeaderTab } from "./AdminHeader";

type Translate = (key: TranslationKey) => string;

export type AdminUiShellOptions = AdminTabModelOptions & {
  tab: Tab;
  authMode: AuthMode;
  accountLoginExpanded: boolean;
  authAccountSwitch: boolean;
  authReturnTo: string | null;
  forceLogin: boolean;
  isAuthPage: boolean;
  selectAccount: boolean;
  user: User | null;
  onSearchNavigate?: () => void;
};

export type AdminUiShellResult = AdminTabModel & {
  theme: Theme;
  sidebarOpen: boolean;
  sidebarRef: RefObject<HTMLElement>;
  mobileMenuButtonRef: RefObject<HTMLButtonElement>;
  searchQuery: string;
  setSearchQuery: Dispatch<SetStateAction<string>>;
  openSidebar: () => void;
  closeSidebar: () => void;
  toggleTheme: () => void;
  navigateSearch: (value: string) => void;
  resetNavigationUi: () => void;
  activeNavigationGroup: AdminTabModel["navigationGroups"][number] | undefined;
  activeHeaderNavigationGroup: AdminHeaderNavigationGroup | undefined;
  headerTabs: AdminHeaderTab[];
  sidebarNavigationGroups: AdminSidebarNavigationGroup[];
  searchEnabled: boolean;
};

const searchableTabs: readonly Tab[] = [
  "users",
  "applications",
  "organizations",
  "invitations",
  "providers",
  "security"
];

export function useAdminUiShell(options: AdminUiShellOptions): AdminUiShellResult {
  const {
    tab,
    locale,
    translate,
    user,
    authMode,
    accountLoginExpanded,
    authAccountSwitch,
    authReturnTo,
    forceLogin,
    isAuthPage,
    selectAccount,
    onSearchNavigate,
    ...tabModelOptions
  } = options;
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const sidebarRef = useRef<HTMLElement | null>(null);
  const mobileMenuButtonRef = useRef<HTMLButtonElement | null>(null);
  const tabModel = useAdminTabModel({ locale, translate, user, ...tabModelOptions });
  const activeNavigationGroup = useMemo(
    () => tabModel.navigationGroups.find((group) => group.items.some((item) => item.id === tab)),
    [tab, tabModel.navigationGroups]
  );
  const headerTabs = useMemo<AdminHeaderTab[]>(
    () => tabModel.tabs.map((item) => ({ id: item.id, label: item.label })),
    [tabModel.tabs]
  );
  const sidebarNavigationGroups = useMemo<AdminSidebarNavigationGroup[]>(
    () => tabModel.navigationGroups.map((group) => ({
      id: group.id,
      label: group.label,
      items: group.items.map((item) => ({
        id: item.id,
        label: item.label,
        icon: item.icon
      }))
    })),
    [tabModel.navigationGroups]
  );
  const activeHeaderNavigationGroup = activeNavigationGroup
    ? { label: activeNavigationGroup.label, hint: activeNavigationGroup.hint }
    : undefined;

  useDocumentPreferences(locale, theme);
  useMobileSidebarFocusTrap({
    open: sidebarOpen,
    sidebarRef,
    mobileMenuButtonRef,
    setOpen: setSidebarOpen
  });

  const openSidebar = useCallback(() => setSidebarOpen(true), []);
  const closeSidebar = useCallback(() => setSidebarOpen(false), []);
  const toggleTheme = useCallback(() => {
    setTheme((current) => current === "dark" ? "light" : "dark");
  }, []);
  const navigateSearch = useCallback((value: string) => {
    onSearchNavigate?.();
    setSearchQuery(value);
  }, [onSearchNavigate]);
  const resetNavigationUi = useCallback(() => {
    setSearchQuery("");
    setSidebarOpen(false);
  }, []);

  useEffect(() => {
    const authenticated = Boolean(
      user
      && !authAccountSwitch
      && !(authReturnTo && forceLogin)
      && !isAuthPage
      && !selectAccount
    );
    const label = selectAccount && !accountLoginExpanded
      ? translate("selectAccount")
      : authenticated
      ? tabModel.tabs.find((item) => item.id === tab)?.label
      : authMode === "register"
        ? translate("register")
        : authMode === "reset"
          ? translate("resetPassword")
          : translate("signIn");
    document.title = label ? `${label} · Signet` : "Signet";
  }, [accountLoginExpanded, authAccountSwitch, authMode, authReturnTo, forceLogin, isAuthPage, locale, selectAccount, tab, tabModel.tabs, translate, user]);

  return {
    ...tabModel,
    activeNavigationGroup,
    activeHeaderNavigationGroup,
    headerTabs,
    sidebarNavigationGroups,
    searchEnabled: searchableTabs.includes(tab),
    theme,
    sidebarOpen,
    sidebarRef,
    mobileMenuButtonRef,
    searchQuery,
    setSearchQuery,
    openSidebar,
    closeSidebar,
    toggleTheme,
    navigateSearch,
    resetNavigationUi
  };
}
