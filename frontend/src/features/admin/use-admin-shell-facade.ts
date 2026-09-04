import {
  useAdminDataLoader,
  type AdminDataLoaderOptions,
  type AdminDataLoaderResult
} from "./use-admin-data-loader";
import {
  useAdminNavigation,
  type AdminNavigationOptions,
  type AdminNavigationResult
} from "../navigation/useAdminNavigation";
import type { Tab } from "../../types";

export type AdminShellFacadeOptions =
  & Omit<AdminDataLoaderOptions, "enabled" | "tab">
  & AdminNavigationOptions
  & {
    enabledForTab: (tab: Tab) => boolean;
  };

export type AdminShellFacadeResult = AdminNavigationResult & AdminDataLoaderResult;

export function useAdminShellFacade({
  initialState,
  confirmNavigation,
  onAccepted,
  enabledForTab,
  ...dataOptions
}: AdminShellFacadeOptions): AdminShellFacadeResult {
  const navigation = useAdminNavigation({ initialState, confirmNavigation, onAccepted });
  const data = useAdminDataLoader({
    ...dataOptions,
    tab: navigation.tab,
    enabled: enabledForTab(navigation.tab)
  });

  return { ...navigation, ...data };
}
