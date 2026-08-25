import { useEffect, useState } from "react";

import type { ApplicationSection, Tab } from "../../types";
import {
  initialNavigation,
  type NavigationState
} from "../../lib/navigation";
import {
  useDirtyNavigation,
  type DirtyNavigationHookResult
} from "./useDirtyNavigation";

export type AdminNavigationOptions = {
  initialState: NavigationState;
  confirmNavigation: () => boolean;
  onAccepted?: () => void;
};

export type AdminNavigationResult = NavigationState & {
  dirtyNavigation: DirtyNavigationHookResult;
  navigateToTab: (
    next: Tab,
    options?: {
      applicationId?: string | null;
      applicationSection?: ApplicationSection | null;
    }
  ) => boolean;
};

/**
 * Owns the admin URL/state boundary.  Components issue a navigation command;
 * this hook is the only place that translates it into a hash and commits the
 * parsed state after dirty confirmation succeeds.
 */
export function useAdminNavigation(options: AdminNavigationOptions): AdminNavigationResult {
  const [tab, setTab] = useState<Tab>(options.initialState.tab);
  const [applicationId, setApplicationId] = useState<string | null>(options.initialState.applicationId);
  const [applicationSection, setApplicationSection] = useState<ApplicationSection | null>(options.initialState.applicationSection);
  const [billingOrder, setBillingOrder] = useState<string | null>(options.initialState.billingOrder);

  const dirtyNavigation = useDirtyNavigation({
    confirmNavigation: options.confirmNavigation,
    onNavigationAccepted: () => {
      commitFromLocation();
      options.onAccepted?.();
    }
  });

  useEffect(() => dirtyNavigation.connect(), [dirtyNavigation.connect]);

  function commitFromLocation(): NavigationState {
    const navigation = initialNavigation();
    setTab(navigation.tab);
    setApplicationId(navigation.applicationId);
    setApplicationSection(navigation.applicationSection);
    setBillingOrder(navigation.billingOrder);
    return navigation;
  }

  function navigateToTab(
    next: Tab,
    navigationOptions: {
      applicationId?: string | null;
      applicationSection?: ApplicationSection | null;
    } = {}
  ): boolean {
    const currentNavigation = initialNavigation();
    const nextApplicationId = next === "applications"
      ? navigationOptions.applicationId ?? currentNavigation.applicationId
      : null;
    const nextApplicationSection = next === "applications"
      ? navigationOptions.applicationSection ?? currentNavigation.applicationSection
      : null;
    const nextBillingOrder = next === "billing" ? currentNavigation.billingOrder : null;
    const params = new URLSearchParams();
    if (nextApplicationId) params.set("application", nextApplicationId);
    if (nextApplicationSection) params.set("section", nextApplicationSection);
    if (nextBillingOrder) params.set("billing_order", nextBillingOrder);
    const query = params.toString();
    const nextHash = `#/${next}${query ? `?${query}` : ""}`;

    if (next !== tab) {
      if (!dirtyNavigation.requestNavigation(nextHash)) return false;
      return true;
    }

    setApplicationId(nextApplicationId);
    setApplicationSection(nextApplicationSection);
    setBillingOrder(nextBillingOrder);
    if (window.location.hash !== nextHash) {
      window.history.pushState(null, "", nextHash);
    }
    dirtyNavigation.syncAcceptedHash(nextHash);
    commitFromLocation();
    options.onAccepted?.();
    return true;
  }

  return {
    tab,
    applicationId,
    applicationSection,
    billingOrder,
    dirtyNavigation,
    navigateToTab
  };
}
