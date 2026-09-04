import type { ReactNode } from "react";
import type { Tab } from "../../types";

type AdminWorkspaceRouterProps = {
  tab: Tab;
  route: Tab;
  enabled?: boolean;
  children: ReactNode;
};

export function AdminWorkspaceRouter({
  tab,
  route,
  enabled = true,
  children
}: AdminWorkspaceRouterProps) {
  if (!enabled || tab !== route) return null;
  return <>{children}</>;
}
