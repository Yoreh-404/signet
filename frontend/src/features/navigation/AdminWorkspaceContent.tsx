import { Suspense, type ReactNode } from "react";

import type { Tab } from "../../types";
import { AdminWorkspaceRouter } from "./AdminWorkspaceRouter";

export type AdminWorkspaceSlot = {
  route: Tab;
  enabled?: boolean;
  content: () => ReactNode;
};

export type AdminWorkspaceContentProps = {
  tab: Tab;
  slots: readonly AdminWorkspaceSlot[];
  noAdminMessage?: ReactNode;
};

export function AdminWorkspaceContent({ tab, slots, noAdminMessage }: AdminWorkspaceContentProps) {
  const activeSlot = slots.find(({ route, enabled = true }) => route === tab && enabled);

  return (
    <>
      {noAdminMessage}
      {activeSlot ? (
        <AdminWorkspaceRouter tab={tab} route={activeSlot.route}>
          <Suspense fallback={<div className="loading-state">Loading…</div>}>
            {activeSlot.content()}
          </Suspense>
        </AdminWorkspaceRouter>
      ) : null}
    </>
  );
}
