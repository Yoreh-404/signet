import type { LucideIcon } from "lucide-react";

import type { TranslationKey } from "../../i18n";
import type { Tab } from "../../types";

export type AdminNavigationTab = {
  id: Tab;
  label: string;
  icon: LucideIcon;
};

export type AdminNavigationGroup = {
  id: string;
  label: string;
  hint: string;
  items: AdminNavigationTab[];
};

type Translate = (key: TranslationKey) => string;

const GROUP_DEFINITIONS: ReadonlyArray<{
  id: string;
  label: TranslationKey;
  hint: TranslationKey;
  ids: readonly Tab[];
}> = [
  {
    id: "workspace",
    label: "navWorkspace",
    hint: "navWorkspaceHint",
    ids: ["overview", "billing"]
  },
  {
    id: "directory",
    label: "navDirectory",
    hint: "navDirectoryHint",
    ids: ["users", "organizations", "invitations"]
  },
  {
    id: "applications",
    label: "navApplications",
    hint: "navApplicationsHint",
    ids: ["applications"]
  },
  {
    id: "access",
    label: "navAccess",
    hint: "navAccessHint",
    ids: ["registration", "providers", "portal", "security", "settings"]
  }
];

export function buildAdminNavigationGroups(
  tabs: readonly AdminNavigationTab[],
  translate: Translate
): AdminNavigationGroup[] {
  const tabsById = new Map(tabs.map((tab) => [tab.id, tab]));
  return GROUP_DEFINITIONS
    .map((group) => ({
      id: group.id,
      label: translate(group.label),
      hint: translate(group.hint),
      items: group.ids
        .map((id) => tabsById.get(id))
        .filter((tab): tab is AdminNavigationTab => Boolean(tab))
    }))
    .filter((group) => group.items.length > 0);
}
