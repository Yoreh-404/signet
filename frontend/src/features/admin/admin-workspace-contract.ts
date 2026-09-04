import type { ComponentProps } from "react";

import type { ApplicationWorkspace } from "../applications/ApplicationWorkspace";
import type { OrganizationsWorkspaceProps } from "../organizations/OrganizationsWorkspace";
import type { ProvidersWorkspaceProps } from "../providers/ProvidersWorkspace";
import type { SecurityWorkspaceProps } from "../security/SecurityWorkspace";
import type { SettingsWorkspaceProps } from "../settings/SettingsWorkspace";
import type { AdminUsersWorkspaceProps } from "../users/AdminUsersWorkspace";

export type ApplicationWorkspaceProps = ComponentProps<typeof ApplicationWorkspace>;

export type AdminWorkspaceController = {
  users: AdminUsersWorkspaceProps;
  organizations: OrganizationsWorkspaceProps;
  applications: ApplicationWorkspaceProps;
  providers: ProvidersWorkspaceProps;
  security: SecurityWorkspaceProps;
  settings: SettingsWorkspaceProps | null;
};
