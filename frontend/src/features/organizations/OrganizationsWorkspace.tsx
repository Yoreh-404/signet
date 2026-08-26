import { OrganizationWorkspace } from "./OrganizationWorkspace";
import type { OrganizationWorkspaceProps } from "./OrganizationWorkspace";

export type OrganizationsWorkspaceProps = OrganizationWorkspaceProps;

export function OrganizationsWorkspace(props: OrganizationsWorkspaceProps) {
  return <OrganizationWorkspace {...props} />;
}
