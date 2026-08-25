import { useRef, useState } from "react";
import { emptyOrganizationForm } from "../../lib/form-defaults";
import type {
  Invitation,
  Organization,
  OrganizationMember,
  OrganizationMemberInvitationCreateResponse,
  OrganizationMemberRole
} from "../../types";

export type EnterpriseFormState = {
  slug: string;
  name: string;
  description: string;
  allowed_email_domains: string;
};

export const emptyEnterpriseForm: EnterpriseFormState = {
  slug: "",
  name: "",
  description: "",
  allowed_email_domains: ""
};

/** Owns enterprise and organization editing state, including membership UI. */
export function useOrganizationController() {
  const [enterpriseForm, setEnterpriseForm] = useState<EnterpriseFormState>(emptyEnterpriseForm);
  const [enterpriseFormBaseline, setEnterpriseFormBaseline] = useState<EnterpriseFormState | null>(null);
  const [enterpriseMemberEmail, setEnterpriseMemberEmail] = useState("");
  const [enterpriseMemberRole, setEnterpriseMemberRole] = useState<OrganizationMemberRole>("member");
  const [organizationMemberInvitationForm, setOrganizationMemberInvitationForm] = useState({
    email: "",
    display_name: "",
    description: "",
    expires_at: "",
    organization_role: "member" as OrganizationMemberRole,
    is_active: true
  });
  const [revealedOrganizationMemberInvitation, setRevealedOrganizationMemberInvitation] = useState<OrganizationMemberInvitationCreateResponse | null>(null);
  const [organizationForm, setOrganizationForm] = useState(emptyOrganizationForm);
  const [organizationFormBaseline, setOrganizationFormBaseline] = useState<typeof emptyOrganizationForm | null>(null);
  const [organizationMemberRolesBaseline, setOrganizationMemberRolesBaseline] = useState<Record<string, string> | null>(null);
  const [organizationMemberRoles, setOrganizationMemberRoles] = useState<Record<string, string>>({});
  const [organizationMembers, setOrganizationMembers] = useState<OrganizationMember[]>([]);
  const [organizationMemberInvitations, setOrganizationMemberInvitations] = useState<Invitation[]>([]);
  const [organizationMembersLoading, setOrganizationMembersLoading] = useState(false);
  const organizationMembersLoadId = useRef(0);
  const [organizationsSnapshot, setOrganizationsSnapshot] = useState<Organization | null>(null);

  return {
    enterpriseForm,
    setEnterpriseForm,
    enterpriseFormBaseline,
    setEnterpriseFormBaseline,
    enterpriseMemberEmail,
    setEnterpriseMemberEmail,
    enterpriseMemberRole,
    setEnterpriseMemberRole,
    organizationMemberInvitationForm,
    setOrganizationMemberInvitationForm,
    revealedOrganizationMemberInvitation,
    setRevealedOrganizationMemberInvitation,
    organizationForm,
    setOrganizationForm,
    organizationFormBaseline,
    setOrganizationFormBaseline,
    organizationMemberRolesBaseline,
    setOrganizationMemberRolesBaseline,
    organizationMemberRoles,
    setOrganizationMemberRoles,
    organizationMembers,
    setOrganizationMembers,
    organizationMemberInvitations,
    setOrganizationMemberInvitations,
    organizationMembersLoading,
    setOrganizationMembersLoading,
    organizationMembersLoadId,
    organizationsSnapshot,
    setOrganizationsSnapshot
  };
}

export type OrganizationController = ReturnType<typeof useOrganizationController>;
