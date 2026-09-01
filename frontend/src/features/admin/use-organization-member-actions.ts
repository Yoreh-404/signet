import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";
import type {
  Invitation,
  OrganizationMember,
  OrganizationMemberInvitationCreateResponse,
  OrganizationMemberRole,
} from "../../types";
import type { TranslationKey } from "../../i18n";
import * as adminApi from "../../lib/api/admin";

export type OrganizationMemberInvitationForm = {
  email: string;
  display_name: string;
  description: string;
  expires_at: string;
  organization_role: OrganizationMemberRole;
  is_active: boolean;
};

type Options = {
  organizationContext: { id: string } | null;
  enterpriseMemberEmail: string;
  enterpriseMemberRole: OrganizationMemberRole;
  setEnterpriseMemberEmail: Dispatch<SetStateAction<string>>;
  setEnterpriseMemberRole: Dispatch<SetStateAction<OrganizationMemberRole>>;
  setOrganizationMembers: Dispatch<SetStateAction<OrganizationMember[]>>;
  organizationMemberInvitationForm: OrganizationMemberInvitationForm;
  setOrganizationMemberInvitationForm: Dispatch<
    SetStateAction<OrganizationMemberInvitationForm>
  >;
  setOrganizationMemberInvitations: Dispatch<SetStateAction<Invitation[]>>;
  setRevealedOrganizationMemberInvitation: Dispatch<
    SetStateAction<OrganizationMemberInvitationCreateResponse | null>
  >;
  setBusy: (busy: boolean) => void;
  setError: (error: string) => void;
  setVerificationMessage: (message: string) => void;
  messageOr: (error: unknown, fallback: TranslationKey) => string;
  translate: (key: TranslationKey) => string;
  toTimestamp: (value: string) => number | null;
};

export function useOrganizationMemberActions({
  organizationContext,
  enterpriseMemberEmail,
  enterpriseMemberRole,
  setEnterpriseMemberEmail,
  setEnterpriseMemberRole,
  setOrganizationMembers,
  organizationMemberInvitationForm,
  setOrganizationMemberInvitationForm,
  setOrganizationMemberInvitations,
  setRevealedOrganizationMemberInvitation,
  setBusy,
  setError,
  setVerificationMessage,
  messageOr,
  translate,
  toTimestamp,
}: Options) {
  const addEnterpriseMember = useCallback(async () => {
    if (!organizationContext || !enterpriseMemberEmail.trim()) return;
    setBusy(true);
    setError("");
    try {
      await adminApi.addAdminOrganizationMember(organizationContext.id, {
        email: enterpriseMemberEmail.trim(),
        role: enterpriseMemberRole,
      });
      setOrganizationMembers(
        await adminApi.listAdminOrganizationMembers(organizationContext.id),
      );
      setEnterpriseMemberEmail("");
      setEnterpriseMemberRole("member");
      setVerificationMessage(translate("operationCompleted"));
    } catch (error) {
      setError(messageOr(error, "operationFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    enterpriseMemberEmail,
    enterpriseMemberRole,
    messageOr,
    organizationContext,
    setBusy,
    setEnterpriseMemberEmail,
    setEnterpriseMemberRole,
    setError,
    setOrganizationMembers,
    setVerificationMessage,
    translate,
  ]);

  const createOrganizationMemberInvitation = useCallback(async () => {
    if (!organizationContext) return;
    const expiresAt = toTimestamp(organizationMemberInvitationForm.expires_at);
    if (!organizationMemberInvitationForm.email.trim() || expiresAt === null) {
      setError(translate("organizationMemberInvitationValidation"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      const created = await adminApi.createAdminOrganizationInvitation(
        organizationContext.id,
        {
          email: organizationMemberInvitationForm.email.trim(),
          display_name: organizationMemberInvitationForm.display_name || null,
          description: organizationMemberInvitationForm.description || null,
          expires_at: expiresAt,
          organization_role: organizationMemberInvitationForm.organization_role,
          is_active: organizationMemberInvitationForm.is_active,
        },
      );
      setOrganizationMemberInvitations((current) => [
        created.invitation,
        ...current,
      ]);
      setRevealedOrganizationMemberInvitation(created);
      setOrganizationMemberInvitationForm({
        email: "",
        display_name: "",
        description: "",
        expires_at: "",
        organization_role: "member",
        is_active: true,
      });
      setVerificationMessage(translate("organizationMemberInvitationCreated"));
    } catch (error) {
      setError(messageOr(error, "operationFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    messageOr,
    organizationContext,
    organizationMemberInvitationForm,
    setBusy,
    setError,
    setOrganizationMemberInvitationForm,
    setOrganizationMemberInvitations,
    setRevealedOrganizationMemberInvitation,
    setVerificationMessage,
    toTimestamp,
    translate,
  ]);

  const deleteOrganizationMemberInvitation = useCallback(
    async (invitationId: string) => {
      if (!organizationContext) return;
      await adminApi.deleteAdminOrganizationInvitation(
        organizationContext.id,
        invitationId,
      );
      setOrganizationMemberInvitations((current) =>
        current.filter((invitation) => invitation.id !== invitationId),
      );
      setRevealedOrganizationMemberInvitation((current) =>
        current?.invitation.id === invitationId ? null : current,
      );
    },
    [
      organizationContext,
      setOrganizationMemberInvitations,
      setRevealedOrganizationMemberInvitation,
    ],
  );

  return {
    addEnterpriseMember,
    createOrganizationMemberInvitation,
    deleteOrganizationMemberInvitation,
  };
}
