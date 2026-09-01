import { useCallback } from "react";
import type { Dispatch, MutableRefObject, SetStateAction } from "react";
import type { TranslationKey } from "../../i18n";
import { emptyOrganizationForm } from "../../lib/form-defaults";
import * as adminApi from "../../lib/api/admin";
import type { Organization, OrganizationMemberRole } from "../../types";

type OrganizationFormState = typeof emptyOrganizationForm;

type Options = {
  organizationMembersLoadId: MutableRefObject<number>;
  setOrganizationForm: Dispatch<SetStateAction<OrganizationFormState>>;
  setOrganizationFormBaseline: Dispatch<SetStateAction<OrganizationFormState | null>>;
  setOrganizationMemberRoles: Dispatch<SetStateAction<Record<string, string>>>;
  setOrganizationMemberRolesBaseline: Dispatch<SetStateAction<Record<string, string> | null>>;
  setOrganizationMembersLoading: Dispatch<SetStateAction<boolean>>;
  openOrganizationEditor: () => void;
  setError: (error: string) => void;
  messageOr: (error: unknown, fallback: TranslationKey) => string;
};

export function useOrganizationEditorActions({
  organizationMembersLoadId,
  setOrganizationForm,
  setOrganizationFormBaseline,
  setOrganizationMemberRoles,
  setOrganizationMemberRolesBaseline,
  setOrganizationMembersLoading,
  openOrganizationEditor,
  setError,
  messageOr
}: Options) {
  const createOrganization = useCallback(() => {
    organizationMembersLoadId.current += 1;
    setOrganizationForm(emptyOrganizationForm);
    setOrganizationFormBaseline(emptyOrganizationForm);
    setOrganizationMemberRoles({});
    setOrganizationMemberRolesBaseline({});
    setOrganizationMembersLoading(false);
    openOrganizationEditor();
  }, [
    openOrganizationEditor,
    organizationMembersLoadId,
    setOrganizationForm,
    setOrganizationFormBaseline,
    setOrganizationMemberRoles,
    setOrganizationMemberRolesBaseline,
    setOrganizationMembersLoading
  ]);

  const editOrganization = useCallback(async (organization: Organization) => {
    const loadId = ++organizationMembersLoadId.current;
    const nextForm = {
      id: organization.id,
      slug: organization.slug,
      name: organization.name,
      description: organization.description ?? "",
      allowed_email_domains: organization.allowed_email_domains.join("\n"),
      is_active: organization.is_active
    };
    setOrganizationForm(nextForm);
    setOrganizationFormBaseline(nextForm);
    setOrganizationMemberRoles({});
    setOrganizationMemberRolesBaseline(null);
    setOrganizationMembersLoading(true);
    openOrganizationEditor();
    try {
      const members = await adminApi.listAdminOrganizationMembers(organization.id);
      if (loadId !== organizationMembersLoadId.current) return;
      const nextRoles = Object.fromEntries(members.map((member) => [member.user_id, member.role]));
      setOrganizationMemberRoles(nextRoles);
      setOrganizationMemberRolesBaseline(nextRoles);
    } catch (error) {
      if (loadId === organizationMembersLoadId.current) {
        setError(messageOr(error, "loadFailed"));
      }
    } finally {
      if (loadId === organizationMembersLoadId.current) {
        setOrganizationMembersLoading(false);
      }
    }
  }, [
    messageOr,
    openOrganizationEditor,
    organizationMembersLoadId,
    setError,
    setOrganizationForm,
    setOrganizationFormBaseline,
    setOrganizationMemberRoles,
    setOrganizationMemberRolesBaseline,
    setOrganizationMembersLoading
  ]);

  const setOrganizationMemberRole = useCallback((userId: string, role: string | null) => {
    setOrganizationMemberRoles((current) => {
      const next = { ...current };
      if (role) next[userId] = role;
      else delete next[userId];
      return next;
    });
  }, [setOrganizationMemberRoles]);

  return { createOrganization, editOrganization, setOrganizationMemberRole };
}
