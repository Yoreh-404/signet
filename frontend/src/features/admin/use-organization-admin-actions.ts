import { useCallback } from "react";
import type { Dispatch, FormEvent, MutableRefObject, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import { emptyOrganizationForm } from "../../lib/form-defaults";
import * as adminApi from "../../lib/api/admin";
import { normalizeDomain } from "../../lib/auth-flow";
import { splitList } from "../../lib/formatters";
import type { OrganizationFormState } from "../organizations/OrganizationWorkspace";

type Options = {
  organizationForm: OrganizationFormState;
  organizationMemberRoles: Record<string, string>;
  organizationMembersLoading: boolean;
  organizationMembersLoadId: MutableRefObject<number>;
  setOrganizationForm: Dispatch<SetStateAction<OrganizationFormState>>;
  setOrganizationFormBaseline: Dispatch<SetStateAction<OrganizationFormState | null>>;
  setOrganizationMemberRoles: Dispatch<SetStateAction<Record<string, string>>>;
  setOrganizationMemberRolesBaseline: Dispatch<SetStateAction<Record<string, string> | null>>;
  setOrganizationMembersLoading: Dispatch<SetStateAction<boolean>>;
  setEditor: (editor: "organization" | null) => void;
  runUiAction: (action: () => Promise<void>, fallback?: TranslationKey) => Promise<boolean>;
  loadAdminData: () => Promise<void>;
  setVerificationMessage: (message: string) => void;
  changesSavedMessage: string;
};

export function useOrganizationAdminActions({
  organizationForm,
  organizationMemberRoles,
  organizationMembersLoading,
  organizationMembersLoadId,
  setOrganizationForm,
  setOrganizationFormBaseline,
  setOrganizationMemberRoles,
  setOrganizationMemberRolesBaseline,
  setOrganizationMembersLoading,
  setEditor,
  runUiAction,
  loadAdminData,
  setVerificationMessage,
  changesSavedMessage
}: Options) {
  const saveOrganization = useCallback(async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (organizationMembersLoading) return;
    await runUiAction(async () => {
      const body = {
        slug: organizationForm.slug,
        name: organizationForm.name,
        description: organizationForm.description || null,
        allowed_email_domains: splitList(organizationForm.allowed_email_domains).map(normalizeDomain),
        is_active: organizationForm.is_active
      };
      const organization = organizationForm.id
        ? await adminApi.updateAdminOrganization(organizationForm.id, body)
        : await adminApi.createAdminOrganization(body);
      await adminApi.replaceAdminOrganizationMembers(organization.id, {
        members: Object.entries(organizationMemberRoles).map(([user_id, role]) => ({ user_id, role }))
      });
      organizationMembersLoadId.current += 1;
      setOrganizationForm(emptyOrganizationForm);
      setOrganizationFormBaseline(null);
      setOrganizationMemberRolesBaseline(null);
      setOrganizationMemberRoles({});
      setOrganizationMembersLoading(false);
      setEditor(null);
      setVerificationMessage(changesSavedMessage);
      await loadAdminData();
    }, "saveOrganizationFailed");
  }, [
    changesSavedMessage,
    loadAdminData,
    organizationForm,
    organizationMemberRoles,
    organizationMembersLoadId,
    organizationMembersLoading,
    runUiAction,
    setEditor,
    setOrganizationForm,
    setOrganizationFormBaseline,
    setOrganizationMemberRoles,
    setOrganizationMemberRolesBaseline,
    setOrganizationMembersLoading,
    setVerificationMessage
  ]);

  const deleteOrganization = useCallback(async (id: string) => {
    await runUiAction(async () => {
      await adminApi.deleteAdminOrganization(id);
      if (organizationForm.id === id) {
        organizationMembersLoadId.current += 1;
        setOrganizationForm(emptyOrganizationForm);
        setOrganizationFormBaseline(null);
        setOrganizationMemberRoles({});
        setOrganizationMemberRolesBaseline(null);
        setOrganizationMembersLoading(false);
      }
      await loadAdminData();
    });
  }, [
    loadAdminData,
    organizationForm.id,
    organizationMembersLoadId,
    runUiAction,
    setOrganizationForm,
    setOrganizationFormBaseline,
    setOrganizationMemberRoles,
    setOrganizationMemberRolesBaseline,
    setOrganizationMembersLoading
  ]);

  return { saveOrganization, deleteOrganization };
}
