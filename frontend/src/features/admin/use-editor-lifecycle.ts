import { useCallback } from "react";
import type { Dispatch, MutableRefObject, SetStateAction } from "react";

import { emptyApplicationForm, emptyGroupForm, emptyInvitationForm, emptyLdapProviderForm, emptyOrganizationForm, emptyProviderForm, emptyRoleForm, emptyUserForm } from "../../lib/form-defaults";
import type { AdminEditor } from "./use-settings-controller";

type EnterpriseFormState = {
  slug: string;
  name: string;
  description: string;
  allowed_email_domains: string;
};

const emptyEnterpriseForm: EnterpriseFormState = {
  slug: "",
  name: "",
  description: "",
  allowed_email_domains: ""
};

type ApplicationMutationRef = MutableRefObject<{ fingerprint: string; key: string } | null>;
type ApplicationDeleteMutationRef = MutableRefObject<{
  applicationId: string;
  organizationId: string | null;
  scopeKey: string | null;
  key: string;
} | null>;

type Options = {
  editor: AdminEditor;
  editorDirty: boolean;
  confirmDiscard: () => boolean;
  setEditor: Dispatch<SetStateAction<AdminEditor>>;
  setError: Dispatch<SetStateAction<string>>;
  organizationMembersLoadId: MutableRefObject<number>;
  setOrganizationMembersLoading: Dispatch<SetStateAction<boolean>>;
  setUserForm: Dispatch<SetStateAction<typeof emptyUserForm>>;
  setUserFormBaseline: Dispatch<SetStateAction<typeof emptyUserForm | null>>;
  setEnterpriseForm: Dispatch<SetStateAction<EnterpriseFormState>>;
  setEnterpriseFormBaseline: Dispatch<SetStateAction<EnterpriseFormState | null>>;
  setOrganizationForm: Dispatch<SetStateAction<typeof emptyOrganizationForm>>;
  setOrganizationFormBaseline: Dispatch<SetStateAction<typeof emptyOrganizationForm | null>>;
  setOrganizationMemberRoles: Dispatch<SetStateAction<Record<string, string>>>;
  setOrganizationMemberRolesBaseline: Dispatch<SetStateAction<Record<string, string> | null>>;
  applicationCreateMutationRef: ApplicationMutationRef;
  applicationDeleteMutationRef: ApplicationDeleteMutationRef;
  setApplicationForm: Dispatch<SetStateAction<typeof emptyApplicationForm>>;
  setApplicationFormBaseline: Dispatch<SetStateAction<typeof emptyApplicationForm | null>>;
  setProviderForm: Dispatch<SetStateAction<typeof emptyProviderForm>>;
  setProviderFormBaseline: Dispatch<SetStateAction<typeof emptyProviderForm | null>>;
  setProviderTemplateId: Dispatch<SetStateAction<string>>;
  providerDiscoveryRequest: { cancel: () => void };
  setLdapProviderForm: Dispatch<SetStateAction<typeof emptyLdapProviderForm>>;
  setLdapProviderFormBaseline: Dispatch<SetStateAction<typeof emptyLdapProviderForm | null>>;
  setInvitationForm: Dispatch<SetStateAction<typeof emptyInvitationForm>>;
  setInvitationFormBaseline: Dispatch<SetStateAction<typeof emptyInvitationForm | null>>;
  setLastInvitationCode: Dispatch<SetStateAction<string>>;
  setRoleForm: Dispatch<SetStateAction<typeof emptyRoleForm>>;
  setRoleFormBaseline: Dispatch<SetStateAction<typeof emptyRoleForm | null>>;
  setGroupForm: Dispatch<SetStateAction<typeof emptyGroupForm>>;
  setGroupFormBaseline: Dispatch<SetStateAction<typeof emptyGroupForm | null>>;
};

export function useEditorLifecycle({
  editor,
  editorDirty,
  confirmDiscard,
  setEditor,
  setError,
  organizationMembersLoadId,
  setOrganizationMembersLoading,
  setUserForm,
  setUserFormBaseline,
  setEnterpriseForm,
  setEnterpriseFormBaseline,
  setOrganizationForm,
  setOrganizationFormBaseline,
  setOrganizationMemberRoles,
  setOrganizationMemberRolesBaseline,
  applicationCreateMutationRef,
  applicationDeleteMutationRef,
  setApplicationForm,
  setApplicationFormBaseline,
  setProviderForm,
  setProviderFormBaseline,
  setProviderTemplateId,
  providerDiscoveryRequest,
  setLdapProviderForm,
  setLdapProviderFormBaseline,
  setInvitationForm,
  setInvitationFormBaseline,
  setLastInvitationCode,
  setRoleForm,
  setRoleFormBaseline,
  setGroupForm,
  setGroupFormBaseline
}: Options) {
  return useCallback((force = false): boolean => {
    if (!force && editorDirty && !confirmDiscard()) return false;

    switch (editor) {
      case "user":
        setUserForm(emptyUserForm);
        setUserFormBaseline(null);
        break;
      case "enterprise":
        setEnterpriseForm(emptyEnterpriseForm);
        setEnterpriseFormBaseline(null);
        break;
      case "organization":
        organizationMembersLoadId.current += 1;
        setOrganizationMembersLoading(false);
        setOrganizationForm(emptyOrganizationForm);
        setOrganizationFormBaseline(null);
        setOrganizationMemberRoles({});
        setOrganizationMemberRolesBaseline(null);
        break;
      case "application":
        applicationCreateMutationRef.current = null;
        applicationDeleteMutationRef.current = null;
        setApplicationForm(emptyApplicationForm);
        setApplicationFormBaseline(null);
        break;
      case "provider":
        setProviderForm(emptyProviderForm);
        setProviderFormBaseline(null);
        setProviderTemplateId("");
        providerDiscoveryRequest.cancel();
        break;
      case "ldap":
        setLdapProviderForm(emptyLdapProviderForm);
        setLdapProviderFormBaseline(null);
        break;
      case "invitation":
        setInvitationForm(emptyInvitationForm);
        setInvitationFormBaseline(null);
        setLastInvitationCode("");
        break;
      case "role":
        setRoleForm(emptyRoleForm);
        setRoleFormBaseline(null);
        break;
      case "group":
        setGroupForm(emptyGroupForm);
        setGroupFormBaseline(null);
        break;
      case null:
        break;
    }
    setEditor(null);
    setError("");
    return true;
  }, [
    applicationCreateMutationRef,
    applicationDeleteMutationRef,
    confirmDiscard,
    editor,
    editorDirty,
    organizationMembersLoadId,
    providerDiscoveryRequest,
    setApplicationForm,
    setApplicationFormBaseline,
    setEditor,
    setEnterpriseForm,
    setEnterpriseFormBaseline,
    setError,
    setGroupForm,
    setGroupFormBaseline,
    setInvitationForm,
    setInvitationFormBaseline,
    setLastInvitationCode,
    setLdapProviderForm,
    setLdapProviderFormBaseline,
    setOrganizationForm,
    setOrganizationFormBaseline,
    setOrganizationMemberRoles,
    setOrganizationMemberRolesBaseline,
    setOrganizationMembersLoading,
    setProviderForm,
    setProviderFormBaseline,
    setProviderTemplateId,
    setRoleForm,
    setRoleFormBaseline,
    setUserForm,
    setUserFormBaseline
  ]);
}
