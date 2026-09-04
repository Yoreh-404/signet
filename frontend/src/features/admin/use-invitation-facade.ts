import type { Dispatch, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import { emptyInvitationForm } from "../../lib/form-defaults";
import type { Invitation, Tab, User } from "../../types";
import { useInvitationActions } from "./use-invitation-actions";

type InvitationForm = typeof emptyInvitationForm;
type RunCopyText = (value: string, copiedKey: TranslationKey, unavailableKey: TranslationKey) => Promise<void>;

export type InvitationFacadeOptions = {
  form: {
    value: InvitationForm;
    setValue: Dispatch<SetStateAction<InvitationForm>>;
    setBaseline: Dispatch<SetStateAction<InvitationForm | null>>;
    setLastCode: Dispatch<SetStateAction<string>>;
    setEditor: (editor: "invitation" | null) => void;
  };
  reveal: {
    setInvitation: Dispatch<SetStateAction<Invitation | null>>;
    setCode: Dispatch<SetStateAction<string>>;
    setLoadingId: Dispatch<SetStateAction<string>>;
    setError: Dispatch<SetStateAction<string>>;
  };
  authorization: {
    canManageOrganizations: boolean;
    user: User | null;
  };
  admin: {
    setBusy: Dispatch<SetStateAction<boolean>>;
    setError: Dispatch<SetStateAction<string>>;
    loadAdminData: (tab?: Tab, options?: { force?: boolean }) => Promise<void>;
  };
  ui: {
    copyText: RunCopyText;
    translate: (key: TranslationKey) => string;
    formatError: (error: unknown, fallback: TranslationKey) => string;
  };
};

export function useInvitationFacade({
  form,
  reveal,
  authorization,
  admin,
  ui
}: InvitationFacadeOptions) {
  return useInvitationActions({
    invitationForm: form.value,
    setInvitationForm: form.setValue,
    setInvitationFormBaseline: form.setBaseline,
    setLastInvitationCode: form.setLastCode,
    setEditor: form.setEditor,
    setRevealedInvitation: reveal.setInvitation,
    setRevealedInvitationCode: reveal.setCode,
    setRevealingInvitationId: reveal.setLoadingId,
    setInvitationRevealError: reveal.setError,
    canManageOrganizations: authorization.canManageOrganizations,
    user: authorization.user,
    setBusy: admin.setBusy,
    setError: admin.setError,
    loadAdminData: admin.loadAdminData,
    copyText: ui.copyText,
    translate: ui.translate,
    formatError: ui.formatError
  });
}
