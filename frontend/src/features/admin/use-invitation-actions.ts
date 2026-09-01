import { useCallback } from "react";
import type { Dispatch, FormEvent, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import * as adminApi from "../../lib/api/admin";
import { emptyInvitationForm } from "../../lib/form-defaults";
import { toTimestamp } from "../../lib/formatters";
import { toInvitationForm } from "./form-adapters";
import type { Invitation, Tab, User } from "../../types";

type InvitationForm = typeof emptyInvitationForm;

type Options = {
  invitationForm: InvitationForm;
  setInvitationForm: Dispatch<SetStateAction<InvitationForm>>;
  setInvitationFormBaseline: Dispatch<SetStateAction<InvitationForm | null>>;
  setLastInvitationCode: Dispatch<SetStateAction<string>>;
  setEditor: (editor: "invitation" | null) => void;
  setRevealedInvitation: Dispatch<SetStateAction<Invitation | null>>;
  setRevealedInvitationCode: Dispatch<SetStateAction<string>>;
  setRevealingInvitationId: Dispatch<SetStateAction<string>>;
  setInvitationRevealError: Dispatch<SetStateAction<string>>;
  canManageOrganizations: boolean;
  user: User | null;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  loadAdminData: (tab?: Tab, options?: { force?: boolean }) => Promise<void>;
  copyText: (value: string, copiedKey: TranslationKey, unavailableKey: TranslationKey) => Promise<void>;
  translate: (key: TranslationKey) => string;
  formatError: (error: unknown, fallback: TranslationKey) => string;
};

export function useInvitationActions({
  invitationForm,
  setInvitationForm,
  setInvitationFormBaseline,
  setLastInvitationCode,
  setEditor,
  setRevealedInvitation,
  setRevealedInvitationCode,
  setRevealingInvitationId,
  setInvitationRevealError,
  canManageOrganizations,
  user,
  setBusy,
  setError,
  loadAdminData,
  copyText,
  translate,
  formatError
}: Options) {
  const openCreateInvitation = useCallback(() => {
    setInvitationForm(emptyInvitationForm);
    setInvitationFormBaseline(emptyInvitationForm);
    setLastInvitationCode("");
    setEditor("invitation");
  }, [setEditor, setInvitationForm, setInvitationFormBaseline, setLastInvitationCode]);

  const editInvitation = useCallback((invitation: Invitation) => {
    const nextForm = toInvitationForm(invitation);
    setInvitationForm(nextForm);
    setInvitationFormBaseline(nextForm);
    setLastInvitationCode("");
    setEditor("invitation");
  }, [setEditor, setInvitationForm, setInvitationFormBaseline, setLastInvitationCode]);

  const saveInvitation = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    const editingInvitation = Boolean(invitationForm.id);
    const isAccountRecoveryCode = invitationForm.code_type === "login"
      && invitationForm.login_code_level === "account_recovery";
    const isTrialEnrollmentCode = invitationForm.code_type === "login"
      && invitationForm.login_code_level === "trial_enrollment";
    const isAdminUniversalCode = invitationForm.code_type === "login"
      && invitationForm.login_code_level === "admin_universal";
    const isApplicationBoundLoginCode = isTrialEnrollmentCode || isAdminUniversalCode;
    if (isAccountRecoveryCode && !invitationForm.authorized_username.trim()) {
      setError(translate("loginCodeUsernameRequired"));
      return;
    }
    if (isAdminUniversalCode && !user?.is_admin) {
      setError(translate("adminUniversalCodeAdminOnly"));
      return;
    }
    if (isApplicationBoundLoginCode && invitationForm.allowed_client_ids.length === 0) {
      setError(translate(isTrialEnrollmentCode ? "trialEnrollmentApplicationsRequired" : "allowedApplicationsRequired"));
      return;
    }
    if (isTrialEnrollmentCode && !canManageOrganizations) {
      setError(translate("trialEnrollmentOrganizationManageRequired"));
      return;
    }
    if (isTrialEnrollmentCode && !invitationForm.organization_id) {
      setError(translate("trialEnrollmentOrganizationRequired"));
      return;
    }
    if (isTrialEnrollmentCode && !invitationForm.organization_role) {
      setError(translate("trialEnrollmentRoleRequired"));
      return;
    }
    if (isTrialEnrollmentCode && (!invitationForm.expires_at || !invitationForm.max_uses)) {
      setError(translate("trialEnrollmentLimitsRequired"));
      return;
    }
    setBusy(true);
    setError("");
    setLastInvitationCode("");
    try {
      const body = {
        code_type: invitationForm.code_type,
        login_code_level: invitationForm.code_type === "login" ? invitationForm.login_code_level : null,
        allowed_client_ids: isApplicationBoundLoginCode ? invitationForm.allowed_client_ids : [],
        organization_id: isTrialEnrollmentCode ? invitationForm.organization_id : null,
        organization_role: isTrialEnrollmentCode ? invitationForm.organization_role : null,
        description: invitationForm.description || null,
        authorized_email: invitationForm.code_type === "login" ? null : invitationForm.authorized_email || null,
        authorized_username: isApplicationBoundLoginCode ? null : invitationForm.authorized_username || null,
        authorized_display_name: invitationForm.code_type === "registration"
          ? invitationForm.authorized_display_name || null
          : null,
        expires_at: toTimestamp(invitationForm.expires_at),
        max_uses: invitationForm.max_uses ? Number(invitationForm.max_uses) : null,
        is_active: invitationForm.is_active
      };
      if (invitationForm.id) {
        await adminApi.updateAdminAuthorizationCode(invitationForm.id, body);
      } else {
        const result = await adminApi.createAdminAuthorizationCode(body);
        setLastInvitationCode(result.code);
      }
      setInvitationForm(emptyInvitationForm);
      setInvitationFormBaseline(null);
      setEditor(editingInvitation ? null : "invitation");
      await loadAdminData();
    } catch (error) {
      setError(formatError(error, "saveInvitationFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    canManageOrganizations,
    formatError,
    invitationForm,
    loadAdminData,
    setBusy,
    setEditor,
    setError,
    setInvitationForm,
    setInvitationFormBaseline,
    setLastInvitationCode,
    translate,
    user
  ]);

  const deleteInvitation = useCallback(async (id: string) => {
    await adminApi.deleteAdminAuthorizationCode(id);
    await loadAdminData();
  }, [loadAdminData]);

  const copyLastInvitationCode = useCallback(async (code: string) => {
    await copyText(code, "authorizationCodeCopied", "copyAuthorizationCodeUnavailable");
  }, [copyText]);

  const revealInvitationCode = useCallback(async (invitation: Invitation) => {
    if (!invitation.can_reveal) return;
    setRevealedInvitation(invitation);
    setRevealedInvitationCode("");
    setInvitationRevealError("");
    setRevealingInvitationId(invitation.id);
    try {
      const result = await adminApi.revealAdminAuthorizationCode(invitation.id);
      setRevealedInvitationCode(result.code);
    } catch (error) {
      setInvitationRevealError(formatError(error, "revealAuthorizationCodeFailed"));
    } finally {
      setRevealingInvitationId("");
    }
  }, [formatError, setInvitationRevealError, setRevealedInvitation, setRevealedInvitationCode, setRevealingInvitationId]);

  const closeInvitationReveal = useCallback(() => {
    setRevealedInvitation(null);
    setRevealedInvitationCode("");
    setInvitationRevealError("");
    setRevealingInvitationId("");
  }, [setInvitationRevealError, setRevealedInvitation, setRevealedInvitationCode, setRevealingInvitationId]);

  return {
    openCreateInvitation,
    editInvitation,
    saveInvitation,
    deleteInvitation,
    copyLastInvitationCode,
    revealInvitationCode,
    closeInvitationReveal
  };
}
