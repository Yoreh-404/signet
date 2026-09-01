import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";

import * as adminApi from "../../lib/api/admin";
import { normalizeDomain } from "../../lib/auth-flow";
import { createQuickLinkId } from "../../lib/form-defaults";
import { emptyQuickLinkForm } from "../../lib/form-defaults";
import { splitList } from "../../lib/formatters";
import type { LoginSettings, LoginSettingsDraft, QuickLink } from "../../types";

type Options = {
  loginSettingsDraft: LoginSettingsDraft;
  quickLinkForm: typeof emptyQuickLinkForm;
  setLoginSettings: Dispatch<SetStateAction<LoginSettings | null>>;
  setLoginSettingsDraft: Dispatch<SetStateAction<LoginSettingsDraft>>;
  setLoginSettingsBaseline: Dispatch<SetStateAction<LoginSettingsDraft | null>>;
  setQuickLinkForm: Dispatch<SetStateAction<typeof emptyQuickLinkForm>>;
  setQuickLinkFormBaseline: Dispatch<SetStateAction<typeof emptyQuickLinkForm>>;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  setVerificationMessage: Dispatch<SetStateAction<string>>;
  loadBootstrap: () => Promise<void>;
  messageOr: (error: unknown, fallback: "saveLoginSettingsFailed") => string;
  changesSavedMessage: string;
  saveLoginSettingsFailedMessage: string;
};

export function useLoginSettingsActions({
  loginSettingsDraft,
  quickLinkForm,
  setLoginSettings,
  setLoginSettingsDraft,
  setLoginSettingsBaseline,
  setQuickLinkForm,
  setQuickLinkFormBaseline,
  setBusy,
  setError,
  setVerificationMessage,
  loadBootstrap,
  messageOr,
  changesSavedMessage,
  saveLoginSettingsFailedMessage
}: Options) {
  const persistLoginSettings = useCallback(async (draft: LoginSettingsDraft) => {
    setBusy(true);
    setError("");
    try {
      const updated = await adminApi.updateAdminLoginSettings({
        brand_logo_url: draft.brand_logo_url,
        email_domains: splitList(draft.email_domains).map(normalizeDomain),
        quick_links: draft.quick_links
      });
      const nextDraft = {
        brand_logo_url: updated.brand_logo_url,
        email_domains: updated.email_domains.join("\n"),
        quick_links: updated.quick_links
      };
      setLoginSettings(updated);
      setLoginSettingsDraft(nextDraft);
      setLoginSettingsBaseline(nextDraft);
      setVerificationMessage(changesSavedMessage);
      await loadBootstrap();
      return true;
    } catch (error) {
      setError(messageOr(error, "saveLoginSettingsFailed"));
      return false;
    } finally {
      setBusy(false);
    }
  }, [
    changesSavedMessage,
    loadBootstrap,
    messageOr,
    setBusy,
    setError,
    setLoginSettings,
    setLoginSettingsBaseline,
    setLoginSettingsDraft,
    setVerificationMessage
  ]);

  const resetQuickLinkForm = useCallback(() => {
    const empty = { ...emptyQuickLinkForm };
    setQuickLinkForm(empty);
    setQuickLinkFormBaseline(empty);
  }, [setQuickLinkForm, setQuickLinkFormBaseline]);

  const saveQuickLinkDraft = useCallback(async () => {
    if (!quickLinkForm.label.trim() || !quickLinkForm.url.trim()) return;
    const link: QuickLink = {
      id: quickLinkForm.id || createQuickLinkId(),
      label: quickLinkForm.label.trim(),
      url: quickLinkForm.url.trim(),
      icon: "",
      is_active: quickLinkForm.is_active
    };
    const nextLinks = quickLinkForm.id
      ? loginSettingsDraft.quick_links.map((item) => (item.id === quickLinkForm.id ? link : item))
      : [...loginSettingsDraft.quick_links, link];
    if (await persistLoginSettings({ ...loginSettingsDraft, quick_links: nextLinks })) {
      resetQuickLinkForm();
    }
  }, [loginSettingsDraft, persistLoginSettings, quickLinkForm, resetQuickLinkForm]);

  const editQuickLink = useCallback((link: QuickLink) => {
    const nextForm = {
      id: link.id,
      label: link.label,
      url: link.url,
      is_active: link.is_active
    };
    setQuickLinkForm(nextForm);
    setQuickLinkFormBaseline(nextForm);
  }, [setQuickLinkForm, setQuickLinkFormBaseline]);

  const removeQuickLink = useCallback(async (id: string) => {
    const saved = await persistLoginSettings({
      ...loginSettingsDraft,
      quick_links: loginSettingsDraft.quick_links.filter((item) => item.id !== id)
    });
    if (saved && quickLinkForm.id === id) resetQuickLinkForm();
    if (!saved) throw new Error(saveLoginSettingsFailedMessage);
  }, [
    loginSettingsDraft,
    persistLoginSettings,
    quickLinkForm.id,
    resetQuickLinkForm,
    saveLoginSettingsFailedMessage
  ]);

  return {
    persistLoginSettings,
    resetQuickLinkForm,
    saveQuickLinkDraft,
    editQuickLink,
    removeQuickLink
  };
}
