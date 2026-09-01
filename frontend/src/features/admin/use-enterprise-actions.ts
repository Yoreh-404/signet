import { useCallback } from "react";
import type { Dispatch, FormEvent, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import { api } from "../../lib/api";
import { emptyEnterpriseForm } from "../../lib/form-defaults";
import { splitList } from "../../lib/formatters";
import { normalizeDomain } from "../../lib/auth-flow";
import type { Organization, Tab } from "../../types";

type EnterpriseForm = typeof emptyEnterpriseForm;

type Options = {
  enterpriseForm: EnterpriseForm;
  setEnterpriseForm: Dispatch<SetStateAction<EnterpriseForm>>;
  setEnterpriseFormBaseline: Dispatch<SetStateAction<EnterpriseForm | null>>;
  currentOrganizationId: string | null;
  currentUserId: string | null;
  formsDirty: boolean;
  confirmDiscard: () => boolean;
  switchOrganization: (organizationId: string) => Promise<unknown>;
  clearScopedData: () => void;
  loadOrganizationContext: (userId?: string) => Promise<unknown>;
  navigateToTab: (tab: Tab) => boolean;
  setEditor: (editor: "enterprise" | null) => void;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  setVerificationMessage: Dispatch<SetStateAction<string>>;
  translate: (key: TranslationKey) => string;
  formatError: (error: unknown, fallback: TranslationKey) => string;
};

export function useEnterpriseActions({
  enterpriseForm,
  setEnterpriseForm,
  setEnterpriseFormBaseline,
  currentOrganizationId,
  currentUserId,
  formsDirty,
  confirmDiscard,
  switchOrganization,
  clearScopedData,
  loadOrganizationContext,
  navigateToTab,
  setEditor,
  setBusy,
  setError,
  setVerificationMessage,
  translate,
  formatError
}: Options) {
  const switchEnterprise = useCallback(async (organizationId: string) => {
    if (!organizationId || organizationId === currentOrganizationId) return;
    if (formsDirty && !confirmDiscard()) return;
    setBusy(true);
    setError("");
    try {
      await switchOrganization(organizationId);
      clearScopedData();
      setVerificationMessage(translate("operationCompleted"));
    } catch (error) {
      setError(formatError(error, "operationFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    clearScopedData,
    confirmDiscard,
    currentOrganizationId,
    formatError,
    formsDirty,
    setBusy,
    setError,
    setVerificationMessage,
    switchOrganization,
    translate
  ]);

  const saveEnterprise = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api<Organization>("/api/me/organizations", {
        method: "POST",
        body: JSON.stringify({
          slug: enterpriseForm.slug,
          name: enterpriseForm.name,
          description: enterpriseForm.description || null,
          allowed_email_domains: splitList(enterpriseForm.allowed_email_domains).map(normalizeDomain)
        })
      });
      setEnterpriseForm(emptyEnterpriseForm);
      setEnterpriseFormBaseline(null);
      setEditor(null);
      await loadOrganizationContext(currentUserId ?? undefined);
      setVerificationMessage(translate("changesSaved"));
      navigateToTab("applications");
    } catch (error) {
      setError(formatError(error, "saveOrganizationFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    currentUserId,
    enterpriseForm,
    formatError,
    loadOrganizationContext,
    navigateToTab,
    setBusy,
    setEditor,
    setEnterpriseForm,
    setEnterpriseFormBaseline,
    setError,
    setVerificationMessage,
    translate
  ]);

  return { switchEnterprise, saveEnterprise };
}
