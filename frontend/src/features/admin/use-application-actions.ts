import { useCallback } from "react";
import type { Dispatch, FormEvent, MutableRefObject, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import { ApiError } from "../../lib/api";
import * as applicationApi from "../../lib/api/applications";
import { emptyApplicationForm } from "../../lib/form-defaults";
import type { ApplicationSection, Tab, TenantApplication } from "../../types";
import {
  toApplicationForm,
  toApplicationPayload
} from "../applications/form-adapters";

type ApplicationForm = typeof emptyApplicationForm;

type CreateMutation = { fingerprint: string; key: string } | null;
type DeleteMutation = {
  applicationId: string;
  organizationId: string | null;
  scopeKey: string | null;
  key: string;
} | null;

type Options = {
  applicationForm: ApplicationForm;
  setApplicationForm: Dispatch<SetStateAction<ApplicationForm>>;
  setApplicationFormBaseline: Dispatch<SetStateAction<ApplicationForm | null>>;
  applications: TenantApplication[];
  setApplications: Dispatch<SetStateAction<TenantApplication[]>>;
  applicationCreateMutationRef: MutableRefObject<CreateMutation>;
  applicationDeleteMutationRef: MutableRefObject<DeleteMutation>;
  organizationId: string | null;
  scopeKey: string | null;
  applicationNavigationId: string | null;
  openEditor: () => void;
  closeEditor: () => void;
  navigateToTab: (tab: Tab, options?: { applicationId?: string | null; applicationSection?: ApplicationSection | null }) => boolean;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  setVerificationMessage: Dispatch<SetStateAction<string>>;
  loadAdminData: (tab?: Tab, options?: { force?: boolean }) => Promise<void>;
  translate: (key: TranslationKey) => string;
  formatError: (error: unknown, fallback: TranslationKey) => string;
};

function mutationKey(prefix: string): string {
  return `${prefix}-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;
}

export function useApplicationActions({
  applicationForm,
  setApplicationForm,
  setApplicationFormBaseline,
  applications,
  setApplications,
  applicationCreateMutationRef,
  applicationDeleteMutationRef,
  organizationId,
  scopeKey,
  applicationNavigationId,
  openEditor,
  closeEditor,
  navigateToTab,
  setBusy,
  setError,
  setVerificationMessage,
  loadAdminData,
  translate,
  formatError
}: Options) {
  const openCreateApplication = useCallback(() => {
    applicationCreateMutationRef.current = null;
    setApplicationForm(emptyApplicationForm);
    setApplicationFormBaseline(emptyApplicationForm);
    openEditor();
  }, [applicationCreateMutationRef, openEditor, setApplicationForm, setApplicationFormBaseline]);

  const editApplication = useCallback((application: TenantApplication) => {
    const nextForm = toApplicationForm(application);
    setApplicationForm(nextForm);
    setApplicationFormBaseline(nextForm);
    openEditor();
  }, [openEditor, setApplicationForm, setApplicationFormBaseline]);

  const saveApplication = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    const creatingApplication = !applicationForm.id;
    setBusy(true);
    setError("");
    try {
      const input = toApplicationPayload(applicationForm);
      let application: TenantApplication;
      if (applicationForm.id) {
        application = await applicationApi.updateApplication(applicationForm.id, input);
        const currentProtocolModule = application.modules?.find((module) => module.module_key === "protocols");
        const currentProtocolConfig = currentProtocolModule?.config ?? {};
        await applicationApi.updateApplicationModule(application.id, "protocols", {
          config: {
            ...(currentProtocolConfig && typeof currentProtocolConfig === "object" ? currentProtocolConfig : {}),
            website_url: applicationForm.website_url
          },
          is_enabled: currentProtocolModule?.is_enabled ?? Boolean(application.client_bindings.length)
        });
      } else {
        const fingerprint = JSON.stringify(input);
        const existingMutation = applicationCreateMutationRef.current;
        const idempotencyKey = existingMutation?.fingerprint === fingerprint
          ? existingMutation.key
          : mutationKey("ui-application-create");
        applicationCreateMutationRef.current = { fingerprint, key: idempotencyKey };
        application = await applicationApi.createApplication(input, { idempotencyKey });
        applicationCreateMutationRef.current = null;
        setApplicationForm((current) => ({ ...current, id: application.id }));
      }
      setApplicationForm(emptyApplicationForm);
      setApplicationFormBaseline(null);
      closeEditor();
      setVerificationMessage(translate("changesSaved"));
      await loadAdminData("applications", { force: true });
    } catch (error) {
      if (
        creatingApplication
        && error instanceof ApiError
        && (error.code === "network_error" || error.status >= 500)
      ) {
        try {
          const recoveredApplications = await applicationApi.listApplications({ force: true });
          const recovered = recoveredApplications.find((candidate) => (
            candidate.organization_id === organizationId
            && candidate.slug === applicationForm.slug.trim()
            && candidate.name === applicationForm.name.trim()
          ));
          if (recovered) setApplicationForm((current) => ({ ...current, id: recovered.id }));
        } catch {
        }
      }
      try {
        await loadAdminData("applications", { force: true });
      } catch {
      }
      setError(formatError(error, "saveApplicationFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    applicationCreateMutationRef,
    applicationForm,
    closeEditor,
    formatError,
    loadAdminData,
    organizationId,
    setApplicationForm,
    setApplicationFormBaseline,
    setBusy,
    setError,
    setVerificationMessage,
    translate
  ]);

  const deleteApplication = useCallback(async (id: string) => {
    const target = applications.find((application) => application.id === id);
    if (target && organizationId && target.organization_id !== organizationId) {
      throw new Error("application does not belong to the active organization");
    }
    const existingMutation = applicationDeleteMutationRef.current;
    const idempotencyKey = existingMutation
      && existingMutation.applicationId === id
      && existingMutation.organizationId === organizationId
      && existingMutation.scopeKey === scopeKey
      ? existingMutation.key
      : mutationKey("ui-application-delete");
    applicationDeleteMutationRef.current = { applicationId: id, organizationId, scopeKey, key: idempotencyKey };

    const clearDeletedApplication = () => {
      setApplications((current) => current.filter((application) => application.id !== id));
      if (applicationForm.id === id) {
        setApplicationForm(emptyApplicationForm);
        setApplicationFormBaseline(null);
        closeEditor();
      }
      if (applicationNavigationId === id) {
        navigateToTab("applications", { applicationId: null, applicationSection: null });
      }
    };

    try {
      await applicationApi.deleteApplication(id, { idempotencyKey });
      clearDeletedApplication();
      await loadAdminData("applications", { force: true });
      applicationDeleteMutationRef.current = null;
    } catch (error) {
      try {
        const recovered = await applicationApi.listApplications({ force: true });
        setApplications(recovered);
        if (!recovered.some((application) => application.id === id)) {
          clearDeletedApplication();
          applicationDeleteMutationRef.current = null;
          return;
        }
      } catch {
      }
      throw error;
    }
  }, [
    applicationDeleteMutationRef,
    applicationForm.id,
    applicationNavigationId,
    applications,
    closeEditor,
    loadAdminData,
    navigateToTab,
    organizationId,
    scopeKey,
    setApplicationForm,
    setApplicationFormBaseline,
    setApplications
  ]);

  return { openCreateApplication, editApplication, saveApplication, deleteApplication };
}
