import { useCallback } from "react";
import type { Dispatch, FormEvent, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import * as adminApi from "../../lib/api/admin";
import { emptyLdapProviderForm, emptyProviderForm } from "../../lib/form-defaults";
import { joinList } from "../../lib/formatters";
import type { ExternalProviderTemplate, LdapProvider } from "../../types";
import {
  toExternalOidcProviderPayload,
  toLdapProviderForm,
  toLdapProviderPayload
} from "./form-adapters";
import type { AdminEditor } from "./use-settings-controller";
import type { LatestRequestToken } from "./use-latest-request";

type Options = {
  providerForm: typeof emptyProviderForm;
  providerTemplates: ExternalProviderTemplate[];
  providerTemplateId: string;
  setProviderForm: Dispatch<SetStateAction<typeof emptyProviderForm>>;
  setProviderFormBaseline: Dispatch<SetStateAction<typeof emptyProviderForm | null>>;
  providerDiscoveryRequest: {
    begin: () => LatestRequestToken;
    cancel: () => void;
  };
  ldapProviderForm: typeof emptyLdapProviderForm;
  setLdapProviderForm: Dispatch<SetStateAction<typeof emptyLdapProviderForm>>;
  setLdapProviderFormBaseline: Dispatch<SetStateAction<typeof emptyLdapProviderForm | null>>;
  setEditor: Dispatch<SetStateAction<AdminEditor>>;
  setBusy: Dispatch<SetStateAction<boolean>>;
  setError: Dispatch<SetStateAction<string>>;
  setVerificationMessage: Dispatch<SetStateAction<string>>;
  loadAdminData: () => Promise<void>;
  loadBootstrap: () => Promise<void>;
  messageOr: (error: unknown, fallback: TranslationKey) => string;
  changesSavedMessage: string;
};

export function useProviderAdminActions({
  providerForm,
  providerTemplates,
  providerTemplateId,
  setProviderForm,
  setProviderFormBaseline,
  providerDiscoveryRequest,
  ldapProviderForm,
  setLdapProviderForm,
  setLdapProviderFormBaseline,
  setEditor,
  setBusy,
  setError,
  setVerificationMessage,
  loadAdminData,
  loadBootstrap,
  messageOr,
  changesSavedMessage
}: Options) {
  const providerRedirectPath = useCallback((slug: string) => (
    `/api/register/oidc/${slug.trim() || "provider"}/callback`
  ), []);

  const applyProviderTemplate = useCallback(() => {
    const template = providerTemplates.find((item) => item.id === providerTemplateId);
    if (!template) return;
    providerDiscoveryRequest.cancel();
    setProviderForm({
      ...providerForm,
      slug: template.slug,
      display_name: template.display_name,
      issuer: template.issuer,
      redirect_path: providerRedirectPath(template.slug),
      scopes: joinList(template.scopes)
    });
  }, [
    providerDiscoveryRequest,
    providerForm,
    providerRedirectPath,
    providerTemplateId,
    providerTemplates,
    setProviderForm
  ]);

  const discoverProviderEndpoints = useCallback(async () => {
    const requestedIssuer = providerForm.issuer.trim();
    if (!requestedIssuer) return;
    const request = providerDiscoveryRequest.begin();
    setBusy(true);
    setError("");
    try {
      const discovered = await adminApi.discoverAdminExternalOidcProvider(requestedIssuer, {
        signal: request.signal
      });
      setProviderForm((current) => {
        if (!request.isCurrent() || current.issuer.trim() !== requestedIssuer) return current;
        return {
          ...current,
          issuer: discovered.issuer,
          authorization_endpoint: discovered.authorization_endpoint,
          token_endpoint: discovered.token_endpoint,
          userinfo_endpoint: discovered.userinfo_endpoint,
          scopes: joinList(discovered.scopes)
        };
      });
    } catch (error) {
      if (request.isCurrent()) setError(messageOr(error, "discoverProviderFailed"));
    } finally {
      if (request.isCurrent()) setBusy(false);
    }
  }, [messageOr, providerDiscoveryRequest, providerForm.issuer, setBusy, setError, setProviderForm]);

  const saveProvider = useCallback(async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = toExternalOidcProviderPayload(providerForm);
      if (providerForm.id) {
        await adminApi.updateAdminExternalOidcProvider(providerForm.id, body);
      } else {
        await adminApi.createAdminExternalOidcProvider(body);
      }
      setProviderForm(emptyProviderForm);
      setProviderFormBaseline(null);
      setEditor(null);
      setVerificationMessage(changesSavedMessage);
      await loadAdminData();
      await loadBootstrap();
    } catch (error) {
      setError(messageOr(error, "saveProviderFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    changesSavedMessage,
    loadAdminData,
    loadBootstrap,
    messageOr,
    providerForm,
    setBusy,
    setEditor,
    setError,
    setProviderForm,
    setProviderFormBaseline,
    setVerificationMessage
  ]);

  const deleteProvider = useCallback(async (id: string) => {
    await adminApi.deleteAdminExternalOidcProvider(id);
    await loadAdminData();
    await loadBootstrap();
  }, [loadAdminData, loadBootstrap]);

  const saveLdapProvider = useCallback(async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = toLdapProviderPayload(ldapProviderForm);
      if (ldapProviderForm.id) {
        await adminApi.updateAdminLdapProvider(ldapProviderForm.id, body);
      } else {
        await adminApi.createAdminLdapProvider(body);
      }
      setLdapProviderForm(emptyLdapProviderForm);
      setLdapProviderFormBaseline(null);
      setEditor(null);
      setVerificationMessage(changesSavedMessage);
      await loadAdminData();
      await loadBootstrap();
    } catch (error) {
      setError(messageOr(error, "saveLdapProviderFailed"));
    } finally {
      setBusy(false);
    }
  }, [
    changesSavedMessage,
    ldapProviderForm,
    loadAdminData,
    loadBootstrap,
    messageOr,
    setBusy,
    setEditor,
    setError,
    setLdapProviderForm,
    setLdapProviderFormBaseline,
    setVerificationMessage
  ]);

  const deleteLdapProvider = useCallback(async (id: string) => {
    await adminApi.deleteAdminLdapProvider(id);
    await loadAdminData();
    await loadBootstrap();
  }, [loadAdminData, loadBootstrap]);

  const editLdapProvider = useCallback((provider: LdapProvider) => {
    const nextForm = toLdapProviderForm(provider);
    setLdapProviderForm(nextForm);
    setLdapProviderFormBaseline(nextForm);
    setEditor("ldap");
  }, [setEditor, setLdapProviderForm, setLdapProviderFormBaseline]);

  return {
    providerRedirectPath,
    applyProviderTemplate,
    discoverProviderEndpoints,
    saveProvider,
    deleteProvider,
    saveLdapProvider,
    deleteLdapProvider,
    editLdapProvider
  };
}
