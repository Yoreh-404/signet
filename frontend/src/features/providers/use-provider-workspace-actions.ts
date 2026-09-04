import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";

import { emptyLdapProviderForm, emptyProviderForm } from "../../lib/form-defaults";
import type { ExternalProvider, LdapProvider } from "../../types";
import {
  toExternalOidcProviderForm,
  toLdapProviderForm
} from "../admin/form-adapters";
import type { AdminEditor } from "../admin/use-settings-controller";
import type { ExternalOidcProviderForm } from "./ExternalOidcProviderEditor";
import type { LdapProviderForm } from "../settings/LdapProviderEditor";

export type ProviderWorkspaceActions = {
  updateProviderForm: (form: ExternalOidcProviderForm) => void;
  createProvider: () => void;
  editProvider: (provider: ExternalProvider) => void;
  deleteProvider: (id: string) => void;
  updateLdapProviderForm: (form: LdapProviderForm) => void;
  createLdapProvider: () => void;
  editLdapProvider: (provider: LdapProvider) => void;
  deleteLdapProvider: (id: string) => void;
};

type Options = {
  providerForm: typeof emptyProviderForm;
  setProviderForm: Dispatch<SetStateAction<typeof emptyProviderForm>>;
  setProviderFormBaseline: Dispatch<SetStateAction<typeof emptyProviderForm | null>>;
  providerDiscoveryRequest: { cancel: () => void };
  setProviderTemplateId: Dispatch<SetStateAction<string>>;
  setLdapProviderForm: Dispatch<SetStateAction<typeof emptyLdapProviderForm>>;
  setLdapProviderFormBaseline: Dispatch<SetStateAction<typeof emptyLdapProviderForm | null>>;
  setEditor: Dispatch<SetStateAction<AdminEditor>>;
  requestConfirmation: (action: () => Promise<void> | void) => void;
  deleteProviderRequest: (id: string) => Promise<void>;
  deleteLdapProviderRequest: (id: string) => Promise<void>;
};

export function useProviderWorkspaceActions({
  providerForm,
  setProviderForm,
  setProviderFormBaseline,
  providerDiscoveryRequest,
  setProviderTemplateId,
  setLdapProviderForm,
  setLdapProviderFormBaseline,
  setEditor,
  requestConfirmation,
  deleteProviderRequest,
  deleteLdapProviderRequest
}: Options): ProviderWorkspaceActions {
  const updateProviderForm = useCallback((next: typeof emptyProviderForm) => {
    if (next.issuer !== providerForm.issuer) providerDiscoveryRequest.cancel();
    setProviderForm(next);
  }, [providerDiscoveryRequest, providerForm.issuer, setProviderForm]);

  const createProvider = useCallback(() => {
    providerDiscoveryRequest.cancel();
    setProviderForm(emptyProviderForm);
    setProviderFormBaseline(emptyProviderForm);
    setProviderTemplateId("");
    setEditor("provider");
  }, [
    providerDiscoveryRequest,
    setEditor,
    setProviderForm,
    setProviderFormBaseline,
    setProviderTemplateId
  ]);

  const editProvider = useCallback((provider: ExternalProvider) => {
    providerDiscoveryRequest.cancel();
    const nextForm = toExternalOidcProviderForm(provider);
    setProviderForm(nextForm);
    setProviderFormBaseline(nextForm);
    setProviderTemplateId("");
    setEditor("provider");
  }, [
    providerDiscoveryRequest,
    setEditor,
    setProviderForm,
    setProviderFormBaseline,
    setProviderTemplateId
  ]);

  const deleteProvider = useCallback((id: string) => {
    requestConfirmation(() => deleteProviderRequest(id));
  }, [deleteProviderRequest, requestConfirmation]);

  const updateLdapProviderForm = useCallback((next: typeof emptyLdapProviderForm) => {
    setLdapProviderForm(next);
  }, [setLdapProviderForm]);

  const createLdapProvider = useCallback(() => {
    setLdapProviderForm(emptyLdapProviderForm);
    setLdapProviderFormBaseline(emptyLdapProviderForm);
    setEditor("ldap");
  }, [setEditor, setLdapProviderForm, setLdapProviderFormBaseline]);

  const editLdapProvider = useCallback((provider: LdapProvider) => {
    const nextForm = toLdapProviderForm(provider);
    setLdapProviderForm(nextForm);
    setLdapProviderFormBaseline(nextForm);
    setEditor("ldap");
  }, [setEditor, setLdapProviderForm, setLdapProviderFormBaseline]);

  const deleteLdapProvider = useCallback((id: string) => {
    requestConfirmation(() => deleteLdapProviderRequest(id));
  }, [deleteLdapProviderRequest, requestConfirmation]);

  return {
    updateProviderForm,
    createProvider,
    editProvider,
    deleteProvider,
    updateLdapProviderForm,
    createLdapProvider,
    editLdapProvider,
    deleteLdapProvider
  };
}
