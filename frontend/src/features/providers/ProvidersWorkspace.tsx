import type { FormEvent } from "react";

import { ExternalOidcProviderEditor } from "./ExternalOidcProviderEditor";
import type { ExternalOidcProviderForm } from "./ExternalOidcProviderEditor";
import { LdapProviderEditor } from "../settings/LdapProviderEditor";
import type { LdapProviderForm } from "../settings/LdapProviderEditor";
import { LdapProviderList, OidcProviderList } from "./ProviderLists";
import type { TranslationKey } from "../../i18n";
import type {
  ExternalProvider,
  ExternalProviderTemplate,
  LdapProvider,
  OrganizationOption,
  UserOrganization
} from "../../types";
import type { AdminEditor } from "../admin/use-settings-controller";

export type ProvidersWorkspaceProps = {
  state: {
    editor: Extract<AdminEditor, "provider" | "ldap"> | null;
    providerForm: ExternalOidcProviderForm;
    providerTemplateId: string;
    ldapProviderForm: LdapProviderForm;
    providerTemplates: ExternalProviderTemplate[];
    providers: ExternalProvider[];
    ldapProviders: LdapProvider[];
    organizationOptions: OrganizationOption[];
    organizationContext: UserOrganization | null;
    loading: boolean;
    searchActive: boolean;
    error: string;
    providerDirty: boolean;
    ldapDirty: boolean;
  };
  actions: {
    updateProviderForm: (form: ExternalOidcProviderForm) => void;
    updateProviderTemplateId: (id: string) => void;
    applyProviderTemplate: () => void;
    discoverProvider: () => void;
    saveProvider: (event: FormEvent<HTMLFormElement>) => void;
    createProvider: () => void;
    editProvider: (provider: ExternalProvider) => void;
    deleteProvider: (id: string) => void;
    updateLdapProviderForm: (form: LdapProviderForm) => void;
    saveLdapProvider: (event: FormEvent<HTMLFormElement>) => void | Promise<void>;
    createLdapProvider: () => void;
    editLdapProvider: (provider: LdapProvider) => void;
    deleteLdapProvider: (id: string) => void;
    closeEditor: () => boolean;
    providerRedirectPath: (slug: string) => string;
  };
  access: {
    busy: boolean;
    canManagePlatformProviders: boolean;
  };
  i18n: {
    t: (key: TranslationKey) => string;
  };
};

export function ProvidersWorkspace({ state, actions, access, i18n }: ProvidersWorkspaceProps) {
  const { t } = i18n;

  return (
    <section className="management-list identity-sources-page">
      {state.editor === "provider" && (
        <ExternalOidcProviderEditor
          providerForm={state.providerForm}
          templates={state.providerTemplates}
          organizationOptions={state.organizationOptions}
          canManagePlatformProviders={access.canManagePlatformProviders}
          busy={access.busy}
          error={state.error}
          dirty={state.providerDirty}
          translate={t}
          providerTemplateId={state.providerTemplateId}
          onChange={actions.updateProviderForm}
          onTemplateChange={actions.updateProviderTemplateId}
          onApplyTemplate={actions.applyProviderTemplate}
          onDiscover={actions.discoverProvider}
          onCancel={actions.closeEditor}
          onSubmit={actions.saveProvider}
          providerRedirectPath={actions.providerRedirectPath}
        />
      )}
      <OidcProviderList
        providers={state.providers}
        loading={state.loading}
        searchActive={state.searchActive}
        translate={t}
        organizationOptions={state.organizationOptions}
        organizationContext={state.organizationContext}
        onCreate={actions.createProvider}
        onEdit={actions.editProvider}
        onDelete={actions.deleteProvider}
      />
      {access.canManagePlatformProviders && state.editor === "ldap" && (
        <LdapProviderEditor
          form={state.ldapProviderForm}
          organizationOptions={state.organizationOptions}
          busy={access.busy}
          error={state.error}
          dirty={state.ldapDirty}
          translate={t}
          onChange={actions.updateLdapProviderForm}
          onSubmit={actions.saveLdapProvider}
          onClose={actions.closeEditor}
        />
      )}
      {access.canManagePlatformProviders && (
        <LdapProviderList
          providers={state.ldapProviders}
          loading={state.loading}
          searchActive={state.searchActive}
          translate={t}
          onCreate={actions.createLdapProvider}
          onEdit={actions.editLdapProvider}
          onDelete={actions.deleteLdapProvider}
        />
      )}
    </section>
  );
}
