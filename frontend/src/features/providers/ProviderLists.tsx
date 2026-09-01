import { Link2, Plus, Users } from "lucide-react";
import { useMemo } from "react";

import { EmptyState } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type {
  ExternalProvider,
  LdapProvider,
  Locale,
  OrganizationOption,
  UserOrganization
} from "../../types";

type Translate = (key: TranslationKey) => string;

export type OidcProviderListProps = {
  providers: ExternalProvider[];
  loading: boolean;
  searchActive: boolean;
  translate: Translate;
  organizationOptions: OrganizationOption[];
  organizationContext: UserOrganization | null;
  onCreate: () => void;
  onEdit: (provider: ExternalProvider) => void;
  onDelete: (id: string) => void;
};

export function OidcProviderList({
  providers,
  loading,
  searchActive,
  translate: t,
  organizationOptions,
  organizationContext,
  onCreate,
  onEdit,
  onDelete
}: OidcProviderListProps) {
  const organizationOptionsById = useMemo(
    () => new Map(organizationOptions.map((organization) => [organization.id, organization])),
    [organizationOptions]
  );
  return (
    <section className="identity-source-section">
      <div className="table-toolbar identity-source-toolbar">
        <div>
          <h3>{t("providers")}</h3>
          <p className="muted">{t("externalLogin")}</p>
        </div>
        <button type="button" onClick={onCreate}><Plus size={14} />{t("createProvider")}</button>
      </div>
      <div className="client-list identity-source-list">
        {providers.map((provider) => {
          const organization = (provider.organization_id
            ? organizationOptionsById.get(provider.organization_id)
            : undefined)
            ?? (provider.organization_id === organizationContext?.id ? organizationContext : undefined);
          return (
            <article className="client-card" key={provider.id}>
              <h3>{provider.display_name}</h3>
              <p>{provider.slug} · {provider.is_active ? t("active") : t("disabled")} · {organization?.name ?? t("noOrganization")}</p>
              <small>{provider.issuer}</small>
              {provider.email_domains.length > 0 && (
                <div className="tag-row">
                  {provider.email_domains.map((domain) => <span key={domain}>@{domain}</span>)}
                </div>
              )}
              <div className="tag-row">
                {provider.allow_login && <span>{t("allowLogin")}</span>}
                {provider.allow_registration && <span>{t("allowRegistration")}</span>}
              </div>
              <div className="actions">
                <button type="button" onClick={() => onEdit(provider)}>{t("edit")}</button>
                <button type="button" onClick={() => onDelete(provider.id)}>{t("delete")}</button>
              </div>
            </article>
          );
        })}
        {!loading && providers.length === 0 && <EmptyState title={searchActive ? t("noSearchResults") : t("noData")} icon={<Link2 size={22} />} />}
      </div>
    </section>
  );
}

export type LdapProviderListProps = {
  providers: LdapProvider[];
  loading: boolean;
  searchActive: boolean;
  translate: Translate;
  onCreate: () => void;
  onEdit: (provider: LdapProvider) => void;
  onDelete: (id: string) => void;
};

export function LdapProviderList({
  providers,
  loading,
  searchActive,
  translate: t,
  onCreate,
  onEdit,
  onDelete
}: LdapProviderListProps) {
  return (
    <section className="identity-source-section">
      <div className="table-toolbar identity-source-toolbar">
        <div>
          <h3>{t("ldapProviders")}</h3>
          <p className="muted">{t("directoryLogin")}</p>
        </div>
        <button type="button" onClick={onCreate}><Plus size={14} />{t("createLdapProvider")}</button>
      </div>
      <div className="client-list identity-source-list">
        {providers.map((provider) => (
          <article className="client-card" key={provider.id}>
            <h3>{provider.display_name}</h3>
            <p>{provider.slug} · {provider.is_active ? t("active") : t("disabled")}</p>
            <small>{provider.url} · {provider.base_dn}</small>
            <div className="tag-row">
              {provider.allow_login && <span>{t("allowLogin")}</span>}
              {provider.allow_registration && <span>{t("allowRegistration")}</span>}
              {provider.starttls && <span>{t("startTls")}</span>}
              {provider.has_bind_password && <span>{t("hasSecret")}</span>}
            </div>
            <div className="tag-row">
              <span>{provider.user_id_attribute}</span>
              <span>{provider.email_attribute}</span>
              <span>{provider.username_attribute}</span>
            </div>
            <small>{provider.user_filter}</small>
            <div className="actions">
              <button type="button" onClick={() => onEdit(provider)}>{t("edit")}</button>
              <button type="button" onClick={() => onDelete(provider.id)}>{t("delete")}</button>
            </div>
          </article>
        ))}
        {!loading && providers.length === 0 && <EmptyState title={searchActive ? t("noSearchResults") : t("noData")} icon={<Users size={22} />} />}
      </div>
    </section>
  );
}
