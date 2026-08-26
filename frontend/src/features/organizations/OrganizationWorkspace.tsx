import { Building2, Plus } from "lucide-react";
import type { FormEvent } from "react";
import {
  Check,
  EmptyState,
  Field,
  FormActions,
  Modal,
  StatusBadge
} from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { Locale, Organization, OrganizationMemberRole, UserOption } from "../../types";
import { formatTime } from "../../lib/formatters";

export type OrganizationFormState = {
  id: string;
  slug: string;
  name: string;
  description: string;
  allowed_email_domains: string;
  is_active: boolean;
};

export type OrganizationWorkspaceProps = {
  organizationForm: OrganizationFormState;
  organizationMemberRoles: Record<string, string>;
  userOptions: UserOption[];
  filteredOrganizations: Organization[];
  permissions: {
    canManageOrganizations: boolean;
    canReadUsers: boolean;
  };
  busy: boolean;
  loading: boolean;
  membersLoading: boolean;
  error: string;
  dirty: boolean;
  locale: Locale;
  translate: (key: TranslationKey) => string;
  editorOpen: boolean;
  searchActive: boolean;
  onCreate: () => void;
  onEdit: (organization: Organization) => void;
  onDelete: (id: string) => void;
  onSave: (event: FormEvent<HTMLFormElement>) => void;
  onViewMembers: (organization: Organization) => void;
  onClose: () => void;
  onSetForm: (form: OrganizationFormState) => void;
  onSetRole: (userId: string, role: OrganizationMemberRole | null) => void;
};

export function OrganizationWorkspace({
  organizationForm,
  organizationMemberRoles,
  userOptions,
  filteredOrganizations,
  permissions,
  busy,
  loading,
  membersLoading,
  error,
  dirty,
  locale,
  translate,
  editorOpen,
  searchActive,
  onCreate,
  onEdit,
  onDelete,
  onSave,
  onViewMembers,
  onClose,
  onSetForm,
  onSetRole
}: OrganizationWorkspaceProps) {
  const { canManageOrganizations, canReadUsers } = permissions;

  return (
    <section className="management-list">
      {canManageOrganizations && editorOpen && (
        <Modal
          title={organizationForm.id ? translate("updateOrganization") : translate("createOrganization")}
          closeLabel={translate("close")}
          error={error}
          dismissible={!busy}
          onClose={onClose}
        >
          <form className="panel" onSubmit={onSave}>
            <Field label={translate("organizationSlug")} value={organizationForm.slug} onChange={(value) => onSetForm({ ...organizationForm, slug: value })} />
            <Field label={translate("organizationName")} value={organizationForm.name} onChange={(value) => onSetForm({ ...organizationForm, name: value })} />
            <Field label={translate("description")} value={organizationForm.description} onChange={(value) => onSetForm({ ...organizationForm, description: value })} textarea />
            <Field label={translate("allowedEmailDomains")} value={organizationForm.allowed_email_domains} onChange={(value) => onSetForm({ ...organizationForm, allowed_email_domains: value })} textarea />
            <Check label={translate("active")} checked={organizationForm.is_active} onChange={(value) => onSetForm({ ...organizationForm, is_active: value })} />
            <label>{translate("organizationMembers")}</label>
            {membersLoading ? (
              <div className="info" role="status">{translate("loading")}</div>
            ) : (
              <div className="checkbox-grid tall">
                {userOptions.map((item) => {
                  const role = organizationMemberRoles[item.id] ?? "";
                  return (
                    <div key={item.id} className="member-row">
                      <Check
                        label={`${item.email} · ${item.username}`}
                        checked={Boolean(role)}
                        onChange={(selected) => onSetRole(item.id, selected ? "member" : null)}
                      />
                      {role && (
                        <select
                          aria-label={`${item.email} · ${translate("role")}`}
                          value={role}
                          onChange={(event) => onSetRole(item.id, event.target.value as OrganizationMemberRole)}
                        >
                          <option value="member">member</option>
                          <option value="admin">admin</option>
                          <option value="owner">owner</option>
                        </select>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
            <FormActions
              submitLabel={organizationForm.id ? translate("save") : translate("create")}
              cancelLabel={translate("cancel")}
              onCancel={onClose}
              busy={busy || membersLoading}
              dirty={dirty}
              statusLabel={dirty ? translate("unsavedChanges") : undefined}
              savingLabel={translate("saving")}
            />
          </form>
        </Modal>
      )}
      <div className="table-panel">
        <div className="table-toolbar">
          <h3>{translate("organizations")}</h3>
          {canManageOrganizations && <button type="button" onClick={onCreate}><Plus size={14} />{translate("createOrganization")}</button>}
        </div>
        <table>
          <thead>
            <tr>
              <th>{translate("organizationName")}</th>
              <th>{translate("memberCount")}</th>
              <th>{translate("status")}</th>
              <th>{translate("updatedAt")}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filteredOrganizations.map((organization) => (
              <tr key={organization.id}>
                <td className="organization-name-cell">
                  <div className="organization-name-summary">
                    <strong>{organization.name}</strong>
                    <span className="organization-slug">{organization.slug}</span>
                    {organization.allowed_email_domains.length > 0 && (
                      <span
                        className="organization-domains"
                        title={organization.allowed_email_domains.map((domain) => `@${domain}`).join(", ")}
                      >
                        @{organization.allowed_email_domains[0]}
                        {organization.allowed_email_domains.length > 1 && ` +${organization.allowed_email_domains.length - 1}`}
                      </span>
                    )}
                  </div>
                </td>
                <td className="organization-member-count">{organization.member_count}</td>
                <td><StatusBadge tone={organization.is_active ? "success" : "warning"}>{organization.is_active ? translate("active") : translate("disabled")}</StatusBadge></td>
                <td>{formatTime(organization.updated_at, locale)}</td>
                <td className="actions">
                  {canReadUsers && <button type="button" onClick={() => onViewMembers(organization)}>{translate("viewMembers")}</button>}
                  {canManageOrganizations && <button type="button" onClick={() => onEdit(organization)}>{translate("edit")}</button>}
                  {canManageOrganizations && <button type="button" onClick={() => onDelete(organization.id)}>{translate("delete")}</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!loading && filteredOrganizations.length === 0 && <EmptyState title={searchActive ? translate("noSearchResults") : translate("noData")} icon={<Building2 size={22} />} />}
      </div>
    </section>
  );
}
