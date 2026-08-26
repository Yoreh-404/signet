import { Clock3, Copy, Eye, Plus, Ticket } from "lucide-react";
import type { FormEvent } from "react";

import {
  Check,
  EmptyState,
  Field,
  FormActions,
  Modal,
  SelectField,
  StatusBadge
} from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { emptyInvitationForm } from "../../lib/form-defaults";
import { formatTime } from "../../lib/formatters";
import type {
  AuthorizationCodeType,
  Client,
  Invitation,
  Locale,
  LoginAuthorizationCodeLevel,
  OrganizationMemberRole,
  OrganizationOption
} from "../../types";

export type AuthorizationCodesForm = typeof emptyInvitationForm;

export type AuthorizationCodesWorkspaceProps = {
  open: boolean;
  form: AuthorizationCodesForm;
  clients: Client[];
  organizations: OrganizationOption[];
  filteredInvitations: Invitation[];
  canManageOrganizations: boolean;
  isAdmin: boolean;
  busy: boolean;
  error: string;
  dirty: boolean;
  adminViewLoading: boolean;
  searchQuery: string;
  locale: Locale;
  lastInvitationCode: string;
  revealingInvitationId: string;
  translate: (key: TranslationKey) => string;
  onChange: (form: AuthorizationCodesForm) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onClose: () => void;
  onCreate: () => void;
  onEdit: (invitation: Invitation) => void;
  onDelete: (id: string) => void;
  onReveal: (invitation: Invitation) => void;
  onCopyLastInvitationCode: () => void;
  onOpenRedemptions: (invitation: Invitation) => void;
};

export function AuthorizationCodesWorkspace({
  open,
  form,
  clients,
  organizations,
  filteredInvitations,
  canManageOrganizations,
  isAdmin,
  busy,
  error,
  dirty,
  adminViewLoading,
  searchQuery,
  locale,
  lastInvitationCode,
  revealingInvitationId,
  translate,
  onChange,
  onSubmit,
  onClose,
  onCreate,
  onEdit,
  onDelete,
  onReveal,
  onCopyLastInvitationCode,
  onOpenRedemptions
}: AuthorizationCodesWorkspaceProps) {
  const selectedClientIds = new Set(form.allowed_client_ids);
  const clientsByClientId = new Map(clients.map((client) => [client.client_id, client]));
  const organizationsById = new Map(organizations.map((organization) => [organization.id, organization]));

  return (
    <>
      <div className="table-panel">
        <div className="table-toolbar">
          <h3>{translate("invitations")}</h3>
          <button type="button" onClick={onCreate}>
            <Plus size={14} />
            {translate("createInvitation")}
          </button>
        </div>
        <table className="authorization-codes-table">
          <thead><tr><th>{translate("authorizationCodePrefix")}</th><th>{translate("authorizationCodeType")}</th><th>{translate("description")}</th><th>{translate("authorizedIdentity")}</th><th>{translate("expiresAt")}</th><th>{translate("used")}</th><th>{translate("status")}</th><th></th></tr></thead>
          <tbody>
            {filteredInvitations.map((item) => (
              <tr key={item.id}>
                <td className="authorization-code-prefix-cell">
                  <code>{item.code_prefix}...</code>
                  <button
                    className="icon-button compact-icon-button"
                    type="button"
                    aria-label={item.can_reveal ? translate("revealAuthorizationCode") : translate("authorizationCodeRevealUnavailable")}
                    title={item.can_reveal ? translate("revealAuthorizationCode") : translate("authorizationCodeRevealUnavailable")}
                    disabled={!item.can_reveal || revealingInvitationId === item.id}
                    onClick={() => onReveal(item)}
                  >
                    <Eye size={15} />
                  </button>
                </td>
                <td>
                  <div className="invitation-type-badges">
                    <StatusBadge tone={item.code_type === "login" ? "info" : "neutral"}>
                      {translate(item.code_type === "login" ? "loginAuthorizationCodeType" : "registrationAuthorizationCodeType")}
                    </StatusBadge>
                    {item.code_type === "login" && (
                      <StatusBadge tone={item.login_code_level === "admin_universal" ? "danger" : item.login_code_level === "trial_enrollment" ? "success" : "neutral"}>
                        {translate(
                          item.login_code_level === "admin_universal"
                            ? "adminUniversalCode"
                            : item.login_code_level === "trial_enrollment"
                              ? "trialEnrollmentCode"
                              : "accountRecoveryCode"
                        )}
                      </StatusBadge>
                    )}
                  </div>
                </td>
                <td>{item.description ?? "-"}</td>
                <td>
                  {item.code_type === "login" && item.login_code_level === "trial_enrollment" ? (
                    <div className="token-list">
                      <span>{organizationsById.get(item.organization_id ?? "")?.name ?? item.organization_id ?? "-"}</span>
                      <span>{translate("enrollmentOrganizationRole")}: {translate(
                        item.organization_role === "owner"
                          ? "organizationRoleOwner"
                          : item.organization_role === "admin"
                            ? "organizationRoleAdmin"
                            : "organizationRoleMember"
                      )}</span>
                      {(item.allowed_client_ids ?? []).map((clientId) => (
                        <span key={clientId}>{clientsByClientId.get(clientId)?.client_name ?? clientId}</span>
                      ))}
                    </div>
                  ) : item.code_type === "login" && item.login_code_level === "admin_universal" ? (
                    <div className="token-list">
                      {(item.allowed_client_ids ?? []).map((clientId) => (
                        <span key={clientId}>{clientsByClientId.get(clientId)?.client_name ?? clientId}</span>
                      ))}
                      {(item.allowed_client_ids ?? []).length === 0 && <span>-</span>}
                    </div>
                  ) : (
                    item.authorized_email ?? item.authorized_username ?? "-"
                  )}
                </td>
                <td>{item.expires_at ? formatTime(item.expires_at, locale) : translate("permanent")}</td>
                <td className="invitation-usage-cell">
                  <span>{item.uses_count}/{item.max_uses ?? translate("unlimited")}</span>
                  <button type="button" className="link-button" onClick={() => onOpenRedemptions(item)}>
                    <Clock3 size={14} />
                    {translate("viewRedemptions")}
                  </button>
                </td>
                <td>{item.is_active ? translate("active") : translate("disabled")}</td>
                <td className="actions">
                  <button type="button" onClick={() => onEdit(item)}>{translate("edit")}</button>
                  <button type="button" onClick={() => onDelete(item.id)}>{translate("delete")}</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!adminViewLoading && filteredInvitations.length === 0 && (
          <EmptyState title={searchQuery ? translate("noSearchResults") : translate("noData")} icon={<Ticket size={22} />} />
        )}
      </div>

      {open && (
        <Modal
          title={form.id ? translate("updateInvitation") : translate("createInvitation")}
          closeLabel={translate("close")}
          error={error}
          dismissible={!busy}
          onClose={onClose}
          wide
        >
          <form className="panel" onSubmit={onSubmit}>
            <SelectField
              label={translate("authorizationCodeType")}
              value={form.code_type}
              disabled={Boolean(form.id)}
              description={form.id ? translate("authorizationCodeTypeLocked") : undefined}
              onChange={(value) => {
                const codeType = value as AuthorizationCodeType;
                onChange({
                  ...form,
                  code_type: codeType,
                  authorized_email: codeType === "login" ? "" : form.authorized_email,
                  authorized_display_name: codeType === "login" ? "" : form.authorized_display_name,
                  allowed_client_ids: codeType === "registration" ? [] : form.allowed_client_ids,
                  organization_id: codeType === "registration" ? "" : form.organization_id,
                  organization_role: codeType === "registration" ? "member" : form.organization_role
                });
              }}
            >
              <option value="registration">{translate("registrationAuthorizationCodeType")}</option>
              <option value="login">{translate("loginAuthorizationCodeType")}</option>
            </SelectField>
            {form.code_type === "login" && (
              <SelectField
                label={translate("loginCodeLevel")}
                value={form.login_code_level}
                disabled={Boolean(form.id)}
                description={form.id
                  ? translate("loginCodeLevelLocked")
                  : translate(
                    form.login_code_level === "admin_universal"
                      ? "adminUniversalCodeHint"
                      : form.login_code_level === "trial_enrollment"
                        ? "trialEnrollmentCodeHint"
                        : "accountRecoveryCodeHint"
                  )}
                onChange={(value) => {
                  const level = value as LoginAuthorizationCodeLevel;
                  const applicationBound = level === "trial_enrollment" || level === "admin_universal";
                  onChange({
                    ...form,
                    login_code_level: level,
                    authorized_username: applicationBound ? "" : form.authorized_username,
                    authorized_display_name: applicationBound ? "" : form.authorized_display_name,
                    allowed_client_ids: applicationBound ? form.allowed_client_ids : [],
                    organization_id: level === "trial_enrollment" ? form.organization_id : "",
                    organization_role: level === "trial_enrollment" ? form.organization_role : "member"
                  });
                }}
              >
                <option value="account_recovery">{translate("accountRecoveryCode")}</option>
                <option value="trial_enrollment">{translate("trialEnrollmentCode")}</option>
                <option value="admin_universal" disabled={!isAdmin}>{translate("adminUniversalCode")}</option>
              </SelectField>
            )}
            <Field label={translate("description")} value={form.description} onChange={(description) => onChange({ ...form, description })} />
            {form.code_type === "registration" && (
              <Field label={translate("authorizedEmail")} value={form.authorized_email} onChange={(authorized_email) => onChange({ ...form, authorized_email })} />
            )}
            {(form.code_type === "registration" || form.login_code_level === "account_recovery") && (
              <Field
                label={form.code_type === "login" ? translate("username") : translate("authorizedUsername")}
                value={form.authorized_username}
                onChange={(authorized_username) => onChange({ ...form, authorized_username })}
                required={form.code_type === "login"}
                disabled={Boolean(form.id) && form.code_type === "login"}
                description={form.code_type === "login"
                  ? translate(form.id ? "boundAccountLocked" : "loginCodeUsernameHint")
                  : undefined}
              />
            )}
            {form.code_type === "registration" && (
              <Field
                label={translate("authorizedDisplayName")}
                value={form.authorized_display_name}
                onChange={(authorized_display_name) => onChange({ ...form, authorized_display_name })}
              />
            )}
            {form.code_type === "login" && (form.login_code_level === "admin_universal" || form.login_code_level === "trial_enrollment") && (
              <>
                {form.login_code_level === "admin_universal" ? (
                  <div className="error" role="alert">{translate("adminUniversalCodeRisk")}</div>
                ) : (
                  <div className="info" role="status">{translate("trialEnrollmentCodeScope")}</div>
                )}
                <div role="group" aria-label={translate("allowedApplications")}>
                  <label>{translate("allowedApplications")}</label>
                  {form.id && <small className="field-description">{translate(form.login_code_level === "trial_enrollment" ? "trialEnrollmentScopeLocked" : "allowedApplicationsLocked")}</small>}
                  {clients.length > 0 ? (
                    <div className="checkbox-grid">
                      {clients.map((client) => (
                        <Check
                          key={client.client_id}
                          label={`${client.client_name} · ${client.client_id}${client.is_active ? "" : ` · ${translate("disabled")}`}`}
                          checked={selectedClientIds.has(client.client_id)}
                          disabled={Boolean(form.id)}
                          onChange={() => onChange({ ...form, allowed_client_ids: form.allowed_client_ids.includes(client.client_id) ? form.allowed_client_ids.filter((id) => id !== client.client_id) : [...form.allowed_client_ids, client.client_id] })}
                        />
                      ))}
                    </div>
                  ) : (
                    <div className="info">{translate("noOidcClients")}</div>
                  )}
                </div>
              </>
            )}
            {form.code_type === "login" && form.login_code_level === "trial_enrollment" && (
              <div className="enrollment-code-scope">
                {!canManageOrganizations && <div className="error" role="alert">{translate("trialEnrollmentOrganizationManageRequired")}</div>}
                <SelectField
                  label={translate("enrollmentOrganization")}
                  value={form.organization_id}
                  disabled={Boolean(form.id)}
                  description={form.id ? translate("trialEnrollmentScopeLocked") : translate("trialEnrollmentOrganizationHint")}
                  onChange={(organization_id) => onChange({ ...form, organization_id })}
                >
                  <option value="">{translate("selectOrganization")}</option>
                  {organizations.map((organization) => (
                    <option key={organization.id} value={organization.id} disabled={!organization.is_active}>
                      {organization.name} · {organization.slug}{organization.is_active ? "" : ` · ${translate("disabled")}`}
                    </option>
                  ))}
                </SelectField>
                {organizations.length === 0 && <div className="error" role="alert">{translate("trialEnrollmentOrganizationUnavailable")}</div>}
                <SelectField
                  label={translate("enrollmentOrganizationRole")}
                  value={form.organization_role}
                  disabled={Boolean(form.id)}
                  description={form.id ? translate("trialEnrollmentScopeLocked") : translate("trialEnrollmentRoleHint")}
                  onChange={(organization_role) => onChange({ ...form, organization_role: organization_role as OrganizationMemberRole })}
                >
                  <option value="member">{translate("organizationRoleMember")}</option>
                  <option value="admin">{translate("organizationRoleAdmin")}</option>
                  <option value="owner">{translate("organizationRoleOwner")}</option>
                </SelectField>
              </div>
            )}
            <Field
              label={translate("expiresAt")}
              type="datetime-local"
              value={form.expires_at}
              onChange={(expires_at) => onChange({ ...form, expires_at })}
              required={form.code_type === "login" && form.login_code_level === "trial_enrollment"}
              description={form.code_type === "login" && form.login_code_level === "trial_enrollment" ? translate("trialEnrollmentExpiryHint") : undefined}
            />
            <Field
              label={translate("maxUses")}
              type="number"
              min={1}
              step={1}
              value={form.max_uses}
              onChange={(max_uses) => onChange({ ...form, max_uses })}
              required={form.code_type === "login" && form.login_code_level === "trial_enrollment"}
              description={form.code_type === "login" && form.login_code_level === "trial_enrollment" ? translate("trialEnrollmentUsesHint") : undefined}
            />
            <Check label={translate("active")} checked={form.is_active} onChange={(is_active) => onChange({ ...form, is_active })} />
            <FormActions
              submitLabel={translate("save")}
              cancelLabel={translate("cancel")}
              onCancel={onClose}
              busy={busy}
              dirty={dirty}
              statusLabel={dirty ? translate("unsavedChanges") : undefined}
              savingLabel={translate("saving")}
            />
            {lastInvitationCode && (
              <div className="info">
                {translate("createdInvitation")}: <strong>{lastInvitationCode}</strong>
                <button className="link-button" type="button" onClick={onCopyLastInvitationCode}>
                  <Copy size={14} />
                  {translate("copyAuthorizationCode")}
                </button>
              </div>
            )}
          </form>
        </Modal>
      )}
    </>
  );
}
