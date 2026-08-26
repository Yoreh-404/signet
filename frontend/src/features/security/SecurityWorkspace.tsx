import { ExternalLink, Plus } from "lucide-react";
import type { FormEvent } from "react";

import { EmptyState } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import { formatTime } from "../../lib/formatters";
import type { AuditWebhookForm } from "./AuditWebhookEditor";
import { AccessEditors, type GroupEditorForm, type RoleEditorForm } from "./AccessEditors";
import { AuditEventsPanel } from "./AuditEventsPanel";
import { AuditWebhookEditor } from "./AuditWebhookEditor";
import { GroupTable } from "./GroupTable";
import { MfaSecurityPanel } from "./MfaSecurityPanel";
import { RoleTable } from "./RoleTable";
import { SecurityPolicyPanel } from "./SecurityPolicyPanel";
import { SigningKeysPanel } from "./SigningKeysPanel";
import { UserAccessPanel } from "./UserAccessPanel";
import type {
  AccessGroup,
  AuditEvent,
  Locale,
  MfaStatus,
  PermissionInfo,
  Role,
  SecurityPolicy,
  SigningKey,
  TotpSetup,
  UserAccess,
  UserOption,
  AuditWebhook
} from "../../types";

export type SecurityWorkspaceProps = {
  canManageSecurity: boolean;
  canReadAudit: boolean;
  canMutateAccount: boolean;
  busy: boolean;
  error: string;
  locale: Locale;
  translate: (key: TranslationKey) => string;
  searchQuery: string;
  adminViewLoading: boolean;
  mfaStatus: MfaStatus | null;
  totpSetup: TotpSetup | null;
  totpSetupCode: string;
  newRecoveryCodes: string[];
  signingKeys: SigningKey[];
  signingKeyKid: string;
  securityPolicy: SecurityPolicy | null;
  roleForm: RoleEditorForm;
  groupForm: GroupEditorForm;
  permissionCatalog: PermissionInfo[];
  roles: Role[];
  filteredRoles: Role[];
  groups: AccessGroup[];
  filteredGroups: AccessGroup[];
  userOptions: UserOption[];
  selectedAccessUserId: string;
  userAccess: UserAccess | null;
  auditWebhookForm: AuditWebhookForm;
  filteredAuditWebhooks: AuditWebhook[];
  filteredAuditEvents: AuditEvent[];
  editor: string | null;
  roleDirty: boolean;
  groupDirty: boolean;
  securityPolicyDirty: boolean;
  auditWebhookDirty: boolean;
  onStartTotpSetup: () => void | Promise<void>;
  onConfirmTotpSetup: () => void | Promise<void>;
  onDisableMfa: () => void | Promise<void>;
  onRotateRecoveryCodes: () => void | Promise<void>;
  onTotpSetupCodeChange: (value: string) => void;
  onSigningKeyKidChange: (value: string) => void;
  onRotateSigningKey: () => void | Promise<void>;
  onSecurityPolicyChange: (policy: SecurityPolicy) => void;
  onSaveSecurityPolicy: (event: FormEvent<HTMLFormElement>) => void | Promise<void>;
  onRoleChange: (form: RoleEditorForm) => void;
  onGroupChange: (form: GroupEditorForm) => void;
  onRoleSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onGroupSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onCloseEditor: () => void;
  onCreateRole: () => void;
  onEditRole: (role: Role) => void;
  onDeleteRole: (role: Role) => void;
  onSelectUser: (userId: string) => void;
  onToggleUserRole: (role: Role) => void;
  onSaveUserRoles: () => void | Promise<void>;
  onCreateGroup: () => void;
  onEditGroup: (group: AccessGroup) => void;
  onDeleteGroup: (group: AccessGroup) => void;
  onAuditWebhookChange: (form: AuditWebhookForm) => void;
  onSaveAuditWebhook: (event: FormEvent<HTMLFormElement>) => void;
  onCancelAuditWebhook: () => void;
  onEditAuditWebhook: (webhook: AuditWebhook) => void;
  onDeleteAuditWebhook: (webhook: AuditWebhook) => void;
};

export function SecurityWorkspace({
  canManageSecurity,
  canReadAudit,
  canMutateAccount,
  busy,
  error,
  locale,
  translate: t,
  searchQuery,
  adminViewLoading,
  mfaStatus,
  totpSetup,
  totpSetupCode,
  newRecoveryCodes,
  signingKeys,
  signingKeyKid,
  securityPolicy,
  roleForm,
  groupForm,
  permissionCatalog,
  roles,
  filteredRoles,
  filteredGroups,
  userOptions,
  selectedAccessUserId,
  userAccess,
  auditWebhookForm,
  filteredAuditWebhooks,
  filteredAuditEvents,
  editor,
  roleDirty,
  groupDirty,
  securityPolicyDirty,
  auditWebhookDirty,
  onStartTotpSetup,
  onConfirmTotpSetup,
  onDisableMfa,
  onRotateRecoveryCodes,
  onTotpSetupCodeChange,
  onSigningKeyKidChange,
  onRotateSigningKey,
  onSecurityPolicyChange,
  onSaveSecurityPolicy,
  onRoleChange,
  onGroupChange,
  onRoleSubmit,
  onGroupSubmit,
  onCloseEditor,
  onCreateRole,
  onEditRole,
  onDeleteRole,
  onSelectUser,
  onToggleUserRole,
  onSaveUserRoles,
  onCreateGroup,
  onEditGroup,
  onDeleteGroup,
  onAuditWebhookChange,
  onSaveAuditWebhook,
  onCancelAuditWebhook,
  onEditAuditWebhook,
  onDeleteAuditWebhook
}: SecurityWorkspaceProps) {
  return (
    <section className="security-page wide">
      {canManageSecurity && (
        <>
          <div className="security-overview-grid">
            <MfaSecurityPanel
              mfaStatus={mfaStatus}
              totpSetup={totpSetup}
              totpSetupCode={totpSetupCode}
              recoveryCodes={newRecoveryCodes}
              busy={busy}
              canMutateAccount={canMutateAccount}
              translate={t}
              onStartTotpSetup={onStartTotpSetup}
              onConfirmTotpSetup={onConfirmTotpSetup}
              onDisableMfa={onDisableMfa}
              onRotateRecoveryCodes={onRotateRecoveryCodes}
              onTotpSetupCodeChange={onTotpSetupCodeChange}
            />
            <SigningKeysPanel
              signingKeys={signingKeys}
              signingKeyKid={signingKeyKid}
              busy={busy}
              locale={locale}
              translate={t}
              onSigningKeyKidChange={onSigningKeyKidChange}
              onRotate={onRotateSigningKey}
            />
          </div>

          {securityPolicy && (
            <SecurityPolicyPanel
              policy={securityPolicy}
              busy={busy}
              dirty={securityPolicyDirty}
              translate={t}
              onChange={onSecurityPolicyChange}
              onSubmit={onSaveSecurityPolicy}
            />
          )}

          <AccessEditors
            roleOpen={editor === "role"}
            groupOpen={editor === "group"}
            roleForm={roleForm}
            groupForm={groupForm}
            permissionCatalog={permissionCatalog}
            roles={roles}
            userOptions={userOptions}
            busy={busy}
            error={error}
            roleDirty={roleDirty}
            groupDirty={groupDirty}
            translate={t}
            onRoleChange={onRoleChange}
            onGroupChange={onGroupChange}
            onRoleSubmit={onRoleSubmit}
            onGroupSubmit={onGroupSubmit}
            onClose={onCloseEditor}
          />

          <div className="security-management-grid">
            <section className="table-panel security-roles-panel">
              <div className="table-toolbar"><h3>{t("roles")}</h3><button type="button" onClick={onCreateRole}><Plus size={14} />{t("createRole")}</button></div>
              <RoleTable
                roles={filteredRoles}
                canManage={canManageSecurity}
                locale={locale}
                translate={t}
                onEdit={onEditRole}
                onDelete={onDeleteRole}
              />
              {!adminViewLoading && filteredRoles.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} />}
            </section>

            <UserAccessPanel
              userOptions={userOptions}
              roles={roles}
              selectedUserId={selectedAccessUserId}
              userAccess={userAccess}
              busy={busy}
              translate={t}
              onSelectUser={onSelectUser}
              onToggleRole={onToggleUserRole}
              onSave={onSaveUserRoles}
            />

            <section className="table-panel security-groups-panel">
              <div className="table-toolbar"><h3>{t("groups")}</h3><button type="button" onClick={onCreateGroup}><Plus size={14} />{t("createGroup")}</button></div>
              <GroupTable
                groups={filteredGroups}
                loading={adminViewLoading}
                searchActive={Boolean(searchQuery)}
                canManage={canManageSecurity}
                translate={t}
                onEdit={onEditGroup}
                onDelete={onDeleteGroup}
              />
            </section>
          </div>
        </>
      )}

      <div className="security-audit-layout">
        {canManageSecurity && (
          <AuditWebhookEditor
            form={auditWebhookForm}
            busy={busy}
            dirty={auditWebhookDirty}
            canManage={canManageSecurity}
            translate={t}
            onChange={onAuditWebhookChange}
            onSubmit={onSaveAuditWebhook}
            onCancel={onCancelAuditWebhook}
          />
        )}
        {(canReadAudit || canManageSecurity) && (
          <section className="table-panel security-webhooks-panel">
            <h3>{t("auditWebhooks")}</h3>
            <table>
              <thead><tr><th>{t("webhookName")}</th><th>{t("webhookActions")}</th><th>{t("deliveryStatus")}</th><th>{t("status")}</th><th></th></tr></thead>
              <tbody>
                {filteredAuditWebhooks.map((webhook) => (
                  <tr key={webhook.id}>
                    <td>{webhook.name}<br /><a href={webhook.url} target="_blank" rel="noreferrer"><ExternalLink size={12} /> {webhook.url}</a></td>
                    <td><div className="token-list">{(webhook.actions.length > 0 ? webhook.actions : ["*"]).map((action) => <span key={action}>{action}</span>)}{webhook.has_secret && <span>{t("hasSecret")}</span>}</div></td>
                    <td>{webhook.last_status_code ?? "-"}<br /><small>{webhook.last_error ?? formatTime(webhook.last_delivered_at, locale)}</small></td>
                    <td>{webhook.is_active ? t("active") : t("disabled")}</td>
                    <td className="actions">{canManageSecurity && <button type="button" onClick={() => onEditAuditWebhook(webhook)}>{t("edit")}</button>}{canManageSecurity && <button type="button" onClick={() => onDeleteAuditWebhook(webhook)}>{t("delete")}</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!adminViewLoading && filteredAuditWebhooks.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} />}
          </section>
        )}
      </div>

      {canReadAudit && <AuditEventsPanel events={filteredAuditEvents} loading={adminViewLoading} searchActive={Boolean(searchQuery)} locale={locale} translate={t} />}
    </section>
  );
}
