import type { TranslationKey } from "../../i18n";
import type { PendingConfirmation, Role, AccessGroup, AuditWebhook } from "../../types";
import { emptyAuditWebhookForm, emptyGroupForm, emptyRoleForm } from "../../lib/form-defaults";
import type { AuditWebhookForm } from "../security/AuditWebhookEditor";
import type { GroupEditorForm, RoleEditorForm } from "../security/AccessEditors";
import type { SecurityWorkspaceProps } from "../security/SecurityWorkspace";

type SecurityWorkspaceActionProps = Pick<SecurityWorkspaceProps,
  | "onStartTotpSetup" | "onConfirmTotpSetup" | "onDisableMfa" | "onRotateRecoveryCodes"
  | "onTotpSetupCodeChange" | "onSigningKeyKidChange" | "onRotateSigningKey"
  | "onSecurityPolicyChange" | "onSaveSecurityPolicy" | "onRoleChange" | "onGroupChange"
  | "onRoleSubmit" | "onGroupSubmit" | "onCloseEditor" | "onCreateRole" | "onEditRole"
  | "onDeleteRole" | "onSelectUser" | "onToggleUserRole" | "onSaveUserRoles"
  | "onCreateGroup" | "onEditGroup" | "onDeleteGroup" | "onAuditWebhookChange"
  | "onSaveAuditWebhook" | "onCancelAuditWebhook" | "onEditAuditWebhook" | "onDeleteAuditWebhook"
>;

type SecurityWorkspaceState = Omit<SecurityWorkspaceProps, keyof SecurityWorkspaceActionProps>;

type Options = SecurityWorkspaceState & {
  setEditor: (editor: "role" | "group" | null) => void;
  setRoleForm: (form: RoleEditorForm) => void;
  setRoleFormBaseline: (form: RoleEditorForm) => void;
  setGroupForm: (form: GroupEditorForm) => void;
  setGroupFormBaseline: (form: GroupEditorForm) => void;
  setUserAccess: (access: NonNullable<SecurityWorkspaceProps["userAccess"]>) => void;
  setAuditWebhookForm: (form: AuditWebhookForm) => void;
  setAuditWebhookFormBaseline: (form: AuditWebhookForm) => void;
  setTotpSetupCode: (value: string) => void;
  setSigningKeyKid: (value: string) => void;
  setSecurityPolicy: (value: NonNullable<SecurityWorkspaceProps["securityPolicy"]>) => void;
  setRoleFormValue: (form: RoleEditorForm) => void;
  setGroupFormValue: (form: GroupEditorForm) => void;
  requestConfirmation: (
    action: PendingConfirmation["action"],
    title?: string,
    description?: string
  ) => void;
  startTotpSetup: SecurityWorkspaceProps["onStartTotpSetup"];
  confirmTotpSetup: SecurityWorkspaceProps["onConfirmTotpSetup"];
  disableMfa: SecurityWorkspaceProps["onDisableMfa"];
  rotateRecoveryCodes: SecurityWorkspaceProps["onRotateRecoveryCodes"];
  rotateSigningKey: SecurityWorkspaceProps["onRotateSigningKey"];
  saveSecurityPolicy: SecurityWorkspaceProps["onSaveSecurityPolicy"];
  saveRole: SecurityWorkspaceProps["onRoleSubmit"];
  saveGroup: SecurityWorkspaceProps["onGroupSubmit"];
  saveUserRoles: SecurityWorkspaceProps["onSaveUserRoles"];
  editRole: (role: Role) => void;
  deleteRole: (id: string) => Promise<void>;
  editGroup: (group: AccessGroup) => void;
  deleteGroup: (id: string) => Promise<void>;
  saveAuditWebhook: SecurityWorkspaceProps["onSaveAuditWebhook"];
  editAuditWebhook: (webhook: AuditWebhook) => void;
  deleteAuditWebhook: (id: string) => Promise<void>;
  selectUser: (userId: string) => void;
  translate: (key: TranslationKey) => string;
};

export function useSecurityWorkspaceFacade({
  setEditor, setRoleForm, setRoleFormBaseline, setGroupForm, setGroupFormBaseline,
  setUserAccess, setAuditWebhookForm, setAuditWebhookFormBaseline, requestConfirmation,
  setTotpSetupCode, setSigningKeyKid, setSecurityPolicy, setRoleFormValue, setGroupFormValue,
  startTotpSetup, confirmTotpSetup, disableMfa, rotateRecoveryCodes, rotateSigningKey,
  saveSecurityPolicy, saveRole, saveGroup, saveUserRoles, editRole, deleteRole, editGroup,
  deleteGroup, saveAuditWebhook, editAuditWebhook, deleteAuditWebhook, selectUser, translate,
  ...state
}: Options): SecurityWorkspaceProps {
  return {
    ...state,
    translate,
    onStartTotpSetup: startTotpSetup,
    onConfirmTotpSetup: confirmTotpSetup,
    onDisableMfa: () => requestConfirmation(disableMfa, translate("disableMfa"), translate("disableMfaDescription")),
    onRotateRecoveryCodes: () => requestConfirmation(rotateRecoveryCodes, translate("rotateRecoveryCodes"), translate("rotateRecoveryCodesDescription")),
    onTotpSetupCodeChange: setTotpSetupCode,
    onSigningKeyKidChange: setSigningKeyKid,
    onRotateSigningKey: () => requestConfirmation(rotateSigningKey),
    onSecurityPolicyChange: setSecurityPolicy,
    onSaveSecurityPolicy: saveSecurityPolicy,
    onRoleChange: setRoleFormValue,
    onGroupChange: setGroupFormValue,
    onRoleSubmit: saveRole,
    onGroupSubmit: saveGroup,
    onCloseEditor: () => setEditor(null),
    onCreateRole: () => { setRoleForm(emptyRoleForm); setRoleFormBaseline(emptyRoleForm); setEditor("role"); },
    onEditRole: (role) => { editRole(role); setEditor("role"); },
    onDeleteRole: (role) => requestConfirmation(() => deleteRole(role.id)),
    onSelectUser: selectUser,
    onToggleUserRole: (role) => {
      if (!state.userAccess) return;
      const selected = state.userAccess.direct_roles.some((item) => item.id === role.id);
      setUserAccess({
        ...state.userAccess,
        direct_roles: selected
          ? state.userAccess.direct_roles.filter((item) => item.id !== role.id)
          : [...state.userAccess.direct_roles, role]
      });
    },
    onSaveUserRoles: saveUserRoles,
    onCreateGroup: () => { setGroupForm(emptyGroupForm); setGroupFormBaseline(emptyGroupForm); setEditor("group"); },
    onEditGroup: (group) => { editGroup(group); setEditor("group"); },
    onDeleteGroup: (group) => requestConfirmation(() => deleteGroup(group.id)),
    onAuditWebhookChange: setAuditWebhookForm,
    onSaveAuditWebhook: saveAuditWebhook,
    onCancelAuditWebhook: () => { setAuditWebhookForm(emptyAuditWebhookForm); setAuditWebhookFormBaseline(emptyAuditWebhookForm); },
    onEditAuditWebhook: editAuditWebhook,
    onDeleteAuditWebhook: (webhook) => requestConfirmation(() => deleteAuditWebhook(webhook.id))
  };
}
