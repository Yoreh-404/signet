import type { FormEvent } from "react";
import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { TranslationKey } from "../../i18n";
import { emptyGroupForm, emptyRoleForm } from "../../lib/form-defaults";
import * as adminApi from "../../lib/api/admin";
import type { AccessGroup, Role, UserAccess } from "../../types";

type RoleFormState = typeof emptyRoleForm;
type GroupFormState = typeof emptyGroupForm;
type RunUiAction = (
  action: () => Promise<void>,
  fallback?: TranslationKey
) => Promise<boolean>;

type Options = {
  roleForm: RoleFormState;
  setRoleForm: Dispatch<SetStateAction<RoleFormState>>;
  setRoleFormBaseline: Dispatch<SetStateAction<RoleFormState | null>>;
  groupForm: GroupFormState;
  setGroupForm: Dispatch<SetStateAction<GroupFormState>>;
  setGroupFormBaseline: Dispatch<SetStateAction<GroupFormState | null>>;
  selectedAccessUserId: string;
  userAccess: UserAccess | null;
  setUserAccess: Dispatch<SetStateAction<UserAccess | null>>;
  loadAdminData: () => Promise<void>;
  loadUserAccess: (id: string) => Promise<void>;
  runUiAction: RunUiAction;
  clearEditor: () => void;
  setVerificationMessage: (message: string) => void;
  translate: (key: TranslationKey) => string;
};

export function useAdminAccessActions({
  roleForm,
  setRoleForm,
  setRoleFormBaseline,
  groupForm,
  setGroupForm,
  setGroupFormBaseline,
  selectedAccessUserId,
  userAccess,
  setUserAccess,
  loadAdminData,
  loadUserAccess,
  runUiAction,
  clearEditor,
  setVerificationMessage,
  translate
}: Options) {
  const editRole = useCallback((role: Role) => {
    if (role.is_system) return;
    const nextForm = {
      id: role.id,
      name: role.name,
      description: role.description ?? "",
      permissions: role.permissions
    };
    setRoleForm(nextForm);
    setRoleFormBaseline(nextForm);
  }, [setRoleForm, setRoleFormBaseline]);

  const editGroup = useCallback((group: AccessGroup) => {
    const nextForm = {
      id: group.id,
      name: group.name,
      description: group.description ?? "",
      role_ids: (group.roles ?? []).map((role) => role.id),
      user_ids: (group.members ?? []).map((member) => member.id)
    };
    setGroupForm(nextForm);
    setGroupFormBaseline(nextForm);
  }, [setGroupForm, setGroupFormBaseline]);

  const refreshAccess = useCallback(async () => {
    await loadAdminData();
    if (selectedAccessUserId) await loadUserAccess(selectedAccessUserId);
  }, [loadAdminData, loadUserAccess, selectedAccessUserId]);

  const saveRole = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    await runUiAction(async () => {
      const body = {
        name: roleForm.name,
        description: roleForm.description || null,
        permissions: roleForm.permissions
      };
      if (roleForm.id) await adminApi.updateAdminRole(roleForm.id, body);
      else await adminApi.createAdminRole(body);
      setRoleForm(emptyRoleForm);
      setRoleFormBaseline(null);
      clearEditor();
      setVerificationMessage(translate("changesSaved"));
      await refreshAccess();
    }, "saveRoleFailed");
  }, [
    clearEditor,
    refreshAccess,
    roleForm,
    runUiAction,
    setRoleForm,
    setRoleFormBaseline,
    setVerificationMessage,
    translate
  ]);

  const deleteRole = useCallback(async (id: string) => {
    await runUiAction(async () => {
      await adminApi.deleteAdminRole(id);
      if (roleForm.id === id) {
        setRoleForm(emptyRoleForm);
        setRoleFormBaseline(null);
      }
      await refreshAccess();
    });
  }, [refreshAccess, roleForm.id, runUiAction, setRoleForm, setRoleFormBaseline]);

  const saveGroup = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    await runUiAction(async () => {
      const body = {
        name: groupForm.name,
        description: groupForm.description || null
      };
      const group = groupForm.id
        ? await adminApi.updateAdminGroup(groupForm.id, body)
        : await adminApi.createAdminGroup(body);
      await adminApi.updateAdminGroupRoles(group.id, groupForm.role_ids);
      await adminApi.updateAdminGroupMembers(group.id, groupForm.user_ids);
      setGroupForm(emptyGroupForm);
      setGroupFormBaseline(null);
      clearEditor();
      setVerificationMessage(translate("changesSaved"));
      await refreshAccess();
    }, "saveGroupFailed");
  }, [
    clearEditor,
    groupForm,
    refreshAccess,
    runUiAction,
    setGroupForm,
    setGroupFormBaseline,
    setVerificationMessage,
    translate
  ]);

  const deleteGroup = useCallback(async (id: string) => {
    await runUiAction(async () => {
      await adminApi.deleteAdminGroup(id);
      if (groupForm.id === id) {
        setGroupForm(emptyGroupForm);
        setGroupFormBaseline(null);
      }
      await refreshAccess();
    });
  }, [groupForm.id, refreshAccess, runUiAction, setGroupForm, setGroupFormBaseline]);

  const saveUserRoles = useCallback(async () => {
    if (!selectedAccessUserId || !userAccess) return;
    const completed = await runUiAction(async () => {
      const updated = await adminApi.updateAdminUserRoles(
        selectedAccessUserId,
        userAccess.direct_roles.map((role) => role.id)
      );
      setUserAccess(updated);
      await loadAdminData();
    });
    if (completed) setVerificationMessage(translate("changesSaved"));
  }, [
    loadAdminData,
    runUiAction,
    selectedAccessUserId,
    setUserAccess,
    setVerificationMessage,
    translate,
    userAccess
  ]);

  return { editRole, editGroup, saveRole, deleteRole, saveGroup, deleteGroup, saveUserRoles };
}
