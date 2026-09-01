import type { FormEvent } from "react";
import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { TranslationKey } from "../../i18n";
import { emptyUserForm } from "../../lib/form-defaults";
import * as adminApi from "../../lib/api/admin";
import type { UserDetail } from "../../types";

type UserFormState = typeof emptyUserForm;
type RunUiAction = (
  action: () => Promise<void>,
  fallback?: TranslationKey
) => Promise<boolean>;

type Options = {
  userForm: UserFormState;
  setUserForm: Dispatch<SetStateAction<UserFormState>>;
  setUserFormBaseline: Dispatch<SetStateAction<UserFormState | null>>;
  selectedUser: UserDetail | null;
  setSelectedUser: Dispatch<SetStateAction<UserDetail | null>>;
  setSelectedUserIds: Dispatch<SetStateAction<string[]>>;
  reloadUsers: () => Promise<void>;
  runUiAction: RunUiAction;
  clearEditor: () => void;
  setVerificationMessage: (message: string) => void;
  translate: (key: TranslationKey) => string;
};

export function useAdminUserActions({
  userForm,
  setUserForm,
  setUserFormBaseline,
  selectedUser,
  setSelectedUser,
  setSelectedUserIds,
  reloadUsers,
  runUiAction,
  clearEditor,
  setVerificationMessage,
  translate
}: Options) {
  const saveUser = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    await runUiAction(async () => {
      const body = {
        email: userForm.email,
        username: userForm.username,
        display_name: userForm.display_name || null,
        phone: userForm.phone || null,
        password: userForm.password || null,
        is_admin: userForm.is_admin,
        is_active: userForm.is_active
      };
      if (userForm.id) {
        await adminApi.updateAdminUser(userForm.id, body);
      } else {
        await adminApi.createAdminUser(body);
      }
      setUserForm(emptyUserForm);
      setUserFormBaseline(null);
      clearEditor();
      setVerificationMessage(translate("changesSaved"));
      await reloadUsers();
    }, "saveUserFailed");
  }, [
    reloadUsers,
    runUiAction,
    clearEditor,
    setUserForm,
    setUserFormBaseline,
    setVerificationMessage,
    translate,
    userForm
  ]);

  const enableUser = useCallback(async (id: string) => {
    const completed = await runUiAction(async () => {
      await adminApi.enableAdminUser(id);
      await reloadUsers();
      if (selectedUser?.user.id === id) setSelectedUser(null);
    });
    if (completed) setVerificationMessage(translate("operationCompleted"));
  }, [
    reloadUsers,
    runUiAction,
    selectedUser,
    setSelectedUser,
    setVerificationMessage,
    translate
  ]);

  const advanceUserLifecycle = useCallback(async (id: string) => {
    await adminApi.advanceAdminUserLifecycle(id);
    setSelectedUserIds((current) => current.filter((selectedId) => selectedId !== id));
    await reloadUsers();
    if (selectedUser?.user.id === id) setSelectedUser(null);
    if (userForm.id === id) {
      setUserForm(emptyUserForm);
      setUserFormBaseline(null);
    }
  }, [
    reloadUsers,
    selectedUser,
    setSelectedUser,
    setSelectedUserIds,
    setUserForm,
    setUserFormBaseline,
    userForm.id
  ]);

  return { saveUser, enableUser, advanceUserLifecycle };
}
