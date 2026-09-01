import { useCallback } from "react";
import type { Dispatch, MutableRefObject, SetStateAction } from "react";

import type { TranslationKey } from "../../i18n";
import type { User } from "../../types";
import type { BulkLifecycleMutation } from "./bulk-lifecycle";
import { resolveBulkLifecycleMutationKey } from "./bulk-lifecycle";
import type { BulkUserAction } from "./user-lifecycle";

type RequestConfirmation = (
  action: () => Promise<void>,
  title?: string,
  description?: string
) => void;

type Options = {
  selectedUsers: readonly Pick<User, "id">[];
  selectedUserIds: readonly string[];
  availableActions: readonly BulkUserAction[];
  mutationRef: MutableRefObject<BulkLifecycleMutation | null>;
  requestConfirmation: RequestConfirmation;
  applyLifecycle: (
    action: BulkUserAction,
    userIds: string[],
    options: { idempotencyKey: string }
  ) => Promise<unknown>;
  setSelectedUserIds: Dispatch<SetStateAction<string[]>>;
  reloadUsers: () => Promise<void>;
  setVerificationMessage: Dispatch<SetStateAction<string>>;
  translate: (key: TranslationKey) => string;
};

function actionTitleKey(action: BulkUserAction): TranslationKey {
  switch (action) {
    case "enable": return "bulkEnable";
    case "disable": return "bulkDisable";
    case "archive": return "bulkArchive";
    case "delete": return "bulkDelete";
    case "reset_mfa": return "bulkResetMfa";
  }
}

export function useBulkUserLifecycleAction({
  selectedUsers,
  selectedUserIds,
  availableActions,
  mutationRef,
  requestConfirmation,
  applyLifecycle,
  setSelectedUserIds,
  reloadUsers,
  setVerificationMessage,
  translate
}: Options) {
  const requestBulkAction = useCallback((action: BulkUserAction) => {
    if (!availableActions.includes(action)) return;
    const targetIds = selectedUsers.map((user) => user.id);
    if (targetIds.length === 0 || targetIds.length !== selectedUserIds.length) return;
    const targetIdSet = new Set(targetIds);
    const idempotencyKey = resolveBulkLifecycleMutationKey(
      mutationRef.current,
      action,
      targetIds,
      () => `ui-bulk-lifecycle-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`}`
    );
    mutationRef.current = { action, userIds: [...targetIds], key: idempotencyKey };
    requestConfirmation(async () => {
      await applyLifecycle(action, targetIds, { idempotencyKey });
      setSelectedUserIds((current) => current.filter((id) => !targetIdSet.has(id)));
      await reloadUsers();
      setVerificationMessage(translate("bulkActionCompleted"));
      mutationRef.current = null;
    }, translate(actionTitleKey(action)));
  }, [
    applyLifecycle,
    availableActions,
    mutationRef,
    reloadUsers,
    requestConfirmation,
    selectedUserIds,
    selectedUsers,
    setSelectedUserIds,
    setVerificationMessage,
    translate
  ]);

  return { requestBulkAction };
}
