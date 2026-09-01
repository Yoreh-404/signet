import { useMemo } from "react";
import type { User } from "../../types";
import {
  availableUserActions,
  lifecycleStateForUser
} from "./user-lifecycle";
import type { BulkUserAction } from "./user-lifecycle";

type ManagedUser = Pick<User, "id" | "is_active" | "archived_at">;

export function useUserBulkActions(
  selectedUsers: ManagedUser[],
  currentUserId: string | undefined,
  selectedUsersAreCurrent: boolean
) {
  return useMemo(() => {
    const snapshots = selectedUsers.map((user) => ({
      lifecycleState: lifecycleStateForUser(user),
      actions: availableUserActions(user, currentUserId)
    }));
    const selectedLifecycleState = snapshots[0]?.lifecycleState ?? null;
    const selectedUsersShareLifecycleState = Boolean(
      selectedUsersAreCurrent
      && selectedLifecycleState
      && snapshots.every(({ lifecycleState }) => lifecycleState === selectedLifecycleState)
    );
    const sharedLifecycleActions: BulkUserAction[] = selectedUsersShareLifecycleState
      ? snapshots.reduce<BulkUserAction[] | null>((shared, snapshot) => {
        if (!shared) return null;
        return shared.filter((action) => action !== "reset_mfa" && snapshot.actions.includes(action));
      }, snapshots[0]?.actions.filter((action) => action !== "reset_mfa") ?? []) ?? []
      : [];
    const canResetMfa = selectedUsersAreCurrent
      && selectedUsers.length > 0
      && snapshots.every(({ actions }) => actions.includes("reset_mfa"));

    return {
      availableActions: [
        ...sharedLifecycleActions,
        ...(canResetMfa ? ["reset_mfa" as const] : [])
      ] as BulkUserAction[]
    };
  }, [currentUserId, selectedUsers, selectedUsersAreCurrent]);
}
