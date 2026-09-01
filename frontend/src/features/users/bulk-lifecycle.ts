import type { BulkUserAction } from "./user-lifecycle";

export type BulkLifecycleMutation = {
  action: BulkUserAction;
  userIds: readonly string[];
  key: string;
};

export function sameUserIdSet(
  left: readonly string[],
  right: readonly string[]
): boolean {
  if (left.length !== right.length) return false;
  const rightIds = new Set(right);
  return left.every((id) => rightIds.has(id));
}

export function resolveBulkLifecycleMutationKey(
  previous: BulkLifecycleMutation | null,
  action: BulkUserAction,
  userIds: readonly string[],
  createKey: () => string
): string {
  if (previous?.action === action && sameUserIdSet(previous.userIds, userIds)) {
    return previous.key;
  }
  return createKey();
}
