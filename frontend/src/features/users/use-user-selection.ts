import { useCallback, useMemo } from "react";
import type { Dispatch, SetStateAction } from "react";

export type UserSelectionItem = { id: string };

export type UserSelectionOptions<T extends UserSelectionItem> = {
  users: T[];
  visibleUsers: T[];
  selectedIds: string[];
  setSelectedIds: Dispatch<SetStateAction<string[]>>;
};

export function updateVisibleUserSelection<T extends UserSelectionItem>(
  currentIds: string[],
  visibleUsers: T[],
  selected: boolean
): string[] {
  if (selected) {
    const next = new Set(currentIds);
    for (const user of visibleUsers) next.add(user.id);
    return [...next];
  }

  const visibleIdSet = new Set<string>();
  for (const user of visibleUsers) visibleIdSet.add(user.id);
  return currentIds.filter((id) => !visibleIdSet.has(id));
}

/**
 * Owns page selection mechanics separately from lifecycle commands. The
 * shell can decide what actions are allowed, while this hook only guarantees
 * stable selection semantics and O(1) membership checks during rendering.
 */
export function useUserSelection<T extends UserSelectionItem>({
  users,
  visibleUsers,
  selectedIds,
  setSelectedIds
}: UserSelectionOptions<T>) {
  const selectedIdSet = useMemo(() => new Set(selectedIds), [selectedIds]);
  const selectedUsers = useMemo(
    () => users.filter((user) => selectedIdSet.has(user.id)),
    [selectedIdSet, users]
  );
  const allVisibleSelected = visibleUsers.length > 0
    && visibleUsers.every((user) => selectedIdSet.has(user.id));

  const toggle = useCallback((id: string) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return [...next];
    });
  }, [setSelectedIds]);

  const toggleVisible = useCallback((selected: boolean) => {
    setSelectedIds((current) => updateVisibleUserSelection(current, visibleUsers, selected));
  }, [setSelectedIds, visibleUsers]);

  return {
    selectedIdSet,
    selectedUsers,
    selectedIdsAreCurrent: selectedUsers.length === selectedIds.length,
    allVisibleSelected,
    toggle,
    toggleVisible
  };
}
