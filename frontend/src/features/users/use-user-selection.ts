import { useCallback, useMemo } from "react";
import type { Dispatch, SetStateAction } from "react";

export type UserSelectionItem = { id: string };

export type UserSelectionOptions<T extends UserSelectionItem> = {
  users: T[];
  visibleUsers: T[];
  selectedIds: string[];
  setSelectedIds: Dispatch<SetStateAction<string[]>>;
};

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
    const visibleIds = visibleUsers.map((user) => user.id);
    const visibleIdSet = new Set(visibleIds);
    setSelectedIds((current) => {
      if (selected) return [...new Set([...current, ...visibleIds])];
      return current.filter((id) => !visibleIdSet.has(id));
    });
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
