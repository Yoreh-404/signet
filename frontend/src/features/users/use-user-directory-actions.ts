import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";

import { appendUserDirectoryCursor } from "./user-directory";

type Options = {
  activePage: number;
  nextCursor: string | null;
  setPage: Dispatch<SetStateAction<number>>;
  setCursorHistory: Dispatch<SetStateAction<Array<string | null>>>;
  setSelectedIds: Dispatch<SetStateAction<string[]>>;
};

export function useUserDirectoryActions({
  activePage,
  nextCursor,
  setPage,
  setCursorHistory,
  setSelectedIds
}: Options) {
  const clearSelection = useCallback(() => {
    setSelectedIds([]);
  }, [setSelectedIds]);

  const previousPage = useCallback(() => {
    clearSelection();
    setPage((page) => Math.max(1, page - 1));
  }, [clearSelection, setPage]);

  const nextPage = useCallback(() => {
    if (!nextCursor) return;
    clearSelection();
    setCursorHistory((history) => appendUserDirectoryCursor(history, activePage, nextCursor));
    setPage((page) => page + 1);
  }, [activePage, clearSelection, nextCursor, setCursorHistory, setPage]);

  return { clearSelection, previousPage, nextPage };
}
