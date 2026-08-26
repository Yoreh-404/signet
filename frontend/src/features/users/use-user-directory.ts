import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { UserDirectoryCursorPage, UserDirectoryPage, UserDirectoryQuery } from "../../types";
import {
  fetchUserDirectoryCursorPage,
  fetchUserDirectoryPage,
  normalizeUserDirectoryQuery,
  serializeUserDirectoryQuery
} from "./user-directory";
import type { UserDirectoryQueryInput } from "./user-directory";

export type UseUserDirectoryOptions = {
  /** Explicit integration seam for whichever backend route is selected. */
  endpoint: string;
  query: UserDirectoryQueryInput;
  enabled?: boolean;
  /** Re-run the loader when the authenticated account/tenant scope changes. */
  scopeKey?: string | null;
};

export type UserDirectoryQueryState = {
  data: UserDirectoryPage | null;
  loading: boolean;
  error: unknown | null;
};

export type UseUserDirectoryResult = UserDirectoryQueryState & {
  query: UserDirectoryQuery;
  queryString: string;
  reload: () => Promise<void>;
};

export type UserDirectoryCursorQueryState = {
  data: UserDirectoryCursorPage | null;
  loading: boolean;
  error: unknown | null;
};

export type UseUserDirectoryCursorResult = UserDirectoryCursorQueryState & {
  query: UserDirectoryQuery;
  queryString: string;
  reload: () => Promise<void>;
};

function isAbortError(error: unknown): boolean {
  return typeof DOMException !== "undefined"
    && error instanceof DOMException
    && error.name === "AbortError"
    || (error instanceof Error && error.name === "AbortError");
}

type DirectoryFetch<T> = (
  endpoint: string,
  query: UserDirectoryQueryInput,
  signal?: AbortSignal
) => Promise<T>;

function useDirectoryQuery<T>(
  { endpoint, query, enabled = true, scopeKey = null }: UseUserDirectoryOptions,
  fetchPage: DirectoryFetch<T>
): { data: T | null; loading: boolean; error: unknown | null; query: UserDirectoryQuery; queryString: string; reload: () => Promise<void> } {
  const normalizedQuery = useMemo(() => normalizeUserDirectoryQuery(query), [query]);
  const queryString = useMemo(() => serializeUserDirectoryQuery(normalizedQuery), [normalizedQuery]);
  const [state, setState] = useState<{ data: T | null; loading: boolean; error: unknown | null }>({
    data: null,
    loading: false,
    error: null
  });
  const requestSequence = useRef(0);
  const renderedScope = useRef(scopeKey);
  const scopeChanged = renderedScope.current !== scopeKey;
  if (scopeChanged) {
    // Effects run after paint. Invalidate the old sequence during render so a
    // tenant/account switch cannot briefly render the previous directory.
    renderedScope.current = scopeKey;
    requestSequence.current += 1;
  }
  const renderedQuery = useRef(queryString);
  const queryChanged = renderedQuery.current !== queryString;
  if (queryChanged) {
    // Do not let the previous page remain visible while the canonical query
    // is moving to a new cursor/filter result. The effect below owns the
    // actual fetch and will either publish the new page or its error.
    renderedQuery.current = queryString;
    requestSequence.current += 1;
  }

  const activeController = useRef<AbortController | null>(null);

  const load = useCallback(async (): Promise<void> => {
    activeController.current?.abort();
    const controller = new AbortController();
    activeController.current = controller;
    const sequence = ++requestSequence.current;
    setState((current) => ({ ...current, loading: true, error: null }));
    try {
      const data = await fetchPage(endpoint, normalizedQuery, controller.signal);
      if (sequence !== requestSequence.current || controller.signal.aborted) return;
      setState({ data, loading: false, error: null });
    } catch (error) {
      if (sequence !== requestSequence.current || controller.signal.aborted || isAbortError(error)) return;
      setState((current) => ({ ...current, loading: false, error }));
    } finally {
      if (activeController.current === controller) activeController.current = null;
    }
  }, [endpoint, fetchPage, normalizedQuery]);

  useEffect(() => {
    if (!enabled) {
      requestSequence.current += 1;
      setState((current) => current.loading ? { ...current, loading: false } : current);
      return;
    }
    void load();
    return () => {
      activeController.current?.abort();
      activeController.current = null;
      requestSequence.current += 1;
    };
  }, [enabled, load, scopeKey]);

  const reload = useCallback(() => load(), [load]);
  const transient = scopeChanged || queryChanged;
  return {
    ...(transient
      ? { data: null, loading: enabled, error: null }
      : state),
    query: normalizedQuery,
    queryString,
    reload
  };
}

/**
 * Fetches one user-directory page whenever the endpoint or canonical query
 * changes. Older requests are aborted and also sequence-checked so a server
 * response that wins a race cannot replace newer filter results.
 */
export function useUserDirectory({ endpoint, query, enabled = true, scopeKey = null }: UseUserDirectoryOptions): UseUserDirectoryResult {
  return useDirectoryQuery<UserDirectoryPage>(
    { endpoint, query, enabled, scopeKey },
    fetchUserDirectoryPage
  );
}

/** Same race-safe loader for the bounded keyset/cursor directory endpoint. */
export function useUserDirectoryCursor({ endpoint, query, enabled = true, scopeKey = null }: UseUserDirectoryOptions): UseUserDirectoryCursorResult {
  return useDirectoryQuery<UserDirectoryCursorPage>(
    { endpoint, query, enabled, scopeKey },
    fetchUserDirectoryCursorPage
  );
}
