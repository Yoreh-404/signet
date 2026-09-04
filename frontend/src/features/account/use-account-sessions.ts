import { useCallback, useRef, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import * as accountApi from "../../lib/api/account";
import type { MySession } from "../../types";
import type { SessionController } from "../session/useSessionController";

type AccountSessionsOptions = {
  controller: SessionController;
  onError?: (error: unknown) => void;
  setMySessions: Dispatch<SetStateAction<MySession[]>>;
};

export function useAccountSessions({ controller, onError, setMySessions }: AccountSessionsOptions) {
  const sessionsMoreAbortController = useRef<AbortController | null>(null);
  const sessionsCursor = useRef<string | null>(null);
  const sessionsMoreLoading = useRef(false);
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);

  const reset = useCallback(() => {
    sessionsMoreAbortController.current?.abort();
    sessionsMoreAbortController.current = null;
    sessionsMoreLoading.current = false;
    sessionsCursor.current = null;
    setHasMore(false);
    setLoadingMore(false);
  }, []);

  const replacePage = useCallback((page: accountApi.MySessionPage) => {
    setMySessions(page.sessions);
    sessionsCursor.current = page.nextCursor;
    setHasMore(page.nextCursor !== null);
  }, [setMySessions]);

  const removeSession = useCallback((sessionId: string) => {
    setMySessions((current) => current.filter((session) => session.id !== sessionId));
  }, [setMySessions]);

  const loadMore = useCallback(async () => {
    const cursor = sessionsCursor.current;
    if (!cursor || sessionsMoreLoading.current) return;

    const started = controller.getSnapshot();
    const startedUserId = started.user?.id ?? null;
    const startedOrganizationId = started.organizationContext?.id ?? null;
    const startedScope = started.cacheScope;
    const startedSessionGeneration = controller.getGeneration();
    const abortController = new AbortController();
    sessionsMoreAbortController.current = abortController;
    sessionsMoreLoading.current = true;
    setLoadingMore(true);
    const isCurrent = () => {
      const current = controller.getSnapshot();
      return !abortController.signal.aborted
        && controller.getGeneration() === startedSessionGeneration
        && current.cacheScope === startedScope
        && (current.user?.id ?? null) === startedUserId
        && (current.organizationContext?.id ?? null) === startedOrganizationId
        && sessionsCursor.current === cursor;
    };

    try {
      const page = await accountApi.listSessionsPage({ cursor, signal: abortController.signal });
      if (!isCurrent()) return;
      setMySessions((current) => [...current, ...page.sessions]);
      sessionsCursor.current = page.nextCursor;
      setHasMore(page.nextCursor !== null);
    } catch (error) {
      if (!abortController.signal.aborted) onError?.(error);
    } finally {
      if (sessionsMoreAbortController.current === abortController) {
        sessionsMoreAbortController.current = null;
        sessionsMoreLoading.current = false;
        setLoadingMore(false);
      }
    }
  }, [controller, onError, setMySessions]);

  return { hasMore, loadMore, loadingMore, removeSession, replacePage, reset };
}
