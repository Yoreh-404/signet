import { useCallback, useEffect, useMemo, useRef } from "react";
import * as accountApi from "../../lib/api/account";
import type { MfaStatus, MyConsent, MySession, Passkey } from "../../types";
import type { Dispatch, SetStateAction } from "react";
import type { SessionController } from "../session/useSessionController";
import { useAccountSecurityData, type AccountSecurityDataContract } from "./use-account-security-data";
import { useAccountSessions } from "./use-account-sessions";

type AccountDataLoaderProps = {
  controller: SessionController;
  scopeKey: string | null;
  enabled?: boolean;
  onError?: (error: unknown) => void;
  setMfaStatus: (value: MfaStatus | null) => void;
  setPasskeys: (value: Passkey[]) => void;
  setMyConsents: (value: MyConsent[]) => void;
  setMySessions: Dispatch<SetStateAction<MySession[]>>;
};

type AccountDataRefresh = {
  mfaStatus: boolean;
  passkeys: boolean;
  consents: boolean;
  sessions: boolean;
};

export function useAccountDataLoader({
  controller: sessionController,
  scopeKey,
  enabled = true,
  onError,
  setMfaStatus,
  setPasskeys,
  setMyConsents,
  setMySessions
}: AccountDataLoaderProps) {
  const accountLoadId = useRef(0);
  const accountAbortController = useRef<AbortController | null>(null);
  const {
    hasMore: hasMoreSessions,
    loadMore: loadMoreSessions,
    loadingMore: loadingMoreSessions,
    removeSession,
    replacePage: replaceSessionsPage,
    reset: resetSessions
  } = useAccountSessions({
    controller: sessionController,
    onError,
    setMySessions
  });
  const {
    clear: clearSecurityData,
    commit: commitSecurityData,
    load: loadSecurityData
  } = useAccountSecurityData({
    setMfaStatus,
    setPasskeys,
    setMyConsents
  });

  const invalidate = useCallback(() => {
    accountLoadId.current += 1;
    accountAbortController.current?.abort();
    accountAbortController.current = null;
    resetSessions();
  }, [resetSessions]);

  const reload = useCallback(async (refresh: AccountDataRefresh) => {
    const requestId = ++accountLoadId.current;
    accountAbortController.current?.abort();
    if (refresh.sessions) {
      resetSessions();
    }
    const abortController = new AbortController();
    accountAbortController.current = abortController;
    const started = sessionController.getSnapshot();
    const startedUserId = started.user?.id ?? null;
    const startedOrganizationId = started.organizationContext?.id ?? null;
    const startedScope = started.cacheScope;
    const startedSessionGeneration = sessionController.getGeneration();
    const isCurrent = () => {
      const current = sessionController.getSnapshot();
      return accountLoadId.current === requestId
        && !abortController.signal.aborted
        && sessionController.getGeneration() === startedSessionGeneration
        && current.cacheScope === startedScope
        && (current.user?.id ?? null) === startedUserId
        && (current.organizationContext?.id ?? null) === startedOrganizationId;
    };

    try {
      if (!started.user) {
        if (!isCurrent()) return;
        clearSecurityData(refresh);
        if (refresh.sessions) setMySessions([]);
        return;
      }
      const [nextSecurityData, nextSessions] = await Promise.all([
        loadSecurityData(refresh, abortController.signal),
        refresh.sessions
          ? accountApi.listSessionsPage({ signal: abortController.signal })
          : Promise.resolve(undefined)
      ]);
      if (!isCurrent()) return;
      commitSecurityData(nextSecurityData);
      if (nextSessions !== undefined) {
        replaceSessionsPage(nextSessions);
      }
    } catch (error) {
      if (!isCurrent()) return;
      throw error;
    } finally {
      if (accountAbortController.current === abortController) accountAbortController.current = null;
    }
  }, [
    sessionController,
    setMySessions,
    clearSecurityData,
    commitSecurityData,
    loadSecurityData,
    replaceSessionsPage,
    resetSessions
  ]);

  const reloadSessions = useCallback(
    () => reload({ mfaStatus: false, passkeys: false, consents: false, sessions: true }),
    [reload]
  );
  const reloadConsents = useCallback(
    () => reload({ mfaStatus: false, passkeys: false, consents: true, sessions: false }),
    [reload]
  );
  const reloadAll = useCallback(
    () => reload({ mfaStatus: true, passkeys: true, consents: true, sessions: true }),
    [reload]
  );
  const securityRefresh = useMemo(
    () => ({ all: reloadAll, consents: reloadConsents }),
    [reloadAll, reloadConsents]
  );
  const accountData = useMemo<AccountSecurityDataContract>(
    () => ({ securityRefresh, removeSession }),
    [removeSession, securityRefresh]
  );

  useEffect(() => {
    if (!enabled) {
      invalidate();
      return;
    }
    const loadScope = scopeKey;
    void reloadAll().catch((error) => {
      if (scopeKey === loadScope) onError?.(error);
    });
    return invalidate;
  }, [enabled, invalidate, onError, reloadAll, scopeKey]);

  return {
    accountData,
    hasMoreSessions,
    invalidate,
    load: reloadAll,
    loadMoreSessions,
    loadingMoreSessions,
    reloadAll,
    reloadSessions
  };
}
