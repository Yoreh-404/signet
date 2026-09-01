import { useCallback, useEffect, useRef } from "react";
import * as accountApi from "../../lib/api/account";
import type { MfaStatus, MyConsent, MySession, Passkey } from "../../types";
import type { SessionController } from "../session/useSessionController";

type AccountDataLoaderProps = {
  controller: SessionController;
  scopeKey: string | null;
  enabled?: boolean;
  onError?: (error: unknown) => void;
  setMfaStatus: (value: MfaStatus | null) => void;
  setPasskeys: (value: Passkey[]) => void;
  setMyConsents: (value: MyConsent[]) => void;
  setMySessions: (value: MySession[]) => void;
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

  const invalidate = useCallback(() => {
    accountLoadId.current += 1;
    accountAbortController.current?.abort();
    accountAbortController.current = null;
  }, [accountAbortController, accountLoadId]);

  const load = useCallback(async () => {
    const requestId = ++accountLoadId.current;
    accountAbortController.current?.abort();
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
        setMfaStatus(null);
        setPasskeys([]);
        setMyConsents([]);
        setMySessions([]);
        return;
      }
      const [nextMfaStatus, nextPasskeys, nextConsents, nextSessions] = await Promise.all([
        accountApi.getMfaStatus({ signal: abortController.signal }),
        accountApi.listPasskeys({ signal: abortController.signal }),
        accountApi.listConsents({ signal: abortController.signal }),
        accountApi.listSessions({ signal: abortController.signal })
      ]);
      if (!isCurrent()) return;
      setMfaStatus(nextMfaStatus);
      setPasskeys(nextPasskeys);
      setMyConsents(nextConsents);
      setMySessions(nextSessions);
    } catch (error) {
      if (!isCurrent()) return;
      throw error;
    } finally {
      if (accountAbortController.current === abortController) accountAbortController.current = null;
    }
  }, [
    accountAbortController,
    accountLoadId,
    sessionController,
    setMfaStatus,
    setMyConsents,
    setMySessions,
    setPasskeys
  ]);

  useEffect(() => {
    if (!enabled) {
      invalidate();
      return;
    }
    const loadScope = scopeKey;
    void load().catch((error) => {
      if (scopeKey === loadScope) onError?.(error);
    });
    return invalidate;
  }, [enabled, invalidate, load, onError, scopeKey]);

  return { load, invalidate };
}
