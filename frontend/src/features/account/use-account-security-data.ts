import { useCallback } from "react";
import * as accountApi from "../../lib/api/account";
import type { MfaStatus, MyConsent, Passkey } from "../../types";

type AccountSecurityDataRefresh = {
  mfaStatus: boolean;
  passkeys: boolean;
  consents: boolean;
};

export type AccountSecurityRefresh = {
  all: () => Promise<void>;
  consents: () => Promise<void>;
};

export type AccountSecurityDataContract = {
  securityRefresh: AccountSecurityRefresh;
  removeSession: (id: string) => void;
};

type AccountSecurityDataOptions = {
  setMfaStatus: (value: MfaStatus | null) => void;
  setPasskeys: (value: Passkey[]) => void;
  setMyConsents: (value: MyConsent[]) => void;
};

type AccountSecurityDataPage = {
  mfaStatus: MfaStatus | undefined;
  passkeys: Passkey[] | undefined;
  consents: MyConsent[] | undefined;
};

export function useAccountSecurityData({
  setMfaStatus,
  setPasskeys,
  setMyConsents
}: AccountSecurityDataOptions) {
  const load = useCallback(async (
    refresh: AccountSecurityDataRefresh,
    signal: AbortSignal
  ): Promise<AccountSecurityDataPage> => {
    const [mfaStatus, passkeys, consents] = await Promise.all([
      refresh.mfaStatus
        ? accountApi.getMfaStatus({ signal })
        : Promise.resolve(undefined),
      refresh.passkeys
        ? accountApi.listPasskeys({ signal })
        : Promise.resolve(undefined),
      refresh.consents
        ? accountApi.listConsents({ signal })
        : Promise.resolve(undefined)
    ]);
    return { mfaStatus, passkeys, consents };
  }, []);

  const clear = useCallback((refresh: AccountSecurityDataRefresh) => {
    if (refresh.mfaStatus) setMfaStatus(null);
    if (refresh.passkeys) setPasskeys([]);
    if (refresh.consents) setMyConsents([]);
  }, [setMfaStatus, setMyConsents, setPasskeys]);

  const commit = useCallback((page: AccountSecurityDataPage) => {
    if (page.mfaStatus !== undefined) setMfaStatus(page.mfaStatus);
    if (page.passkeys !== undefined) setPasskeys(page.passkeys);
    if (page.consents !== undefined) setMyConsents(page.consents);
  }, [setMfaStatus, setMyConsents, setPasskeys]);

  return { clear, commit, load };
}
