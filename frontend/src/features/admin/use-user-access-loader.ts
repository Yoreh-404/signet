import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";

import * as adminApi from "../../lib/api/admin";
import type { UserAccess } from "../../types";
import { useLatestRequest } from "./use-latest-request";

type Options = {
  setSelectedAccessUserId: Dispatch<SetStateAction<string>>;
  setUserAccess: Dispatch<SetStateAction<UserAccess | null>>;
};

export function useUserAccessLoader({ setSelectedAccessUserId, setUserAccess }: Options) {
  const { begin } = useLatestRequest();

  const loadUserAccess = useCallback(async (id: string) => {
    const current = begin();
    setSelectedAccessUserId(id);
    setUserAccess(null);
    if (!id) return;
    try {
      const access = await adminApi.getAdminUserAccess(id, {
        signal: current.signal,
        force: true
      });
      if (current.isCurrent()) setUserAccess(access);
    } catch (error) {
      if (current.isCurrent()) throw error;
    }
  }, [begin, setSelectedAccessUserId, setUserAccess]);

  return loadUserAccess;
}
