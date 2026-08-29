import { useCallback } from "react";

import type {
  ApplicationRequestBeginOptions,
  ApplicationRequestGuard,
  ApplicationRequestToken
} from "./application-request-guard";

export type ApplicationRequestLifecycleOptions = {
  applicationId: string;
  requestGuard: ApplicationRequestGuard;
};

export function useApplicationRequestLifecycle({
  applicationId,
  requestGuard
}: ApplicationRequestLifecycleOptions) {
  const beginRequest = useCallback(
    (scope: string, options: Omit<ApplicationRequestBeginOptions, "scope"> = {}) =>
      requestGuard.begin(applicationId, { ...options, scope }),
    [applicationId, requestGuard]
  );
  const isCurrent = useCallback(
    (request: ApplicationRequestToken) => requestGuard.isCurrent(request),
    [requestGuard]
  );
  const finishRequest = useCallback(
    (request: ApplicationRequestToken, committed = true) => requestGuard.finish(request, committed),
    [requestGuard]
  );

  return { beginRequest, isCurrent, finishRequest };
}
