import { createContext, createElement, useContext, useMemo, type ReactNode } from "react";

import type {
  ApplicationRequestBeginOptions,
  ApplicationRequestOptions,
  ApplicationRequestGuard,
  ApplicationRequestToken
} from "./application-request-guard";
import { applicationRequestOptions } from "./application-request-guard";

export type ApplicationWorkspaceRequestContextValue = {
  requestGuard: ApplicationRequestGuard;
  beginRequest: (
    scope: string,
    options?: Omit<ApplicationRequestBeginOptions, "scope">
  ) => ApplicationRequestToken | null;
  isCurrent: (request: ApplicationRequestToken) => boolean;
  finishRequest: (request: ApplicationRequestToken, committed?: boolean) => void;
  requestOptions: (request: ApplicationRequestToken) => ApplicationRequestOptions;
};

export type ApplicationWorkspaceRequestApi = Pick<
  ApplicationWorkspaceRequestContextValue,
  "beginRequest" | "isCurrent" | "finishRequest" | "requestOptions"
>;

const ApplicationWorkspaceRequestContext = createContext<ApplicationWorkspaceRequestContextValue | null>(null);

export function ApplicationWorkspaceRequestContextProvider({
  applicationId,
  requestGuard,
  children
}: {
  applicationId: string;
  requestGuard: ApplicationRequestGuard;
  children: ReactNode;
}) {
  const value = useMemo<ApplicationWorkspaceRequestContextValue>(() => ({
    requestGuard,
    beginRequest: (scope, options = {}) => requestGuard.begin(applicationId, { ...options, scope }),
    isCurrent: (request) => requestGuard.isCurrent(request),
    finishRequest: (request, committed = true) => requestGuard.finish(request, committed),
    requestOptions: (request) => applicationRequestOptions(request)
  }), [applicationId, requestGuard]);

  return createElement(ApplicationWorkspaceRequestContext.Provider, { value }, children);
}

export function useApplicationWorkspaceRequestContext(): ApplicationWorkspaceRequestContextValue {
  const context = useContext(ApplicationWorkspaceRequestContext);
  if (!context) {
    throw new Error("useApplicationWorkspaceRequestContext must be used inside its provider");
  }
  return context;
}
