import { useCallback, useEffect, useRef } from "react";

import type { AuthMode, Bootstrap, Locale } from "../../types";

type SessionState = {
  bootstrap: Bootstrap | null;
};

type AuthBootstrapActionsOptions = {
  returnTo: string | null;
  autoInitialize?: boolean;
  loadSessionBootstrap: (returnTo?: string | null) => Promise<Bootstrap>;
  initializeSession: (options?: { returnTo?: string | null }) => Promise<SessionState>;
  transitionToAnonymous: () => unknown;
  setLocale: (locale: Locale) => void;
  setAuthMode: (mode: AuthMode) => void;
  setInitialLoadError: (message: string) => void;
  formatError: (error: unknown, fallback: "loadFailed") => string;
};

export function useAuthBootstrapActions({
  returnTo,
  autoInitialize = false,
  loadSessionBootstrap,
  initializeSession,
  transitionToAnonymous,
  setLocale,
  setAuthMode,
  setInitialLoadError,
  formatError
}: AuthBootstrapActionsOptions) {
  const initializedRef = useRef(false);
  const applyBootstrapDefaults = useCallback((bootstrap: Bootstrap | null | undefined) => {
    if (!bootstrap) return;
    if (!localStorage.getItem("gpt-sso-locale") && bootstrap.default_locale === "en-US") {
      setLocale("en-US");
    }
    if (!bootstrap.has_users) setAuthMode("register");
  }, [setAuthMode, setLocale]);

  const loadBootstrap = useCallback(async () => {
    const bootstrap = await loadSessionBootstrap(returnTo);
    applyBootstrapDefaults(bootstrap);
  }, [applyBootstrapDefaults, loadSessionBootstrap, returnTo]);

  const initialize = useCallback(async () => {
    setInitialLoadError("");
    try {
      const state = await initializeSession({ returnTo });
      applyBootstrapDefaults(state.bootstrap);
      return state;
    } catch (error) {
      transitionToAnonymous();
      setInitialLoadError(formatError(error, "loadFailed"));
      return null;
    }
  }, [applyBootstrapDefaults, formatError, initializeSession, returnTo, setInitialLoadError, transitionToAnonymous]);

  useEffect(() => {
    if (!autoInitialize || initializedRef.current) return;
    initializedRef.current = true;
    void initialize();
  }, [autoInitialize, initialize]);

  return { initialize, loadBootstrap };
}
