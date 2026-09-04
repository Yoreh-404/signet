import type { AuthMode, Locale } from "../../types";
import { useAuthBootstrapActions } from "./use-auth-bootstrap-actions";
import { useSessionController } from "../session/useSessionController";

type Options = {
  returnTo: string | null;
  setLocale: (locale: Locale) => void;
  setAuthMode: (mode: AuthMode) => void;
  setInitialLoadError: (message: string) => void;
  formatError: (error: unknown, fallback: "loadFailed") => string;
};

export function useAuthSessionBootstrap({
  returnTo,
  setLocale,
  setAuthMode,
  setInitialLoadError,
  formatError
}: Options) {
  const session = useSessionController({ returnTo });
  const { initialize: initializeSession, loadBootstrap: loadSessionBootstrap } = session;
  const { initialize, loadBootstrap } = useAuthBootstrapActions({
    returnTo,
    autoInitialize: true,
    loadSessionBootstrap,
    initializeSession,
    transitionToAnonymous: session.transitionToAnonymous,
    setLocale,
    setAuthMode,
    setInitialLoadError,
    formatError
  });

  return {
    ...session,
    initialize,
    loadBootstrap
  };
}
