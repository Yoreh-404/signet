import { useRef, useSyncExternalStore } from "react";

import { api, setApiCacheScope } from "../../lib/api";
import type { ApiRequestInit } from "../../lib/api";
import type {
  Bootstrap,
  OrganizationContext,
  User,
  UserOrganization
} from "../../types";

export type SessionRequest = <T>(path: string, options?: ApiRequestInit) => Promise<T>;

export type SessionStatus = "unknown" | "anonymous" | "authenticated";
export type SessionPhase = "idle" | "loading" | "ready" | "error";

export type SessionControllerState = {
  bootstrap: Bootstrap | null;
  /** `undefined` means that `/api/me` has not completed yet. */
  user: User | null | undefined;
  myOrganizations: UserOrganization[];
  organizationContext: UserOrganization | null;
  organizationContextReady: boolean;
  cacheScope: string | null;
  sessionStatus: SessionStatus;
  phase: SessionPhase;
  error: unknown | null;
};

export type SessionOrganizationState = {
  myOrganizations: UserOrganization[];
  organizationContext: UserOrganization | null;
};

export type SessionControllerOptions = {
  /** Passed to the public bootstrap endpoint when an auth flow needs it. */
  returnTo?: string | null;
  /** Injectable for tests or an alternate same-origin transport. */
  request?: SessionRequest;
  /** Injectable so the controller does not own the cache implementation. */
  setCacheScope?: (scope: string | null) => void;
  initialState?: Partial<SessionControllerState>;
};

export type InitializeSessionOptions = {
  returnTo?: string | null;
};

export type AuthenticatedTransitionOptions = {
  /** Set false when the caller will load organization state separately. */
  loadOrganizationContext?: boolean;
};

export interface SessionController {
  getSnapshot(): SessionControllerState;
  /** Monotonic session/organization operation id for stale request guards. */
  getGeneration(): number;
  subscribe(listener: () => void): () => void;
  initialize(options?: InitializeSessionOptions): Promise<SessionControllerState>;
  loadBootstrap(returnTo?: string | null): Promise<Bootstrap>;
  loadUser(): Promise<User | null>;
  loadOrganizationContext(userId?: string): Promise<SessionOrganizationState>;
  switchOrganization(organizationId: string): Promise<OrganizationContext>;
  transitionToAuthenticated(
    user: User,
    options?: AuthenticatedTransitionOptions
  ): Promise<SessionControllerState>;
  transitionToAnonymous(): SessionControllerState;
  refresh(options?: InitializeSessionOptions): Promise<SessionControllerState>;
}

export type SessionControllerHookResult = SessionControllerState & {
  controller: SessionController;
} & Pick<
    SessionController,
    | "initialize"
    | "loadBootstrap"
    | "loadUser"
    | "loadOrganizationContext"
    | "switchOrganization"
    | "transitionToAuthenticated"
    | "transitionToAnonymous"
    | "refresh"
  >;

const DEFAULT_STATE: SessionControllerState = {
  bootstrap: null,
  user: undefined,
  myOrganizations: [],
  organizationContext: null,
  organizationContextReady: false,
  cacheScope: null,
  sessionStatus: "unknown",
  phase: "idle",
  error: null
};

function sessionStatusFor(user: User | null | undefined): SessionStatus {
  if (user === undefined) return "unknown";
  return user ? "authenticated" : "anonymous";
}

function isAbortError(error: unknown): boolean {
  return (typeof DOMException !== "undefined"
    && error instanceof DOMException
    && error.name === "AbortError")
    || (error instanceof Error && error.name === "AbortError");
}

function bootstrapPath(returnTo: string | null | undefined, defaultReturnTo: string | null | undefined): string {
  const target = returnTo === undefined ? defaultReturnTo : returnTo;
  return target
    ? `/api/public/bootstrap?return_to=${encodeURIComponent(target)}`
    : "/api/public/bootstrap";
}

function organizationScope(userId: string | null | undefined, organizationId: string | null | undefined): string {
  return `${userId ?? "anonymous"}:${organizationId ?? "none"}`;
}

function cloneInitialState(initialState: Partial<SessionControllerState> | undefined): SessionControllerState {
  const next = { ...DEFAULT_STATE, ...initialState };
  return {
    ...next,
    myOrganizations: [...(next.myOrganizations ?? [])],
    sessionStatus: sessionStatusFor(next.user)
  };
}

/**
 * Creates the session state machine without React or automatic network work.
 * The only browser-wide mutation it performs is the injected cache-scope
 * update after an explicit session or organization transition.
 */
export function createSessionController(options: SessionControllerOptions = {}): SessionController {
  const request = options.request ?? api;
  const updateCacheScope = options.setCacheScope ?? setApiCacheScope;
  const defaultReturnTo = options.returnTo;
  const listeners = new Set<() => void>();
  let state = cloneInitialState(options.initialState);
  let generation = 0;
  let bootstrapGeneration = 0;
  let bootstrapAbortController: AbortController | null = null;

  function notify() {
    for (const listener of listeners) listener();
  }

  function patch(next: Partial<SessionControllerState>) {
    const nextUser = next.user === undefined ? state.user : next.user;
    state = {
      ...state,
      ...next,
      sessionStatus: sessionStatusFor(nextUser),
      myOrganizations: next.myOrganizations
        ? [...next.myOrganizations]
        : state.myOrganizations
    };
    notify();
  }

  function setScope(scope: string | null) {
    if (state.cacheScope === scope) return;
    updateCacheScope(scope);
    patch({ cacheScope: scope });
  }

  function isCurrent(operation: number): boolean {
    return operation === generation;
  }

  function cancelBootstrapRequest() {
    bootstrapGeneration += 1;
    bootstrapAbortController?.abort();
    bootstrapAbortController = null;
  }

  async function requestBootstrap(
    returnTo: string | null | undefined
  ): Promise<{ bootstrap: Bootstrap; operation: number }> {
    const operation = ++bootstrapGeneration;
    bootstrapAbortController?.abort();
    const controller = new AbortController();
    bootstrapAbortController = controller;
    try {
      const bootstrap = await request<Bootstrap>(bootstrapPath(returnTo, defaultReturnTo), {
        signal: controller.signal
      });
      return { bootstrap, operation };
    } finally {
      if (operation === bootstrapGeneration && bootstrapAbortController === controller) {
        bootstrapAbortController = null;
      }
    }
  }

  async function fetchOrganizationState(userId: string, operation: number): Promise<SessionOrganizationState> {
    const [myOrganizations, context] = await Promise.all([
      request<UserOrganization[]>("/api/me/organizations"),
      request<OrganizationContext>("/api/me/organization-context")
    ]);
    const result = {
      myOrganizations,
      organizationContext: context.organization
    };
    if (isCurrent(operation)) {
      setScope(organizationScope(userId, result.organizationContext?.id));
      patch({
        myOrganizations: result.myOrganizations,
        organizationContext: result.organizationContext,
        organizationContextReady: true,
        phase: "ready",
        error: null
      });
    }
    return result;
  }

  async function initialize(initializeOptions: InitializeSessionOptions = {}): Promise<SessionControllerState> {
    const operation = ++generation;
    // requestBootstrap increments this synchronously before its first await.
    // Capture the expected generation so a superseded bootstrap failure cannot
    // turn a newer session read model into an error.
    const bootstrapOperation = bootstrapGeneration + 1;
    patch({ phase: "loading", error: null });
    try {
      const [bootstrapResult, user] = await Promise.all([
        requestBootstrap(initializeOptions.returnTo),
        request<User | null>("/api/me")
      ]);
      if (!isCurrent(operation)) return state;

      setScope(user?.id ?? null);
      patch({
        bootstrap: bootstrapResult.bootstrap,
        user,
        myOrganizations: [],
        organizationContext: null,
        organizationContextReady: !user,
        phase: user ? "loading" : "ready",
        error: null
      });

      if (user) {
        await fetchOrganizationState(user.id, operation);
        if (!isCurrent(operation)) return state;
      }
      patch({ phase: "ready", error: null });
      return state;
    } catch (error) {
      if (isCurrent(operation)
        && bootstrapGeneration === bootstrapOperation
        && !isAbortError(error)) {
        patch({ phase: "error", error });
      }
      throw error;
    }
  }

  async function loadBootstrap(returnTo?: string | null): Promise<Bootstrap> {
    const bootstrapOperation = bootstrapGeneration + 1;
    try {
      const result = await requestBootstrap(returnTo);
      // A newer bootstrap request may have superseded this response. Return
      // the value to the caller for compatibility, but never let it mutate
      // the active session read model.
      if (result.operation === bootstrapGeneration) {
        patch({ bootstrap: result.bootstrap, error: null });
      }
      return result.bootstrap;
    } catch (error) {
      if (bootstrapGeneration === bootstrapOperation && !isAbortError(error)) {
        patch({ phase: "error", error });
      }
      throw error;
    }
  }

  async function loadUser(): Promise<User | null> {
    const operation = ++generation;
    try {
      const user = await request<User | null>("/api/me");
      if (!isCurrent(operation)) return user;

      const previousUserId = state.user?.id;
      const nextUserId = user?.id;
      setScope(nextUserId ?? null);
      patch({
        user,
        ...(previousUserId !== nextUserId
          ? {
              myOrganizations: [],
              organizationContext: null,
              organizationContextReady: !user
            }
          : {}),
        phase: "ready",
        error: null
      });
      return user;
    } catch (error) {
      if (isCurrent(operation)) patch({ phase: "error", error });
      throw error;
    }
  }

  async function loadOrganizationContext(userId?: string): Promise<SessionOrganizationState> {
    const operation = ++generation;
    const currentUserId = userId ?? state.user?.id;
    if (!currentUserId) {
      const empty = { myOrganizations: [], organizationContext: null };
      patch({
        myOrganizations: empty.myOrganizations,
        organizationContext: empty.organizationContext,
        organizationContextReady: true,
        phase: "ready",
        error: null
      });
      return empty;
    }

    patch({ phase: "loading", error: null });
    try {
      return await fetchOrganizationState(currentUserId, operation);
    } catch (error) {
      if (isCurrent(operation)) patch({ phase: "error", error });
      throw error;
    }
  }

  async function switchOrganization(organizationId: string): Promise<OrganizationContext> {
    const normalizedId = organizationId.trim();
    if (!normalizedId) throw new TypeError("organizationId must not be empty");

    const operation = ++generation;
    patch({ phase: "loading", error: null });
    try {
      const context = await request<OrganizationContext>("/api/me/organization-context", {
        method: "PUT",
        body: JSON.stringify({ organization_id: normalizedId })
      });
      if (isCurrent(operation)) {
        setScope(organizationScope(state.user?.id, context.organization?.id));
        patch({
          organizationContext: context.organization,
          organizationContextReady: true,
          phase: "ready",
          error: null
        });
      }
      return context;
    } catch (error) {
      if (isCurrent(operation)) patch({ phase: "error", error });
      throw error;
    }
  }

  async function transitionToAuthenticated(
    user: User,
    transitionOptions: AuthenticatedTransitionOptions = {}
  ): Promise<SessionControllerState> {
    const operation = ++generation;
    cancelBootstrapRequest();
    setScope(user.id);
    patch({
      user,
      myOrganizations: [],
      organizationContext: null,
      organizationContextReady: false,
      phase: transitionOptions.loadOrganizationContext === false ? "ready" : "loading",
      error: null
    });

    if (transitionOptions.loadOrganizationContext === false) return state;

    try {
      await fetchOrganizationState(user.id, operation);
      return state;
    } catch (error) {
      if (isCurrent(operation)) patch({ phase: "error", error });
      throw error;
    }
  }

  function transitionToAnonymous(): SessionControllerState {
    ++generation;
    cancelBootstrapRequest();
    setScope(null);
    patch({
      user: null,
      myOrganizations: [],
      organizationContext: null,
      organizationContextReady: true,
      phase: "ready",
      error: null
    });
    return state;
  }

  const controller: SessionController = {
    getSnapshot: () => state,
    getGeneration: () => generation,
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    initialize,
    loadBootstrap,
    loadUser,
    loadOrganizationContext,
    switchOrganization,
    transitionToAuthenticated,
    transitionToAnonymous,
    refresh: initialize
  };
  return controller;
}

/**
 * React facade for the controller. It does not fetch or register browser
 * listeners on mount; the host decides when to call `initialize` or `refresh`.
 */
export function useSessionController(options: SessionControllerOptions = {}): SessionControllerHookResult {
  const controllerRef = useRef<SessionController | null>(null);
  if (!controllerRef.current) controllerRef.current = createSessionController(options);
  const controller = controllerRef.current;
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);

  return {
    ...state,
    controller,
    initialize: controller.initialize,
    loadBootstrap: controller.loadBootstrap,
    loadUser: controller.loadUser,
    loadOrganizationContext: controller.loadOrganizationContext,
    switchOrganization: controller.switchOrganization,
    transitionToAuthenticated: controller.transitionToAuthenticated,
    transitionToAnonymous: controller.transitionToAnonymous,
    refresh: controller.refresh
  };
}
