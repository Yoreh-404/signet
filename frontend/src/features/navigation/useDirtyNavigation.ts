import { useRef, useSyncExternalStore } from "react";

import type { NavigationState } from "../../lib/navigation";

export type NavigationTarget = string | NavigationState;

export type DirtyNavigationReason = "request" | "hashchange" | "popstate";

export type DirtyNavigationConfirmation = {
  fromHash: string;
  toHash: string;
  sourceIds: string[];
  reason: DirtyNavigationReason;
};

export type NavigationAccepted = DirtyNavigationConfirmation;

export type RequestNavigationOptions = {
  replace?: boolean;
  state?: unknown;
};

export type DirtyNavigationSnapshot = {
  sources: Readonly<Record<string, boolean>>;
  dirtySources: string[];
  isDirty: boolean;
  acceptedHash: string;
};

export type NavigationWindow = Pick<
  Window,
  "location" | "history" | "addEventListener" | "removeEventListener"
>;

export type DirtyNavigationControllerOptions = {
  /** Defaults to the browser window; inject one for tests or another host. */
  window?: NavigationWindow;
  initialHash?: string;
  initialSources?: Record<string, boolean>;
  /** Returning false blocks a dirty navigation. No callback means block. */
  confirmNavigation?: (context: DirtyNavigationConfirmation) => boolean;
  onNavigationAccepted?: (navigation: NavigationAccepted) => void;
};

export type DirtyNavigationSourceHandle = {
  setDirty(dirty: boolean): void;
  unregister(): void;
};

export interface DirtyNavigationController {
  getSnapshot(): DirtyNavigationSnapshot;
  subscribe(listener: () => void): () => void;
  setSource(id: string, dirty: boolean): void;
  setSources(sources: Record<string, boolean>): void;
  removeSource(id: string): void;
  registerSource(id: string, dirty?: boolean): DirtyNavigationSourceHandle;
  requestNavigation(target: NavigationTarget, options?: RequestNavigationOptions): boolean;
  handleHashChange(event?: HashChangeEvent): boolean;
  handlePopState(event?: PopStateEvent): boolean;
  /** Returns true when unload is allowed and false when it is blocked. */
  handleBeforeUnload(event: BeforeUnloadEvent): boolean;
  /**
   * Records a host-controlled same-view navigation that was already
   * confirmed by a feature-level guard. This keeps browser Back/Forward in
   * sync without asking the user a second time.
   */
  syncAcceptedHash(target: NavigationTarget): void;
  /** No listeners are attached until this method is explicitly called. */
  connect(): () => void;
}

export type DirtyNavigationHookResult = DirtyNavigationSnapshot & {
  controller: DirtyNavigationController;
} & Pick<
    DirtyNavigationController,
    | "setSource"
    | "setSources"
    | "removeSource"
    | "registerSource"
    | "requestNavigation"
    | "handleHashChange"
    | "handlePopState"
    | "handleBeforeUnload"
    | "syncAcceptedHash"
    | "connect"
>;

function defaultWindow(): NavigationWindow | undefined {
  return typeof window === "undefined" ? undefined : window;
}

export function hashForNavigation(target: NavigationTarget): string {
  if (typeof target === "string") {
    const value = target.trim();
    if (!value) return "";
    if (value.startsWith("#")) return value;
    return value.startsWith("/") ? `#${value}` : `#/${value}`;
  }

  const params = new URLSearchParams();
  if (target.tab === "applications") {
    if (target.applicationId) params.set("application", target.applicationId);
    if (target.applicationSection) params.set("section", target.applicationSection);
  }
  if (target.tab === "billing" && target.billingOrder) {
    params.set("billing_order", target.billingOrder);
  }
  const query = params.toString();
  return `#/${target.tab}${query ? `?${query}` : ""}`;
}

function normalizedHash(value: string): string {
  if (!value) return "";
  return value.startsWith("#") ? value : hashForNavigation(value);
}

function hashFromUrl(value: string, baseHref: string | undefined): string {
  try {
    return new URL(value, baseHref ?? "http://localhost/").hash;
  } catch {
    return "";
  }
}

function createSnapshot(
  sources: Record<string, boolean>,
  acceptedHash: string
): DirtyNavigationSnapshot {
  const sourceSnapshot = Object.freeze({ ...sources });
  const dirtySources = Object.keys(sourceSnapshot).filter((id) => sourceSnapshot[id]);
  return {
    sources: sourceSnapshot,
    dirtySources,
    isDirty: dirtySources.length > 0,
    acceptedHash
  };
}

/**
 * Hash navigation guard with no router assumptions. It only knows how to
 * accept/reject a hash and how to aggregate independent dirty sources.
 */
export function createDirtyNavigationController(
  options: DirtyNavigationControllerOptions = {}
): DirtyNavigationController {
  const hostWindow = options.window ?? defaultWindow();
  const sources: Record<string, boolean> = { ...(options.initialSources ?? {}) };
  let acceptedHash = normalizedHash(options.initialHash ?? hostWindow?.location.hash ?? "");
  let snapshot = createSnapshot(sources, acceptedHash);
  const listeners = new Set<() => void>();
  let disconnect: (() => void) | null = null;

  function notify() {
    for (const listener of listeners) listener();
  }

  function updateSnapshot() {
    snapshot = createSnapshot(sources, acceptedHash);
    notify();
  }

  function sourceId(id: string): string {
    const normalized = id.trim();
    if (!normalized) throw new TypeError("dirty navigation source id must not be empty");
    return normalized;
  }

  function setSource(id: string, dirty: boolean) {
    const key = sourceId(id);
    if (sources[key] === dirty) return;
    sources[key] = dirty;
    updateSnapshot();
  }

  function setSources(nextSources: Record<string, boolean>) {
    for (const key of Object.keys(sources)) delete sources[key];
    for (const [id, dirty] of Object.entries(nextSources)) sources[sourceId(id)] = dirty;
    updateSnapshot();
  }

  function removeSource(id: string) {
    const key = sourceId(id);
    if (!(key in sources)) return;
    delete sources[key];
    updateSnapshot();
  }

  function registerSource(id: string, dirty = false): DirtyNavigationSourceHandle {
    const key = sourceId(id);
    setSource(key, dirty);
    return {
      setDirty: (nextDirty) => setSource(key, nextDirty),
      unregister: () => removeSource(key)
    };
  }

  function currentHash(): string {
    return normalizedHash(hostWindow?.location.hash ?? acceptedHash);
  }

  function restoreAcceptedHash() {
    if (!hostWindow || currentHash() === acceptedHash) return;
    const url = `${hostWindow.location.pathname}${hostWindow.location.search}${acceptedHash}`;
    hostWindow.history.replaceState(hostWindow.history.state, "", url);
  }

  function confirmNavigation(context: DirtyNavigationConfirmation): boolean {
    if (!snapshot.isDirty) return true;
    return options.confirmNavigation?.(context) ?? false;
  }

  function accept(hash: string, reason: DirtyNavigationReason): boolean {
    const toHash = normalizedHash(hash);
    const fromHash = acceptedHash;
    if (toHash === fromHash) return true;
    const context = {
      fromHash,
      toHash,
      sourceIds: [...snapshot.dirtySources],
      reason
    };
    if (!confirmNavigation(context)) {
      restoreAcceptedHash();
      return false;
    }
    acceptedHash = toHash;
    updateSnapshot();
    options.onNavigationAccepted?.(context);
    return true;
  }

  function requestNavigation(target: NavigationTarget, requestOptions: RequestNavigationOptions = {}): boolean {
    const toHash = normalizedHash(hashForNavigation(target));
    if (toHash === acceptedHash) return true;
    const context = {
      fromHash: acceptedHash,
      toHash,
      sourceIds: [...snapshot.dirtySources],
      reason: "request" as const
    };
    if (!confirmNavigation(context)) return false;

    if (hostWindow) {
      const url = `${hostWindow.location.pathname}${hostWindow.location.search}${toHash}`;
      const historyState = requestOptions.state ?? null;
      if (requestOptions.replace) hostWindow.history.replaceState(historyState, "", url);
      else hostWindow.history.pushState(historyState, "", url);
    }
    acceptedHash = toHash;
    updateSnapshot();
    options.onNavigationAccepted?.(context);
    return true;
  }

  function handleHashChange(event?: HashChangeEvent): boolean {
    const hash = event?.newURL
      ? hashFromUrl(event.newURL, hostWindow?.location.href)
      : currentHash();
    return accept(hash, "hashchange");
  }

  function handlePopState(): boolean {
    return accept(currentHash(), "popstate");
  }

  function handleBeforeUnload(event: BeforeUnloadEvent): boolean {
    if (!snapshot.isDirty) return true;
    event.preventDefault();
    event.returnValue = "";
    return false;
  }

  function syncAcceptedHash(target: NavigationTarget): void {
    const nextHash = normalizedHash(hashForNavigation(target));
    if (nextHash === acceptedHash) return;
    acceptedHash = nextHash;
    updateSnapshot();
  }

  function connect(): () => void {
    if (disconnect) return disconnect;
    if (!hostWindow) return () => undefined;

    const onHashChange = (event: HashChangeEvent) => handleHashChange(event);
    const onPopState = () => handlePopState();
    const onBeforeUnload = (event: BeforeUnloadEvent) => handleBeforeUnload(event);
    hostWindow.addEventListener("hashchange", onHashChange);
    hostWindow.addEventListener("popstate", onPopState);
    hostWindow.addEventListener("beforeunload", onBeforeUnload);

    const cleanup = () => {
      hostWindow.removeEventListener("hashchange", onHashChange);
      hostWindow.removeEventListener("popstate", onPopState);
      hostWindow.removeEventListener("beforeunload", onBeforeUnload);
      if (disconnect === cleanup) disconnect = null;
    };
    disconnect = cleanup;
    return cleanup;
  }

  const controller: DirtyNavigationController = {
    getSnapshot: () => snapshot,
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    setSource,
    setSources,
    removeSource,
    registerSource,
    requestNavigation,
    handleHashChange,
    handlePopState,
    handleBeforeUnload,
    syncAcceptedHash,
    connect
  };
  return controller;
}

/**
 * React facade. It exposes event handlers and `connect`, but deliberately
 * leaves listener registration to the host component.
 */
export function useDirtyNavigation(
  options: DirtyNavigationControllerOptions = {}
): DirtyNavigationHookResult {
  const confirmRef = useRef(options.confirmNavigation);
  const acceptedRef = useRef(options.onNavigationAccepted);
  confirmRef.current = options.confirmNavigation;
  acceptedRef.current = options.onNavigationAccepted;

  const controllerRef = useRef<DirtyNavigationController | null>(null);
  if (!controllerRef.current) {
    controllerRef.current = createDirtyNavigationController({
      ...options,
      confirmNavigation: (context) => confirmRef.current?.(context) ?? false,
      onNavigationAccepted: (navigation) => acceptedRef.current?.(navigation)
    });
  }
  const controller = controllerRef.current;
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);

  return {
    ...state,
    controller,
    setSource: controller.setSource,
    setSources: controller.setSources,
    removeSource: controller.removeSource,
    registerSource: controller.registerSource,
    requestNavigation: controller.requestNavigation,
    handleHashChange: controller.handleHashChange,
    handlePopState: controller.handlePopState,
    handleBeforeUnload: controller.handleBeforeUnload,
    syncAcceptedHash: controller.syncAcceptedHash,
    connect: controller.connect
  };
}
