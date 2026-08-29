export type ApplicationRequestKind = "read" | "mutation";

export type ApplicationRequestBeginOptions = {
  /** Requests with the same scope replace and abort their previous request. */
  scope?: string;
  kind?: ApplicationRequestKind;
  /** Used only when a caller has already persisted a logical mutation key. */
  idempotencyKey?: string;
  /**
   * Stable serialization of the request payload. A retry key is reusable only
   * while this fingerprint is unchanged; changing a draft starts a new
   * server-side mutation instead of replaying the old payload.
   */
  payloadFingerprint?: string;
};

export type ApplicationRequestToken = {
  applicationId: string;
  /** The parent workspace generation at the time the request was started. */
  generation: number;
  scope: string;
  signal: AbortSignal;
  /** Stable for retries of the same mutation scope until it succeeds. */
  idempotencyKey: string | null;
};

export type ApplicationRequestOptions = {
  signal: AbortSignal;
  idempotencyKey?: string;
};

export function applicationRequestOptions(
  request: ApplicationRequestToken
): ApplicationRequestOptions {
  return {
    signal: request.signal,
    ...(request.idempotencyKey ? { idempotencyKey: request.idempotencyKey } : {})
  };
}

export type ApplicationRequestCurrentScope = {
  applicationId: string | null;
  generation: number;
};

export type ApplicationRequestGuard = {
  begin: (
    applicationId?: string,
    options?: ApplicationRequestBeginOptions
  ) => ApplicationRequestToken | null;
  isCurrent: (token: ApplicationRequestToken) => boolean;
  /** Abort every request owned by the current application view. */
  invalidate: () => void;
  /** Release a request; successful mutations also release their retry key. */
  finish: (token: ApplicationRequestToken, committed?: boolean) => void;
  dispose: () => void;
};

type ActiveRequest = {
  token: ApplicationRequestToken;
  controller: AbortController;
};

type MutationKey = {
  key: string;
  payloadFingerprint?: string;
};

function newIdempotencyKey(): string {
  const randomUuid = globalThis.crypto?.randomUUID;
  return `ui-${randomUuid ? randomUuid.call(globalThis.crypto) : `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;
}

function isSameScope(left: ApplicationRequestToken, right: ApplicationRequestToken): boolean {
  return left.applicationId === right.applicationId
    && left.generation === right.generation
    && left.scope === right.scope;
}

/**
 * Request lifecycle for an application workspace.
 *
 * Abort is only the transport optimisation. `isCurrent` also fences the
 * response against the selected application/generation and the latest
 * request in the same domain scope, because a mocked/fetch implementation
 * may settle a promise after its signal was aborted.
 */
export function createApplicationRequestGuard(
  getCurrentScope: () => ApplicationRequestCurrentScope
): ApplicationRequestGuard {
  const active = new Map<string, ActiveRequest>();
  const mutationKeys = new Map<string, MutationKey>();
  let disposed = false;

  function keyFor(applicationId: string, scope: string): string {
    return `${applicationId}:${scope}`;
  }

  function begin(
    requestedApplicationId = getCurrentScope().applicationId ?? "",
    options: ApplicationRequestBeginOptions = {}
  ): ApplicationRequestToken | null {
    if (disposed || !requestedApplicationId) return null;
    const current = getCurrentScope();
    if (current.applicationId !== requestedApplicationId) return null;
    const scope = options.scope ?? "workspace";
    const activeKey = keyFor(requestedApplicationId, scope);
    active.get(activeKey)?.controller.abort();

    const controller = new AbortController();
    const mutation = options.kind === "mutation";
    const previousMutation = mutationKeys.get(activeKey);
    const canReusePreviousKey = previousMutation
      && previousMutation.payloadFingerprint === options.payloadFingerprint;
    const idempotencyKey = mutation
      ? options.idempotencyKey ?? (canReusePreviousKey ? previousMutation.key : newIdempotencyKey())
      : null;
    if (mutation && idempotencyKey) {
      mutationKeys.set(activeKey, {
        key: idempotencyKey,
        payloadFingerprint: options.payloadFingerprint
      });
    }
    const token: ApplicationRequestToken = {
      applicationId: requestedApplicationId,
      generation: current.generation,
      scope,
      signal: controller.signal,
      idempotencyKey
    };
    active.set(activeKey, { token, controller });
    return token;
  }

  function isCurrent(token: ApplicationRequestToken): boolean {
    if (disposed || token.signal.aborted) return false;
    const current = getCurrentScope();
    if (current.applicationId !== token.applicationId || current.generation !== token.generation) return false;
    const currentRequest = active.get(keyFor(token.applicationId, token.scope));
    return Boolean(currentRequest && isSameScope(currentRequest.token, token));
  }

  function invalidate() {
    for (const request of active.values()) request.controller.abort();
    active.clear();
  }

  function finish(token: ApplicationRequestToken, committed = true) {
    const activeKey = keyFor(token.applicationId, token.scope);
    const current = active.get(activeKey);
    if (!current || !isSameScope(current.token, token)) return;
    current.controller.abort();
    active.delete(activeKey);
    if (committed && token.idempotencyKey) mutationKeys.delete(activeKey);
  }

  function dispose() {
    disposed = true;
    invalidate();
    mutationKeys.clear();
  }

  return { begin, isCurrent, invalidate, finish, dispose };
}
