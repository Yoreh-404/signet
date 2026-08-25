import { ApiDecodeError } from "./api/validation";
import type { ApiDecoder } from "./api/validation";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string | null;
  /** Parsed API payload when one was returned, including structured 4xx results. */
  readonly body: unknown | null;
  readonly mutationId: string | null;
  readonly mutationStatus: string | null;
  readonly mutationReplayed: boolean;

  constructor(
    message: string,
    status: number,
    code: string | null = null,
    body: unknown | null = null,
    metadata: {
      mutationId?: string | null;
      mutationStatus?: string | null;
      mutationReplayed?: boolean;
    } = {}
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.body = body;
    this.mutationId = metadata.mutationId ?? null;
    this.mutationStatus = metadata.mutationStatus ?? null;
    this.mutationReplayed = metadata.mutationReplayed ?? false;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

type ApiErrorBody = {
  error?: string;
  message?: string;
  error_description?: string;
  mutation_id?: string;
};

/** Request options understood by the shared same-origin API client. */
export type ApiRequestInit = RequestInit & {
  /**
   * Use a flow-specific CSRF endpoint.  The default browser session writes
   * continue to use `/api/csrf`; browser-account writes use their context
   * token without implementing a second transport client.
   */
  csrfTokenPath?: string;
  /** Reuse this key when retrying the same logical mutation. */
  idempotencyKey?: string;
  /** Optimistic-concurrency token for resources that expose one. */
  ifMatch?: string;
};

export type ApiMutationCommand<T> = {
  readonly idempotencyKey: string;
  execute: (overrides?: Omit<ApiRequestInit, "idempotencyKey">) => Promise<T>;
};

const NETWORK_ERROR_MESSAGE = "Unable to reach the server. Check your connection and try again.";
const INVALID_JSON_MESSAGE = "The server returned an invalid JSON response";
const DEFAULT_CSRF_PATH = "/api/csrf";

/**
 * Binds one logical command to one idempotency key.  UI retries must call
 * execute on the same command; recreating a request object would otherwise
 * make the server treat a retry as a second mutation.
 */
export function createApiMutation<T>(
  path: string,
  options: ApiRequestInit = {},
  decoder?: ApiDecoder<T>
): ApiMutationCommand<T> {
  const idempotencyKey = options.idempotencyKey ?? createMutationKey();
  return {
    idempotencyKey,
    execute: (overrides = {}) => api<T>(path, {
      ...options,
      ...overrides,
      idempotencyKey
    }, decoder)
  };
}

const csrfTokens = new Map<string, string>();
const csrfRequests = new Map<string, Promise<string>>();
let csrfGeneration = 0;

/** Keeps localized callers from displaying the transport's English fallback. */
export function getApiErrorMessage(error: unknown, fallback: string): string {
  if (!(error instanceof ApiError) || error.code === "network_error") return fallback;
  return error.message || fallback;
}

/**
 * Admin list responses are sensitive, so they deliberately stay in memory
 * only.  This cache makes page switches instant for the active session while
 * retaining the server's `no-store` guarantee across reloads and logout.
 */
type CachedApiEntry = {
  value: unknown;
  etag: string | null;
  checkedAt: number;
};

export type CachedApiOptions = {
  /** A stable key when the request URL alone is not sufficient. */
  key?: string;
  /** Skip a network revalidation until this interval has elapsed. */
  minRevalidateMs?: number;
  /** Ignore the revalidation interval, for an explicit refresh. */
  force?: boolean;
  /** Cancel this revalidation when its owning session/view is invalidated. */
  signal?: AbortSignal;
};

export type CachedApiResult<T> = {
  value: T;
  changed: boolean;
  revalidated: boolean;
  /** The response finished after a cache/mutation epoch change. */
  stale: boolean;
};

const adminResponseCache = new Map<string, CachedApiEntry>();
type PendingCachedApiRequest = {
  promise: Promise<CachedApiResult<unknown>>;
};

const adminResponseRequests = new Map<string, PendingCachedApiRequest>();
let cacheScope: string | null = null;
let cacheGeneration = 0;

function scopedCacheKey(key: string): string {
  return `${cacheScope ?? "anonymous"}:${key}`;
}

/** Switches the memory cache when the authenticated browser account changes. */
export function setApiCacheScope(scope: string | null) {
  if (cacheScope === scope) return;
  cacheScope = scope;
  cacheGeneration += 1;
  adminResponseCache.clear();
  adminResponseRequests.clear();
}

/** Clears memory-only conditional-response entries after an admin mutation. */
export function clearApiCache() {
  cacheGeneration += 1;
  adminResponseCache.clear();
  adminResponseRequests.clear();
}

export function cachedApiValue<T>(key: string): T | undefined {
  return adminResponseCache.get(scopedCacheKey(key))?.value as T | undefined;
}

/**
 * Revalidates a cached JSON GET with If-None-Match. A short revalidation
 * interval avoids request churn while switching between management pages;
 * after it expires the cached value is still rendered immediately by callers
 * and this function only replaces it if the server representation changed.
 */
export async function cachedApi<T>(
  path: string,
  options: CachedApiOptions = {},
  decoder?: ApiDecoder<T>
): Promise<CachedApiResult<T>> {
  if (options.signal?.aborted) throw createAbortError();

  const key = scopedCacheKey(options.key ?? path);
  const existing = adminResponseCache.get(key);
  const now = Date.now();
  const minRevalidateMs = options.minRevalidateMs ?? 15_000;
  if (existing && !options.force && now - existing.checkedAt < minRevalidateMs) {
    return {
      value: decodeApiValue(existing.value, decoder),
      changed: false,
      revalidated: false,
      stale: false
    };
  }

  const pending = adminResponseRequests.get(key);
  if (pending) {
    // The physical request is deliberately independent of any one view's
    // AbortSignal. Each caller gets its own cancellation wrapper below, so
    // unmounting the first page cannot cancel a request now shared by a newer
    // page. cacheGeneration still fences account changes and mutations.
    return withAbortSignal(pending.promise as Promise<CachedApiResult<T>>, options.signal);
  }

  const generation = cacheGeneration;
  const request = conditionalJsonRequest<T>(path, key, existing, generation, decoder);
  adminResponseRequests.set(key, {
    promise: request as Promise<CachedApiResult<unknown>>
  });
  const clearPending = () => {
    if (adminResponseRequests.get(key)?.promise === request) adminResponseRequests.delete(key);
  };
  void request.then(clearPending, clearPending);
  return withAbortSignal(request, options.signal);
}

async function conditionalJsonRequest<T>(
  path: string,
  key: string,
  existing: CachedApiEntry | undefined,
  generation: number,
  decoder?: ApiDecoder<T>
): Promise<CachedApiResult<T>> {
  const headers = new Headers({ accept: "application/json" });
  if (existing?.etag) headers.set("if-none-match", existing.etag);

  const response = await fetchResponse(path, {
    headers,
    // The browser must not persist sensitive management data; this module
    // owns the short-lived, authenticated in-memory cache instead.
    cache: "no-store"
  });

  if (response.status === 304 && existing) {
    existing.checkedAt = Date.now();
    return {
      value: decodeApiValue(existing.value, decoder),
      changed: false,
      revalidated: true,
      stale: generation !== cacheGeneration
    };
  }

  const payload = await readResponse(response);
  if (!response.ok) {
    if (response.status === 401) clearCsrfToken();
    throw toApiError(response, payload);
  }
  if (!payload.parsed?.ok) {
    throw new ApiError(INVALID_JSON_MESSAGE, response.status);
  }

  const value = decodeApiValue(payload.parsed.value, decoder);
  const entry: CachedApiEntry = {
    value,
    etag: response.headers.get("etag"),
    checkedAt: Date.now()
  };
  // A mutation or account change may have invalidated the cache while this
  // request was on the wire. Never let that older representation repopulate
  // the new cache generation.
  const stale = generation !== cacheGeneration;
  if (!stale) adminResponseCache.set(key, entry);
  return { value: entry.value as T, changed: true, revalidated: true, stale };
}

function isAbortError(error: unknown): boolean {
  return (typeof DOMException !== "undefined"
    && error instanceof DOMException
    && error.name === "AbortError")
    || (error instanceof Error && error.name === "AbortError");
}

function createAbortError(): Error {
  if (typeof DOMException !== "undefined") {
    return new DOMException("The operation was aborted.", "AbortError");
  }
  const error = new Error("The operation was aborted.");
  error.name = "AbortError";
  return error;
}

function withAbortSignal<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(createAbortError());

  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      cleanup();
      reject(createAbortError());
    };
    const cleanup = () => signal.removeEventListener("abort", onAbort);
    signal.addEventListener("abort", onAbort, { once: true });
    void promise.then(
      (value) => {
        cleanup();
        resolve(value);
      },
      (error) => {
        cleanup();
        reject(error);
      }
    );
  });
}

/**
 * Shared JSON client for the same-origin SSO API.
 *
 * It deliberately accepts 204/empty responses, preserves caller headers and
 * turns every non-2xx response into one predictable error type.
 */
export async function api<T = void>(
  path: string,
  options: ApiRequestInit = {},
  decoder?: ApiDecoder<T>
): Promise<T> {
  const method = (options.method ?? "GET").toUpperCase();
  const idempotencyKey = options.idempotencyKey
    ?? (isAdminMutation(path, method) ? createMutationKey() : undefined);
  return request<T>(
    path,
    idempotencyKey === options.idempotencyKey
      ? options
      : { ...options, ...(idempotencyKey ? { idempotencyKey } : {}) },
    true,
    decoder
  );
}

async function request<T>(
  path: string,
  options: ApiRequestInit,
  retryCsrf: boolean,
  decoder?: ApiDecoder<T>
): Promise<T> {
  const { csrfTokenPath, idempotencyKey, ifMatch, ...fetchOptions } = options;
  const headers = new Headers(fetchOptions.headers);
  headers.set("accept", "application/json");
  if (idempotencyKey) headers.set("idempotency-key", idempotencyKey);
  if (ifMatch) headers.set("if-match", ifMatch);
  if (fetchOptions.body && !headers.has("content-type") && !(fetchOptions.body instanceof FormData)) {
    headers.set("content-type", "application/json");
  }
  const method = (fetchOptions.method ?? "GET").toUpperCase();
  const protectedWrite = isProtectedBrowserWrite(path, method);
  const csrfPath = csrfTokenPath ?? DEFAULT_CSRF_PATH;
  const requiresCsrf = protectedWrite || csrfTokenPath !== undefined;
  if (requiresCsrf) {
    headers.set("x-csrf-token", await currentCsrfToken(csrfPath));
  }

  const response = await fetchResponse(path, { ...fetchOptions, headers });

  const payload = await readResponse(response);

  if (!response.ok) {
    if (response.status === 401) clearCsrfToken();
    const body = payload.parsed?.ok ? asApiErrorBody(payload.parsed.value) : null;
    if (retryCsrf && requiresCsrf && response.status === 403 && body?.error === "csrf_failed") {
      clearCsrfToken(csrfPath);
      return request<T>(path, options, false, decoder);
    }
    throw toApiError(response, payload);
  }

  // Browser-account CSRF tokens are scoped to the context and rotate after a
  // successful write.  The ordinary `/api/csrf` token keeps its existing
  // reuse semantics for the rest of the application.
  if (csrfTokenPath !== undefined) clearCsrfToken(csrfPath);
  if (changesBrowserSession(path, method)) {
    clearCsrfToken();
    clearApiCache();
  }
  if (method !== "GET" && new URL(path, window.location.origin).pathname.startsWith("/api/admin/")) {
    // A mutation can affect more than one dashboard panel (for example,
    // deleting an organization also changes users and invitation codes).
    // Clearing the small in-memory cache is cheap and prevents stale views.
    clearApiCache();
  }
  if (!payload.text) return undefined as T;
  return decodeApiValue(payload.parsed?.ok ? payload.parsed.value : payload.text, decoder);
}

function decodeApiValue<T>(value: unknown, decoder?: ApiDecoder<T>): T {
  if (!decoder) return value as T;
  try {
    return decoder(value);
  } catch (error) {
    if (error instanceof ApiDecodeError) {
      throw new ApiError(INVALID_JSON_MESSAGE, 200, "invalid_api_payload", value);
    }
    throw error;
  }
}

async function fetchResponse(path: string, options: RequestInit): Promise<Response> {
  try {
    return await fetch(path, {
      ...options,
      credentials: "include"
    });
  } catch (error) {
    if (isAbortError(error)) throw error;
    throw new ApiError(NETWORK_ERROR_MESSAGE, 0, "network_error");
  }
}

type ParsedJson = { ok: true; value: unknown } | { ok: false };

type ResponsePayload = {
  text: string;
  parsed: ParsedJson | null;
};

async function readResponse(response: Response, forceJson = false): Promise<ResponsePayload> {
  const text = response.status === 204 ? "" : await response.text();
  const contentType = (response.headers.get("content-type") ?? "").toLowerCase();
  const trimmed = text.trimStart();
  const looksLikeJson = trimmed.startsWith("{") || trimmed.startsWith("[");
  const shouldParse = Boolean(text) && (forceJson || contentType.includes("json") || looksLikeJson);
  return {
    text,
    parsed: shouldParse ? safeJson(text) : null
  };
}

function asApiErrorBody(value: unknown): ApiErrorBody | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as ApiErrorBody;
}

function toApiError(response: Response, payload: ResponsePayload): ApiError {
  const value = payload.parsed?.ok ? payload.parsed.value : null;
  const body = asApiErrorBody(value);
  const message = body?.message
    || body?.error_description
    || payload.text
    || response.statusText
    || "Request failed";
  return new ApiError(message, response.status, body?.error ?? null, value, {
    mutationId: response.headers.get("x-mutation-id") ?? body?.mutation_id ?? null,
    mutationStatus: response.headers.get("x-mutation-status"),
    mutationReplayed: response.headers.get("x-mutation-replayed") === "true"
  });
}

function clearCsrfToken(path?: string) {
  csrfGeneration += 1;
  if (path) {
    csrfTokens.delete(path);
    csrfRequests.delete(path);
    return;
  }
  csrfTokens.clear();
  csrfRequests.clear();
}

async function currentCsrfToken(path: string): Promise<string> {
  const token = csrfTokens.get(path);
  if (token) return token;

  const pending = csrfRequests.get(path);
  if (pending) return pending;

  const generation = csrfGeneration;
  const request = fetchResponse(path, {
    headers: { accept: "application/json" }
  }).then(async (response) => {
    const payload = await readResponse(response, true);
    if (!response.ok) throw toApiError(response, payload);

    const value = payload.parsed?.ok ? payload.parsed.value : null;
    const body = asApiErrorBody(value) as (ApiErrorBody & { csrf_token?: unknown }) | null;
    if (typeof body?.csrf_token !== "string" || !body.csrf_token) {
      throw new ApiError("Invalid CSRF response", response.status, "invalid_csrf_response", value);
    }
    if (generation === csrfGeneration) csrfTokens.set(path, body.csrf_token);
    return body.csrf_token;
  });
  csrfRequests.set(path, request);
  const clearPending = () => {
    if (csrfRequests.get(path) === request) csrfRequests.delete(path);
  };
  void request.then(clearPending, clearPending);
  return request;
}

function isProtectedBrowserWrite(path: string, method: string): boolean {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) return false;
  const url = new URL(path, window.location.origin);
  if (url.origin !== window.location.origin) return false;
  const pathname = url.pathname;
  return pathname.startsWith("/api/admin/")
    || pathname === "/api/logout"
    || pathname.startsWith("/api/me/")
    || pathname.startsWith("/api/mfa/")
    || pathname === "/api/passkeys/registration/start"
    || pathname === "/api/passkeys/registration/finish"
    || (method === "DELETE" && pathname.startsWith("/api/passkeys/"));
}

function isAdminMutation(path: string, method: string): boolean {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) return false;
  return new URL(path, window.location.origin).pathname.startsWith("/api/admin/");
}

function createMutationKey(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

function changesBrowserSession(path: string, method: string): boolean {
  const pathname = new URL(path, window.location.origin).pathname;
  return (method === "POST" && (
    pathname === "/api/login"
      || pathname === "/api/login/authorization-code"
      || pathname === "/api/register"
      || pathname === "/api/passkeys/authentication/finish"
      || pathname === "/api/logout"
      || pathname === "/api/browser-accounts/select"
      || pathname === "/api/browser-accounts/activate"
      || pathname === "/api/browser-accounts/logout-all"
  )) || (method === "DELETE" && pathname.startsWith("/api/browser-accounts/"));
}

function safeJson(value: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(value) };
  } catch {
    return { ok: false };
  }
}
