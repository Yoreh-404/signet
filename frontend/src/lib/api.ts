export class ApiError extends Error {
  readonly status: number;
  readonly code: string | null;
  /** Parsed API payload when one was returned, including structured 4xx results. */
  readonly body: unknown | null;

  constructor(message: string, status: number, code: string | null = null, body: unknown | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

type ApiErrorBody = {
  error?: string;
  message?: string;
  error_description?: string;
};

const NETWORK_ERROR_MESSAGE = "Unable to reach the server. Check your connection and try again.";

let csrfToken: string | null = null;
let csrfRequest: Promise<string> | null = null;

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

type CachedApiOptions = {
  /** A stable key when the request URL alone is not sufficient. */
  key?: string;
  /** Skip a network revalidation until this interval has elapsed. */
  minRevalidateMs?: number;
  /** Ignore the revalidation interval, for an explicit refresh. */
  force?: boolean;
};

export type CachedApiResult<T> = {
  value: T;
  changed: boolean;
  revalidated: boolean;
};

const adminResponseCache = new Map<string, CachedApiEntry>();
const adminResponseRequests = new Map<string, Promise<CachedApiResult<unknown>>>();
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
export async function cachedApi<T>(path: string, options: CachedApiOptions = {}): Promise<CachedApiResult<T>> {
  const key = scopedCacheKey(options.key ?? path);
  const existing = adminResponseCache.get(key);
  const now = Date.now();
  const minRevalidateMs = options.minRevalidateMs ?? 15_000;
  if (existing && !options.force && now - existing.checkedAt < minRevalidateMs) {
    return { value: existing.value as T, changed: false, revalidated: false };
  }

  const pending = adminResponseRequests.get(key);
  if (pending) return pending as Promise<CachedApiResult<T>>;

  const generation = cacheGeneration;
  const request = conditionalJsonRequest<T>(path, key, existing, generation);
  adminResponseRequests.set(key, request as Promise<CachedApiResult<unknown>>);
  const clearPending = () => {
    if (adminResponseRequests.get(key) === request) adminResponseRequests.delete(key);
  };
  void request.then(clearPending, clearPending);
  return request;
}

async function conditionalJsonRequest<T>(
  path: string,
  key: string,
  existing: CachedApiEntry | undefined,
  generation: number
): Promise<CachedApiResult<T>> {
  const headers = new Headers({ accept: "application/json" });
  if (existing?.etag) headers.set("if-none-match", existing.etag);

  let response: Response;
  try {
    response = await fetch(path, {
      credentials: "include",
      headers,
      // The browser must not persist sensitive management data; this module
      // owns the short-lived, authenticated in-memory cache instead.
      cache: "no-store"
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(NETWORK_ERROR_MESSAGE, 0, "network_error");
  }

  if (response.status === 304 && existing) {
    existing.checkedAt = Date.now();
    return { value: existing.value as T, changed: false, revalidated: true };
  }

  const text = await response.text();
  const contentType = response.headers.get("content-type") ?? "";
  const parsed = text && contentType.includes("json") ? safeJson(text) : null;
  if (!response.ok) {
    const body = parsed?.ok ? parsed.value as ApiErrorBody | null : null;
    if (response.status === 401) clearCsrfToken();
    const message = body?.message || body?.error_description || text || response.statusText;
    throw new ApiError(message, response.status, body?.error ?? null, body);
  }
  if (!parsed?.ok) {
    throw new ApiError("The server returned an invalid JSON response", response.status);
  }

  const entry: CachedApiEntry = {
    value: parsed.value,
    etag: response.headers.get("etag"),
    checkedAt: Date.now()
  };
  // A mutation or account change may have invalidated the cache while this
  // request was on the wire. Never let that older representation repopulate
  // the new cache generation.
  if (generation === cacheGeneration) adminResponseCache.set(key, entry);
  return { value: entry.value as T, changed: true, revalidated: true };
}

function clearCsrfToken() {
  csrfToken = null;
  csrfRequest = null;
}

/**
 * Shared JSON client for the same-origin SSO API.
 *
 * It deliberately accepts 204/empty responses, preserves caller headers and
 * turns every non-2xx response into one predictable error type.
 */
export async function api<T = void>(path: string, options: RequestInit = {}): Promise<T> {
  return request<T>(path, options, true);
}

async function request<T>(path: string, options: RequestInit, retryCsrf: boolean): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("accept", "application/json");
  if (options.body && !headers.has("content-type") && !(options.body instanceof FormData)) {
    headers.set("content-type", "application/json");
  }
  const method = (options.method ?? "GET").toUpperCase();
  const protectedWrite = isProtectedBrowserWrite(path, method);
  if (protectedWrite) {
    headers.set("x-csrf-token", await currentCsrfToken());
  }

  let response: Response;
  try {
    response = await fetch(path, {
      ...options,
      credentials: "include",
      headers
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(NETWORK_ERROR_MESSAGE, 0, "network_error");
  }

  const text = response.status === 204 ? "" : await response.text();
  const contentType = response.headers.get("content-type") ?? "";
  const parsed = text && contentType.includes("json") ? safeJson(text) : null;

  if (!response.ok) {
    const body = parsed?.ok ? parsed.value as ApiErrorBody | null : null;
    if (response.status === 401) clearCsrfToken();
    if (retryCsrf && protectedWrite && response.status === 403 && body?.error === "csrf_failed") {
      clearCsrfToken();
      return request<T>(path, options, false);
    }
    const message = body?.message || body?.error_description || text || response.statusText;
    throw new ApiError(message, response.status, body?.error ?? null, body);
  }

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
  if (!text) return undefined as T;
  return (parsed?.ok ? parsed.value : text) as T;
}

async function currentCsrfToken(): Promise<string> {
  if (csrfToken) return csrfToken;
  if (!csrfRequest) {
    csrfRequest = fetch("/api/csrf", {
      credentials: "include",
      headers: { accept: "application/json" }
    }).then(async (response) => {
      const body = await response.json().catch(() => null) as (ApiErrorBody & { csrf_token?: string }) | null;
      if (!response.ok || !body?.csrf_token) {
        throw new ApiError(
          body?.message || body?.error_description || body?.error || response.statusText || "Invalid CSRF response",
          response.status,
          body?.error ?? null
        );
      }
      csrfToken = body.csrf_token;
      return csrfToken;
    }).catch((error) => {
      if (error instanceof ApiError) throw error;
      throw new ApiError(NETWORK_ERROR_MESSAGE, 0, "network_error");
    }).finally(() => {
      csrfRequest = null;
    });
  }
  return csrfRequest;
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

function changesBrowserSession(path: string, method: string): boolean {
  if (method !== "POST") return false;
  const pathname = new URL(path, window.location.origin).pathname;
  return pathname === "/api/login"
    || pathname === "/api/login/authorization-code"
    || pathname === "/api/register"
    || pathname === "/api/passkeys/authentication/finish"
    || pathname === "/api/logout";
}

function safeJson(value: string): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: JSON.parse(value) };
  } catch {
    return { ok: false };
  }
}
