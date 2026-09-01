import { api } from "../../lib/api";
import type {
  User,
  UserDirectoryCursorPage,
  UserDirectoryLinkedIdentity,
  UserDirectoryPage,
  UserDirectoryQuery,
  UserDirectoryRoleFilter,
  UserDirectoryServerFilters,
  UserDirectoryLoginRegion,
  UserFilter
} from "../../types";

export type {
  PaginatedEnvelope,
  UserDirectoryLinkedIdentity,
  UserDirectoryLoginRegion,
  UserDirectoryPage,
  UserDirectoryCursorPage,
  UserDirectoryQuery,
  UserDirectoryRoleFilter,
  UserDirectoryServerFilters
} from "../../types";

export const DEFAULT_USER_DIRECTORY_PAGE = 1;
export const DEFAULT_USER_DIRECTORY_PAGE_SIZE = 25;
export const MAX_USER_DIRECTORY_PAGE_SIZE = 200;
export const DEFAULT_USER_DIRECTORY_STATUS: UserFilter = "live";

export function appendUserDirectoryCursor(
  history: readonly (string | null)[],
  currentPage: number,
  nextCursor: string | null,
): Array<string | null> {
  if (!nextCursor || !Number.isFinite(currentPage) || currentPage < 1) {
    return [...history];
  }
  const nextPage = Math.trunc(currentPage) + 1;
  const nextHistory = history.slice(0, nextPage);
  nextHistory[nextPage - 1] = nextCursor;
  return nextHistory;
}

const USER_FILTER_VALUES: readonly UserFilter[] = [
  "live",
  "active",
  "disabled",
  "archived",
  "authorization_code",
  "all"
];
const USER_DIRECTORY_ROLE_VALUES: readonly UserDirectoryRoleFilter[] = ["admin", "user"];
const USER_DIRECTORY_LINKED_IDENTITY_VALUES: readonly UserDirectoryLinkedIdentity[] = ["linked", "unlinked"];
const USER_DIRECTORY_LOGIN_REGION_VALUES: readonly UserDirectoryLoginRegion[] = ["domestic", "overseas"];

export type UserDirectoryQueryInput = Partial<UserDirectoryQuery>;

export type UserDirectoryResponse = UserDirectoryPage | User[];

export const DEFAULT_USER_DIRECTORY_QUERY: UserDirectoryQuery = {
  page: DEFAULT_USER_DIRECTORY_PAGE,
  page_size: DEFAULT_USER_DIRECTORY_PAGE_SIZE,
  status: DEFAULT_USER_DIRECTORY_STATUS
};

function isValue<T extends string>(value: string | null | undefined, values: readonly T[]): value is T {
  return value !== null && value !== undefined && values.includes(value as T);
}

function positiveInteger(value: number | undefined, fallback: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.max(1, Math.trunc(value));
}

function queryStringValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function optionalString(value: unknown): string | undefined {
  return queryStringValue(value);
}

function optionalEnum<T extends string>(value: unknown, values: readonly T[]): T | undefined {
  return typeof value === "string" && isValue(value, values) ? value : undefined;
}

/**
 * Fills defaults and removes empty filters without mutating the caller's
 * object. Keeping this normalization in one place makes parsing and
 * serialization inverse operations even when a URL contains bad input.
 */
export function normalizeUserDirectoryQuery(input: UserDirectoryQueryInput): UserDirectoryQuery {
  const query: UserDirectoryQuery = {
    page: positiveInteger(input.page, DEFAULT_USER_DIRECTORY_QUERY.page),
    page_size: Math.min(
      MAX_USER_DIRECTORY_PAGE_SIZE,
      positiveInteger(input.page_size, DEFAULT_USER_DIRECTORY_QUERY.page_size),
    ),
    status: optionalEnum(input.status, USER_FILTER_VALUES) ?? DEFAULT_USER_DIRECTORY_QUERY.status
  };
  const cursor = optionalString(input.cursor);
  if (cursor !== undefined) query.cursor = cursor;

  const filters: UserDirectoryServerFilters = {
    search: optionalString(input.search),
    organization_id: optionalString(input.organization_id),
    linked_identity: optionalEnum(input.linked_identity, USER_DIRECTORY_LINKED_IDENTITY_VALUES),
    email: optionalString(input.email),
    phone: optionalString(input.phone),
    role: optionalEnum(input.role, USER_DIRECTORY_ROLE_VALUES),
    registration_from: optionalString(input.registration_from),
    registration_to: optionalString(input.registration_to),
    last_login_from: optionalString(input.last_login_from),
    last_login_to: optionalString(input.last_login_to),
    login_region: optionalEnum(input.login_region, USER_DIRECTORY_LOGIN_REGION_VALUES)
  };

  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined) query[key as keyof UserDirectoryServerFilters] = value as never;
  }
  return query;
}

/**
 * Serializes fields in a fixed order. URLSearchParams supplies the standard
 * percent-encoding, while the explicit order keeps cache keys and shareable
 * URLs stable when callers construct equivalent objects in different orders.
 */
export function serializeUserDirectoryQuery(input: UserDirectoryQueryInput): string {
  const query = normalizeUserDirectoryQuery(input);
  const params = new URLSearchParams();
  params.set("page", String(query.page));
  params.set("page_size", String(query.page_size));
  params.set("status", query.status ?? DEFAULT_USER_DIRECTORY_STATUS);
  if (query.cursor !== undefined) params.set("cursor", query.cursor);

  const orderedFilters: Array<[keyof UserDirectoryServerFilters, string | undefined]> = [
    ["search", query.search],
    ["organization_id", query.organization_id],
    ["linked_identity", query.linked_identity],
    ["email", query.email],
    ["phone", query.phone],
    ["role", query.role],
    ["registration_from", query.registration_from],
    ["registration_to", query.registration_to],
    ["last_login_from", query.last_login_from],
    ["last_login_to", query.last_login_to],
    ["login_region", query.login_region]
  ];
  for (const [key, value] of orderedFilters) {
    if (value !== undefined) params.set(key, value);
  }
  return params.toString();
}

function queryParam(search: string | URLSearchParams, key: string): string | null {
  if (search instanceof URLSearchParams) return search.get(key);
  return new URLSearchParams(search.startsWith("?") ? search.slice(1) : search).get(key);
}

function positiveIntegerParam(value: string | null, fallback: number): number {
  if (!value || !/^\d+$/.test(value)) return fallback;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

/** Parses a query string into the same normalized model used by the serializer. */
export function parseUserDirectoryQuery(search: string | URLSearchParams): UserDirectoryQuery {
  const input: UserDirectoryQueryInput = {
    page: positiveIntegerParam(queryParam(search, "page"), DEFAULT_USER_DIRECTORY_PAGE),
    page_size: positiveIntegerParam(queryParam(search, "page_size"), DEFAULT_USER_DIRECTORY_PAGE_SIZE),
    cursor: queryParam(search, "cursor") ?? undefined,
    status: optionalEnum(queryParam(search, "status"), USER_FILTER_VALUES),
    search: queryParam(search, "search") ?? undefined,
    organization_id: queryParam(search, "organization_id") ?? undefined,
    linked_identity: optionalEnum(queryParam(search, "linked_identity"), USER_DIRECTORY_LINKED_IDENTITY_VALUES),
    email: queryParam(search, "email") ?? undefined,
    phone: queryParam(search, "phone") ?? undefined,
    role: optionalEnum(queryParam(search, "role"), USER_DIRECTORY_ROLE_VALUES),
    registration_from: queryParam(search, "registration_from") ?? undefined,
    registration_to: queryParam(search, "registration_to") ?? undefined,
    last_login_from: queryParam(search, "last_login_from") ?? undefined,
    last_login_to: queryParam(search, "last_login_to") ?? undefined,
    login_region: optionalEnum(queryParam(search, "login_region"), USER_DIRECTORY_LOGIN_REGION_VALUES)
  };
  return normalizeUserDirectoryQuery(input);
}

/**
 * Joins a caller-supplied endpoint with the canonical query. The endpoint is
 * deliberately a parameter: the backend route is an integration decision,
 * not a dependency hidden inside the users feature.
 */
export function buildUserDirectoryPath(endpoint: string, query: UserDirectoryQueryInput): string {
  const queryString = serializeUserDirectoryQuery(query);
  if (!queryString) return endpoint;
  if (endpoint.endsWith("?") || endpoint.endsWith("&")) return `${endpoint}${queryString}`;
  return `${endpoint}${endpoint.includes("?") ? "&" : "?"}${queryString}`;
}

export function fetchUserDirectoryPage(
  endpoint: string,
  query: UserDirectoryQueryInput,
  signal?: AbortSignal
): Promise<UserDirectoryPage> {
  return api<unknown>(buildUserDirectoryPath(endpoint, query), { signal })
    .then(normalizeUserDirectoryResponse);
}

export function fetchUserDirectoryCursorPage(
  endpoint: string,
  query: UserDirectoryQueryInput,
  signal?: AbortSignal
): Promise<UserDirectoryCursorPage> {
  return api<unknown>(buildUserDirectoryPath(endpoint, query), { signal })
    .then(normalizeUserDirectoryCursorResponse);
}

/**
 * The paginated envelope is canonical, but older self-hosted backends still
 * return a plain user array. Normalize both shapes at the transport boundary
 * so feature code never has to branch on historical DTOs.
 */
export function normalizeUserDirectoryResponse(value: unknown): UserDirectoryPage {
  if (Array.isArray(value)) {
    return {
      items: value as User[],
      page: DEFAULT_USER_DIRECTORY_PAGE,
      page_size: value.length || DEFAULT_USER_DIRECTORY_PAGE_SIZE,
      total: value.length
    };
  }
  if (!value || typeof value !== "object") {
    throw new Error("invalid user directory response");
  }
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record.items)) {
    throw new Error("invalid user directory response");
  }
  const page = typeof record.page === "number" && Number.isFinite(record.page)
    ? Math.max(1, Math.trunc(record.page))
    : DEFAULT_USER_DIRECTORY_PAGE;
  const pageSize = typeof record.page_size === "number" && Number.isFinite(record.page_size)
    ? Math.min(MAX_USER_DIRECTORY_PAGE_SIZE, Math.max(1, Math.trunc(record.page_size)))
    : DEFAULT_USER_DIRECTORY_PAGE_SIZE;
  const total = typeof record.total === "number" && Number.isFinite(record.total)
    ? Math.max(0, Math.trunc(record.total))
    : record.items.length;
  return {
    items: record.items as User[],
    page,
    page_size: pageSize,
    total
  };
}

export function normalizeUserDirectoryCursorResponse(value: unknown): UserDirectoryCursorPage {
  if (!value || typeof value !== "object") {
    throw new Error("invalid user directory cursor response");
  }
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record.items)) {
    throw new Error("invalid user directory cursor response");
  }
  const pageSize = typeof record.page_size === "number" && Number.isFinite(record.page_size)
    ? Math.min(MAX_USER_DIRECTORY_PAGE_SIZE, Math.max(1, Math.trunc(record.page_size)))
    : DEFAULT_USER_DIRECTORY_PAGE_SIZE;
  const nextCursor = typeof record.next_cursor === "string" && record.next_cursor.trim()
    ? record.next_cursor
    : null;
  return {
    items: record.items as User[],
    page_size: pageSize,
    next_cursor: nextCursor
  };
}
