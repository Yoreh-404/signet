import { api, cachedApi } from "../api";
import type { ApiRequestInit } from "../api";
import { expectArray, expectRecord } from "./validation";
import type { ApiDecoder } from "./validation";

export type ApiMutationOptions = Omit<ApiRequestInit, "body" | "method">;

export type CachedReadOptions = {
  force?: boolean;
  key?: string;
  minRevalidateMs?: number;
  signal?: AbortSignal | null;
};

export type ApiOkResponse = { ok: boolean };

export function pathSegment(value: string): string {
  return encodeURIComponent(value);
}

export function readCached<T>(
  path: string,
  options: CachedReadOptions | undefined,
  decoder: ApiDecoder<T>
): Promise<T> {
  const requestOptions = options
    ? { ...options, signal: options.signal ?? undefined }
    : undefined;
  return cachedApi<T>(path, requestOptions, decoder).then(({ value }) => value);
}

export function requestJson<TResponse>(
  path: string,
  options?: ApiRequestInit,
  decoder?: ApiDecoder<TResponse>
): Promise<TResponse> {
  return api<TResponse>(path, options, decoder);
}

export const arrayResponse = <T>(value: unknown, label?: string): T[] => expectArray<T>(value, label);
export const objectResponse = <T>(value: unknown, label?: string): T => expectRecord<T>(value, label);

export function writeJson<TResponse, TBody>(
  path: string,
  method: "POST" | "PUT" | "DELETE",
  body: TBody | undefined,
  options?: ApiMutationOptions,
  decoder?: ApiDecoder<TResponse>
): Promise<TResponse> {
  const request: ApiRequestInit = { ...options, method };
  if (body !== undefined) request.body = JSON.stringify(body);
  return api<TResponse>(path, request, decoder);
}
