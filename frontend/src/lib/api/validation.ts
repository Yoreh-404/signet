/**
 * Small runtime decoders for API boundaries.
 *
 * TypeScript types disappear in the browser.  Keeping these decoders
 * dependency-free lets each domain API validate its top-level shape without
 * coupling transport code to every DTO in the application.
 */
export type ApiDecoder<T> = (value: unknown, label?: string) => T;

export class ApiDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApiDecodeError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function expectArray<T = unknown>(value: unknown, label = "response"): T[] {
  if (!Array.isArray(value)) {
    throw new ApiDecodeError(`${label} must be an array`);
  }
  return value as T[];
}

export function expectRecord<T = Record<string, unknown>>(
  value: unknown,
  label = "response"
): T {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiDecodeError(`${label} must be an object`);
  }
  return value as T;
}

export function expectString(value: unknown, label = "value"): string {
  if (typeof value !== "string") {
    throw new ApiDecodeError(`${label} must be a string`);
  }
  return value;
}

export function expectBoolean(value: unknown, label = "value"): boolean {
  if (typeof value !== "boolean") {
    throw new ApiDecodeError(`${label} must be a boolean`);
  }
  return value;
}

export function mapArray<T>(
  value: unknown,
  itemDecoder: ApiDecoder<T>,
  label = "response"
): T[] {
  return expectArray(value, label).map((item, index) => itemDecoder(item, `${label}[${index}]`));
}
