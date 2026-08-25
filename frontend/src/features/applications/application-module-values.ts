/**
 * Small runtime guards shared by application module editors.
 *
 * Module configuration is intentionally JSON-shaped at the API boundary, so
 * each editor needs the same narrow projections before rendering controls.
 * Keeping these guards in one place prevents defaults and malformed-value
 * handling from drifting between modules.
 */
export function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

export function booleanValue(value: unknown, fallback = false): boolean {
  return typeof value === "boolean" ? value : fallback;
}

export function stringValue(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

export function stringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}
