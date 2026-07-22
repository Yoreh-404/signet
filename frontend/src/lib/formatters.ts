import type { Locale } from "../types";

export function splitList(value: string): string[] {
  return value
    .split(/[\n, ]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function joinList(value: string[]): string {
  return value.join(" ");
}

export function formatTime(value: number | null | undefined, locale: Locale): string {
  if (!value) return "-";
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value * 1000));
}

export function shortSessionId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 12)}...` : value;
}

export function toTimestamp(value: string): number | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : Math.floor(date.getTime() / 1000);
}

export function toDatetimeLocalValue(value: number | null | undefined): string {
  if (!value) return "";
  const date = new Date(value * 1000);
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}
