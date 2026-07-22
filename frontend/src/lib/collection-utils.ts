import type { User } from "../types";

export function sortUsersForDisplay(value: User[]): User[] {
  const bucket = (item: User) => {
    if (item.archived_at) return 2;
    return item.is_active ? 0 : 1;
  };
  return [...value].sort((left, right) => {
    const bucketDiff = bucket(left) - bucket(right);
    if (bucketDiff !== 0) return bucketDiff;
    const leftTime = left.archived_at ?? left.created_at;
    const rightTime = right.archived_at ?? right.created_at;
    return rightTime - leftTime;
  });
}

export function toggleValue(values: string[], value: string): string[] {
  return values.includes(value)
    ? values.filter((item) => item !== value)
    : [...values, value];
}

export function matchesSearch(query: string, ...values: Array<string | null | undefined>): boolean {
  if (!query) return true;
  return values.some((value) => value?.toLocaleLowerCase().includes(query));
}
