/**
 * Domain-level equality for drafts and server snapshots.
 *
 * Object key insertion order is transport noise, while array order remains
 * meaningful for fields such as claim mappers and ordered redirect lists.
 * This deliberately avoids serialising secrets or large objects just to
 * answer a dirty-form question.
 */
export function stableDomainEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (left === null || right === null || typeof left !== typeof right) return false;
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
    return left.every((value, index) => stableDomainEqual(value, right[index]));
  }
  if (typeof left !== "object" || typeof right !== "object") return false;
  const leftRecord = left as Record<string, unknown>;
  const rightRecord = right as Record<string, unknown>;
  const leftKeys = Object.keys(leftRecord).sort();
  const rightKeys = Object.keys(rightRecord).sort();
  if (leftKeys.length !== rightKeys.length || leftKeys.some((key, index) => key !== rightKeys[index])) return false;
  return leftKeys.every((key) => stableDomainEqual(leftRecord[key], rightRecord[key]));
}

export function isDirtyDomain<T>(value: T, baseline: T | null | undefined): boolean {
  return baseline !== null && baseline !== undefined && !stableDomainEqual(value, baseline);
}

