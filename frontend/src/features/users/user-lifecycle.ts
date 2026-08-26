import type { BulkUserImportResult, BulkUserImportRow, User } from "../../types";

export type UserLifecycleState = "active" | "disabled" | "archived";
export type BulkUserAction = "enable" | "disable" | "archive" | "delete" | "reset_mfa";

export const BULK_USER_IMPORT_TEMPLATE = [
  "email,username,display_name,organization_slug,organization_role,is_active",
  "alex@example.com,alex,Alex Example,example-club,member,true"
].join("\n");

export function lifecycleStateForUser(user: Pick<User, "is_active" | "archived_at">): UserLifecycleState {
  if (user.archived_at !== null) return "archived";
  return user.is_active ? "active" : "disabled";
}

export function availableUserActions(
  user: Pick<User, "id" | "is_active" | "archived_at">,
  currentUserId?: string
): BulkUserAction[] {
  const actions: BulkUserAction[] = [];
  const canChangeLifecycle = user.id !== currentUserId;
  const lifecycleState = lifecycleStateForUser(user);
  if (canChangeLifecycle) {
    if (lifecycleState === "active") {
      actions.push("disable");
    } else if (lifecycleState === "disabled") {
      actions.push("enable", "archive");
    } else {
      actions.push("enable", "delete");
    }
  }
  if (lifecycleState !== "archived") actions.push("reset_mfa");
  return actions;
}

export function isBulkUserImportResult(value: unknown): value is BulkUserImportResult {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<BulkUserImportResult>;
  return typeof candidate.dry_run === "boolean"
    && typeof candidate.atomic === "boolean"
    && typeof candidate.committed === "boolean"
    && Array.isArray(candidate.rows)
    && Boolean(candidate.summary)
    && typeof candidate.summary?.total === "number"
    && typeof candidate.summary?.created === "number"
    && typeof candidate.summary?.would_create === "number"
    && typeof candidate.summary?.invalid === "number";
}

export function bulkImportOutcomeTone(
  outcome: BulkUserImportRow["outcome"]
): "success" | "warning" | "danger" | "info" {
  switch (outcome) {
    case "created": return "success";
    case "would_create": return "info";
    case "not_committed": return "warning";
    case "invalid": return "danger";
  }
}
