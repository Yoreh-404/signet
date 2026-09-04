import { arrayResponse, readCached, writeJson } from "../transport";
import { appendPathSegment } from "../path-helpers";
import type { ApiMutationOptions, ApiOkResponse, CachedReadOptions } from "../transport";
import type { TenantApplication } from "../../../types";

export const APPLICATIONS_PATH = "/api/admin/applications";

export function applicationsPath(): string {
  return APPLICATIONS_PATH;
}

export function applicationPath(applicationId: string): string {
  return appendPathSegment(APPLICATIONS_PATH, applicationId);
}

export type ApplicationInput = {
  slug: string;
  name: string;
  website_url?: string | null;
  description?: string | null;
  account_selection_mode: "optional" | "required";
  unique_identity_factors: Array<"email" | "phone">;
  is_active: boolean;
};

export function listApplications(options?: CachedReadOptions): Promise<TenantApplication[]> {
  return readCached<TenantApplication[]>(applicationsPath(), options, arrayResponse);
}

export function createApplication(
  input: ApplicationInput,
  options?: ApiMutationOptions
): Promise<TenantApplication> {
  return writeJson<TenantApplication, ApplicationInput>(applicationsPath(), "POST", input, options);
}

export function updateApplication(
  applicationId: string,
  input: ApplicationInput,
  options?: ApiMutationOptions
): Promise<TenantApplication> {
  return writeJson<TenantApplication, ApplicationInput>(applicationPath(applicationId), "PUT", input, options);
}

export function deleteApplication(applicationId: string, options?: ApiMutationOptions): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationPath(applicationId), "DELETE", undefined, options);
}
