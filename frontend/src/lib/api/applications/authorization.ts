import { arrayResponse, readCached, writeJson } from "../transport";
import { appendPathSegment } from "../path-helpers";
import type { ApiMutationOptions, ApiOkResponse, CachedReadOptions } from "../transport";
import type { ApplicationModule, ApplicationModuleKey, ApplicationEnrollmentCodeCreateResponse, Invitation } from "../../../types";
import { applicationPath } from "./base";

export function applicationModulesPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/modules`;
}

export function applicationModulePath(applicationId: string, moduleKey: ApplicationModuleKey): string {
  return appendPathSegment(applicationModulesPath(applicationId), moduleKey);
}

export function applicationEnrollmentCodesPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/enrollment-codes`;
}

export function applicationEnrollmentCodePath(applicationId: string, codeId: string): string {
  return appendPathSegment(applicationEnrollmentCodesPath(applicationId), codeId);
}

export type ApplicationModuleInput = {
  config: Record<string, unknown>;
  is_enabled?: boolean;
};

export type ApplicationEnrollmentCodeInput = {
  description?: string | null;
  account_kind?: "normal" | "restricted_trial";
  expires_at: number;
  max_uses: number;
  organization_role?: "owner" | "admin" | "member" | string;
  is_active?: boolean;
};

export function listApplicationModules(
  applicationId: string,
  options?: CachedReadOptions
): Promise<ApplicationModule[]> {
  return readCached<ApplicationModule[]>(applicationModulesPath(applicationId), options, arrayResponse);
}

export function updateApplicationModule(
  applicationId: string,
  moduleKey: ApplicationModuleKey,
  input: ApplicationModuleInput,
  options?: ApiMutationOptions
): Promise<ApplicationModule> {
  return writeJson<ApplicationModule, ApplicationModuleInput>(
    applicationModulePath(applicationId, moduleKey),
    "PUT",
    input,
    options
  );
}

export function deleteApplicationModule(
  applicationId: string,
  moduleKey: ApplicationModuleKey,
  options?: ApiMutationOptions
): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationModulePath(applicationId, moduleKey), "DELETE", undefined, options);
}

export function listApplicationEnrollmentCodes(
  applicationId: string,
  options?: CachedReadOptions
): Promise<Invitation[]> {
  return readCached<Invitation[]>(applicationEnrollmentCodesPath(applicationId), options, arrayResponse);
}

export function createApplicationEnrollmentCode(
  applicationId: string,
  input: ApplicationEnrollmentCodeInput,
  options?: ApiMutationOptions
): Promise<ApplicationEnrollmentCodeCreateResponse> {
  return writeJson<ApplicationEnrollmentCodeCreateResponse, ApplicationEnrollmentCodeInput>(
    applicationEnrollmentCodesPath(applicationId),
    "POST",
    input,
    options
  );
}

export function deleteApplicationEnrollmentCode(
  applicationId: string,
  codeId: string,
  options?: ApiMutationOptions
): Promise<ApiOkResponse> {
  return writeJson<ApiOkResponse, undefined>(applicationEnrollmentCodePath(applicationId, codeId), "DELETE", undefined, options);
}
