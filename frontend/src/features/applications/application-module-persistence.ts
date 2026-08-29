import * as applicationApi from "../../lib/api/applications";
import type { ApplicationModule, ApplicationModuleKey } from "../../types";
import type { ApplicationModuleInput } from "../../lib/api/applications";
import { applicationRequestOptions, type ApplicationRequestToken } from "./application-request-guard";
import { reloadApplicationModule } from "./application-module-reload";

export type ApplicationModulePersistenceResult = {
  module: ApplicationModule | null;
  moduleWritten: boolean;
  committed: boolean;
  stale: boolean;
  failed: boolean;
};

export async function persistApplicationModule(
  applicationId: string,
  moduleKey: ApplicationModuleKey,
  input: ApplicationModuleInput,
  request: ApplicationRequestToken,
  isCurrent: (request: ApplicationRequestToken) => boolean
): Promise<ApplicationModulePersistenceResult> {
  let moduleWritten = false;
  try {
    const module = await applicationApi.updateApplicationModule(
      applicationId,
      moduleKey,
      input,
      applicationRequestOptions(request)
    );
    moduleWritten = true;
    if (!isCurrent(request)) {
      return { module: null, moduleWritten, committed: false, stale: true, failed: false };
    }
    return { module, moduleWritten, committed: true, stale: false, failed: false };
  } catch {
    if (!isCurrent(request)) {
      return { module: null, moduleWritten, committed: false, stale: true, failed: false };
    }
    try {
      const module = await reloadApplicationModule(applicationId, moduleKey, request.signal);
      if (!isCurrent(request)) {
        return { module: null, moduleWritten, committed: false, stale: true, failed: false };
      }
      return { module, moduleWritten, committed: false, stale: false, failed: false };
    } catch {
      return { module: null, moduleWritten, committed: false, stale: false, failed: true };
    }
  }
}
