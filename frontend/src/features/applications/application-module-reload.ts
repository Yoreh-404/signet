import * as applicationApi from "../../lib/api/applications";
import type { ApplicationModule, ApplicationModuleKey } from "../../types";

export async function reloadApplicationModule(
  applicationId: string,
  moduleKey: ApplicationModuleKey,
  signal: AbortSignal
): Promise<ApplicationModule | null> {
  const modules = await applicationApi.listApplicationModules(applicationId, {
    force: true,
    signal
  });
  return modules.find((module) => module.module_key === moduleKey) ?? null;
}
