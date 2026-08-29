import * as applicationApi from "../../lib/api/applications";
import type { ApplicationJwtClient, ApplicationModule } from "../../types";
import type { ApplicationModuleInput } from "../../lib/api/applications";
import { applicationRequestOptions, type ApplicationRequestToken } from "./application-request-guard";
import { booleanValue, record, stringValue } from "./application-module-values";
import { reloadApplicationModule } from "./application-module-reload";

export type ApplicationProtocolsPersistenceResult = {
  module: ApplicationModule | null;
  jwtClient?: ApplicationJwtClient | null;
  moduleWritten: boolean;
  committed: boolean;
  stale: boolean;
};

export async function persistApplicationProtocols(
  applicationId: string,
  applicationSlug: string,
  input: ApplicationModuleInput,
  request: ApplicationRequestToken,
  isCurrent: (request: ApplicationRequestToken) => boolean
): Promise<ApplicationProtocolsPersistenceResult> {
  let moduleWritten = false;
  try {
    const module = await applicationApi.updateApplicationModule(
      applicationId,
      "protocols",
      input,
      applicationRequestOptions(request)
    );
    moduleWritten = true;
    if (!isCurrent(request)) {
      return { module: null, moduleWritten, committed: false, stale: true };
    }
    const jwt = record(input.config.jwt);
    let jwtClient: ApplicationJwtClient | undefined;
    if (booleanValue(jwt.enabled)) {
      jwtClient = await applicationApi.updateApplicationJwtClient(
        applicationId,
        {
          client_id: stringValue(jwt.client_id, applicationSlug),
          client_type: stringValue(jwt.client_type, "public") as "public" | "confidential",
          is_active: true
        },
        applicationRequestOptions(request)
      );
      if (!isCurrent(request)) {
        return { module: null, moduleWritten, committed: false, stale: true };
      }
    }
    return { module, jwtClient, moduleWritten, committed: true, stale: false };
  } catch {
    if (!isCurrent(request)) {
      return { module: null, moduleWritten, committed: false, stale: true };
    }
    try {
      const module = await reloadApplicationModule(applicationId, "protocols", request.signal);
      if (!isCurrent(request)) {
        return { module: null, moduleWritten, committed: false, stale: true };
      }
      const jwtClient = await applicationApi.getApplicationJwtClient(
        applicationId,
        { force: true, ...applicationRequestOptions(request) }
      );
      if (!isCurrent(request)) {
        return { module: null, moduleWritten, committed: false, stale: true };
      }
      return { module, jwtClient, moduleWritten, committed: false, stale: false };
    } catch {
      return { module: null, moduleWritten, committed: false, stale: false };
    }
  }
}
