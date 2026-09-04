import { objectResponse, readCached, writeJson } from "../transport";
import type { ApiMutationOptions, CachedReadOptions } from "../transport";
import type { ApplicationBillingSettings } from "../../../types";
import { applicationPath } from "./base";

export function applicationBillingSettingsPath(applicationId: string): string {
  return `${applicationPath(applicationId)}/billing-settings`;
}

export type ApplicationBillingSettingsInput = {
  accept_signet_balance?: boolean;
  wallet_mode?: "shared" | "isolated";
  supported_currencies?: string[];
};

export function getApplicationBillingSettings(applicationId: string, options?: CachedReadOptions): Promise<ApplicationBillingSettings> {
  return readCached<ApplicationBillingSettings>(applicationBillingSettingsPath(applicationId), options, objectResponse);
}

export function updateApplicationBillingSettings(applicationId: string, input: ApplicationBillingSettingsInput, options?: ApiMutationOptions): Promise<ApplicationBillingSettings> {
  return writeJson<ApplicationBillingSettings, ApplicationBillingSettingsInput>(applicationBillingSettingsPath(applicationId), "PUT", input, options);
}
