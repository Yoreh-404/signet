import { useMemo } from "react";

import type {
  ApplicationModuleKey,
  TenantApplication
} from "../../types";
import { record } from "./application-module-values";

type ConfigurableModuleKey = "login_adapters" | "authorization";

export function useApplicationModuleState(application: TenantApplication | null) {
  return useMemo(() => {
    const modules = new Map(
      (application?.modules ?? []).map((module) => [module.module_key, module])
    );

    function moduleConfig(key: ConfigurableModuleKey): Record<string, unknown> {
      const defaults = key === "login_adapters"
        ? { enabled: true, provider_ids: [], allow_signet_password: true }
        : { inherit_enterprise_roles: true, permissions: [], denied_permissions: [], claims: [] };
      return { ...defaults, ...record(modules.get(key)?.config) };
    }

    function moduleEnabled(key: ApplicationModuleKey): boolean {
      const module = modules.get(key);
      if (module?.is_enabled !== undefined) return module.is_enabled;
      return Boolean(
        application
        && (
          key === "authorization"
          || key === "login_adapters"
          || (key === "protocols" && application.client_bindings.length > 0)
        )
      );
    }

    return { moduleConfig, moduleEnabled };
  }, [application]);
}
