import { useCallback } from "react";
import type { Dispatch, SetStateAction } from "react";
import type {
  ApplicationClientBinding,
  ApplicationModule,
  Client,
  TenantApplication
} from "../../types";

type Options = {
  applications: TenantApplication[];
  setApplications: Dispatch<SetStateAction<TenantApplication[]>>;
  setClients: Dispatch<SetStateAction<Client[]>>;
};

export function useApplicationAdminStateActions({
  applications,
  setApplications,
  setClients
}: Options) {
  const updateApplicationModuleInState = useCallback((
    applicationId: string,
    module: ApplicationModule,
    clientBindings?: ApplicationClientBinding[]
  ) => {
    setApplications((current) => current.map((application) => {
      if (application.id !== applicationId) return application;
      const modules = [...(application.modules ?? [])];
      const index = modules.findIndex((item) => item.module_key === module.module_key);
      if (index >= 0) modules[index] = module;
      else modules.push(module);
      return {
        ...application,
        modules,
        ...(clientBindings ? { client_bindings: clientBindings } : {})
      };
    }));
  }, [setApplications]);

  const updateApplicationOidcClientsInState = useCallback((
    applicationId: string,
    nextClients: Client[]
  ) => {
    const previousApplicationClientIds = new Set(
      applications
        .find((application) => application.id === applicationId)
        ?.client_bindings
        .filter((binding) => binding.protocol === "oidc")
        .map((binding) => binding.id) ?? []
    );
    setClients((current) => {
      const retained = current.filter((client) => !previousApplicationClientIds.has(client.id));
      return [...retained, ...nextClients];
    });
    setApplications((current) => current.map((application) => {
      if (application.id !== applicationId) return application;
      const previousOidcBindings = application.client_bindings.filter((binding) => binding.protocol === "oidc");
      const oidcBindings = nextClients.map((client) => {
        const previous = previousOidcBindings.find((binding) => binding.id === client.id);
        return {
          ...client,
          protocol: "oidc" as const,
          authorization_profile_id: previous?.authorization_profile_id ?? "default",
          auth_domain_id: previous?.auth_domain_id ?? `auth-domain:${applicationId}`
        };
      });
      return {
        ...application,
        client_bindings: [
          ...application.client_bindings.filter((binding) => binding.protocol !== "oidc"),
          ...oidcBindings
        ]
      };
    }));
  }, [applications, setApplications, setClients]);

  return {
    updateApplicationModuleInState,
    updateApplicationOidcClientsInState
  };
}
