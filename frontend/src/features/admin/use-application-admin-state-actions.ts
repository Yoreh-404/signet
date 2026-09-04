import { useCallback, useRef } from "react";
import type { Dispatch, SetStateAction } from "react";
import { listApplicationClientBindings } from "../../lib/api/applications/protocol";
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
  const bindingRefreshId = useRef(0);

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
    _nextClients: Client[]
  ) => {
    const refreshId = bindingRefreshId.current + 1;
    bindingRefreshId.current = refreshId;
    const previousApplicationClientIds = new Set(
      applications
        .find((application) => application.id === applicationId)
        ?.client_bindings
        .filter((binding) => binding.protocol === "oidc")
        .map((binding) => binding.id) ?? []
    );
    void listApplicationClientBindings(applicationId, { force: true })
      .then((nextBindings) => {
        if (bindingRefreshId.current !== refreshId) return;
        const nextOidcBindings = nextBindings.filter((binding) => binding.protocol === "oidc");
        const nextOidcClientIds = new Set(nextOidcBindings.map((binding) => binding.id));
        setClients((current) => [
          ...current.filter(
            (client) =>
              !previousApplicationClientIds.has(client.id) && !nextOidcClientIds.has(client.id),
          ),
          ...nextOidcBindings,
        ]);
        setApplications((current) => current.map((application) => {
          if (application.id !== applicationId) return application;
          return {
            ...application,
            client_bindings: [
              ...application.client_bindings.filter((binding) => binding.protocol !== "oidc"),
              ...nextOidcBindings,
            ],
          };
        }));
      })
      .catch(() => {});
  }, [applications, setApplications, setClients]);

  return {
    updateApplicationModuleInState,
    updateApplicationOidcClientsInState
  };
}
