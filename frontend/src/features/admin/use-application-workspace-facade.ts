import { useApplicationActions } from "./use-application-actions";
import { useApplicationAdminStateActions } from "./use-application-admin-state-actions";

type ApplicationActionOptions = Parameters<typeof useApplicationActions>[0];
type ApplicationStateOptions = Parameters<typeof useApplicationAdminStateActions>[0];

type Options = ApplicationActionOptions & ApplicationStateOptions;

export function useApplicationWorkspaceFacade(options: Options) {
  const actions = useApplicationActions(options);
  const stateActions = useApplicationAdminStateActions(options);

  return {
    ...actions,
    ...stateActions
  };
}
