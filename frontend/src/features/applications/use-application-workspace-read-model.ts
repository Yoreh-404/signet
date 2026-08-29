import { useCallback, useState } from "react";

export type ApplicationWorkspaceReadModel = {
  applicationId: string;
  config: Record<string, unknown>;
};

export function useApplicationWorkspaceReadModel() {
  const [readModel, setReadModel] = useState<ApplicationWorkspaceReadModel | null>(null);

  const updateReadModel = useCallback(
    (applicationId: string, config: Record<string, unknown> | null) => {
      setReadModel((current) => {
        if (config === null) return current?.applicationId === applicationId ? null : current;
        return { applicationId, config };
      });
    },
    []
  );

  const resetReadModel = useCallback(() => setReadModel(null), []);

  return { readModel, updateReadModel, resetReadModel };
}
