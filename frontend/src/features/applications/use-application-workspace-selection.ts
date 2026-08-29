import { useEffect, useMemo, useRef, useState } from "react";

import type { ApplicationSection, TenantApplication } from "../../types";
import {
  createApplicationRequestGuard,
  type ApplicationRequestGuard,
} from "./application-request-guard";

export function useApplicationWorkspaceSelection({
  applications,
  initialApplicationId,
  initialSection,
}: {
  applications: TenantApplication[];
  initialApplicationId?: string | null;
  initialSection?: ApplicationSection | null;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(
    initialApplicationId ?? applications[0]?.id ?? null,
  );
  const [section, setSection] = useState<ApplicationSection>(
    initialSection ?? "overview",
  );
  const selectedIdRef = useRef(selectedId);
  const applicationGenerationRef = useRef(0);
  if (selectedIdRef.current !== selectedId) {
    selectedIdRef.current = selectedId;
    applicationGenerationRef.current += 1;
  }

  const applicationsById = useMemo(
    () => new Map(applications.map((item) => [item.id, item])),
    [applications],
  );
  const firstApplicationId = applications[0]?.id ?? null;
  const selected = selectedId ? applicationsById.get(selectedId) ?? null : null;
  const requestGuard = useMemo<ApplicationRequestGuard>(
    () =>
      createApplicationRequestGuard(() => ({
        applicationId: selectedIdRef.current,
        generation: applicationGenerationRef.current,
      })),
    [],
  );

  function invalidateApplicationRequests(nextId: string | null) {
    selectedIdRef.current = nextId;
    applicationGenerationRef.current += 1;
    requestGuard.invalidate();
  }

  useEffect(() => () => requestGuard.dispose(), [requestGuard]);

  useEffect(() => {
    if (applicationsById.size === 0) {
      setSelectedId(null);
      return;
    }
    if (initialApplicationId && applicationsById.has(initialApplicationId)) {
      if (selectedId !== initialApplicationId) setSelectedId(initialApplicationId);
    } else if (!selectedId || !applicationsById.has(selectedId)) {
      setSelectedId(firstApplicationId);
    }
  }, [applicationsById, firstApplicationId, initialApplicationId, selectedId]);

  return {
    selectedId,
    setSelectedId,
    section,
    setSection,
    selected,
    requestGuard,
    invalidateApplicationRequests,
  };
}
