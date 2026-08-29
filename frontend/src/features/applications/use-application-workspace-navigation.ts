import { useCallback, useMemo } from "react";

import type { ApplicationSection, TenantApplication } from "../../types";

type ApplicationWorkspaceNavigationOptions = {
  selected: TenantApplication | null;
  selectedId: string | null;
  section: ApplicationSection;
  setSelectedId: (id: string | null) => void;
  setSection: (section: ApplicationSection) => void;
  resetWorkspaceDrafts: () => void;
  invalidateApplicationRequests: (nextId: string | null) => void;
  clearFeedback: () => void;
  hasUnsavedChanges: () => boolean;
  unsavedChanges: string;
  discardChanges: string;
  onNavigationChange?: (applicationId: string, section: ApplicationSection) => void;
  onRequestConfirmation?: (
    action: () => Promise<void> | void,
    title: string,
    description: string
  ) => void;
};

export function useApplicationWorkspaceNavigation({
  selected,
  selectedId,
  section,
  setSelectedId,
  setSection,
  resetWorkspaceDrafts,
  invalidateApplicationRequests,
  clearFeedback,
  hasUnsavedChanges,
  unsavedChanges,
  discardChanges,
  onNavigationChange,
  onRequestConfirmation
}: ApplicationWorkspaceNavigationOptions) {
  const commitSectionChange = useCallback((next: ApplicationSection) => {
    clearFeedback();
    setSection(next);
    if (selected) onNavigationChange?.(selected.id, next);
  }, [clearFeedback, onNavigationChange, selected, setSection]);

  const runAfterDiscard = useCallback((action: () => void): boolean => {
    if (!hasUnsavedChanges()) {
      action();
      return true;
    }
    if (onRequestConfirmation) {
      onRequestConfirmation(() => {
        resetWorkspaceDrafts();
        action();
      }, unsavedChanges, discardChanges);
      return false;
    }
    if (!window.confirm(`${unsavedChanges}\n${discardChanges}?`)) return false;
    resetWorkspaceDrafts();
    action();
    return true;
  }, [discardChanges, hasUnsavedChanges, onRequestConfirmation, resetWorkspaceDrafts, unsavedChanges]);

  const selectApplication = useCallback((nextId: string) => {
    if (nextId === selectedId) return;
    runAfterDiscard(() => {
      invalidateApplicationRequests(nextId);
      setSelectedId(nextId);
      setSection("overview");
      onNavigationChange?.(nextId, "overview");
    });
  }, [invalidateApplicationRequests, onNavigationChange, resetWorkspaceDrafts, runAfterDiscard, selectedId, setSection, setSelectedId]);

  const openSection = useCallback((next: ApplicationSection) => {
    if (next === section) return;
    runAfterDiscard(() => commitSectionChange(next));
  }, [commitSectionChange, runAfterDiscard, section]);

  return useMemo(() => ({ selectApplication, openSection }), [openSection, selectApplication]);
}
