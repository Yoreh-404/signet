import { useCallback } from "react";

export function useApplicationAuthorizationSelection({
  selectedProfileId,
  selectedUserId,
  selectedGroupId,
  hasUnsavedChanges,
  resetDrafts,
  onDiscardChanges,
  onRequestConfirmation,
  unsavedChangesCopy,
  discardChangesCopy,
  setProfileId,
  setUserId,
  setGroupId,
}: {
  selectedProfileId: string;
  selectedUserId: string;
  selectedGroupId: string;
  hasUnsavedChanges: () => boolean;
  resetDrafts: () => void;
  onDiscardChanges: () => void;
  onRequestConfirmation?: (
    action: () => Promise<void> | void,
    title: string,
    description: string,
  ) => void;
  unsavedChangesCopy: string;
  discardChangesCopy: string;
  setProfileId: (value: string) => void;
  setUserId: (value: string) => void;
  setGroupId: (value: string) => void;
}) {
  const selectContext = useCallback(
    (
      nextId: string,
      currentId: string,
      setSelection: (value: string) => void,
    ) => {
      if (nextId === currentId) return;
      const commit = () => {
        resetDrafts();
        onDiscardChanges();
        setSelection(nextId);
      };
      if (!hasUnsavedChanges()) {
        commit();
        return;
      }
      if (onRequestConfirmation) {
        onRequestConfirmation(commit, unsavedChangesCopy, discardChangesCopy);
      } else if (window.confirm(`${unsavedChangesCopy}\n${discardChangesCopy}?`)) {
        commit();
      }
    },
    [
      discardChangesCopy,
      hasUnsavedChanges,
      onDiscardChanges,
      onRequestConfirmation,
      resetDrafts,
      unsavedChangesCopy,
    ],
  );

  const selectAuthorizationProfile = useCallback(
    (nextId: string) => selectContext(nextId, selectedProfileId, setProfileId),
    [selectContext, selectedProfileId, setProfileId],
  );
  const selectAuthorizationUser = useCallback(
    (nextId: string) => selectContext(nextId, selectedUserId, setUserId),
    [selectContext, selectedUserId, setUserId],
  );
  const selectAuthorizationGroup = useCallback(
    (nextId: string) => selectContext(nextId, selectedGroupId, setGroupId),
    [selectContext, selectedGroupId, setGroupId],
  );

  return {
    selectAuthorizationProfile,
    selectAuthorizationUser,
    selectAuthorizationGroup,
  };
}
