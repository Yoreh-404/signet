import { useEffect, useRef } from "react";

import type {
  DirtyNavigationController,
  DirtyNavigationSourceHandle
} from "../navigation/useDirtyNavigation";

export type ApplicationDirtySourceOptions = {
  dirtyNavigation?: Pick<DirtyNavigationController, "registerSource">;
  dirtySource?: string;
  dirty: boolean;
  onDirtyChange?: (dirty: boolean) => void;
};

export function useApplicationDirtySource({
  dirtyNavigation,
  dirtySource,
  dirty,
  onDirtyChange
}: ApplicationDirtySourceOptions) {
  const sourceRef = useRef<DirtyNavigationSourceHandle | null>(null);

  useEffect(() => {
    if (!dirtyNavigation || !dirtySource) return;
    const source = dirtyNavigation.registerSource(dirtySource);
    sourceRef.current = source;
    return () => {
      source.unregister();
      if (sourceRef.current === source) sourceRef.current = null;
    };
  }, [dirtyNavigation?.registerSource, dirtySource]);

  useEffect(() => {
    sourceRef.current?.setDirty(dirty);
    onDirtyChange?.(dirty);
  }, [dirty, onDirtyChange]);

  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange]);
}
