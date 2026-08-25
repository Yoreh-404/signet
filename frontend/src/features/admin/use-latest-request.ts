import { useCallback, useEffect, useRef } from "react";

export type LatestRequestToken = {
  signal: AbortSignal;
  isCurrent: () => boolean;
};

/**
 * Owns the cancellation and latest-wins fence for one resource stream.
 *
 * A sequence check alone prevents stale state writes but still leaves the old
 * request consuming sockets and server work.  This primitive does both: a
 * new token aborts the previous request, and consumers can still fence
 * transports that do not honor AbortSignal.
 */
export function useLatestRequest() {
  const sequence = useRef(0);
  const controller = useRef<AbortController | null>(null);

  const cancel = useCallback(() => {
    sequence.current += 1;
    controller.current?.abort();
    controller.current = null;
  }, []);

  const begin = useCallback((): LatestRequestToken => {
    controller.current?.abort();
    const requestSequence = ++sequence.current;
    const nextController = new AbortController();
    controller.current = nextController;
    return {
      signal: nextController.signal,
      isCurrent: () => (
        sequence.current === requestSequence
        && controller.current === nextController
        && !nextController.signal.aborted
      )
    };
  }, []);

  useEffect(() => cancel, [cancel]);

  return { begin, cancel };
}

