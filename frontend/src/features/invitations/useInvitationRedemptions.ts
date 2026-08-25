import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../../lib/api";
import type { ApiRequestInit } from "../../lib/api";
import { adminAuthorizationCodeRedemptionsPath } from "../../lib/api/admin";
import type {
  Invitation,
  InvitationRedemption,
  InvitationRedemptionsPage
} from "../../types";

const PAGE_SIZE = 50;

export type InvitationRedemptionsState = {
  invitation: Invitation | null;
  items: InvitationRedemption[];
  nextCursor: string | null;
  loading: boolean;
  error: unknown | null;
};

export type InvitationRedemptionsController = InvitationRedemptionsState & {
  open: (invitation: Invitation) => void;
  close: () => void;
  reload: () => Promise<void>;
  loadMore: () => Promise<void>;
};

export type InvitationRedemptionsRequest = <T = unknown>(
  path: string,
  options?: ApiRequestInit
) => Promise<T>;

const EMPTY_STATE: InvitationRedemptionsState = {
  invitation: null,
  items: [],
  nextCursor: null,
  loading: false,
  error: null
};

function isAbortError(error: unknown): boolean {
  return (typeof DOMException !== "undefined"
    && error instanceof DOMException
    && error.name === "AbortError")
    || (error instanceof Error && error.name === "AbortError");
}

/**
 * Owns the paginated redemption read model for one invitation.  The sequence
 * guard is intentional even though requests are aborted: a fetch can settle
 * after abort, and a closed/replaced modal must never accept that response.
 */
export function useInvitationRedemptions(
  request: InvitationRedemptionsRequest = api
): InvitationRedemptionsController {
  const [state, setState] = useState<InvitationRedemptionsState>(EMPTY_STATE);
  const sequence = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const invitationId = useRef<string | null>(null);

  const loadPage = useCallback(async (invitation: Invitation, cursor: string | null) => {
    const requestSequence = ++sequence.current;
    controller.current?.abort();
    const requestController = new AbortController();
    controller.current = requestController;
    invitationId.current = invitation.id;

    setState((current) => ({
      ...current,
      invitation,
      items: cursor ? current.items : [],
      nextCursor: cursor ? current.nextCursor : null,
      loading: true,
      error: null
    }));

    try {
      const result = await request<InvitationRedemptionsPage>(
        adminAuthorizationCodeRedemptionsPath(invitation.id, {
          limit: PAGE_SIZE,
          ...(cursor ? { cursor } : {})
        }),
        { signal: requestController.signal }
      );
      if (
        requestSequence !== sequence.current
        || requestController.signal.aborted
        || invitationId.current !== invitation.id
      ) return;
      setState((current) => ({
        ...current,
        invitation,
        items: cursor ? [...current.items, ...result.redemptions] : result.redemptions,
        nextCursor: result.next_cursor,
        loading: false,
        error: null
      }));
    } catch (error) {
      if (
        requestSequence !== sequence.current
        || requestController.signal.aborted
        || invitationId.current !== invitation.id
        || isAbortError(error)
      ) return;
      setState((current) => ({ ...current, loading: false, error }));
    } finally {
      if (controller.current === requestController) controller.current = null;
    }
  }, [request]);

  const open = useCallback((invitation: Invitation) => {
    void loadPage(invitation, null);
  }, [loadPage]);

  const close = useCallback(() => {
    sequence.current += 1;
    controller.current?.abort();
    controller.current = null;
    invitationId.current = null;
    setState(EMPTY_STATE);
  }, []);

  const reload = useCallback(async () => {
    const invitation = state.invitation;
    if (!invitation) return;
    await loadPage(invitation, null);
  }, [loadPage, state.invitation]);

  const loadMore = useCallback(async () => {
    const invitation = state.invitation;
    if (!invitation || !state.nextCursor || state.loading) return;
    await loadPage(invitation, state.nextCursor);
  }, [loadPage, state.invitation, state.loading, state.nextCursor]);

  useEffect(() => () => {
    sequence.current += 1;
    controller.current?.abort();
  }, []);

  return { ...state, open, close, reload, loadMore };
}
