import { useState, type Dispatch, type SetStateAction } from "react";

import * as applicationAuthorizationApi from "../../lib/api/application-authorization";
import type { ApplicationAuthorizationPreview } from "../../lib/api/application-authorization";
import type { ApplicationAuthorizationCopy } from "./application-authorization-copy";
import {
  persistAuthorizationBindings,
  type AuthorizationBindingDraft,
  type AuthorizationBindingScope,
  type AuthorizationBindingSnapshot,
} from "./authorization-bindings-service";
import type { ApplicationWorkspaceRequestApi } from "./use-application-workspace-request-context";

type AuthorizationBindingEffects = {
  applySnapshot: (snapshot: AuthorizationBindingSnapshot) => void;
  setDirty: Dispatch<SetStateAction<boolean>>;
  setFeedback: Dispatch<SetStateAction<string>>;
  setPreview: Dispatch<SetStateAction<ApplicationAuthorizationPreview | null>>;
  setLoading: Dispatch<SetStateAction<boolean>>;
};

export function useApplicationAuthorizationActions({
  applicationId,
  profileId,
  userId,
  groupId,
  organizationRoles,
  draft,
  copy,
  requestContext,
  bindingEffects,
}: {
  applicationId: string;
  profileId: string;
  userId: string;
  groupId: string;
  organizationRoles: string[];
  draft: AuthorizationBindingDraft;
  copy: Pick<ApplicationAuthorizationCopy, "saveFailed" | "saved">;
  requestContext: ApplicationWorkspaceRequestApi;
  bindingEffects: AuthorizationBindingEffects;
}) {
  const [authorizationSaving, setAuthorizationSaving] = useState(false);

  async function saveAuthorizationBindings() {
    if (!profileId) return;
    const request = requestContext.beginRequest("authorization:bindings", {
      kind: "mutation",
      payloadFingerprint: JSON.stringify({ profileId, userId, groupId, ...draft }),
    });
    if (!request) return;
    setAuthorizationSaving(true);
    bindingEffects.setFeedback("");
    let committed = false;
    try {
      const scope: AuthorizationBindingScope = {
        applicationId,
        profileId,
        userId: userId || null,
        groupId: groupId || null,
        organizationRoles,
      };
      const result = await persistAuthorizationBindings(
        scope,
        draft,
        () => requestContext.isCurrent(request),
        undefined,
        requestContext.requestOptions(request),
      );
      if (result.kind === "stale") return;
      if (result.kind === "reconciled") bindingEffects.applySnapshot(result.snapshot);
      if (result.kind === "saved") {
        bindingEffects.setDirty(false);
        bindingEffects.setPreview(null);
        bindingEffects.setFeedback(copy.saved);
        committed = true;
      } else {
        bindingEffects.setFeedback(copy.saveFailed);
      }
    } catch {
      if (requestContext.isCurrent(request)) bindingEffects.setFeedback(copy.saveFailed);
    } finally {
      if (requestContext.isCurrent(request)) setAuthorizationSaving(false);
      requestContext.finishRequest(request, committed);
    }
  }

  async function runAuthorizationPreview() {
    if (!profileId || !userId) return;
    const request = requestContext.beginRequest("authorization:preview", { kind: "read" });
    if (!request) return;
    bindingEffects.setLoading(true);
    bindingEffects.setFeedback("");
    try {
      const preview = await applicationAuthorizationApi.getApplicationProfileAuthorizationPreview(
        applicationId,
        profileId,
        userId,
        requestContext.requestOptions(request),
      );
      if (!requestContext.isCurrent(request)) return;
      bindingEffects.setPreview(preview);
    } catch {
      if (requestContext.isCurrent(request)) {
        bindingEffects.setFeedback(copy.saveFailed);
        bindingEffects.setPreview(null);
      }
    } finally {
      if (requestContext.isCurrent(request)) bindingEffects.setLoading(false);
      requestContext.finishRequest(request, false);
    }
  }

  return { authorizationSaving, saveAuthorizationBindings, runAuthorizationPreview };
}
