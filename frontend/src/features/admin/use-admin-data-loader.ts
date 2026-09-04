import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { ApiError, cachedApi, cachedApiValue } from "../../lib/api";
import { hasCachedAdminTab } from "./admin-tab-cache";
import { loadAdminTab } from "./admin-tab-loader";
import {
  createAdminReadModelSetters,
  createEmptyAdminReadModel,
  resolveAdminReadModelUpdateValue,
  type AdminReadModel,
  type AdminReadModelSetters,
  type AdminReadModelUpdater
} from "./admin-read-model";
export type {
  AdminReadModel,
  AdminReadModelSetters,
  AdminReadModelUpdate,
  AdminReadModelUpdater
} from "./admin-read-model";
import type { SessionController } from "../session/useSessionController";
import type { AdminPermissionState } from "./admin-permissions";
import type { LoginSettingsDraft, Tab } from "../../types";

export type AdminDataLoaderOptions = {
  tab: Tab;
  session: SessionController;
  scopeKey: string | null;
  enabled?: boolean;
  onError?: (error: unknown) => void;
  onLoginSettingsLoaded: (draft: LoginSettingsDraft) => void;
  permissions: AdminDataPermissions;
};

export type AdminDataPermissions = Pick<
  AdminPermissionState,
  | "canAdmin"
  | "canReadUsers"
  | "canManageActiveOrganization"
  | "canReadOrganizations"
  | "canManageOrganizations"
  | "canManageAuthorizationCodes"
  | "canManageSettings"
  | "canManagePlatformProviders"
  | "canManageProviders"
  | "canManageSecurity"
  | "canReadAudit"
>;

/**
 * Admin pages share a session-scoped read model, but they do not share a
 * request lifecycle. Keeping the model and its loader together makes the
 * abort/scope/cache invariants explicit and leaves App responsible only for
 * composing forms and commands.
 */
export type AdminDataLoaderResult = AdminReadModel & AdminReadModelSetters & {
  readModel: AdminReadModel;
  updateReadModel: AdminReadModelUpdater;
  adminLoading: boolean;
  loadAdminData: (targetTab?: Tab, options?: { force?: boolean }) => Promise<void>;
  invalidateAdminLoad: () => void;
  clearScopedAdminData: () => void;
};

/**
 * Loads one management tab at a time. `readModel` and `updateReadModel` are
 * the canonical state boundary. Explicit field setters are a typed command
 * surface for existing form commands; the network lifecycle itself remains
 * private.
 */
export function useAdminDataLoader(options: AdminDataLoaderOptions): AdminDataLoaderResult {
  const {
    tab,
    session,
    scopeKey,
    enabled = true,
    onError,
    onLoginSettingsLoaded,
    permissions,
  } = options;
  const {
    canAdmin,
    canReadUsers,
    canManageActiveOrganization,
    canReadOrganizations,
    canManageOrganizations,
    canManageAuthorizationCodes,
    canManageSettings,
    canManagePlatformProviders,
    canManageProviders,
    canManageSecurity,
    canReadAudit
  } = permissions;

  const [readModel, setReadModel] = useState<AdminReadModel>(createEmptyAdminReadModel);
  const [adminLoading, setAdminLoading] = useState(false);

  const updateReadModel = useCallback<AdminReadModelUpdater>((key, update) => {
    setReadModel((current) => {
      const nextValue = resolveAdminReadModelUpdateValue(current[key], update);
      if (Object.is(current[key], nextValue)) return current;
      const next = { ...current };
      next[key] = nextValue;
      return next;
    });
  }, []);

  const adminReadModelSetters = useMemo(
    () => createAdminReadModelSetters(updateReadModel),
    [updateReadModel]
  );

  const loadId = useRef(0);
  const abortController = useRef<AbortController | null>(null);
  const scopeRef = useRef(scopeKey);
  const scopeChanged = scopeRef.current !== scopeKey;
  if (scopeChanged) {
    // Invalidate during render so a response cannot repopulate an old tenant
    // before the scope effect gets a chance to clear the model.
    scopeRef.current = scopeKey;
    loadId.current += 1;
  }
  const permissionFingerprint = [
    canAdmin,
    canReadUsers,
    canManageActiveOrganization,
    canReadOrganizations,
    canManageOrganizations,
    canManageAuthorizationCodes,
    canManageSettings,
    canManagePlatformProviders,
    canManageProviders,
    canManageSecurity,
    canReadAudit
  ].map((allowed) => (allowed ? "1" : "0")).join("");
  const permissionRef = useRef(permissionFingerprint);
  const permissionsChanged = permissionRef.current !== permissionFingerprint;
  if (permissionsChanged) {
    // Invalidate during render so a permission update cannot expose the old
    // read model before the cleanup effect runs.
    permissionRef.current = permissionFingerprint;
    loadId.current += 1;
  }
  // Effects run after paint. Do not expose the previous account/organization's
  // read model during that one render; a stale admin object is more dangerous
  // than a short loading state because it can look like the new tenant's data.
  const visibleReadModel = scopeChanged || permissionsChanged
    ? createEmptyAdminReadModel()
    : readModel;

  const invalidateAdminLoad = useCallback(() => {
    loadId.current += 1;
    abortController.current?.abort();
    abortController.current = null;
  }, []);

  const clearScopedAdminData = useCallback(() => {
    setReadModel(createEmptyAdminReadModel());
    setAdminLoading(false);
  }, []);

  useEffect(() => {
    invalidateAdminLoad();
    clearScopedAdminData();
  }, [clearScopedAdminData, invalidateAdminLoad, permissionFingerprint, scopeKey]);

  const loadAdminData = useCallback(async (targetTab: Tab = tab, loadOptions: { force?: boolean } = {}) => {
    if (!canAdmin || targetTab === "account") return;

    const requestId = ++loadId.current;
    abortController.current?.abort();
    const controller = new AbortController();
    abortController.current = controller;
    const started = session.getSnapshot();
    const startedScope = started.cacheScope;
    const startedUserId = started.user?.id ?? null;
    const startedOrganizationId = started.organizationContext?.id ?? null;
    const startedGeneration = session.getGeneration();
    const startedPermissionFingerprint = permissionFingerprint;
    const isCurrent = () => {
      const current = session.getSnapshot();
      return loadId.current === requestId
        && scopeRef.current === startedScope
        && scopeKey === startedScope
        && permissionRef.current === startedPermissionFingerprint
        && permissionFingerprint === startedPermissionFingerprint
        && !controller.signal.aborted
        && session.getGeneration() === startedGeneration
        && current.cacheScope === startedScope
        && (current.user?.id ?? null) === startedUserId
        && (current.organizationContext?.id ?? null) === startedOrganizationId;
    };
    const cacheAvailable = !loadOptions.force && hasCachedAdminTab(targetTab, { canManageSecurity, canReadAudit });
    setAdminLoading(!cacheAvailable);

    async function loadCached<T>(path: string, apply: (value: T) => void): Promise<T> {
      const cached = cachedApiValue<T>(path);
      if (cached !== undefined && isCurrent()) apply(cached);
      const result = await cachedApi<T>(path, {
        force: loadOptions.force,
        signal: controller.signal
      });
      if (isCurrent() && !result.stale && (result.changed || cached === undefined)) apply(result.value);
      return result.value;
    }

    try {
      await loadAdminTab({
        targetTab,
        loadCached,
        updateReadModel,
        canReadUsers,
        canManageActiveOrganization,
        canReadOrganizations,
        canManageOrganizations,
        canManageAuthorizationCodes,
        canManageSettings,
        canManagePlatformProviders,
        canManageProviders,
        canManageSecurity,
        canReadAudit,
        onLoginSettingsLoaded
      });
    } catch (error) {
      if (!isCurrent()) return;
      // Cached views remain usable through transient server/network failures;
      // authorization errors still reach the caller and close the boundary.
      if (
        cacheAvailable
        && !loadOptions.force
        && (!(error instanceof ApiError) || error.status === 0 || error.status >= 500)
      ) return;
      throw error;
    } finally {
      if (isCurrent()) setAdminLoading(false);
      if (abortController.current === controller) abortController.current = null;
    }
  }, [
    canAdmin,
    canManageActiveOrganization,
    canManageAuthorizationCodes,
    canManageOrganizations,
    canManagePlatformProviders,
    canManageProviders,
    canManageSecurity,
    canManageSettings,
    canReadAudit,
    canReadOrganizations,
    canReadUsers,
    onLoginSettingsLoaded,
    permissionFingerprint,
    scopeKey,
    session,
    tab,
    updateReadModel
  ]);

  useEffect(() => {
    if (!enabled) {
      invalidateAdminLoad();
      return;
    }
    const loadScope = scopeKey;
    void loadAdminData(tab).catch((error) => {
      if (scopeKey === loadScope) onError?.(error);
    });
    return () => invalidateAdminLoad();
  }, [enabled, invalidateAdminLoad, loadAdminData, onError, scopeKey, tab]);

  return {
    ...visibleReadModel,
    readModel: visibleReadModel,
    ...adminReadModelSetters,
    updateReadModel,
    adminLoading: scopeChanged || adminLoading,
    loadAdminData,
    invalidateAdminLoad,
    clearScopedAdminData
  };
}
