import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { ApiError, cachedApi, cachedApiValue } from "../../lib/api";
import { loadAdminApplicationsQuery } from "./admin-applications-query";
import { loadAdminSecurityQuery } from "./admin-security-query";
import {
  loadAdminPortalQuery,
  loadAdminRegistrationQuery,
  loadAdminRuntimeSettingsQuery
} from "./admin-settings-query";
import { ignoreForbiddenRead } from "./admin-read-query";
import { loadAdminOrganizationsQuery } from "./admin-organizations-query";
import { loadAdminProvidersQuery } from "./admin-providers-query";
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
import type {
  AuditEvent,
  AuditWebhook,
  Client,
  ExternalProvider,
  Invitation,
  LoginSettings,
  LoginSettingsDraft,
  Organization,
  OrganizationOption,
  Overview,
  RegistrationSettings,
  RuntimeSettings,
  Tab,
  SecurityPolicy,
  TenantApplication
} from "../../types";

const AUTHORIZATION_CODES_API = "/api/admin/authorization-codes";

export type AdminDataLoaderOptions = {
  tab: Tab;
  session: SessionController;
  scopeKey: string | null;
  onLoginSettingsLoaded: (draft: LoginSettingsDraft) => void;
  canAdmin: boolean;
  canReadUsers: boolean;
  canManageActiveOrganization: boolean;
  canReadOrganizations: boolean;
  canManageOrganizations: boolean;
  canManageAuthorizationCodes: boolean;
  canManageSettings: boolean;
  canManagePlatformProviders: boolean;
  canManageProviders: boolean;
  canManageSecurity: boolean;
  canReadAudit: boolean;
};

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
    onLoginSettingsLoaded,
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
  } = options;

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
  // Effects run after paint. Do not expose the previous account/organization's
  // read model during that one render; a stale admin object is more dangerous
  // than a short loading state because it can look like the new tenant's data.
  const visibleReadModel = scopeChanged ? createEmptyAdminReadModel() : readModel;

  const hasCachedAdminTab = useCallback((targetTab: Tab): boolean => {
    switch (targetTab) {
      case "overview": return cachedApiValue<Overview>("/api/admin/overview") !== undefined;
      // User pages are owned by useUserDirectory and keyed by their complete
      // canonical query. They must never be inferred from a tab-level cache.
      case "users": return false;
      case "applications": return cachedApiValue<TenantApplication[]>("/api/admin/applications") !== undefined;
      case "organizations": return cachedApiValue<Organization[]>("/api/admin/organizations") !== undefined;
      case "invitations": return cachedApiValue<Invitation[]>(AUTHORIZATION_CODES_API) !== undefined;
      case "registration": return cachedApiValue<RegistrationSettings>("/api/admin/registration-settings") !== undefined;
      case "providers": return cachedApiValue<ExternalProvider[]>("/api/admin/external-oidc-providers") !== undefined;
      case "portal": return cachedApiValue<LoginSettings>("/api/admin/login-settings") !== undefined;
      case "security": return (
        (canManageSecurity && cachedApiValue<SecurityPolicy>("/api/admin/security-policy") !== undefined)
        || (canReadAudit && cachedApiValue<AuditEvent[]>("/api/admin/audit-events") !== undefined)
        || cachedApiValue<AuditWebhook[]>("/api/admin/audit-webhooks") !== undefined
      );
      case "settings": return cachedApiValue<RuntimeSettings>("/api/admin/runtime-settings") !== undefined;
      case "billing": return false;
      case "account": return false;
    }
  }, [canManageSecurity, canReadAudit]);

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
  }, [clearScopedAdminData, invalidateAdminLoad, scopeKey]);

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
    const isCurrent = () => {
      const current = session.getSnapshot();
      return loadId.current === requestId
        && scopeRef.current === startedScope
        && scopeKey === startedScope
        && !controller.signal.aborted
        && session.getGeneration() === startedGeneration
        && current.cacheScope === startedScope
        && (current.user?.id ?? null) === startedUserId
        && (current.organizationContext?.id ?? null) === startedOrganizationId;
    };
    const cacheAvailable = !loadOptions.force && hasCachedAdminTab(targetTab);
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
      switch (targetTab) {
        case "overview":
          await loadCached<Overview>("/api/admin/overview", (next) => updateReadModel("overview", next));
          break;
        case "users":
          if (!canReadUsers) break;
          await loadCached<OrganizationOption[]>(
            "/api/admin/organization-options",
            (next) => updateReadModel("organizationOptions", next)
          ).catch(ignoreForbiddenRead);
          break;
        case "applications":
          await loadAdminApplicationsQuery({
            loadCached,
            updateReadModel,
            canManageActiveOrganization,
            canManagePlatformProviders
          });
          break;
        case "organizations":
          await loadAdminOrganizationsQuery({
            loadCached,
            updateReadModel,
            canReadOrganizations,
            canManageOrganizations
          });
          break;
        case "invitations":
          if (!canManageAuthorizationCodes) break;
          await Promise.all([
            loadCached<Invitation[]>(AUTHORIZATION_CODES_API, (next) => updateReadModel("invitations", next)),
            loadCached<Client[]>("/api/admin/clients", (next) => updateReadModel("clients", next)).catch(ignoreForbiddenRead),
            loadCached<OrganizationOption[]>(
              "/api/admin/organization-options",
              (next) => updateReadModel("organizationOptions", next)
            ).catch(ignoreForbiddenRead)
          ]);
          break;
        case "registration":
          await loadAdminRegistrationQuery({ loadCached, updateReadModel, canManageSettings, onLoginSettingsLoaded });
          break;
        case "providers": {
          if (!canManageProviders) break;
          await loadAdminProvidersQuery({
            loadCached,
            updateReadModel,
            canManagePlatformProviders
          });
          break;
        }
        case "portal":
          await loadAdminPortalQuery({ loadCached, updateReadModel, canManageSettings, onLoginSettingsLoaded });
          break;
        case "security":
          await loadAdminSecurityQuery({ loadCached, updateReadModel, canManageSecurity, canReadAudit });
          break;
        case "settings":
          await loadAdminRuntimeSettingsQuery({ loadCached, updateReadModel, canManageSettings, onLoginSettingsLoaded });
          break;
        case "billing":
          break;
      }
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
    hasCachedAdminTab,
    onLoginSettingsLoaded,
    scopeKey,
    session,
    tab,
    updateReadModel
  ]);

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
