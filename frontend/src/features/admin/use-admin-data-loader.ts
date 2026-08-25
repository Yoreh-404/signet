import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { ApiError, cachedApi, cachedApiValue } from "../../lib/api";
import { adminUserOptionsPath } from "../../lib/api/admin";
import type { SessionController } from "../session/useSessionController";
import type {
  AccessGroup,
  AuditEvent,
  AuditWebhook,
  Client,
  ExternalProvider,
  ExternalProviderTemplate,
  Invitation,
  LdapProvider,
  LoginSettings,
  LoginSettingsDraft,
  Organization,
  OrganizationOption,
  Overview,
  PermissionInfo,
  RegistrationSettings,
  Role,
  RuntimeSettings,
  SecurityPolicy,
  SettingsSummary,
  SigningKey,
  Tab,
  TenantApplication,
  UserOption
} from "../../types";

const AUTHORIZATION_CODES_API = "/api/admin/authorization-codes";

/**
 * Some admin tabs intentionally probe related resources for optional
 * selectors. Only an explicit permission denial is an empty optional result;
 * transport and server failures must reach the page instead of looking like
 * an empty list.
 */
function ignoreForbiddenRead(error: unknown): undefined {
  if (error instanceof ApiError && error.status === 403) return undefined;
  throw error;
}

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
export type AdminReadModel = {
  overview: Overview | null;
  userOptions: UserOption[];
  clients: Client[];
  applications: TenantApplication[];
  invitations: Invitation[];
  registrationSettings: RegistrationSettings | null;
  registrationSettingsBaseline: RegistrationSettings | null;
  providers: ExternalProvider[];
  providerTemplates: ExternalProviderTemplate[];
  ldapProviders: LdapProvider[];
  auditEvents: AuditEvent[];
  auditWebhooks: AuditWebhook[];
  permissionCatalog: PermissionInfo[];
  roles: Role[];
  groups: AccessGroup[];
  organizations: Organization[];
  organizationOptions: OrganizationOption[];
  signingKeys: SigningKey[];
  settings: SettingsSummary | null;
  runtimeSettings: RuntimeSettings | null;
  runtimeSettingsBaseline: RuntimeSettings | null;
  loginSettings: LoginSettings | null;
  loginSettingsBaseline: LoginSettingsDraft | null;
  securityPolicy: SecurityPolicy | null;
  securityPolicyBaseline: SecurityPolicy | null;
};

export type AdminReadModelUpdate<K extends keyof AdminReadModel> =
  | AdminReadModel[K]
  | ((current: AdminReadModel[K]) => AdminReadModel[K]);

export type AdminReadModelUpdater = <K extends keyof AdminReadModel>(
  key: K,
  update: AdminReadModelUpdate<K>
) => void;

type AdminReadModelSetters = {
  [K in keyof AdminReadModel as `set${Capitalize<K & string>}`]:
    (update: AdminReadModelUpdate<K>) => void;
};

function createEmptyAdminReadModel(): AdminReadModel {
  return {
    overview: null,
    userOptions: [],
    clients: [],
    applications: [],
    invitations: [],
    registrationSettings: null,
    registrationSettingsBaseline: null,
    providers: [],
    providerTemplates: [],
    ldapProviders: [],
    auditEvents: [],
    auditWebhooks: [],
    permissionCatalog: [],
    roles: [],
    groups: [],
    organizations: [],
    organizationOptions: [],
    signingKeys: [],
    settings: null,
    runtimeSettings: null,
    runtimeSettingsBaseline: null,
    loginSettings: null,
    loginSettingsBaseline: null,
    securityPolicy: null,
    securityPolicyBaseline: null
  };
}

function resolveAdminReadModelUpdate<K extends keyof AdminReadModel>(
  current: AdminReadModel[K],
  update: AdminReadModelUpdate<K>
): AdminReadModel[K] {
  if (typeof update === "function") {
    return (update as (current: AdminReadModel[K]) => AdminReadModel[K])(current);
  }
  return update;
}

function createAdminReadModelSetter<K extends keyof AdminReadModel>(
  key: K,
  updateReadModel: AdminReadModelUpdater
): (update: AdminReadModelUpdate<K>) => void {
  return (update) => updateReadModel(key, update);
}

function createAdminReadModelSetters(updateReadModel: AdminReadModelUpdater): AdminReadModelSetters {
  // These setters cross the composition-root boundary. Keep the map explicit
  // so a renamed read-model key cannot silently become a runtime API change.
  return {
    setOverview: createAdminReadModelSetter("overview", updateReadModel),
    setUserOptions: createAdminReadModelSetter("userOptions", updateReadModel),
    setClients: createAdminReadModelSetter("clients", updateReadModel),
    setApplications: createAdminReadModelSetter("applications", updateReadModel),
    setInvitations: createAdminReadModelSetter("invitations", updateReadModel),
    setRegistrationSettings: createAdminReadModelSetter("registrationSettings", updateReadModel),
    setRegistrationSettingsBaseline: createAdminReadModelSetter("registrationSettingsBaseline", updateReadModel),
    setProviders: createAdminReadModelSetter("providers", updateReadModel),
    setProviderTemplates: createAdminReadModelSetter("providerTemplates", updateReadModel),
    setLdapProviders: createAdminReadModelSetter("ldapProviders", updateReadModel),
    setAuditEvents: createAdminReadModelSetter("auditEvents", updateReadModel),
    setAuditWebhooks: createAdminReadModelSetter("auditWebhooks", updateReadModel),
    setPermissionCatalog: createAdminReadModelSetter("permissionCatalog", updateReadModel),
    setRoles: createAdminReadModelSetter("roles", updateReadModel),
    setGroups: createAdminReadModelSetter("groups", updateReadModel),
    setOrganizations: createAdminReadModelSetter("organizations", updateReadModel),
    setOrganizationOptions: createAdminReadModelSetter("organizationOptions", updateReadModel),
    setSigningKeys: createAdminReadModelSetter("signingKeys", updateReadModel),
    setSettings: createAdminReadModelSetter("settings", updateReadModel),
    setRuntimeSettings: createAdminReadModelSetter("runtimeSettings", updateReadModel),
    setRuntimeSettingsBaseline: createAdminReadModelSetter("runtimeSettingsBaseline", updateReadModel),
    setLoginSettings: createAdminReadModelSetter("loginSettings", updateReadModel),
    setLoginSettingsBaseline: createAdminReadModelSetter("loginSettingsBaseline", updateReadModel),
    setSecurityPolicy: createAdminReadModelSetter("securityPolicy", updateReadModel),
    setSecurityPolicyBaseline: createAdminReadModelSetter("securityPolicyBaseline", updateReadModel)
  };
}

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
      const nextValue = resolveAdminReadModelUpdate(current[key], update);
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
          if (!canManageActiveOrganization) break;
          await Promise.all([
            loadCached<TenantApplication[]>(
              "/api/admin/applications",
              (next) => updateReadModel("applications", next)
            ),
            loadCached<Client[]>("/api/admin/clients", (next) => updateReadModel("clients", next)).catch(ignoreForbiddenRead),
            loadCached<OrganizationOption[]>(
              "/api/admin/organization-options",
              (next) => updateReadModel("organizationOptions", next)
            ).catch(ignoreForbiddenRead),
            loadCached<ExternalProvider[]>(
              "/api/admin/external-oidc-providers",
              (next) => updateReadModel("providers", next)
            ).catch(ignoreForbiddenRead),
            canManagePlatformProviders
              ? loadCached<LdapProvider[]>(
                  "/api/admin/ldap-providers",
                  (next) => updateReadModel("ldapProviders", next)
                ).catch(ignoreForbiddenRead)
              : Promise.resolve(undefined),
            // Organization membership editing owns its query in
            // useOrganizationController; the applications tab must not
            // preload an unrelated organization aggregate.
          ]);
          break;
        case "organizations":
          if (!canReadOrganizations) break;
          await Promise.all([
            loadCached<Organization[]>("/api/admin/organizations", (next) => {
              updateReadModel("organizations", next);
              updateReadModel(
                "organizationOptions",
                next.map(({ id, slug, name, kind, is_active }) => ({ id, slug, name, kind, is_active }))
              );
            }),
            canManageOrganizations
              ? loadCached<UserOption[]>(
                  adminUserOptionsPath({ status: "live", limit: 200 }),
                  (next) => updateReadModel("userOptions", next)
                )
              : Promise.resolve(undefined)
          ]);
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
          if (!canManageSettings) break;
          await loadCached<RegistrationSettings>("/api/admin/registration-settings", (next) => {
            updateReadModel("registrationSettings", next);
            updateReadModel("registrationSettingsBaseline", next);
          });
          break;
        case "providers": {
          if (!canManageProviders) break;
          const requests: Promise<unknown>[] = [
            loadCached<ExternalProvider[]>(
              "/api/admin/external-oidc-providers",
              (next) => updateReadModel("providers", next)
            ),
            loadCached<ExternalProviderTemplate[]>(
              "/api/admin/external-oidc-provider-templates",
              (next) => updateReadModel("providerTemplates", next)
            )
          ];
          if (canManagePlatformProviders) {
            requests.push(
              loadCached<LdapProvider[]>(
                "/api/admin/ldap-providers",
                (next) => updateReadModel("ldapProviders", next)
              ),
              loadCached<OrganizationOption[]>(
                "/api/admin/organization-options",
                (next) => updateReadModel("organizationOptions", next)
              )
            );
          }
          await Promise.all(requests);
          break;
        }
        case "portal":
          if (!canManageSettings) break;
          await loadCached<LoginSettings>("/api/admin/login-settings", (next) => {
            updateReadModel("loginSettings", next);
            const draft: LoginSettingsDraft = {
              brand_logo_url: next.brand_logo_url,
              email_domains: next.email_domains.join("\n"),
              quick_links: next.quick_links
            };
            onLoginSettingsLoaded(draft);
            updateReadModel("loginSettingsBaseline", draft);
          });
          break;
        case "security":
          if (!canManageSecurity && !canReadAudit) break;
          await Promise.all([
            canManageSecurity
              ? loadCached<SecurityPolicy>("/api/admin/security-policy", (next) => {
                  updateReadModel("securityPolicy", next);
                  updateReadModel("securityPolicyBaseline", next);
                })
              : Promise.resolve(undefined),
            canManageSecurity
              ? loadCached<SigningKey[]>("/api/admin/signing-keys", (next) => updateReadModel("signingKeys", next))
              : Promise.resolve(undefined),
            canManageSecurity
              ? loadCached<PermissionInfo[]>(
                  "/api/admin/access/permissions",
                  (next) => updateReadModel("permissionCatalog", next)
                )
              : Promise.resolve(undefined),
            canManageSecurity
              ? loadCached<Role[]>("/api/admin/access/roles", (next) => updateReadModel("roles", next))
              : Promise.resolve(undefined),
            canManageSecurity
              ? loadCached<AccessGroup[]>("/api/admin/access/groups", (next) => updateReadModel("groups", next))
              : Promise.resolve(undefined),
            canManageSecurity
              ? loadCached<UserOption[]>(
                  adminUserOptionsPath({ status: "live", limit: 200 }),
                  (next) => updateReadModel("userOptions", next)
                )
              : Promise.resolve(undefined),
            canReadAudit
              ? loadCached<AuditEvent[]>("/api/admin/audit-events", (next) => updateReadModel("auditEvents", next))
              : Promise.resolve(undefined),
            loadCached<AuditWebhook[]>(
              "/api/admin/audit-webhooks",
              (next) => updateReadModel("auditWebhooks", next)
            )
          ]);
          break;
        case "settings":
          if (!canManageSettings) break;
          await Promise.all([
            loadCached<RuntimeSettings>("/api/admin/runtime-settings", (next) => {
              updateReadModel("runtimeSettings", next);
              updateReadModel("runtimeSettingsBaseline", next);
            }),
            loadCached<SettingsSummary>("/api/admin/settings", (next) => updateReadModel("settings", next))
          ]);
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
