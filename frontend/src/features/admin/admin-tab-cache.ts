import { cachedApiValue } from "../../lib/api";
import type {
  AuditEvent,
  AuditWebhook,
  ExternalProvider,
  Invitation,
  LoginSettings,
  Organization,
  Overview,
  RegistrationSettings,
  RuntimeSettings,
  SecurityPolicy,
  Tab,
  TenantApplication
} from "../../types";

const AUTHORIZATION_CODES_API = "/api/admin/authorization-codes";

export type AdminTabCacheOptions = {
  canManageSecurity: boolean;
  canReadAudit: boolean;
};

export function hasCachedAdminTab(targetTab: Tab, {
  canManageSecurity,
  canReadAudit
}: AdminTabCacheOptions): boolean {
  switch (targetTab) {
    case "overview": return cachedApiValue<Overview>("/api/admin/overview") !== undefined;
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
}
