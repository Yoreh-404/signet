import type {
  ApplicationModuleKey,
  ApplicationSection,
  ExternalProvider,
  LdapProvider,
  TenantApplication
} from "../../types";
import type {
  ApplicationBasicsReadModel
} from "./ApplicationBasics";
import { booleanValue, record, stringList, stringValue } from "./application-module-values";

export type ApplicationBasicsReadModelInput = {
  applications: TenantApplication[];
  selected: TenantApplication | null;
  section: ApplicationSection;
  protocolConfig: Record<string, unknown>;
  loginAdaptersConfig: Record<string, unknown>;
  directoryConfig: Record<string, unknown>;
  providers: ExternalProvider[];
  ldapProviders: LdapProvider[];
  authorizationConfig: Record<string, unknown>;
  moduleEnabled: Record<ApplicationModuleKey, boolean>;
  inheritEnterprise: string;
  notConfigured: string;
  billingEnabled: boolean;
  iapRuleCount: number;
};

export function buildApplicationBasicsReadModel({
  applications,
  selected,
  section,
  protocolConfig,
  loginAdaptersConfig,
  directoryConfig,
  providers,
  ldapProviders,
  authorizationConfig,
  moduleEnabled,
  inheritEnterprise,
  notConfigured,
  billingEnabled,
  iapRuleCount
}: ApplicationBasicsReadModelInput): ApplicationBasicsReadModel {
  const enabledProtocolCount = selected
    ? ["oauth2_oidc", "saml2", "cas", "jwt"].filter((key) => booleanValue(record(protocolConfig[key]).enabled)).length
    : 0;
  const enabledIdentityCount = selected ? stringList(loginAdaptersConfig.provider_ids).length : 0;
  const enabledSyncCount = selected
    ? stringList(directoryConfig.ldap_provider_ids).length
      + (booleanValue(directoryConfig.scim_enabled) ? 1 : 0)
    : 0;

  return {
    applications,
    selected,
    section,
    websiteUrl: stringValue(protocolConfig.website_url),
    enabledProtocolCount,
    enabledIdentityCount,
    enabledSyncCount,
    identitySourceCount: providers.filter((provider) => provider.is_active).length
      + ldapProviders.filter((provider) => provider.is_active).length,
    authorizationSummary: booleanValue(authorizationConfig.inherit_enterprise_roles, true)
      ? inheritEnterprise
      : notConfigured,
    moduleEnabled,
    billingEnabled,
    iapRuleCount
  };
}
