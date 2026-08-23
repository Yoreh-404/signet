import {
  Activity,
  Archive,
  ArrowLeftRight,
  AtSign,
  Ban,
  Building2,
  ChevronDown,
  ChevronUp,
  Clock3,
  Copy,
  Coins,
  Eye,
  ExternalLink,
  FileUp,
  Filter,
  Globe2,
  KeyRound,
  Link2,
  LogOut,
  Mail,
  Menu,
  Monitor,
  Moon,
  Phone,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Settings,
  Shield,
  Shuffle,
  Sun,
  Trash2,
  Ticket,
  UserRound,
  Users
} from "lucide-react";
import { ChangeEvent, FormEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  Card,
  Check,
  EmptyState,
  Field,
  FormActions,
  FormErrorSummary,
  ListField,
  Modal,
  SearchField,
  SecretField,
  SettingsSection,
  SelectField,
  StatusBadge
} from "./components/ui";
import {
  AuthorizationCodeLoginForm,
  LoginMethodSwitcher
} from "./components/LoginMethod";
import { AccountChooser, startBrowserAccountLogin } from "./features/auth/AccountChooser";
import { ApplicationWorkspace } from "./features/applications/ApplicationWorkspace";
import { WalletWorkspace } from "./features/billing/WalletWorkspace";
import { translations } from "./i18n";
import type { TranslationKey } from "./i18n";
import {
  api,
  ApiError,
  cachedApi,
  cachedApiValue,
  setApiCacheScope
} from "./lib/api";
import {
  applyEmailDomain,
  authContextError,
  deliverFrontchannelLogout,
  findProviderForEmail,
  initialAuthContext,
  loginHintRequiresAccountSwitch,
  normalizeDomain,
  oidcStartUrl,
  randomLocalPart,
  usableEmailDomain
} from "./lib/auth-flow";
import {
  matchesSearch,
  sortUsersForDisplay,
  toggleValue
} from "./lib/collection-utils";
import {
  formatTime,
  joinList,
  shortSessionId,
  splitList,
  toDatetimeLocalValue,
  toTimestamp
} from "./lib/formatters";
import {
  createQuickLinkId,
  emptyAuditWebhookForm,
  emptyAuthorizationCodeLoginForm,
  emptyApplicationForm,
  emptyClaimMapperForm,
  emptyClientForm,
  emptyGroupForm,
  emptyIapApplicationForm,
  emptyInvitationForm,
  emptyLdapProviderForm,
  emptyOrganizationForm,
  emptyPasswordResetForm,
  emptyProviderForm,
  emptyQuickLinkForm,
  emptyRegisterForm,
  emptyRoleForm,
  emptyUserForm
} from "./lib/form-defaults";
import { initialNavigation, initialTheme } from "./lib/navigation";
import {
  authenticationCredentialJson,
  passkeyCreationOptions,
  passkeyRequestOptions,
  registrationCredentialJson
} from "./lib/webauthn";
import type {
  AccessGroup,
  ApplicationClientBinding,
  ApplicationModule,
  ApplicationSection,
  AuditEvent,
  AuditWebhook,
  BrowserAccount,
  BrowserAccountsContext,
  AuthorizationCodeInspection,
  AuthorizationCodeType,
  AuthMode,
  BulkUserImportResult,
  BulkUserImportRow,
  Bootstrap,
  Client,
  ClientClaimMapperForm,
  ExternalProvider,
  ExternalProviderDiscovery,
  ExternalProviderTemplate,
  IapApplication,
  Invitation,
  InvitationRedemption,
  InvitationRedemptionsPage,
  LdapProvider,
  Locale,
  LoginAuthorizationCodeLevel,
  LoginMethod,
  LoginResponse,
  LoginSettings,
  LoginSettingsDraft,
  LogoutResponse,
  MfaConfirmResponse,
  MfaStatus,
  MyConsent,
  MySession,
  Organization,
  OrganizationContext,
  OrganizationMember,
  OrganizationMemberInvitationCreateResponse,
  OrganizationMemberRole,
  OrganizationOption,
  OidcContinuationLoginResponse,
  Overview,
  Passkey,
  PasskeyAuthenticationStart,
  PasskeyRegistrationStart,
  PendingConfirmation,
  PermissionInfo,
  QuickLink,
  RegistrationSettings,
  Role,
  RuntimeSettings,
  SecurityPolicy,
  SettingsSummary,
  SigningKey,
  Tab,
  Theme,
  TenantApplication,
  TotpSetup,
  User,
  UserAccess,
  UserDetail,
  UserFilter,
  UserOrganization
} from "./types";

const AUTHORIZATION_CODES_API = "/api/admin/authorization-codes";
const BULK_USER_IMPORT_API = "/api/admin/users/import-csv";
const BULK_USER_IMPORT_TEMPLATE = [
  "email,username,display_name,organization_slug,organization_role,is_active",
  "alex@example.com,alex,Alex Example,example-club,member,true"
].join("\n");

type UserRoleFilter = "all" | "admin" | "user";
type UserLoginRegionFilter = "all" | "domestic" | "overseas";
type UserLinkedIdentityFilter = "all" | "linked" | "unlinked";
type UserLifecycleState = "active" | "disabled" | "archived";
type BulkUserAction = "enable" | "disable" | "archive" | "delete" | "reset_mfa";
type BrowserAccountContinuation = () => Promise<void>;
type EnterpriseFormState = {
  slug: string;
  name: string;
  description: string;
  allowed_email_domains: string;
};

const emptyEnterpriseForm: EnterpriseFormState = {
  slug: "",
  name: "",
  description: "",
  allowed_email_domains: ""
};

function timestampAtDayEnd(value: string): number | null {
  const timestamp = toTimestamp(value);
  return timestamp === null ? null : timestamp + 86_400;
}

function isDomesticLoginIp(value: string | null): boolean {
  if (!value) return false;
  const ip = value.trim().toLowerCase();
  // Local/private addresses are common in self-hosted deployments and should
  // remain visible under the domestic view. Public addresses can be enriched
  // with a country code by an upstream proxy in the "cn:<ip>" form.
  return ip.startsWith("cn:")
    || ip === "localhost"
    || ip === "::1"
    || /^127\./.test(ip)
    || /^10\./.test(ip)
    || /^192\.168\./.test(ip)
    || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

function lifecycleStateForUser(user: Pick<User, "is_active" | "archived_at">): UserLifecycleState {
  if (user.archived_at !== null) return "archived";
  return user.is_active ? "active" : "disabled";
}

/**
 * These are the actions a row exposes for its current lifecycle state.
 * Keeping this source of truth shared with bulk actions prevents a selection
 * of mixed rows from offering an operation that one of its rows cannot take.
 */
function availableUserActions(user: Pick<User, "id" | "is_active" | "archived_at">, currentUserId?: string): BulkUserAction[] {
  const actions: BulkUserAction[] = [];
  const canChangeLifecycle = user.id !== currentUserId;
  const lifecycleState = lifecycleStateForUser(user);
  if (canChangeLifecycle) {
    if (lifecycleState === "active") {
      actions.push("disable");
    } else if (lifecycleState === "disabled") {
      actions.push("enable", "archive");
    } else {
      actions.push("enable", "delete");
    }
  }
  if (lifecycleState !== "archived") actions.push("reset_mfa");
  return actions;
}

function isBulkUserImportResult(value: unknown): value is BulkUserImportResult {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<BulkUserImportResult>;
  return typeof candidate.dry_run === "boolean"
    && typeof candidate.atomic === "boolean"
    && typeof candidate.committed === "boolean"
    && Array.isArray(candidate.rows)
    && Boolean(candidate.summary)
    && typeof candidate.summary?.total === "number"
    && typeof candidate.summary?.created === "number"
    && typeof candidate.summary?.would_create === "number"
    && typeof candidate.summary?.invalid === "number";
}

function bulkImportOutcomeTone(outcome: BulkUserImportRow["outcome"]): "success" | "warning" | "danger" | "info" {
  switch (outcome) {
    case "created": return "success";
    case "would_create": return "info";
    case "not_committed": return "warning";
    case "invalid": return "danger";
  }
}

function browserAccountShortName(account: BrowserAccount): string {
  return account.user.username.trim() || account.user.email.trim();
}

/**
 * `/api/browser-accounts/add/start` is the authority that creates an account
 * login flow.  The server-issued token stays on this auth URL (without adding
 * a history entry), so a refresh cannot silently turn an add-account flow
 * into an unrelated primary-session login.
 */
function inlineAccountLoginFlow(loginUrl: string, expectedReturnTo: string): string | null {
  try {
    const target = new URL(loginUrl, window.location.origin);
    if (
      target.origin !== window.location.origin
      || target.searchParams.get("auth") !== "login"
      || target.searchParams.get("force_login") !== "1"
      || target.searchParams.get("return_to") !== expectedReturnTo
    ) {
      return null;
    }
    const flow = target.searchParams.get("account_flow")?.trim() ?? "";
    return /^alf1\.[A-Za-z0-9_-]{20,}$/.test(flow) ? flow : null;
  } catch {
    return null;
  }
}

function matchesHttpUrl(url: URL): boolean {
  return (url.protocol === "http:" || url.protocol === "https:") && Boolean(url.host);
}

function formatDiagnosticValue(
  value: string | number | boolean | string[],
  translate: (key: TranslationKey) => string
): string {
  if (Array.isArray(value)) return value.length > 0 ? value.join(", ") : "-";
  if (typeof value === "boolean") return value ? translate("active") : translate("disabled");
  return String(value);
}

export function App() {
  const initialAuth = useMemo(initialAuthContext, []);
  const initialNavigationState = useMemo(() => initialNavigation(), []);
  const [locale, setLocale] = useState<Locale>(() => {
    const saved = localStorage.getItem("gpt-sso-locale");
    return saved === "en-US" ? "en-US" : "zh-CN";
  });
  const t = (key: TranslationKey) => translations[locale][key];
  const messageOr = (err: unknown, fallback: TranslationKey) => {
    if (err instanceof ApiError && err.code === "network_error") return t("networkError");
    if (err instanceof ApiError && err.code === "csrf_failed") return t("sessionExpired");
    if (err instanceof ApiError && err.status >= 500) return t("serverError");
    if (err instanceof ApiError && (err.status === 401 || err.status === 403)) return t(fallback);
    return err instanceof Error ? err.message : t(fallback);
  };

  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [tab, setTab] = useState<Tab>(initialNavigationState.tab);
  const [applicationNavigationId, setApplicationNavigationId] = useState<string | null>(initialNavigationState.applicationId);
  const [applicationNavigationSection, setApplicationNavigationSection] = useState<ApplicationSection | null>(initialNavigationState.applicationSection);
  const [billingOrderReference, setBillingOrderReference] = useState<string | null>(initialNavigationState.billingOrder);
  const [applicationWorkspaceDirty, setApplicationWorkspaceDirty] = useState(false);
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const sidebarRef = useRef<HTMLElement | null>(null);
  const mobileMenuButtonRef = useRef<HTMLButtonElement | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const [adminLoading, setAdminLoading] = useState(false);
  const [initialLoadError, setInitialLoadError] = useState("");
  const [pendingConfirmation, setPendingConfirmation] = useState<PendingConfirmation | null>(null);
  const adminLoadId = useRef(0);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [applications, setApplications] = useState<TenantApplication[]>([]);
  const [iapApplications, setIapApplications] = useState<IapApplication[]>([]);
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [registrationSettings, setRegistrationSettings] = useState<RegistrationSettings | null>(null);
  const [registrationSettingsBaseline, setRegistrationSettingsBaseline] = useState<RegistrationSettings | null>(null);
  const [providers, setProviders] = useState<ExternalProvider[]>([]);
  const [providerTemplates, setProviderTemplates] = useState<ExternalProviderTemplate[]>([]);
  const [ldapProviders, setLdapProviders] = useState<LdapProvider[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditWebhooks, setAuditWebhooks] = useState<AuditWebhook[]>([]);
  const [permissionCatalog, setPermissionCatalog] = useState<PermissionInfo[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [groups, setGroups] = useState<AccessGroup[]>([]);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [organizationOptions, setOrganizationOptions] = useState<OrganizationOption[]>([]);
  const [myOrganizations, setMyOrganizations] = useState<UserOrganization[]>([]);
  const [organizationContext, setOrganizationContext] = useState<UserOrganization | null>(null);
  const [enterpriseContextReady, setEnterpriseContextReady] = useState(false);
  const [mfaStatus, setMfaStatus] = useState<MfaStatus | null>(null);
  const [totpSetup, setTotpSetup] = useState<TotpSetup | null>(null);
  const [totpSetupCode, setTotpSetupCode] = useState("");
  const [newRecoveryCodes, setNewRecoveryCodes] = useState<string[]>([]);
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [passkeyName, setPasskeyName] = useState("");
  const [myConsents, setMyConsents] = useState<MyConsent[]>([]);
  const [mySessions, setMySessions] = useState<MySession[]>([]);
  const [securityPolicy, setSecurityPolicy] = useState<SecurityPolicy | null>(null);
  const [signingKeys, setSigningKeys] = useState<SigningKey[]>([]);
  const [signingKeyKid, setSigningKeyKid] = useState("");
  const [settings, setSettings] = useState<SettingsSummary | null>(null);
  const [runtimeSettings, setRuntimeSettings] = useState<RuntimeSettings | null>(null);
  const [runtimeSettingsBaseline, setRuntimeSettingsBaseline] = useState<RuntimeSettings | null>(null);
  const [loginSettings, setLoginSettings] = useState<LoginSettings | null>(null);
  const [loginSettingsBaseline, setLoginSettingsBaseline] = useState<LoginSettingsDraft | null>(null);
  const [securityPolicyBaseline, setSecurityPolicyBaseline] = useState<SecurityPolicy | null>(null);
  const [selectedUser, setSelectedUser] = useState<UserDetail | null>(null);
  const [userFilter, setUserFilter] = useState<UserFilter>("live");
  const [userOrganizationFilter, setUserOrganizationFilter] = useState("");
  const [userFiltersExpanded, setUserFiltersExpanded] = useState(false);
  const [userEmailFilter, setUserEmailFilter] = useState("");
  const [userRoleFilter, setUserRoleFilter] = useState<UserRoleFilter>("all");
  const [userRegistrationFrom, setUserRegistrationFrom] = useState("");
  const [userRegistrationTo, setUserRegistrationTo] = useState("");
  const [userLastLoginFrom, setUserLastLoginFrom] = useState("");
  const [userLastLoginTo, setUserLastLoginTo] = useState("");
  const [userPhoneFilter, setUserPhoneFilter] = useState("");
  const [userLoginRegionFilter, setUserLoginRegionFilter] = useState<UserLoginRegionFilter>("all");
  const [userLinkedIdentityFilter, setUserLinkedIdentityFilter] = useState<UserLinkedIdentityFilter>("all");
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [userForm, setUserForm] = useState(emptyUserForm);
  const [userFormBaseline, setUserFormBaseline] = useState<typeof emptyUserForm | null>(null);
  const [bulkImportOpen, setBulkImportOpen] = useState(false);
  const [bulkImportCsv, setBulkImportCsv] = useState("");
  const [bulkImportFileName, setBulkImportFileName] = useState("");
  const [bulkImportDryRun, setBulkImportDryRun] = useState(true);
  const [bulkImportCommitConfirmed, setBulkImportCommitConfirmed] = useState(false);
  const [bulkImportResult, setBulkImportResult] = useState<BulkUserImportResult | null>(null);
  const [bulkImportError, setBulkImportError] = useState("");
  const [registerForm, setRegisterForm] = useState(emptyRegisterForm);
  const [registrationCodeInspection, setRegistrationCodeInspection] = useState<AuthorizationCodeInspection | null>(null);
  const [registrationCodeInspecting, setRegistrationCodeInspecting] = useState(false);
  const [passwordResetForm, setPasswordResetForm] = useState(emptyPasswordResetForm);
  const [clientForm, setClientForm] = useState(emptyClientForm);
  const [clientFormBaseline, setClientFormBaseline] = useState<typeof emptyClientForm | null>(null);
  const [clientFormErrors, setClientFormErrors] = useState<string[]>([]);
  const [clientFieldErrors, setClientFieldErrors] = useState<Record<string, string>>({});
  const [applicationForm, setApplicationForm] = useState(emptyApplicationForm);
  const [applicationFormBaseline, setApplicationFormBaseline] = useState<typeof emptyApplicationForm | null>(null);
  const [enterpriseForm, setEnterpriseForm] = useState<EnterpriseFormState>(emptyEnterpriseForm);
  const [enterpriseFormBaseline, setEnterpriseFormBaseline] = useState<EnterpriseFormState | null>(null);
  const [enterpriseMemberEmail, setEnterpriseMemberEmail] = useState("");
  const [enterpriseMemberRole, setEnterpriseMemberRole] = useState<OrganizationMemberRole>("member");
  const [organizationMemberInvitations, setOrganizationMemberInvitations] = useState<Invitation[]>([]);
  const [organizationMemberInvitationForm, setOrganizationMemberInvitationForm] = useState({
    email: "",
    display_name: "",
    description: "",
    expires_at: "",
    organization_role: "member" as OrganizationMemberRole,
    is_active: true
  });
  const [revealedOrganizationMemberInvitation, setRevealedOrganizationMemberInvitation] = useState<OrganizationMemberInvitationCreateResponse | null>(null);
  const [iapApplicationForm, setIapApplicationForm] = useState(emptyIapApplicationForm);
  const [iapApplicationFormBaseline, setIapApplicationFormBaseline] = useState<typeof emptyIapApplicationForm | null>(null);
  const [invitationForm, setInvitationForm] = useState(emptyInvitationForm);
  const [invitationFormBaseline, setInvitationFormBaseline] = useState<typeof emptyInvitationForm | null>(null);
  const [revealedInvitation, setRevealedInvitation] = useState<Invitation | null>(null);
  const [revealedInvitationCode, setRevealedInvitationCode] = useState("");
  const [revealingInvitationId, setRevealingInvitationId] = useState("");
  const [invitationRevealError, setInvitationRevealError] = useState("");
  const [redemptionsInvitation, setRedemptionsInvitation] = useState<Invitation | null>(null);
  const [invitationRedemptions, setInvitationRedemptions] = useState<InvitationRedemption[]>([]);
  const [invitationRedemptionsNextCursor, setInvitationRedemptionsNextCursor] = useState<string | null>(null);
  const [invitationRedemptionsLoading, setInvitationRedemptionsLoading] = useState(false);
  const [invitationRedemptionsError, setInvitationRedemptionsError] = useState("");
  const invitationRedemptionsLoadId = useRef(0);
  const [roleForm, setRoleForm] = useState(emptyRoleForm);
  const [roleFormBaseline, setRoleFormBaseline] = useState<typeof emptyRoleForm | null>(null);
  const [groupForm, setGroupForm] = useState(emptyGroupForm);
  const [groupFormBaseline, setGroupFormBaseline] = useState<typeof emptyGroupForm | null>(null);
  const [organizationForm, setOrganizationForm] = useState(emptyOrganizationForm);
  const [organizationFormBaseline, setOrganizationFormBaseline] = useState<typeof emptyOrganizationForm | null>(null);
  const [organizationMemberRolesBaseline, setOrganizationMemberRolesBaseline] = useState<Record<string, string> | null>(null);
  const [organizationMemberRoles, setOrganizationMemberRoles] = useState<Record<string, string>>({});
  const [organizationMembers, setOrganizationMembers] = useState<OrganizationMember[]>([]);
  const [organizationMembersLoading, setOrganizationMembersLoading] = useState(false);
  const organizationMembersLoadId = useRef(0);
  const [selectedAccessUserId, setSelectedAccessUserId] = useState("");
  const [userAccess, setUserAccess] = useState<UserAccess | null>(null);
  const [providerForm, setProviderForm] = useState(emptyProviderForm);
  const [providerFormBaseline, setProviderFormBaseline] = useState<typeof emptyProviderForm | null>(null);
  const [providerTemplateId, setProviderTemplateId] = useState("");
  const [ldapProviderForm, setLdapProviderForm] = useState(emptyLdapProviderForm);
  const [ldapProviderFormBaseline, setLdapProviderFormBaseline] = useState<typeof emptyLdapProviderForm | null>(null);
  const [auditWebhookForm, setAuditWebhookForm] = useState(emptyAuditWebhookForm);
  const [auditWebhookFormBaseline, setAuditWebhookFormBaseline] = useState<typeof emptyAuditWebhookForm>(emptyAuditWebhookForm);
  const [editor, setEditor] = useState<
    "user" | "organization" | "enterprise" | "application" | "client" | "iap" | "invitation" | "provider" | "ldap" | "role" | "group" | null
  >(null);
  const [loginSettingsDraft, setLoginSettingsDraft] = useState<LoginSettingsDraft>({
    brand_logo_url: "",
    email_domains: "",
    quick_links: []
  });
  const [quickLinkForm, setQuickLinkForm] = useState(emptyQuickLinkForm);
  const [authEmail, setAuthEmail] = useState(initialAuth.loginHint || "");
  const [loginMethod, setLoginMethod] = useState<LoginMethod>("password");
  const [authorizationCodeLoginForm, setAuthorizationCodeLoginForm] = useState(emptyAuthorizationCodeLoginForm);
  const [loginPassword, setLoginPassword] = useState("");
  const [loginMfaChallengeId, setLoginMfaChallengeId] = useState("");
  const [loginMfaCode, setLoginMfaCode] = useState("");
  const [loginRecoveryAvailable, setLoginRecoveryAvailable] = useState(false);
  const [loginCaptchaChallengeId, setLoginCaptchaChallengeId] = useState("");
  const [loginCaptchaPrompt, setLoginCaptchaPrompt] = useState("");
  const [loginCaptchaAnswer, setLoginCaptchaAnswer] = useState("");
  const [loginCustomDomain, setLoginCustomDomain] = useState("");
  const [registerCustomDomain, setRegisterCustomDomain] = useState("");
  const [resetCustomDomain, setResetCustomDomain] = useState("");
  const [authMode, setAuthMode] = useState<AuthMode>(initialAuth.mode);
  const [authReturnTo] = useState(initialAuth.returnTo);
  const [accountLoginExpanded, setAccountLoginExpanded] = useState(
    () => Boolean(initialAuth.accountFlow)
  );
  const [accountLoginFlow, setAccountLoginFlow] = useState<string | null>(null);
  const [browserAccountsContext, setBrowserAccountsContext] = useState<BrowserAccountsContext | null>(null);
  const [selectedBrowserAccount, setSelectedBrowserAccount] = useState<BrowserAccount | null>(null);
  const [continueWithBrowserAccount, setContinueWithBrowserAccount] = useState<BrowserAccountContinuation | null>(null);
  const [browserAccountContinuing, setBrowserAccountContinuing] = useState(false);
  const [lastInvitationCode, setLastInvitationCode] = useState("");
  const [verificationMessage, setVerificationMessage] = useState("");
  const [error, setError] = useState(() => authContextError(initialAuth, t));
  const [busy, setBusy] = useState(false);
  const authModeHeadingRef = useRef<HTMLHeadingElement | null>(null);

  const userPermissions = user?.permissions ?? [];
  const isTrialEnrollmentSession = user?.session_kind === "trial_enrollment"
    || user?.login_code_level === "trial_enrollment";
  const isAccountRecoverySession = user?.session_kind === "temporary_authorization_code"
    || user?.login_code_level === "account_recovery";
  const isRestrictedLoginCodeSession = isTrialEnrollmentSession || isAccountRecoverySession;
  const canMutateAccount = Boolean(
    user && !user.archived_at && !isRestrictedLoginCodeSession
  );
  const authAccountSwitch = Boolean(authReturnTo && loginHintRequiresAccountSwitch(user, initialAuth.loginHint));
  const authCanCompleteWithCurrentUser = Boolean(
    user
    && authReturnTo
    && !authAccountSwitch
    && !initialAuth.forceLogin
    && !initialAuth.isAuthPage
    && !initialAuth.selectAccount
  );
  const effectiveAccountFlow = accountLoginFlow ?? initialAuth.accountFlow;
  const authFormsVisible = accountLoginExpanded || !selectedBrowserAccount;
  const hasPermission = (...permissions: string[]) =>
    permissions.some((permission) => userPermissions.includes(permission));
  const canManageActiveOrganization = Boolean(
    organizationContext
    && (
      hasPermission("organizations.manage")
      || (
        organizationContext.kind !== "system"
        && (organizationContext.role === "owner" || organizationContext.role === "admin")
      )
    )
  );
  const hasGlobalConsolePermission = userPermissions.length > 0;
  const canAdmin = !isRestrictedLoginCodeSession && (hasGlobalConsolePermission || canManageActiveOrganization);
  const canReadUsers = hasPermission("users.read", "users.manage", "organizations.manage", "security.manage");
  const canManageUsers = hasPermission("users.manage");
  const canReadClients = hasPermission("clients.read", "clients.manage") || canManageActiveOrganization;
  const canManageClients = hasPermission("clients.manage") || canManageActiveOrganization;
  const canReadIap = hasPermission("iap.read", "iap.manage");
  const canManageIap = hasPermission("iap.manage");
  const canReadOrganizations = hasPermission(
    "organizations.read",
    "organizations.manage"
  );
  const canManageOrganizations = hasPermission("organizations.manage");
  const canManageAuthorizationCodes = hasPermission("authorization_codes.manage");
  const canManageSettings = hasPermission("settings.manage");
  const canManagePlatformProviders = hasPermission("providers.manage");
  const canManageProviders = canManagePlatformProviders || canManageActiveOrganization;
  const canReadAudit = hasPermission("audit.read");
  const canManageSecurity = hasPermission("security.manage");

  function setSharedAuthEmail(value: string) {
    setAuthEmail(value);
  }

  function selectBrowserAccount(
    account: BrowserAccount,
    continuation: BrowserAccountContinuation
  ) {
    if (accountLoginFlow) {
      const currentUrl = new URL(window.location.href);
      currentUrl.searchParams.delete("account_flow");
      window.history.replaceState(
        window.history.state,
        "",
        `${currentUrl.pathname}${currentUrl.search}${currentUrl.hash}`
      );
      setAccountLoginFlow(null);
    }
    setSelectedBrowserAccount(account);
    setContinueWithBrowserAccount(() => continuation);
    setAccountLoginExpanded(false);
    setError("");
    setVerificationMessage("");
  }

  function handleBrowserAccountsLoaded(
    accounts: BrowserAccount[],
    context: BrowserAccountsContext,
    continuationForAccount?: (accountRef: string) => Promise<void>
  ) {
    setBrowserAccountsContext(context);
    if (accounts.length === 0) {
      setSelectedBrowserAccount(null);
      setContinueWithBrowserAccount(null);
      return;
    }
    if (accountLoginExpanded) return;
    const next = accounts.find((account) => account.account_ref === selectedBrowserAccount?.account_ref)
      ?? accounts[0];
    setSelectedBrowserAccount(next);
    if (continuationForAccount) {
      setContinueWithBrowserAccount(() => () => continuationForAccount(next.account_ref));
    }
  }

  async function continueSelectedBrowserAccount() {
    if (!continueWithBrowserAccount) return;
    setBrowserAccountContinuing(true);
    setError("");
    try {
      await continueWithBrowserAccount();
    } finally {
      setBrowserAccountContinuing(false);
    }
  }

  function openAnotherAccountLogin(loginUrl: string) {
    const accountFlow = inlineAccountLoginFlow(loginUrl, authReturnTo ?? "/");
    if (!accountFlow) {
      throw new Error(t("browserAccountAddFailed"));
    }
    const currentUrl = new URL(window.location.href);
    currentUrl.searchParams.set("account_flow", accountFlow);
    window.history.replaceState(
      window.history.state,
      "",
      `${currentUrl.pathname}${currentUrl.search}${currentUrl.hash}`
    );
    setAccountLoginFlow(accountFlow);
    setAccountLoginExpanded(true);
    setSelectedBrowserAccount(null);
    setContinueWithBrowserAccount(null);
    setAuthMode("login");
    setLoginMethod("password");
    setLoginPassword("");
    setAuthorizationCodeLoginForm(emptyAuthorizationCodeLoginForm);
    setLoginMfaChallengeId("");
    setLoginMfaCode("");
    setLoginRecoveryAvailable(false);
    setLoginCaptchaChallengeId("");
    setLoginCaptchaPrompt("");
    setLoginCaptchaAnswer("");
    setError("");
    setVerificationMessage("");
  }

  function finishInteractiveAuth(nextUser: User): boolean {
    setUser(nextUser);
    if (!authReturnTo) {
      // Explicit auth routes deliberately keep the unified chooser visible
      // for an already authenticated visitor. Once this page itself has just
      // completed a login or registration, however, retaining `auth=...`
      // would strand the new session on the form instead of opening the app.
      if (initialAuth.isAuthPage) {
        window.location.replace("/");
        return true;
      }
      return false;
    }
    // An account-flow is created only after an explicit chooser action.  The
    // backend consumes it atomically and, for reauthentication, verifies the
    // expected user.  A login_hint remains a hint here rather than blocking a
    // deliberate "use another account" sign-in.
    if (!effectiveAccountFlow && loginHintRequiresAccountSwitch(nextUser, initialAuth.loginHint)) {
      setSharedAuthEmail(initialAuth.loginHint);
      setError(t("authAccountSwitch"));
      return false;
    }
    window.location.assign(authReturnTo);
    return true;
  }

  async function copyTextToClipboard(value: string, copiedKey: TranslationKey, unavailableKey: TranslationKey) {
    if (!value) return;
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("clipboard unavailable");
      }
      await navigator.clipboard.writeText(value);
      setVerificationMessage(t(copiedKey));
    } catch {
      setVerificationMessage(`${t(unavailableKey)}: ${value}`);
    }
  }

  function switchLocale(next: Locale) {
    setLocale(next);
    localStorage.setItem("gpt-sso-locale", next);
  }

  async function loadBootstrap() {
    const target = authReturnTo ? `?return_to=${encodeURIComponent(authReturnTo)}` : "";
    const next = await api<Bootstrap>(`/api/public/bootstrap${target}`);
    setBootstrap(next);
    if (!localStorage.getItem("gpt-sso-locale") && next.default_locale === "en-US") {
      setLocale("en-US");
    }
    if (!next.has_users) {
      setAuthMode("register");
    }
  }

  async function loadMe() {
    const me = await api<User | null>("/api/me");
    setApiCacheScope(me?.id ?? null);
    setUser(me);
    return me;
  }

  async function loadEnterpriseContext(userId?: string) {
    try {
      const [nextOrganizations, nextContext] = await Promise.all([
        api<UserOrganization[]>("/api/me/organizations"),
        api<OrganizationContext>("/api/me/organization-context")
      ]);
      setMyOrganizations(nextOrganizations);
      setOrganizationContext(nextContext.organization);
      setApiCacheScope(`${userId ?? user?.id ?? "anonymous"}:${nextContext.organization?.id ?? "none"}`);
    } finally {
      setEnterpriseContextReady(true);
    }
  }

  async function loadAccountData() {
    if (!user) {
      setMfaStatus(null);
      setPasskeys([]);
      setMyConsents([]);
      setMySessions([]);
      return;
    }
    const [nextMfaStatus, nextPasskeys, nextConsents, nextSessions] = await Promise.all([
      api<MfaStatus>("/api/mfa/status"),
      api<Passkey[]>("/api/passkeys"),
      api<MyConsent[]>("/api/me/consents"),
      api<MySession[]>("/api/me/sessions")
    ]);
    setMfaStatus(nextMfaStatus);
    setPasskeys(nextPasskeys);
    setMyConsents(nextConsents);
    setMySessions(nextSessions);
  }

  function usersListPath() {
    const params = new URLSearchParams({ status: userFilter });
    if (userOrganizationFilter) params.set("organization_id", userOrganizationFilter);
    if (userLinkedIdentityFilter !== "all") params.set("linked_identity", userLinkedIdentityFilter);
    return `/api/admin/users?${params.toString()}`;
  }

  function hasCachedAdminTab(targetTab: Tab): boolean {
    switch (targetTab) {
      case "overview": return cachedApiValue<Overview>("/api/admin/overview") !== undefined;
      case "users": return cachedApiValue<User[]>(usersListPath()) !== undefined;
      case "applications": return cachedApiValue<TenantApplication[]>("/api/admin/applications") !== undefined;
      case "clients": return cachedApiValue<Client[]>("/api/admin/clients") !== undefined;
      case "iap": return cachedApiValue<IapApplication[]>("/api/admin/iap-applications") !== undefined;
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

  async function loadAdminData(targetTab: Tab = tab, options: { force?: boolean } = {}) {
    if (!canAdmin || targetTab === "account") return;
    const loadId = ++adminLoadId.current;
    const isCurrent = () => adminLoadId.current === loadId;
    const cacheAvailable = !options.force && hasCachedAdminTab(targetTab);
    setAdminLoading(!cacheAvailable);

    async function loadCached<T>(path: string, apply: (value: T) => void): Promise<T> {
      const cached = cachedApiValue<T>(path);
      if (cached !== undefined && isCurrent()) apply(cached);
      const result = await cachedApi<T>(path, { force: options.force });
      if (isCurrent() && (result.changed || cached === undefined)) apply(result.value);
      return result.value;
    }

    try {
      switch (targetTab) {
        case "overview": {
          await loadCached<Overview>("/api/admin/overview", setOverview);
          break;
        }
        case "users": {
          if (!canReadUsers) break;
          await Promise.all([
            loadCached<User[]>(usersListPath(), (next) => setUsers(sortUsersForDisplay(next))),
            loadCached<OrganizationOption[]>("/api/admin/organization-options", setOrganizationOptions).catch(() => undefined)
          ]);
          break;
        }
        case "clients": {
          if (!canReadClients) break;
          await Promise.all([
            loadCached<Client[]>("/api/admin/clients", setClients),
            // A client is only the protocol connection. Load the current
            // enterprise applications beside it so the client list can make
            // its governing access policy visible and reachable.
            canManageActiveOrganization
              ? loadCached<TenantApplication[]>("/api/admin/applications", setApplications).catch(() => undefined)
              : Promise.resolve(undefined),
            hasPermission("clients.manage")
              ? loadCached<OrganizationOption[]>("/api/admin/organization-options", setOrganizationOptions)
              : Promise.resolve(undefined)
          ]);
          break;
        }
        case "applications": {
          if (!canManageActiveOrganization) break;
          await Promise.all([
            loadCached<TenantApplication[]>("/api/admin/applications", setApplications),
            loadCached<Client[]>("/api/admin/clients", setClients).catch(() => undefined),
            loadCached<ExternalProvider[]>("/api/admin/external-oidc-providers", setProviders).catch(() => undefined),
            canManagePlatformProviders
              ? loadCached<LdapProvider[]>("/api/admin/ldap-providers", setLdapProviders).catch(() => undefined)
              : Promise.resolve(undefined),
            organizationContext
              ? Promise.all([
                  loadCached<OrganizationMember[]>(`/api/admin/organizations/${organizationContext.id}/members`, setOrganizationMembers),
                  loadCached<Invitation[]>(`/api/admin/organizations/${organizationContext.id}/member-invitations`, setOrganizationMemberInvitations)
                ]).catch(() => undefined)
              : Promise.resolve(undefined)
          ]);
          break;
        }
        case "iap": {
          if (!canReadIap) break;
          await Promise.all([
            loadCached<IapApplication[]>("/api/admin/iap-applications", setIapApplications),
            loadCached<OrganizationOption[]>("/api/admin/organization-options", setOrganizationOptions)
          ]);
          break;
        }
        case "organizations": {
          if (!canReadOrganizations) break;
          await Promise.all([
            loadCached<Organization[]>("/api/admin/organizations", (next) => {
              setOrganizations(next);
              setOrganizationOptions(next.map(({ id, slug, name, kind, is_active }) => ({ id, slug, name, kind, is_active })));
            }),
            canManageOrganizations
              ? loadCached<User[]>("/api/admin/users?status=live", (next) => setUsers(sortUsersForDisplay(next)))
              : Promise.resolve(undefined)
          ]);
          break;
        }
        case "invitations": {
          if (!canManageAuthorizationCodes) break;
          await Promise.all([
            loadCached<Invitation[]>(AUTHORIZATION_CODES_API, setInvitations),
            // An authorization-code manager needs only minimal organization
            // metadata. Older servers may deny these two optional lists.
            loadCached<Client[]>("/api/admin/clients", setClients).catch(() => undefined),
            loadCached<OrganizationOption[]>("/api/admin/organization-options", setOrganizationOptions).catch(() => undefined)
          ]);
          break;
        }
        case "registration": {
          if (!canManageSettings) break;
          await loadCached<RegistrationSettings>("/api/admin/registration-settings", (next) => {
            setRegistrationSettings(next);
            setRegistrationSettingsBaseline(next);
          });
          break;
        }
        case "providers": {
          if (!canManageProviders) break;
          const requests: Promise<unknown>[] = [
            loadCached<ExternalProvider[]>("/api/admin/external-oidc-providers", setProviders),
            loadCached<ExternalProviderTemplate[]>("/api/admin/external-oidc-provider-templates", setProviderTemplates)
          ];
          if (canManagePlatformProviders) {
            requests.push(
              loadCached<LdapProvider[]>("/api/admin/ldap-providers", setLdapProviders),
              loadCached<OrganizationOption[]>("/api/admin/organization-options", setOrganizationOptions)
            );
          }
          await Promise.all(requests);
          break;
        }
        case "portal": {
          if (!canManageSettings) break;
          await loadCached<LoginSettings>("/api/admin/login-settings", (next) => {
            setLoginSettings(next);
            const draft = {
              brand_logo_url: next.brand_logo_url,
              email_domains: next.email_domains.join("\n"),
              quick_links: next.quick_links
            };
            setLoginSettingsDraft(draft);
            setLoginSettingsBaseline(draft);
          });
          break;
        }
        case "security": {
          if (!canManageSecurity && !canReadAudit) break;
          await Promise.all([
            canManageSecurity
              ? loadCached<SecurityPolicy>("/api/admin/security-policy", (next) => {
                  setSecurityPolicy(next);
                  setSecurityPolicyBaseline(next);
                })
              : Promise.resolve(undefined),
            canManageSecurity
              ? loadCached<SigningKey[]>("/api/admin/signing-keys", setSigningKeys)
              : Promise.resolve(undefined),
            canManageSecurity
              ? loadCached<PermissionInfo[]>("/api/admin/access/permissions", setPermissionCatalog)
              : Promise.resolve(undefined),
            canManageSecurity
              ? loadCached<Role[]>("/api/admin/access/roles", setRoles)
              : Promise.resolve(undefined),
            canManageSecurity
              ? loadCached<AccessGroup[]>("/api/admin/access/groups", setGroups)
              : Promise.resolve(undefined),
            canManageSecurity
              ? loadCached<User[]>("/api/admin/users?status=live", (next) => setUsers(sortUsersForDisplay(next)))
              : Promise.resolve(undefined),
            canReadAudit
              ? loadCached<AuditEvent[]>("/api/admin/audit-events", setAuditEvents)
              : Promise.resolve(undefined),
            loadCached<AuditWebhook[]>("/api/admin/audit-webhooks", setAuditWebhooks)
          ]);
          break;
        }
        case "settings": {
          if (!canManageSettings) break;
          await Promise.all([
            loadCached<RuntimeSettings>("/api/admin/runtime-settings", (next) => {
              setRuntimeSettings(next);
              setRuntimeSettingsBaseline(next);
            }),
            loadCached<SettingsSummary>("/api/admin/settings", setSettings)
          ]);
          break;
        }
      }
    } catch (err) {
      // Preserve a usable stale view when the optional background validation
      // is temporarily offline. Authorization and validation failures still
      // surface immediately instead of leaving a now-forbidden view visible.
      if (
        cacheAvailable
        && !options.force
        && (!(err instanceof ApiError) || err.status === 0 || err.status >= 500)
      ) return;
      throw err;
    } finally {
      if (isCurrent()) setAdminLoading(false);
    }
  }

  async function initialize() {
    setInitialLoadError("");
    try {
      const [, me] = await Promise.all([loadBootstrap(), loadMe()]);
      if (me) await loadEnterpriseContext(me.id);
      else setEnterpriseContextReady(true);
    } catch (err) {
      setUser(null);
      setMyOrganizations([]);
      setOrganizationContext(null);
      setEnterpriseContextReady(true);
      setInitialLoadError(messageOr(err, "loadFailed"));
    }
  }

  useEffect(() => {
    void initialize();
  }, []);

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("gpt-sso-theme", theme);
  }, [theme]);

  useEffect(() => {
    if (authCanCompleteWithCurrentUser && authReturnTo) {
      window.location.assign(authReturnTo);
    }
  }, [authCanCompleteWithCurrentUser, authReturnTo]);

  useEffect(() => {
    if (initialAuth.isAuthPage) return;
    loadAccountData().catch((err) => setError(messageOr(err, "loadFailed")));
  }, [initialAuth.isAuthPage, user?.id]);

  useEffect(() => {
    if (!canAdmin || initialAuth.isAuthPage || tab === "account" || tab === "billing" || (tab === "overview" && !hasGlobalConsolePermission)) return;
    loadAdminData(tab).catch((err) =>
      setError(messageOr(err, "loadFailed"))
    );
  }, [canAdmin, canManageActiveOrganization, hasGlobalConsolePermission, initialAuth.isAuthPage, tab, userFilter, userOrganizationFilter, userLinkedIdentityFilter, organizationContext?.id]);

  useEffect(() => {
    const authorizationCode = registerForm.authorization_code.trim();
    if (!bootstrap?.has_users || authMode !== "register" || !authorizationCode) {
      setRegistrationCodeInspection(null);
      setRegistrationCodeInspecting(false);
      return;
    }
    let current = true;
    setRegistrationCodeInspection(null);
    setRegistrationCodeInspecting(true);
    const timer = window.setTimeout(() => {
      void api<AuthorizationCodeInspection>("/api/public/authorization-code/inspect", {
        method: "POST",
        body: JSON.stringify({ authorization_code: authorizationCode })
      }).then((inspection) => {
        if (current) setRegistrationCodeInspection(inspection);
      }).catch(() => {
        // The final registration request always re-checks the code.  Keep a
        // transient inspection failure separate from an unavailable code so a
        // network hiccup never becomes a client-side authorization decision.
        if (current) setRegistrationCodeInspection(null);
      }).finally(() => {
        if (current) setRegistrationCodeInspecting(false);
      });
    }, 350);
    return () => {
      current = false;
      window.clearTimeout(timer);
    };
  }, [authMode, bootstrap?.has_users, registerForm.authorization_code]);

  useEffect(() => {
    if (userOrganizationFilter) setUserFiltersExpanded(true);
  }, [userOrganizationFilter]);

  useEffect(() => {
    setSelectedUserIds([]);
  }, [
    searchQuery,
    userFilter,
    userOrganizationFilter,
    userLinkedIdentityFilter,
    userEmailFilter,
    userRoleFilter,
    userRegistrationFrom,
    userRegistrationTo,
    userLastLoginFrom,
    userLastLoginTo,
    userPhoneFilter,
    userLoginRegionFilter
  ]);

  useEffect(() => {
    const handleHashChange = () => {
      const navigation = initialNavigation();
      setTab(navigation.tab);
      setApplicationNavigationId(navigation.applicationId);
      setApplicationNavigationSection(navigation.applicationSection);
      setBillingOrderReference(navigation.billingOrder);
      setSidebarOpen(false);
    };
    window.addEventListener("hashchange", handleHashChange);
    window.addEventListener("popstate", handleHashChange);
    return () => {
      window.removeEventListener("hashchange", handleHashChange);
      window.removeEventListener("popstate", handleHashChange);
    };
  }, []);

  useEffect(() => {
    if (!sidebarOpen || !sidebarRef.current) return;
    const sidebar = sidebarRef.current;
    const previousOverflow = document.body.style.overflow;
    const focusableElements = () => [...sidebar.querySelectorAll<HTMLElement>(
      "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])"
    )].filter((element) => element.getClientRects().length > 0);
    const focusFrame = window.requestAnimationFrame(() => focusableElements()[0]?.focus());
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setSidebarOpen(false);
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = focusableElements();
      if (focusable.length === 0) {
        event.preventDefault();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.body.style.overflow = "hidden";
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      window.cancelAnimationFrame(focusFrame);
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      window.requestAnimationFrame(() => mobileMenuButtonRef.current?.focus());
    };
  }, [sidebarOpen]);

  useEffect(() => {
    if (!user || !verificationMessage) return;
    const timer = window.setTimeout(() => setVerificationMessage(""), 4200);
    return () => window.clearTimeout(timer);
  }, [user, verificationMessage]);

  useEffect(() => {
    if (!initialAuth.isAuthPage && !loginMfaChallengeId && !loginCaptchaChallengeId) return;
    const frame = window.requestAnimationFrame(() => authModeHeadingRef.current?.focus());
    return () => window.cancelAnimationFrame(frame);
  }, [authMode, loginMethod, loginMfaChallengeId, loginCaptchaChallengeId, initialAuth.isAuthPage]);

  useEffect(() => {
    if (editor) setError("");
  }, [editor]);

  function changeLoginMethod(next: LoginMethod) {
    setLoginMethod(next);
    setError("");
    setLoginMfaChallengeId("");
    setLoginMfaCode("");
    setLoginRecoveryAvailable(false);
    setLoginCaptchaChallengeId("");
    setLoginCaptchaPrompt("");
    setLoginCaptchaAnswer("");
  }

  async function handleLogin(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await api<LoginResponse>("/api/login", {
        method: "POST",
        body: JSON.stringify({
          email: authEmail,
          password: loginPassword,
          mfa_challenge_id: loginMfaChallengeId || null,
          mfa_code: loginMfaCode || null,
          captcha_challenge_id: loginCaptchaChallengeId || null,
          captcha_answer: loginCaptchaAnswer || null,
          return_to: authReturnTo,
          account_flow: effectiveAccountFlow
        })
      });
      if ("continue_to" in result) {
        window.location.assign(result.continue_to);
        return;
      }
      if (result.captcha_required) {
        setLoginCaptchaChallengeId(result.captcha_challenge_id ?? "");
        setLoginCaptchaPrompt(result.captcha_prompt ?? "");
        setLoginCaptchaAnswer("");
        return;
      }
      if (result.mfa_required) {
        setLoginMfaChallengeId(result.mfa_challenge_id ?? "");
        setLoginRecoveryAvailable(result.recovery_available);
        setLoginMfaCode("");
        setLoginCaptchaChallengeId("");
        setLoginCaptchaPrompt("");
        setLoginCaptchaAnswer("");
        return;
      }
      if (!result.user) throw new Error(t("loginFailed"));
      setLoginMfaChallengeId("");
      setLoginMfaCode("");
      setLoginRecoveryAvailable(false);
      setLoginCaptchaChallengeId("");
      setLoginCaptchaPrompt("");
      setLoginCaptchaAnswer("");
      if (finishInteractiveAuth(result.user)) return;
      await loadBootstrap();
    } catch (err) {
      setError(messageOr(err, "loginFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function handleAuthorizationCodeLogin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const result = await api<LoginResponse>("/api/login/authorization-code", {
        method: "POST",
        body: JSON.stringify({
          email: authorizationCodeLoginForm.email.trim(),
          authorization_code: authorizationCodeLoginForm.authorization_code.trim(),
          return_to: authReturnTo,
          account_flow: effectiveAccountFlow
        })
      });
      if (result.mode === "oidc_continuation") {
        setAuthorizationCodeLoginForm(emptyAuthorizationCodeLoginForm);
        window.location.assign(result.continue_to);
        return;
      }
      if (!result.user) throw new Error(t("authorizationCodeLoginFailed"));
      setAuthorizationCodeLoginForm(emptyAuthorizationCodeLoginForm);
      if (finishInteractiveAuth(result.user)) return;
      await loadBootstrap();
    } catch (err) {
      setError(messageOr(err, "authorizationCodeLoginFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function handlePasskeyLogin() {
    const email = authEmail.trim();
    if (!email) {
      setError(t("passkeyEmailRequired"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      if (!navigator.credentials?.get || !window.PublicKeyCredential) {
        throw new Error(t("passkeyLoginFailed"));
      }
      const start = await api<PasskeyAuthenticationStart>("/api/passkeys/authentication/start", {
        method: "POST",
        body: JSON.stringify({ email, account_flow: effectiveAccountFlow })
      });
      const credential = await navigator.credentials.get(passkeyRequestOptions(start.public_key));
      if (!credential || credential.type !== "public-key") {
        throw new Error(t("passkeyLoginFailed"));
      }
      const result = await api<{ user: User } | OidcContinuationLoginResponse>("/api/passkeys/authentication/finish", {
        method: "POST",
        body: JSON.stringify({
          challenge_id: start.challenge_id,
          credential: authenticationCredentialJson(credential as PublicKeyCredential),
          account_flow: effectiveAccountFlow
        })
      });
      if ("continue_to" in result) {
        window.location.assign(result.continue_to);
        return;
      }
      setLoginMfaChallengeId("");
      setLoginMfaCode("");
      setLoginRecoveryAvailable(false);
      setLoginCaptchaChallengeId("");
      setLoginCaptchaPrompt("");
      setLoginCaptchaAnswer("");
      if (finishInteractiveAuth(result.user)) return;
      await loadBootstrap();
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401
        ? t("passkeyLoginFailed")
        : messageOr(err, "passkeyLoginFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function handleRegister(event: FormEvent) {
    event.preventDefault();
    if (
      bootstrap?.has_users
      && !bootstrap.registration.allow_password_registration
      && !bootstrap.registration.require_invitation
      && !registerForm.authorization_code.trim()
    ) {
      setError(t("passwordRegistrationUnavailable"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      const body: Record<string, string | null> = isTrialEnrollmentRegistration
        ? {
            // The server has classified this as an enrollment code.  Do not
            // manufacture usernames, passwords or code rules in the browser.
            email: authEmail,
            authorization_code: registerForm.authorization_code.trim() || null,
            return_to: authReturnTo,
            account_flow: effectiveAccountFlow
          }
        : {
            email: authEmail,
            username: registerForm.username,
            display_name: null,
            phone: registerForm.phone || null,
            password: registerForm.password,
            email_code: registerForm.email_code || null,
            phone_code: registerForm.phone_code || null,
            authorization_code: registerForm.authorization_code.trim() || null,
            return_to: authReturnTo,
            account_flow: effectiveAccountFlow
          };
      const result = await api<{ user: User; first_admin: boolean } | OidcContinuationLoginResponse>("/api/register", {
        method: "POST",
        body: JSON.stringify(body)
      });
      if ("continue_to" in result) {
        setRegisterForm(emptyRegisterForm);
        window.location.assign(result.continue_to);
        return;
      }
      if (finishInteractiveAuth(result.user)) return;
      setRegisterForm(emptyRegisterForm);
      await loadBootstrap();
    } catch (err) {
      setError(messageOr(err, "registrationFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function sendVerification(channel: "email" | "phone") {
    const target = channel === "email" ? authEmail : registerForm.phone;
    await runUiAction(async () => {
      const result = await api<{ dev_code: string | null; expires_at: number }>("/api/register/verification/start", {
        method: "POST",
        body: JSON.stringify({ channel, target })
      });
      setVerificationMessage(
        `${t("codeSent")}${result.dev_code ? `: ${result.dev_code}. ${t("copiedCodeHint")}` : ""}`
      );
      const devCode = result.dev_code;
      if (channel === "email" && devCode) {
        setRegisterForm((current) => ({ ...current, email_code: devCode }));
      }
      if (channel === "phone" && devCode) {
        setRegisterForm((current) => ({ ...current, phone_code: devCode }));
      }
    }, "sendVerificationFailed");
  }

  async function sendPasswordResetCode() {
    await runUiAction(async () => {
      const result = await api<{ dev_code: string | null; expires_at: number }>("/api/password-reset/start", {
        method: "POST",
        body: JSON.stringify({ email: authEmail })
      });
      setVerificationMessage(
        `${t("codeSent")}${result.dev_code ? `: ${result.dev_code}. ${t("copiedCodeHint")}` : ""}`
      );
      const devCode = result.dev_code;
      if (devCode) {
        setPasswordResetForm((current) => ({ ...current, code: devCode }));
      }
    }, "sendResetCodeFailed");
  }

  async function handlePasswordReset(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api("/api/password-reset/complete", {
        method: "POST",
        body: JSON.stringify({
          email: authEmail,
          code: passwordResetForm.code,
          password: passwordResetForm.password
        })
      });
      setPasswordResetForm(emptyPasswordResetForm);
      setAuthMode("login");
      setVerificationMessage(t("passwordResetComplete"));
    } catch (err) {
      setError(messageOr(err, "resetPasswordFailed"));
    } finally {
      setBusy(false);
    }
  }

  function nextRegisterEmail() {
    const domain =
      usableEmailDomain(registerCustomDomain)
      || bootstrap?.login.email_domains.find((domain) => usableEmailDomain(domain))
      || "example.com";
    const local = randomLocalPart();
    return { email: `${local}@${domain}`, local };
  }

  function generateRegisterEmail() {
    const generated = nextRegisterEmail();
    setSharedAuthEmail(generated.email);
    setRegisterForm({
      ...registerForm,
      username: registerForm.username || generated.local
    });
  }

  async function copyRegisterEmail() {
    const generated = authEmail.trim() ? null : nextRegisterEmail();
    const email = authEmail.trim() || generated?.email || "";
    if (!email) return;
    if (generated) {
      setSharedAuthEmail(email);
      setRegisterForm({
        ...registerForm,
        username: registerForm.username || generated.local
      });
    }
    await copyTextToClipboard(email, "copiedEmail", "copyEmailUnavailable");
  }

  async function runUiAction(
    action: () => Promise<void>,
    fallback: TranslationKey = "operationFailed"
  ): Promise<boolean> {
    setBusy(true);
    setError("");
    try {
      await action();
      return true;
    } catch (err) {
      setError(messageOr(err, fallback));
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function handleLogout() {
    await runUiAction(async () => {
      const result = await api<LogoutResponse>("/api/logout", { method: "POST" });
      deliverFrontchannelLogout(result.frontchannel_logout_frames);
      setUser(null);
      await loadBootstrap();
    });
  }

  async function openAccountSwitcher() {
    const returnTo = `${window.location.pathname}${window.location.search}${window.location.hash}` || "/";
    setBusy(true);
    setError("");
    try {
      window.location.assign(await startBrowserAccountLogin(returnTo));
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : t("browserAccountAddFailed"));
      setBusy(false);
    }
  }

  async function saveUser(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = JSON.stringify({
        email: userForm.email,
        username: userForm.username,
        display_name: userForm.display_name || null,
        phone: userForm.phone || null,
        password: userForm.password || null,
        is_admin: userForm.is_admin,
        is_active: userForm.is_active
      });
      if (userForm.id) {
        await api<User>(`/api/admin/users/${userForm.id}`, { method: "PUT", body });
      } else {
        await api<User>("/api/admin/users", { method: "POST", body });
      }
      setUserForm(emptyUserForm);
      setUserFormBaseline(null);
      setEditor(null);
      setVerificationMessage(t("changesSaved"));
      await loadAdminData();
    } catch (err) {
      setError(messageOr(err, "saveUserFailed"));
    } finally {
      setBusy(false);
    }
  }

  function openBulkUserImport() {
    setBulkImportOpen(true);
    setBulkImportError("");
  }

  function closeBulkUserImport() {
    if (busy) return;
    setBulkImportOpen(false);
    setBulkImportError("");
  }

  function resetBulkUserImport() {
    setBulkImportCsv("");
    setBulkImportFileName("");
    setBulkImportDryRun(true);
    setBulkImportCommitConfirmed(false);
    setBulkImportResult(null);
    setBulkImportError("");
  }

  async function readBulkUserImportFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0];
    // Let the same file be selected again after an accidental choice.
    event.currentTarget.value = "";
    if (!file) return;
    try {
      const csv = await file.text();
      setBulkImportCsv(csv);
      setBulkImportFileName(file.name);
      setBulkImportResult(null);
      setBulkImportError("");
    } catch {
      setBulkImportError(t("bulkImportFileReadFailed"));
    }
  }

  async function submitBulkUserImport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!bulkImportCsv.trim()) {
      setBulkImportError(t("bulkImportCsvRequired"));
      return;
    }
    if (!bulkImportDryRun && !bulkImportCommitConfirmed) {
      setBulkImportError(t("bulkImportCommitConfirmationRequired"));
      return;
    }
    setBusy(true);
    setBulkImportError("");
    try {
      const result = await api<BulkUserImportResult>(
        `${BULK_USER_IMPORT_API}?dry_run=${bulkImportDryRun ? "true" : "false"}`,
        {
          method: "POST",
          headers: { "content-type": "text/csv" },
          body: bulkImportCsv
        }
      );
      setBulkImportResult(result);
      if (result.committed) {
        setVerificationMessage(t("bulkImportCompleted"));
        await loadAdminData("users");
      } else {
        setVerificationMessage(t("bulkImportDryRunComplete"));
      }
    } catch (err) {
      if (err instanceof ApiError && isBulkUserImportResult(err.body)) {
        setBulkImportResult(err.body);
        setBulkImportError(t("bulkImportValidationFailed"));
      } else {
        setBulkImportError(messageOr(err, "bulkImportFailed"));
      }
    } finally {
      setBusy(false);
    }
  }

  async function showUserDetails(id: string) {
    await runUiAction(async () => {
      setSelectedUser(await api<UserDetail>(`/api/admin/users/${id}`));
    });
  }

  async function enableUser(id: string) {
    const completed = await runUiAction(async () => {
      await api(`/api/admin/users/${id}/enable`, { method: "POST" });
      await loadAdminData();
      if (selectedUser?.user.id === id) setSelectedUser(null);
    });
    if (completed) setVerificationMessage(t("operationCompleted"));
  }

  async function advanceUserLifecycle(id: string) {
    await api(`/api/admin/users/${id}`, { method: "DELETE" });
    await loadAdminData();
    if (selectedUser?.user.id === id) setSelectedUser(null);
    if (userForm.id === id) {
      setUserForm(emptyUserForm);
      setUserFormBaseline(null);
    }
  }

  async function saveClient(event: FormEvent) {
    event.preventDefault();
    const isNewClient = !clientForm.id;
    const validationErrors: string[] = [];
    const fieldErrors: Record<string, string> = {};
    const fieldLabels: Record<string, string> = {
      client_id: t("clientId"),
      client_name: t("clientName"),
      redirect_uris: t("redirectUris"),
      post_logout_redirect_uris: t("postLogoutUris"),
      require_s256_pkce: t("requireS256Pkce")
    };
    const addFieldError = (field: string, message: string) => {
      validationErrors.push(`${fieldLabels[field] ?? field} · ${message}`);
      if (!fieldErrors[field]) fieldErrors[field] = message;
    };
    if (!clientForm.client_id.trim()) addFieldError("client_id", t("requiredField"));
    if (!clientForm.client_name.trim()) addFieldError("client_name", t("requiredField"));
    const redirectValues = splitList(clientForm.redirect_uris);
    if (redirectValues.length === 0) {
      addFieldError("redirect_uris", t("requiredField"));
    } else {
      redirectValues.forEach((value) => {
        try {
          const url = new URL(value);
          if (!matchesHttpUrl(url)) throw new Error("invalid");
        } catch {
          addFieldError("redirect_uris", `${value} · ${t("invalidUrl")}`);
        }
      });
    }
    if (clientForm.post_logout_redirect_uris.trim()) {
      splitList(clientForm.post_logout_redirect_uris).forEach((value) => {
        try {
          const url = new URL(value);
          if (!matchesHttpUrl(url)) throw new Error("invalid");
        } catch {
          addFieldError("post_logout_redirect_uris", `${value} · ${t("invalidUrl")}`);
        }
      });
    }
    if (clientForm.require_s256_pkce && !clientForm.require_pkce) {
      addFieldError("require_s256_pkce", t("requirePkce"));
    }
    if (validationErrors.length > 0) {
      setClientFormErrors(validationErrors);
      setClientFieldErrors(fieldErrors);
      window.requestAnimationFrame(() => document.querySelector<HTMLElement>(".form-error-summary")?.focus());
      return;
    }
    setBusy(true);
    setError("");
    setClientFormErrors([]);
    setClientFieldErrors({});
    try {
      const body = JSON.stringify({
        client_id: clientForm.client_id,
        client_name: clientForm.client_name,
        logo_uri: clientForm.logo_uri,
        organization_id: clientForm.organization_id || null,
        client_secret: clientForm.client_secret || null,
        redirect_uris: splitList(clientForm.redirect_uris),
        post_logout_redirect_uris: splitList(clientForm.post_logout_redirect_uris),
        scopes: splitList(clientForm.scopes),
        grant_types: splitList(clientForm.grant_types),
        response_types: splitList(clientForm.response_types),
        token_endpoint_auth_method: clientForm.token_endpoint_auth_method,
        require_pkce: clientForm.require_pkce,
        require_mfa: clientForm.require_mfa,
        require_pushed_authorization_requests: clientForm.require_pushed_authorization_requests,
        require_s256_pkce: clientForm.require_s256_pkce,
        require_confidential_client: clientForm.require_confidential_client,
        require_dpop: clientForm.require_dpop,
        require_account_selection: clientForm.require_account_selection,
        trust_email_verified: clientForm.trust_email_verified,
        authorization_details_types: splitList(clientForm.authorization_details_types),
        subject_type: clientForm.subject_type,
        sector_identifier_uri: clientForm.sector_identifier_uri,
        jwks_uri: clientForm.jwks_uri,
        jwks: clientForm.jwks,
        backchannel_logout_uri: clientForm.backchannel_logout_uri,
        backchannel_logout_session_required: clientForm.backchannel_logout_session_required,
        frontchannel_logout_uri: clientForm.frontchannel_logout_uri,
        frontchannel_logout_session_required: clientForm.frontchannel_logout_session_required,
        service_account_enabled: clientForm.service_account_enabled,
        service_account_permissions: splitList(clientForm.service_account_permissions),
        is_active: clientForm.is_active,
        claim_mappers: clientForm.claim_mappers
          .filter((mapper) => mapper.claim_name.trim())
          .map((mapper, index) => ({
            claim_name: mapper.claim_name.trim(),
            source: mapper.source,
            source_value: mapper.source_value.trim(),
            value_type: mapper.value_type,
            include_in_id_token: mapper.include_in_id_token,
            include_in_access_token: mapper.include_in_access_token,
            include_in_userinfo: mapper.include_in_userinfo,
            is_active: mapper.is_active,
            sort_order: index
          }))
      });
      if (clientForm.id) {
        await api<Client>(`/api/admin/clients/${clientForm.id}`, { method: "PUT", body });
      } else {
        await api<Client>("/api/admin/clients", { method: "POST", body });
      }
      setClientForm(emptyClientForm);
      setClientFormBaseline(null);
      setClientFormErrors([]);
      setClientFieldErrors({});
      setEditor(null);
      setVerificationMessage(t(isNewClient ? "clientCreatedApplicationHint" : "changesSaved"));
      await loadAdminData();
      if (isNewClient) await loadAdminData("applications", { force: true });
    } catch (err) {
      setError(messageOr(err, "saveClientFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function deleteClient(id: string) {
    await api(`/api/admin/clients/${id}`, { method: "DELETE" });
    if (clientForm.id === id) {
      setClientForm(emptyClientForm);
      setEditor(null);
    }
    await loadAdminData("clients");
  }

  async function editApplication(application: TenantApplication) {
    const protocolModule = application.modules?.find((module) => module.module_key === "protocols");
    const protocolConfig = protocolModule?.config && typeof protocolModule.config === "object"
      ? protocolModule.config
      : {};
    const websiteUrl = typeof protocolConfig.website_url === "string" ? protocolConfig.website_url : "";
    const nextForm = {
      id: application.id,
      slug: application.slug,
      name: application.name,
      website_url: websiteUrl,
      description: application.description ?? "",
      account_selection_mode: application.account_selection_mode,
      unique_identity_factors: application.unique_identity_factors,
      is_active: application.is_active,
    };
    setApplicationForm(nextForm);
    setApplicationFormBaseline(nextForm);
    setEditor("application");
  }

  async function saveApplication(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = JSON.stringify({
        slug: applicationForm.slug,
        name: applicationForm.name,
        description: applicationForm.description || null,
        account_selection_mode: applicationForm.account_selection_mode,
        unique_identity_factors: applicationForm.unique_identity_factors,
        is_active: applicationForm.is_active
      });
      const application = applicationForm.id
        ? await api<TenantApplication>(`/api/admin/applications/${applicationForm.id}`, { method: "PUT", body })
        : await api<TenantApplication>("/api/admin/applications", { method: "POST", body });
      const currentProtocolModule = application.modules?.find((module) => module.module_key === "protocols");
      const currentProtocolConfig = currentProtocolModule?.config ?? {};
      await api<ApplicationModule>(`/api/admin/applications/${application.id}/modules/protocols`, {
        method: "PUT",
        body: JSON.stringify({
          config: {
            ...(currentProtocolConfig && typeof currentProtocolConfig === "object" ? currentProtocolConfig : {}),
            website_url: applicationForm.website_url
          },
          is_enabled: currentProtocolModule?.is_enabled ?? Boolean(application.client_bindings.length)
        })
      });
      setApplicationForm(emptyApplicationForm);
      setApplicationFormBaseline(null);
      setEditor(null);
      setVerificationMessage(t("changesSaved"));
      await loadAdminData("applications", { force: true });
    } catch (err) {
      setError(messageOr(err, "saveApplicationFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function deleteApplication(id: string) {
    await api(`/api/admin/applications/${id}`, { method: "DELETE" });
    if (applicationForm.id === id) {
      setApplicationForm(emptyApplicationForm);
      setApplicationFormBaseline(null);
      setEditor(null);
    }
    await loadAdminData("applications", { force: true });
  }

  function updateApplicationModuleInState(
    applicationId: string,
    module: ApplicationModule,
    clientBindings?: ApplicationClientBinding[]
  ) {
    setApplications((current) => current.map((application) => {
      if (application.id !== applicationId) return application;
      const modules = [...(application.modules ?? [])];
      const index = modules.findIndex((item) => item.module_key === module.module_key);
      if (index >= 0) modules[index] = module;
      else modules.push(module);
      return {
        ...application,
        modules,
        ...(clientBindings ? { client_bindings: clientBindings } : {})
      };
    }));
  }

  async function addEnterpriseMember() {
    if (!organizationContext || !enterpriseMemberEmail.trim()) return;
    setBusy(true);
    setError("");
    try {
      await api(`/api/admin/organizations/${organizationContext.id}/members`, {
        method: "POST",
        body: JSON.stringify({ email: enterpriseMemberEmail.trim(), role: enterpriseMemberRole })
      });
      setOrganizationMembers(await api<OrganizationMember[]>(`/api/admin/organizations/${organizationContext.id}/members`));
      setEnterpriseMemberEmail("");
      setEnterpriseMemberRole("member");
      setVerificationMessage(t("operationCompleted"));
    } catch (err) {
      setError(messageOr(err, "operationFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function createOrganizationMemberInvitation() {
    if (!organizationContext) return;
    const expiresAt = toTimestamp(organizationMemberInvitationForm.expires_at);
    if (!organizationMemberInvitationForm.email.trim() || expiresAt === null) {
      setError(t("organizationMemberInvitationValidation"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      const created = await api<OrganizationMemberInvitationCreateResponse>(
        `/api/admin/organizations/${organizationContext.id}/member-invitations`,
        {
          method: "POST",
          body: JSON.stringify({
            email: organizationMemberInvitationForm.email.trim(),
            display_name: organizationMemberInvitationForm.display_name || null,
            description: organizationMemberInvitationForm.description || null,
            expires_at: expiresAt,
            organization_role: organizationMemberInvitationForm.organization_role,
            is_active: organizationMemberInvitationForm.is_active
          })
        }
      );
      setOrganizationMemberInvitations((current) => [created.invitation, ...current]);
      setRevealedOrganizationMemberInvitation(created);
      setOrganizationMemberInvitationForm({
        email: "",
        display_name: "",
        description: "",
        expires_at: "",
        organization_role: "member",
        is_active: true
      });
      setVerificationMessage(t("organizationMemberInvitationCreated"));
    } catch (err) {
      setError(messageOr(err, "operationFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function deleteOrganizationMemberInvitation(invitationId: string) {
    if (!organizationContext) return;
    await api(`/api/admin/organizations/${organizationContext.id}/member-invitations/${invitationId}`, {
      method: "DELETE"
    });
    setOrganizationMemberInvitations((current) => current.filter((invitation) => invitation.id !== invitationId));
    setRevealedOrganizationMemberInvitation((current) =>
      current?.invitation.id === invitationId ? null : current
    );
  }

  function addClientClaimMapper() {
    setClientForm({
      ...clientForm,
      claim_mappers: [
        ...clientForm.claim_mappers,
        emptyClaimMapperForm(clientForm.claim_mappers.length)
      ]
    });
  }

  function updateClientClaimMapper(index: number, patch: Partial<ClientClaimMapperForm>) {
    setClientForm({
      ...clientForm,
      claim_mappers: clientForm.claim_mappers.map((mapper, mapperIndex) =>
        mapperIndex === index ? { ...mapper, ...patch } : mapper
      )
    });
  }

  function removeClientClaimMapper(index: number) {
    setClientForm({
      ...clientForm,
      claim_mappers: clientForm.claim_mappers.filter((_, mapperIndex) => mapperIndex !== index)
    });
  }

  async function saveIapApplication(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = JSON.stringify({
        slug: iapApplicationForm.slug,
        name: iapApplicationForm.name,
        description: iapApplicationForm.description || null,
        external_host: iapApplicationForm.external_host,
        path_prefix: iapApplicationForm.path_prefix,
        required_organization_id: iapApplicationForm.required_organization_id || null,
        required_organization_roles: iapApplicationForm.required_organization_roles,
        required_permissions: splitList(iapApplicationForm.required_permissions),
        is_active: iapApplicationForm.is_active
      });
      if (iapApplicationForm.id) {
        await api<IapApplication>(`/api/admin/iap-applications/${iapApplicationForm.id}`, {
          method: "PUT",
          body
        });
      } else {
        await api<IapApplication>("/api/admin/iap-applications", { method: "POST", body });
      }
      setIapApplicationForm(emptyIapApplicationForm);
      setIapApplicationFormBaseline(null);
      setEditor(null);
      setVerificationMessage(t("changesSaved"));
      await loadAdminData();
    } catch (err) {
      setError(messageOr(err, "saveIapApplicationFailed"));
    } finally {
      setBusy(false);
    }
  }

  function editIapApplication(application: IapApplication) {
    setIapApplicationForm({
      id: application.id,
      slug: application.slug,
      name: application.name,
      description: application.description ?? "",
      external_host: application.external_host,
      path_prefix: application.path_prefix,
      required_organization_id: application.required_organization_id ?? "",
      required_organization_roles: application.required_organization_roles,
      required_permissions: application.required_permissions.join("\n"),
      is_active: application.is_active
    });
    setIapApplicationFormBaseline({
      id: application.id,
      slug: application.slug,
      name: application.name,
      description: application.description ?? "",
      external_host: application.external_host,
      path_prefix: application.path_prefix,
      required_organization_id: application.required_organization_id ?? "",
      required_organization_roles: application.required_organization_roles,
      required_permissions: application.required_permissions.join("\n"),
      is_active: application.is_active
    });
  }

  async function deleteIapApplication(id: string) {
    await api(`/api/admin/iap-applications/${id}`, { method: "DELETE" });
    if (iapApplicationForm.id === id) {
      setIapApplicationForm(emptyIapApplicationForm);
      setIapApplicationFormBaseline(null);
    }
    await loadAdminData();
  }

  async function saveInvitation(event: FormEvent) {
    event.preventDefault();
    const editingInvitation = Boolean(invitationForm.id);
    const isAccountRecoveryCode = invitationForm.code_type === "login"
      && invitationForm.login_code_level === "account_recovery";
    const isTrialEnrollmentCode = invitationForm.code_type === "login"
      && invitationForm.login_code_level === "trial_enrollment";
    const isAdminUniversalCode = invitationForm.code_type === "login"
      && invitationForm.login_code_level === "admin_universal";
    const isApplicationBoundLoginCode = isTrialEnrollmentCode || isAdminUniversalCode;
    if (isAccountRecoveryCode && !invitationForm.authorized_username.trim()) {
      setError(t("loginCodeUsernameRequired"));
      return;
    }
    if (isAdminUniversalCode && !user?.is_admin) {
      setError(t("adminUniversalCodeAdminOnly"));
      return;
    }
    if (isApplicationBoundLoginCode && invitationForm.allowed_client_ids.length === 0) {
      setError(t(isTrialEnrollmentCode ? "trialEnrollmentApplicationsRequired" : "allowedApplicationsRequired"));
      return;
    }
    if (isTrialEnrollmentCode && !canManageOrganizations) {
      setError(t("trialEnrollmentOrganizationManageRequired"));
      return;
    }
    if (isTrialEnrollmentCode && !invitationForm.organization_id) {
      setError(t("trialEnrollmentOrganizationRequired"));
      return;
    }
    if (isTrialEnrollmentCode && !invitationForm.organization_role) {
      setError(t("trialEnrollmentRoleRequired"));
      return;
    }
    if (isTrialEnrollmentCode && (!invitationForm.expires_at || !invitationForm.max_uses)) {
      setError(t("trialEnrollmentLimitsRequired"));
      return;
    }
    setBusy(true);
    setError("");
    setLastInvitationCode("");
    try {
      const body = JSON.stringify({
        code_type: invitationForm.code_type,
        login_code_level: invitationForm.code_type === "login" ? invitationForm.login_code_level : null,
        allowed_client_ids: isApplicationBoundLoginCode ? invitationForm.allowed_client_ids : [],
        organization_id: isTrialEnrollmentCode ? invitationForm.organization_id : null,
        organization_role: isTrialEnrollmentCode ? invitationForm.organization_role : null,
        description: invitationForm.description || null,
        authorized_email: invitationForm.code_type === "login" ? null : invitationForm.authorized_email || null,
        authorized_username: isApplicationBoundLoginCode ? null : invitationForm.authorized_username || null,
        authorized_display_name: invitationForm.code_type === "registration"
          ? invitationForm.authorized_display_name || null
          : null,
        expires_at: toTimestamp(invitationForm.expires_at),
        max_uses: invitationForm.max_uses ? Number(invitationForm.max_uses) : null,
        is_active: invitationForm.is_active
      });
      if (invitationForm.id) {
        await api<Invitation>(`${AUTHORIZATION_CODES_API}/${invitationForm.id}`, { method: "PUT", body });
      } else {
        const result = await api<{ invitation: Invitation; code: string }>(AUTHORIZATION_CODES_API, {
          method: "POST",
          body
        });
        setLastInvitationCode(result.code);
      }
      setInvitationForm(emptyInvitationForm);
      setInvitationFormBaseline(null);
      // Keep a newly-created code visible so it can be copied once; edits can
      // return straight to the list.
      setEditor(editingInvitation ? null : "invitation");
      await loadAdminData();
    } catch (err) {
      setError(messageOr(err, "saveInvitationFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function deleteInvitation(id: string) {
    await api(`${AUTHORIZATION_CODES_API}/${id}`, { method: "DELETE" });
    await loadAdminData();
  }

  async function copyLastInvitationCode() {
    await copyTextToClipboard(
      lastInvitationCode,
      "authorizationCodeCopied",
      "copyAuthorizationCodeUnavailable"
    );
  }

  async function revealInvitationCode(invitation: Invitation) {
    if (!invitation.can_reveal) return;
    setRevealedInvitation(invitation);
    setRevealedInvitationCode("");
    setInvitationRevealError("");
    setRevealingInvitationId(invitation.id);
    try {
      const result = await api<{ code: string }>(
        `${AUTHORIZATION_CODES_API}/${encodeURIComponent(invitation.id)}/reveal`,
        { method: "POST" }
      );
      setRevealedInvitationCode(result.code);
    } catch (err) {
      setInvitationRevealError(messageOr(err, "revealAuthorizationCodeFailed"));
    } finally {
      setRevealingInvitationId("");
    }
  }

  function closeInvitationReveal() {
    setRevealedInvitation(null);
    setRevealedInvitationCode("");
    setInvitationRevealError("");
    setRevealingInvitationId("");
  }

  async function loadInvitationRedemptions(invitation: Invitation, cursor: string | null = null) {
    const loadId = ++invitationRedemptionsLoadId.current;
    setInvitationRedemptionsLoading(true);
    setInvitationRedemptionsError("");
    if (!cursor) {
      setInvitationRedemptions([]);
      setInvitationRedemptionsNextCursor(null);
    }
    try {
      const query = new URLSearchParams({ limit: "50" });
      if (cursor) query.set("cursor", cursor);
      const result = await api<InvitationRedemptionsPage>(
        `${AUTHORIZATION_CODES_API}/${encodeURIComponent(invitation.id)}/redemptions?${query.toString()}`
      );
      if (loadId !== invitationRedemptionsLoadId.current) return;
      setInvitationRedemptions((existing) => cursor
        ? [...existing, ...result.redemptions]
        : result.redemptions
      );
      setInvitationRedemptionsNextCursor(result.next_cursor);
    } catch (err) {
      if (loadId === invitationRedemptionsLoadId.current) {
        setInvitationRedemptionsError(messageOr(err, "loadAuthorizationCodeRedemptionsFailed"));
      }
    } finally {
      if (loadId === invitationRedemptionsLoadId.current) setInvitationRedemptionsLoading(false);
    }
  }

  function openInvitationRedemptions(invitation: Invitation) {
    setRedemptionsInvitation(invitation);
    void loadInvitationRedemptions(invitation);
  }

  function closeInvitationRedemptions() {
    invitationRedemptionsLoadId.current += 1;
    setRedemptionsInvitation(null);
    setInvitationRedemptions([]);
    setInvitationRedemptionsNextCursor(null);
    setInvitationRedemptionsLoading(false);
    setInvitationRedemptionsError("");
  }

  async function saveRole(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = JSON.stringify({
        name: roleForm.name,
        description: roleForm.description || null,
        permissions: roleForm.permissions
      });
      if (roleForm.id) {
        await api<Role>(`/api/admin/access/roles/${roleForm.id}`, { method: "PUT", body });
      } else {
        await api<Role>("/api/admin/access/roles", { method: "POST", body });
      }
      setRoleForm(emptyRoleForm);
      setRoleFormBaseline(null);
      setEditor(null);
      setVerificationMessage(t("changesSaved"));
      await loadAdminData();
      if (selectedAccessUserId) await loadUserAccess(selectedAccessUserId);
    } catch (err) {
      setError(messageOr(err, "saveRoleFailed"));
    } finally {
      setBusy(false);
    }
  }

  function editRole(role: Role) {
    if (role.is_system) return;
    setRoleForm({
      id: role.id,
      name: role.name,
      description: role.description ?? "",
      permissions: role.permissions
    });
    setRoleFormBaseline({
      id: role.id,
      name: role.name,
      description: role.description ?? "",
      permissions: role.permissions
    });
  }

  async function deleteRole(id: string) {
    await api(`/api/admin/access/roles/${id}`, { method: "DELETE" });
    if (roleForm.id === id) {
      setRoleForm(emptyRoleForm);
      setRoleFormBaseline(null);
    }
    await loadAdminData();
    if (selectedAccessUserId) await loadUserAccess(selectedAccessUserId);
  }

  async function saveGroup(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = JSON.stringify({
        name: groupForm.name,
        description: groupForm.description || null
      });
      const group = groupForm.id
        ? await api<AccessGroup>(`/api/admin/access/groups/${groupForm.id}`, { method: "PUT", body })
        : await api<AccessGroup>("/api/admin/access/groups", { method: "POST", body });
      await api<AccessGroup>(`/api/admin/access/groups/${group.id}/roles`, {
        method: "PUT",
        body: JSON.stringify({ role_ids: groupForm.role_ids })
      });
      await api<AccessGroup>(`/api/admin/access/groups/${group.id}/members`, {
        method: "PUT",
        body: JSON.stringify({ user_ids: groupForm.user_ids })
      });
      setGroupForm(emptyGroupForm);
      setGroupFormBaseline(null);
      setEditor(null);
      setVerificationMessage(t("changesSaved"));
      await loadAdminData();
      if (selectedAccessUserId) await loadUserAccess(selectedAccessUserId);
    } catch (err) {
      setError(messageOr(err, "saveGroupFailed"));
    } finally {
      setBusy(false);
    }
  }

  function editGroup(group: AccessGroup) {
    setGroupForm({
      id: group.id,
      name: group.name,
      description: group.description ?? "",
      role_ids: (group.roles ?? []).map((role) => role.id),
      user_ids: (group.members ?? []).map((member) => member.id)
    });
    setGroupFormBaseline({
      id: group.id,
      name: group.name,
      description: group.description ?? "",
      role_ids: (group.roles ?? []).map((role) => role.id),
      user_ids: (group.members ?? []).map((member) => member.id)
    });
  }

  async function deleteGroup(id: string) {
    await api(`/api/admin/access/groups/${id}`, { method: "DELETE" });
    if (groupForm.id === id) {
      setGroupForm(emptyGroupForm);
      setGroupFormBaseline(null);
    }
    await loadAdminData();
    if (selectedAccessUserId) await loadUserAccess(selectedAccessUserId);
  }

  async function saveOrganization(event: FormEvent) {
    event.preventDefault();
    if (organizationMembersLoading) return;
    setBusy(true);
    setError("");
    try {
      const body = JSON.stringify({
        slug: organizationForm.slug,
        name: organizationForm.name,
        description: organizationForm.description || null,
        allowed_email_domains: splitList(organizationForm.allowed_email_domains).map(normalizeDomain),
        is_active: organizationForm.is_active
      });
      const organization = organizationForm.id
        ? await api<Organization>(`/api/admin/organizations/${organizationForm.id}`, { method: "PUT", body })
        : await api<Organization>("/api/admin/organizations", { method: "POST", body });
      await api<Organization>(`/api/admin/organizations/${organization.id}/members`, {
        method: "PUT",
        body: JSON.stringify({
          members: Object.entries(organizationMemberRoles).map(([user_id, role]) => ({ user_id, role }))
        })
      });
      organizationMembersLoadId.current += 1;
      setOrganizationForm(emptyOrganizationForm);
      setOrganizationFormBaseline(null);
      setOrganizationMemberRolesBaseline(null);
      setOrganizationMemberRoles({});
      setOrganizationMembersLoading(false);
      setEditor(null);
      setVerificationMessage(t("changesSaved"));
      await loadAdminData();
    } catch (err) {
      setError(messageOr(err, "saveOrganizationFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function editOrganization(organization: Organization) {
    const loadId = ++organizationMembersLoadId.current;
    const nextForm = {
      id: organization.id,
      slug: organization.slug,
      name: organization.name,
      description: organization.description ?? "",
      allowed_email_domains: organization.allowed_email_domains.join("\n"),
      is_active: organization.is_active
    };
    setOrganizationForm(nextForm);
    setOrganizationFormBaseline(nextForm);
    setOrganizationMemberRoles({});
    setOrganizationMemberRolesBaseline(null);
    setOrganizationMembersLoading(true);
    setEditor("organization");
    try {
      const members = await api<OrganizationMember[]>(`/api/admin/organizations/${organization.id}/members`);
      if (loadId !== organizationMembersLoadId.current) return;
      const nextRoles = Object.fromEntries(members.map((member) => [member.user_id, member.role]));
      setOrganizationMemberRoles(nextRoles);
      setOrganizationMemberRolesBaseline(nextRoles);
    } catch (err) {
      if (loadId === organizationMembersLoadId.current) {
        setError(messageOr(err, "loadFailed"));
      }
    } finally {
      if (loadId === organizationMembersLoadId.current) {
        setOrganizationMembersLoading(false);
      }
    }
  }

  function setOrganizationMemberRole(userId: string, role: string | null) {
    setOrganizationMemberRoles((current) => {
      const next = { ...current };
      if (role) {
        next[userId] = role;
      } else {
        delete next[userId];
      }
      return next;
    });
  }

  async function deleteOrganization(id: string) {
    await api(`/api/admin/organizations/${id}`, { method: "DELETE" });
    if (organizationForm.id === id) {
      organizationMembersLoadId.current += 1;
      setOrganizationForm(emptyOrganizationForm);
      setOrganizationFormBaseline(null);
      setOrganizationMemberRoles({});
      setOrganizationMemberRolesBaseline(null);
      setOrganizationMembersLoading(false);
    }
    await loadAdminData();
  }

  async function loadUserAccess(id: string) {
    setSelectedAccessUserId(id);
    setUserAccess(null);
    if (!id) {
      return;
    }
    setUserAccess(await api<UserAccess>(`/api/admin/users/${id}/access`));
  }

  async function saveUserRoles() {
    if (!selectedAccessUserId || !userAccess) return;
    const completed = await runUiAction(async () => {
      const updated = await api<UserAccess>(`/api/admin/users/${selectedAccessUserId}/roles`, {
        method: "PUT",
        body: JSON.stringify({ role_ids: userAccess.direct_roles.map((role) => role.id) })
      });
      setUserAccess(updated);
      await loadAdminData();
    });
    if (completed) setVerificationMessage(t("changesSaved"));
  }

  async function startTotpSetup() {
    setNewRecoveryCodes([]);
    setTotpSetupCode("");
    await runUiAction(async () => {
      setTotpSetup(await api<TotpSetup>("/api/mfa/totp", { method: "POST" }));
    }, "startMfaSetupFailed");
  }

  async function confirmTotpSetup() {
    if (!totpSetup) return;
    await runUiAction(async () => {
      const result = await api<MfaConfirmResponse>("/api/mfa/totp/confirm", {
        method: "POST",
        body: JSON.stringify({ setup_id: totpSetup.setup_id, code: totpSetupCode })
      });
      setMfaStatus(result.status);
      setNewRecoveryCodes(result.recovery_codes);
      setTotpSetup(null);
      setTotpSetupCode("");
      await loadAccountData();
    }, "confirmMfaSetupFailed");
  }

  async function rotateRecoveryCodes() {
    await runUiAction(async () => {
      const result = await api<MfaConfirmResponse>("/api/mfa/recovery-codes/rotate", { method: "POST" });
      setMfaStatus(result.status);
      setNewRecoveryCodes(result.recovery_codes);
      await loadAccountData();
    }, "rotateRecoveryCodesFailed");
  }

  async function disableMfa() {
    setError("");
    try {
      const result = await api<MfaStatus>("/api/mfa/totp", { method: "DELETE" });
      setMfaStatus(result);
      setTotpSetup(null);
      setNewRecoveryCodes([]);
      await loadAccountData();
    } catch (err) {
      const message = messageOr(err, "disableMfaFailed");
      setError(message);
      throw new Error(message);
    }
  }

  async function registerPasskey() {
    setBusy(true);
    setError("");
    try {
      if (!navigator.credentials?.create || !window.PublicKeyCredential) {
        throw new Error(t("registerPasskeyFailed"));
      }
      const start = await api<PasskeyRegistrationStart>("/api/passkeys/registration/start", {
        method: "POST",
        body: JSON.stringify({ name: passkeyName || null })
      });
      const credential = await navigator.credentials.create(passkeyCreationOptions(start.public_key));
      if (!credential || credential.type !== "public-key") {
        throw new Error(t("registerPasskeyFailed"));
      }
      const created = await api<Passkey>("/api/passkeys/registration/finish", {
        method: "POST",
        body: JSON.stringify({
          challenge_id: start.challenge_id,
          name: passkeyName || null,
          credential: registrationCredentialJson(credential as PublicKeyCredential)
        })
      });
      setPasskeys((current) => [created, ...current.filter((item) => item.id !== created.id)]);
      setPasskeyName("");
    } catch (err) {
      setError(messageOr(err, "registerPasskeyFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function deletePasskey(id: string) {
    setBusy(true);
    setError("");
    try {
      await api(`/api/passkeys/${encodeURIComponent(id)}`, { method: "DELETE" });
      setPasskeys((current) => current.filter((item) => item.id !== id));
    } catch (err) {
      const message = messageOr(err, "deletePasskeyFailed");
      setError(message);
      throw new Error(message);
    } finally {
      setBusy(false);
    }
  }

  async function revokeMyConsent(clientId: string) {
    setBusy(true);
    setError("");
    try {
      await api(`/api/me/consents/${encodeURIComponent(clientId)}`, { method: "DELETE" });
      await loadAccountData();
    } catch (err) {
      const message = messageOr(err, "revokeAuthorizationFailed");
      setError(message);
      throw new Error(message);
    } finally {
      setBusy(false);
    }
  }

  async function revokeMySession(sessionId: string) {
    setBusy(true);
    setError("");
    try {
      await api(`/api/me/sessions/${encodeURIComponent(sessionId)}`, { method: "DELETE" });
      await loadAccountData();
    } catch (err) {
      const message = messageOr(err, "revokeSessionFailed");
      setError(message);
      throw new Error(message);
    } finally {
      setBusy(false);
    }
  }

  async function resetUserMfa(id: string) {
    await api(`/api/admin/users/${id}/mfa/reset`, { method: "POST" });
    await loadAdminData();
  }

  async function saveSecurityPolicy(event: FormEvent) {
    event.preventDefault();
    if (!securityPolicy) return;
    setBusy(true);
    setError("");
    try {
      const updated = await api<SecurityPolicy>("/api/admin/security-policy", {
        method: "PUT",
        body: JSON.stringify({
          password_min_length: Number(securityPolicy.password_min_length),
          password_require_uppercase: Boolean(securityPolicy.password_require_uppercase),
          password_require_lowercase: Boolean(securityPolicy.password_require_lowercase),
          password_require_digit: Boolean(securityPolicy.password_require_digit),
          password_require_symbol: Boolean(securityPolicy.password_require_symbol),
          password_reject_user_info: Boolean(securityPolicy.password_reject_user_info),
          login_lockout_enabled: Boolean(securityPolicy.login_lockout_enabled),
          max_failed_login_attempts: Number(securityPolicy.max_failed_login_attempts),
          failure_window_seconds: Number(securityPolicy.failure_window_seconds),
          lockout_seconds: Number(securityPolicy.lockout_seconds),
          trusted_ip_cidrs: securityPolicy.trusted_ip_cidrs,
          require_mfa_outside_trusted_networks: securityPolicy.require_mfa_outside_trusted_networks,
          allowed_ip_cidrs: securityPolicy.allowed_ip_cidrs,
          blocked_ip_cidrs: securityPolicy.blocked_ip_cidrs,
          allowed_email_domains: securityPolicy.allowed_email_domains,
          blocked_email_domains: securityPolicy.blocked_email_domains,
          captcha_enabled: securityPolicy.captcha_enabled,
          captcha_after_failed_attempts: Number(securityPolicy.captcha_after_failed_attempts),
          captcha_ttl_seconds: Number(securityPolicy.captcha_ttl_seconds)
        })
      });
      setSecurityPolicy(updated);
      setSecurityPolicyBaseline(updated);
      setVerificationMessage(t("changesSaved"));
      await loadAdminData();
    } catch (err) {
      setError(messageOr(err, "saveSecurityPolicyFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function rotateSigningKey() {
    setBusy(true);
    setError("");
    try {
      await api<SigningKey>("/api/admin/signing-keys", {
        method: "POST",
        body: JSON.stringify({ kid: signingKeyKid.trim() || null })
      });
      setSigningKeyKid("");
      await loadAdminData();
    } catch (err) {
      const message = messageOr(err, "rotateSigningKeyFailed");
      setError(message);
      throw new Error(message);
    } finally {
      setBusy(false);
    }
  }

  async function saveRegistrationSettings(event: FormEvent) {
    event.preventDefault();
    if (!registrationSettings) return;
    setBusy(true);
    setError("");
    try {
      const updated = await api<RegistrationSettings>("/api/admin/registration-settings", {
        method: "PUT",
        body: JSON.stringify({
          ...registrationSettings
        })
      });
      setRegistrationSettings(updated);
      setRegistrationSettingsBaseline(updated);
      setVerificationMessage(t("changesSaved"));
      await loadBootstrap();
    } catch (err) {
      setError(messageOr(err, "saveRegistrationSettingsFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function saveRuntimeSettings(event: FormEvent) {
    event.preventDefault();
    if (!runtimeSettings) return;
    setBusy(true);
    setError("");
    try {
      const updated = await api<RuntimeSettings>("/api/admin/runtime-settings", {
        method: "PUT",
        body: JSON.stringify({
          public_base_url: runtimeSettings.public_base_url,
          issuer: runtimeSettings.issuer || runtimeSettings.public_base_url,
          trust_proxy_headers: runtimeSettings.trust_proxy_headers
        })
      });
      setRuntimeSettings(updated);
      setRuntimeSettingsBaseline(updated);
      setVerificationMessage(t("changesSaved"));
      await loadAdminData();
    } catch (err) {
      setError(messageOr(err, "saveRuntimeSettingsFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function persistLoginSettings(draft: LoginSettingsDraft): Promise<boolean> {
    setBusy(true);
    setError("");
    try {
      const updated = await api<LoginSettings>("/api/admin/login-settings", {
        method: "PUT",
        body: JSON.stringify({
          brand_logo_url: draft.brand_logo_url,
          email_domains: splitList(draft.email_domains).map(normalizeDomain),
          quick_links: draft.quick_links
        })
      });
      setLoginSettings(updated);
      setLoginSettingsDraft({
        brand_logo_url: updated.brand_logo_url,
        email_domains: updated.email_domains.join("\n"),
        quick_links: updated.quick_links
      });
      setLoginSettingsBaseline({
        brand_logo_url: updated.brand_logo_url,
        email_domains: updated.email_domains.join("\n"),
        quick_links: updated.quick_links
      });
      setVerificationMessage(t("changesSaved"));
      await loadBootstrap();
      return true;
    } catch (err) {
      setError(messageOr(err, "saveLoginSettingsFailed"));
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function saveLoginSettings(event: FormEvent) {
    event.preventDefault();
    await persistLoginSettings(loginSettingsDraft);
  }

  async function saveQuickLinkDraft() {
    if (!quickLinkForm.label.trim() || !quickLinkForm.url.trim()) return;
    const link: QuickLink = {
      id: quickLinkForm.id || createQuickLinkId(),
      label: quickLinkForm.label.trim(),
      url: quickLinkForm.url.trim(),
      // Kept for API compatibility. Quick links derive their visual icon from
      // the destination instead of relying on an application-side icon list.
      icon: "",
      is_active: quickLinkForm.is_active
    };
    const nextLinks = quickLinkForm.id
      ? loginSettingsDraft.quick_links.map((item) => (item.id === quickLinkForm.id ? link : item))
      : [...loginSettingsDraft.quick_links, link];
    const saved = await persistLoginSettings({ ...loginSettingsDraft, quick_links: nextLinks });
    if (saved) setQuickLinkForm(emptyQuickLinkForm);
  }

  function editQuickLink(link: QuickLink) {
    setQuickLinkForm({
      id: link.id,
      label: link.label,
      url: link.url,
      is_active: link.is_active
    });
  }

  async function removeQuickLink(id: string) {
    const saved = await persistLoginSettings({
      ...loginSettingsDraft,
      quick_links: loginSettingsDraft.quick_links.filter((item) => item.id !== id)
    });
    if (!saved) throw new Error(t("saveLoginSettingsFailed"));
    if (quickLinkForm.id === id) setQuickLinkForm(emptyQuickLinkForm);
  }

  function providerRedirectPath(slug: string): string {
    return `/api/register/oidc/${slug.trim() || "provider"}/callback`;
  }

  function applyProviderTemplate() {
    const template = providerTemplates.find((item) => item.id === providerTemplateId);
    if (!template) return;
    setProviderForm({
      ...providerForm,
      slug: template.slug,
      display_name: template.display_name,
      issuer: template.issuer,
      redirect_path: providerRedirectPath(template.slug),
      scopes: joinList(template.scopes)
    });
  }

  async function discoverProviderEndpoints() {
    if (!providerForm.issuer.trim()) return;
    setBusy(true);
    setError("");
    try {
      const discovered = await api<ExternalProviderDiscovery>("/api/admin/external-oidc-provider-discovery", {
        method: "POST",
        body: JSON.stringify({ issuer: providerForm.issuer })
      });
      setProviderForm({
        ...providerForm,
        issuer: discovered.issuer,
        authorization_endpoint: discovered.authorization_endpoint,
        token_endpoint: discovered.token_endpoint,
        userinfo_endpoint: discovered.userinfo_endpoint,
        scopes: joinList(discovered.scopes)
      });
    } catch (err) {
      setError(messageOr(err, "discoverProviderFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function saveProvider(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = JSON.stringify({
        slug: providerForm.slug,
        display_name: providerForm.display_name,
        organization_id: providerForm.organization_id || null,
        issuer: providerForm.issuer,
        client_id: providerForm.client_id,
        client_secret: providerForm.client_secret,
        clear_client_secret: providerForm.clear_client_secret,
        authorization_endpoint: providerForm.authorization_endpoint,
        token_endpoint: providerForm.token_endpoint,
        userinfo_endpoint: providerForm.userinfo_endpoint,
        redirect_path: providerForm.redirect_path,
        scopes: splitList(providerForm.scopes),
        email_domains: splitList(providerForm.email_domains).map(normalizeDomain),
        is_active: providerForm.is_active,
        allow_login: providerForm.allow_login,
        allow_registration: providerForm.allow_registration
      });
      if (providerForm.id) {
        await api<ExternalProvider>(`/api/admin/external-oidc-providers/${providerForm.id}`, {
          method: "PUT",
          body
        });
      } else {
        await api<ExternalProvider>("/api/admin/external-oidc-providers", { method: "POST", body });
      }
      setProviderForm(emptyProviderForm);
      setProviderFormBaseline(null);
      setEditor(null);
      setVerificationMessage(t("changesSaved"));
      await loadAdminData();
      await loadBootstrap();
    } catch (err) {
      setError(messageOr(err, "saveProviderFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function deleteProvider(id: string) {
    await api(`/api/admin/external-oidc-providers/${id}`, { method: "DELETE" });
    await loadAdminData();
    await loadBootstrap();
  }

  async function saveLdapProvider(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = JSON.stringify({
        slug: ldapProviderForm.slug,
        display_name: ldapProviderForm.display_name,
        organization_id: ldapProviderForm.organization_id || null,
        url: ldapProviderForm.url,
        starttls: ldapProviderForm.starttls,
        bind_dn: ldapProviderForm.bind_dn,
        bind_password: ldapProviderForm.bind_password || null,
        clear_bind_password: ldapProviderForm.clear_bind_password,
        base_dn: ldapProviderForm.base_dn,
        user_filter: ldapProviderForm.user_filter,
        user_id_attribute: ldapProviderForm.user_id_attribute,
        email_attribute: ldapProviderForm.email_attribute,
        username_attribute: ldapProviderForm.username_attribute,
        display_name_attribute: ldapProviderForm.display_name_attribute,
        phone_attribute: ldapProviderForm.phone_attribute,
        is_active: ldapProviderForm.is_active,
        allow_login: ldapProviderForm.allow_login,
        allow_registration: ldapProviderForm.allow_registration
      });
      if (ldapProviderForm.id) {
        await api<LdapProvider>(`/api/admin/ldap-providers/${ldapProviderForm.id}`, {
          method: "PUT",
          body
        });
      } else {
        await api<LdapProvider>("/api/admin/ldap-providers", { method: "POST", body });
      }
      setLdapProviderForm(emptyLdapProviderForm);
      setLdapProviderFormBaseline(null);
      setEditor(null);
      setVerificationMessage(t("changesSaved"));
      await loadAdminData();
      await loadBootstrap();
    } catch (err) {
      setError(messageOr(err, "saveLdapProviderFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function deleteLdapProvider(id: string) {
    await api(`/api/admin/ldap-providers/${id}`, { method: "DELETE" });
    await loadAdminData();
    await loadBootstrap();
  }

  function editLdapProvider(provider: LdapProvider) {
    const nextForm = {
                        id: provider.id,
                        slug: provider.slug,
                        display_name: provider.display_name,
                        organization_id: provider.organization_id ?? "",
                        url: provider.url,
      starttls: provider.starttls,
      bind_dn: provider.bind_dn,
      bind_password: "",
      clear_bind_password: false,
      base_dn: provider.base_dn,
      user_filter: provider.user_filter,
      user_id_attribute: provider.user_id_attribute,
      email_attribute: provider.email_attribute,
      username_attribute: provider.username_attribute,
      display_name_attribute: provider.display_name_attribute,
      phone_attribute: provider.phone_attribute,
      is_active: provider.is_active,
      allow_login: provider.allow_login,
      allow_registration: provider.allow_registration
    };
    setLdapProviderForm(nextForm);
    setLdapProviderFormBaseline(nextForm);
    setEditor("ldap");
  }

  async function saveAuditWebhook(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = JSON.stringify({
        name: auditWebhookForm.name,
        url: auditWebhookForm.url,
        secret: auditWebhookForm.secret || null,
        clear_secret: auditWebhookForm.clear_secret,
        actions: splitList(auditWebhookForm.actions),
        is_active: auditWebhookForm.is_active,
        timeout_seconds: Number(auditWebhookForm.timeout_seconds)
      });
      if (auditWebhookForm.id) {
        await api<AuditWebhook>(`/api/admin/audit-webhooks/${auditWebhookForm.id}`, {
          method: "PUT",
          body
        });
      } else {
        await api<AuditWebhook>("/api/admin/audit-webhooks", { method: "POST", body });
      }
      setAuditWebhookForm(emptyAuditWebhookForm);
      setAuditWebhookFormBaseline(emptyAuditWebhookForm);
      setVerificationMessage(t("changesSaved"));
      await loadAdminData();
    } catch (err) {
      setError(messageOr(err, "saveAuditWebhookFailed"));
    } finally {
      setBusy(false);
    }
  }

  function editAuditWebhook(webhook: AuditWebhook) {
    const nextForm = {
      id: webhook.id,
      name: webhook.name,
      url: webhook.url,
      secret: "",
      clear_secret: false,
      actions: webhook.actions.join("\n"),
      is_active: webhook.is_active,
      timeout_seconds: webhook.timeout_seconds
    };
    setAuditWebhookForm(nextForm);
    setAuditWebhookFormBaseline(nextForm);
  }

  async function deleteAuditWebhook(id: string) {
    await api(`/api/admin/audit-webhooks/${id}`, { method: "DELETE" });
    setAuditWebhookForm((current) => (current.id === id ? emptyAuditWebhookForm : current));
    setAuditWebhookFormBaseline((current) => (current.id === id ? emptyAuditWebhookForm : current));
    await loadAdminData();
  }

  async function refreshCurrentTab() {
    setError("");
    setRefreshing(true);
    try {
      if (tab === "account" || tab === "billing") {
        await loadAccountData();
      } else {
        await loadAdminData(tab, { force: true });
      }
      setVerificationMessage(t("operationCompleted"));
    } catch (err) {
      setError(messageOr(err, "refreshFailed"));
    } finally {
      setRefreshing(false);
    }
  }

  async function switchEnterprise(organizationId: string) {
    if (!organizationId || organizationId === organizationContext?.id) return;
    if (configurationFormsDirty() && !window.confirm(`${t("unsavedChanges")}\n${t("discardChanges")}?`)) {
      return;
    }
    setBusy(true);
    setError("");
    try {
      const next = await api<OrganizationContext>("/api/me/organization-context", {
        method: "PUT",
        body: JSON.stringify({ organization_id: organizationId })
      });
      setOrganizationContext(next.organization);
      setApiCacheScope(`${user?.id ?? "anonymous"}:${next.organization?.id ?? "none"}`);
      setApplications([]);
      setClients([]);
      setOrganizationMembers([]);
      setVerificationMessage(t("operationCompleted"));
    } catch (err) {
      setError(messageOr(err, "operationFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function saveEnterprise(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api<Organization>("/api/me/organizations", {
        method: "POST",
        body: JSON.stringify({
          slug: enterpriseForm.slug,
          name: enterpriseForm.name,
          description: enterpriseForm.description || null,
          allowed_email_domains: splitList(enterpriseForm.allowed_email_domains).map(normalizeDomain)
        })
      });
      setEnterpriseForm(emptyEnterpriseForm);
      setEnterpriseFormBaseline(null);
      setEditor(null);
      await loadEnterpriseContext(user?.id);
      setVerificationMessage(t("changesSaved"));
      navigateToTab("applications");
    } catch (err) {
      setError(messageOr(err, "saveOrganizationFailed"));
    } finally {
      setBusy(false);
    }
  }

  function navigateToTab(
    next: Tab,
    options: { applicationId?: string | null; applicationSection?: ApplicationSection | null } = {}
  ) {
    if (next !== tab && configurationFormsDirty() && !window.confirm(`${t("unsavedChanges")}\n${t("discardChanges")}?`)) {
      return;
    }
    setTab(next);
    setSearchQuery("");
    setSidebarOpen(false);
    const applicationId = next === "applications"
      ? options.applicationId ?? applicationNavigationId
      : null;
    const applicationSection = next === "applications"
      ? options.applicationSection ?? applicationNavigationSection
      : null;
    const billingOrder = next === "billing" ? billingOrderReference : null;
    setApplicationNavigationId(applicationId);
    setApplicationNavigationSection(applicationSection);
    setBillingOrderReference(billingOrder);
    const params = new URLSearchParams();
    if (applicationId) params.set("application", applicationId);
    if (applicationSection) params.set("section", applicationSection);
    if (billingOrder) params.set("billing_order", billingOrder);
    const query = params.toString();
    const nextHash = `#/${next}${query ? `?${query}` : ""}`;
    if (window.location.hash !== nextHash) {
      window.history.pushState(null, "", nextHash);
    }
  }

  function clientDraftIsDirty(): boolean {
    return clientFormBaseline !== null
      && JSON.stringify(clientForm) !== JSON.stringify(clientFormBaseline);
  }

  function providerFormIsDirty(): boolean {
    return providerFormBaseline !== null
      && JSON.stringify(providerForm) !== JSON.stringify(providerFormBaseline);
  }

  function ldapProviderFormIsDirty(): boolean {
    return ldapProviderFormBaseline !== null
      && JSON.stringify(ldapProviderForm) !== JSON.stringify(ldapProviderFormBaseline);
  }

  function auditWebhookFormIsDirty(): boolean {
    return JSON.stringify(auditWebhookForm) !== JSON.stringify(auditWebhookFormBaseline);
  }

  function registrationSettingsIsDirty(): boolean {
    return registrationSettingsBaseline !== null
      && registrationSettings !== null
      && JSON.stringify(registrationSettings) !== JSON.stringify(registrationSettingsBaseline);
  }

  function runtimeSettingsIsDirty(): boolean {
    return runtimeSettingsBaseline !== null
      && runtimeSettings !== null
      && JSON.stringify(runtimeSettings) !== JSON.stringify(runtimeSettingsBaseline);
  }

  function loginSettingsIsDirty(): boolean {
    return loginSettingsBaseline !== null
      && JSON.stringify(loginSettingsDraft) !== JSON.stringify(loginSettingsBaseline);
  }

  function applicationFormIsDirty(): boolean {
    return applicationFormBaseline !== null
      && JSON.stringify(applicationForm) !== JSON.stringify(applicationFormBaseline);
  }

  function securityPolicyIsDirty(): boolean {
    return securityPolicyBaseline !== null
      && securityPolicy !== null
      && JSON.stringify(securityPolicy) !== JSON.stringify(securityPolicyBaseline);
  }

  function userFormIsDirty(): boolean {
    return userFormBaseline !== null
      && JSON.stringify(userForm) !== JSON.stringify(userFormBaseline);
  }

  function enterpriseFormIsDirty(): boolean {
    return enterpriseFormBaseline !== null
      && JSON.stringify(enterpriseForm) !== JSON.stringify(enterpriseFormBaseline);
  }

  function iapApplicationFormIsDirty(): boolean {
    return iapApplicationFormBaseline !== null
      && JSON.stringify(iapApplicationForm) !== JSON.stringify(iapApplicationFormBaseline);
  }

  function invitationFormIsDirty(): boolean {
    return invitationFormBaseline !== null
      && JSON.stringify(invitationForm) !== JSON.stringify(invitationFormBaseline);
  }

  function roleFormIsDirty(): boolean {
    return roleFormBaseline !== null
      && JSON.stringify(roleForm) !== JSON.stringify(roleFormBaseline);
  }

  function groupFormIsDirty(): boolean {
    return groupFormBaseline !== null
      && JSON.stringify(groupForm) !== JSON.stringify(groupFormBaseline);
  }

  function organizationFormIsDirty(): boolean {
    const formDirty = organizationFormBaseline !== null
      && JSON.stringify(organizationForm) !== JSON.stringify(organizationFormBaseline);
    const membersDirty = organizationMemberRolesBaseline !== null
      && JSON.stringify(organizationMemberRoles) !== JSON.stringify(organizationMemberRolesBaseline);
    return formDirty || membersDirty;
  }

  function configurationFormsDirty(): boolean {
    return applicationWorkspaceDirty
      || userFormIsDirty()
      || enterpriseFormIsDirty()
      || organizationFormIsDirty()
      || clientDraftIsDirty()
      || providerFormIsDirty()
      || ldapProviderFormIsDirty()
      || applicationFormIsDirty()
      || iapApplicationFormIsDirty()
      || invitationFormIsDirty()
      || roleFormIsDirty()
      || groupFormIsDirty()
      || auditWebhookFormIsDirty()
      || registrationSettingsIsDirty()
      || runtimeSettingsIsDirty()
      || loginSettingsIsDirty()
      || securityPolicyIsDirty();
  }

  function openClientEditor(next: typeof emptyClientForm) {
    setClientForm(next);
    setClientFormBaseline(next);
    setClientFormErrors([]);
    setClientFieldErrors({});
    setError("");
    setEditor("client");
  }

  function closeEditor(force = false): boolean {
    const editorDirty = editor === "client"
      ? clientDraftIsDirty()
      : editor === "application"
        ? applicationFormIsDirty()
      : editor === "user"
        ? userFormIsDirty()
      : editor === "enterprise"
        ? enterpriseFormIsDirty()
      : editor === "organization"
        ? organizationFormIsDirty()
      : editor === "iap"
        ? iapApplicationFormIsDirty()
      : editor === "invitation"
        ? invitationFormIsDirty()
      : editor === "role"
        ? roleFormIsDirty()
      : editor === "group"
        ? groupFormIsDirty()
      : editor === "provider"
        ? providerFormIsDirty()
        : editor === "ldap"
          ? ldapProviderFormIsDirty()
          : false;
    if (!force && editorDirty && !window.confirm(`${t("unsavedChanges")}\n${t("discardChanges")}?`)) {
      return false;
    }
    if (editor === "organization") {
      organizationMembersLoadId.current += 1;
      setOrganizationMembersLoading(false);
    }
    if (editor === "client") {
      setClientFormBaseline(null);
      setClientFormErrors([]);
      setClientFieldErrors({});
    }
    if (editor === "user") {
      setUserForm(emptyUserForm);
      setUserFormBaseline(null);
    }
    if (editor === "enterprise") {
      setEnterpriseForm(emptyEnterpriseForm);
      setEnterpriseFormBaseline(null);
    }
    if (editor === "organization") {
      setOrganizationForm(emptyOrganizationForm);
      setOrganizationFormBaseline(null);
      setOrganizationMemberRoles({});
      setOrganizationMemberRolesBaseline(null);
    }
    if (editor === "application") {
      setApplicationForm(emptyApplicationForm);
      setApplicationFormBaseline(null);
    }
    if (editor === "provider") {
      setProviderForm(emptyProviderForm);
      setProviderFormBaseline(null);
      setProviderTemplateId("");
    }
    if (editor === "ldap") {
      setLdapProviderForm(emptyLdapProviderForm);
      setLdapProviderFormBaseline(null);
    }
    if (editor === "iap") {
      setIapApplicationForm(emptyIapApplicationForm);
      setIapApplicationFormBaseline(null);
    }
    if (editor === "invitation") {
      setInvitationForm(emptyInvitationForm);
      setInvitationFormBaseline(null);
      setLastInvitationCode("");
    }
    if (editor === "role") {
      setRoleForm(emptyRoleForm);
      setRoleFormBaseline(null);
    }
    if (editor === "group") {
      setGroupForm(emptyGroupForm);
      setGroupFormBaseline(null);
    }
    setEditor(null);
    setError("");
    return true;
  }

  function requestConfirmation(
    action: () => Promise<void> | void,
    title = t("confirmAction"),
    description = t("confirmActionDescription")
  ) {
    setError("");
    setPendingConfirmation({ action, title, description });
  }

  async function runPendingConfirmation() {
    if (!pendingConfirmation) return;
    setBusy(true);
    setError("");
    try {
      await pendingConfirmation.action();
      setPendingConfirmation(null);
      setVerificationMessage(t("operationCompleted"));
    } catch (err) {
      setError(messageOr(err, "operationFailed"));
    } finally {
      setBusy(false);
    }
  }

  const tabs = useMemo(
    () => {
      const accountTab = { id: "account" as const, label: t("account"), icon: UserRound };
      const billingTab = user && !isRestrictedLoginCodeSession
        ? { id: "billing" as const, label: t("billing"), icon: Coins }
        : null;
      const adminTabs = [
        hasGlobalConsolePermission ? { id: "overview" as const, label: t("overview"), icon: Shield } : null,
        canReadUsers ? { id: "users" as const, label: t("users"), icon: Users } : null,
        canManageActiveOrganization ? { id: "applications" as const, label: t("applications"), icon: Building2 } : null,
        canReadClients ? { id: "clients" as const, label: t("clients"), icon: KeyRound } : null,
        canReadIap ? { id: "iap" as const, label: t("iap"), icon: Shield } : null,
        canReadOrganizations ? { id: "organizations" as const, label: t("organizations"), icon: Building2 } : null,
        canManageAuthorizationCodes ? { id: "invitations" as const, label: t("invitations"), icon: Ticket } : null,
        canManageSettings ? { id: "registration" as const, label: t("registration"), icon: UserRound } : null,
        canManageProviders ? { id: "providers" as const, label: t("providers"), icon: Link2 } : null,
        canManageSettings ? { id: "portal" as const, label: t("portal"), icon: AtSign } : null,
        (canManageSecurity || canReadAudit) ? { id: "security" as const, label: t("security"), icon: Shield } : null,
        canManageSettings ? { id: "settings" as const, label: t("settings"), icon: Settings } : null
      ].filter((item): item is NonNullable<typeof item> => Boolean(item));
      return canAdmin
        ? [accountTab, ...(billingTab ? [billingTab] : []), ...adminTabs]
        : [accountTab, ...(billingTab ? [billingTab] : [])];
    },
    [
      locale,
      canAdmin,
      hasGlobalConsolePermission,
      canReadUsers,
      canManageActiveOrganization,
      canReadClients,
      canReadIap,
      canReadOrganizations,
      canManageAuthorizationCodes,
      canManageSettings,
      canManageProviders,
      canManageSecurity,
      canReadAudit,
      user,
      isRestrictedLoginCodeSession
    ]
  );

  const navigationGroups = useMemo(() => {
    const groups = [
      {
        id: "workspace",
        label: t("navWorkspace"),
        hint: t("navWorkspaceHint"),
        ids: ["overview", "billing"] as Tab[]
      },
      {
        id: "directory",
        label: t("navDirectory"),
        hint: t("navDirectoryHint"),
        ids: ["users", "organizations", "invitations"] as Tab[]
      },
      {
        id: "applications",
        label: t("navApplications"),
        hint: t("navApplicationsHint"),
        ids: ["applications", "clients", "iap"] as Tab[]
      },
      {
        id: "access",
        label: t("navAccess"),
        hint: t("navAccessHint"),
        ids: ["registration", "providers", "portal", "security", "settings"] as Tab[]
      }
    ];
    return groups
      .map((group) => ({
        ...group,
        items: group.ids
          .map((id) => tabs.find((item) => item.id === id))
          .filter((item): item is (typeof tabs)[number] => Boolean(item))
      }))
      .filter((group) => group.items.length > 0);
  }, [locale, tabs]);

  const activeNavigationGroup = navigationGroups.find((group) => group.items.some((item) => item.id === tab));

  useEffect(() => {
    if (!user || !enterpriseContextReady) return;
    if (!tabs.some((item) => item.id === tab)) {
      navigateToTab("account");
    }
  }, [enterpriseContextReady, tab, tabs, user]);

  useEffect(() => {
    if (!configurationFormsDirty()) return;
    const handleBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [
    applicationWorkspaceDirty,
    userForm,
    userFormBaseline,
    enterpriseForm,
    enterpriseFormBaseline,
    organizationForm,
    organizationFormBaseline,
    organizationMemberRoles,
    organizationMemberRolesBaseline,
    clientForm,
    clientFormBaseline,
    providerForm,
    providerFormBaseline,
    ldapProviderForm,
    ldapProviderFormBaseline,
    auditWebhookForm,
    auditWebhookFormBaseline,
    iapApplicationForm,
    iapApplicationFormBaseline,
    invitationForm,
    invitationFormBaseline,
    roleForm,
    roleFormBaseline,
    groupForm,
    groupFormBaseline,
    registrationSettings,
    registrationSettingsBaseline,
    runtimeSettings,
    runtimeSettingsBaseline,
    loginSettingsDraft,
    loginSettingsBaseline,
    securityPolicy,
    securityPolicyBaseline
  ]);

  useEffect(() => {
    const authenticated = Boolean(
      user
      && !authAccountSwitch
      && !(authReturnTo && initialAuth.forceLogin)
      && !initialAuth.isAuthPage
      && !initialAuth.selectAccount
    );
    const label = initialAuth.selectAccount && !accountLoginExpanded
      ? t("selectAccount")
      : authenticated
      ? tabs.find((item) => item.id === tab)?.label
      : authMode === "register"
        ? t("register")
        : authMode === "reset"
          ? t("resetPassword")
          : t("signIn");
    document.title = label ? `${label} · Signet` : "Signet";
  }, [accountLoginExpanded, authAccountSwitch, authMode, authReturnTo, initialAuth.forceLogin, initialAuth.isAuthPage, initialAuth.selectAccount, locale, tab, tabs, user]);

  const normalizedSearchQuery = searchQuery.trim().toLocaleLowerCase();
  const normalizedUserEmailFilter = userEmailFilter.trim().toLocaleLowerCase();
  const normalizedUserPhoneFilter = userPhoneFilter.trim().toLocaleLowerCase();
  const userRegistrationFromTimestamp = toTimestamp(userRegistrationFrom);
  const userRegistrationToTimestamp = timestampAtDayEnd(userRegistrationTo);
  const userLastLoginFromTimestamp = toTimestamp(userLastLoginFrom);
  const userLastLoginToTimestamp = timestampAtDayEnd(userLastLoginTo);
  const filteredUsers = users.filter((item) => {
    if (!matchesSearch(
      normalizedSearchQuery,
      item.email,
      item.username,
      item.display_name,
      item.phone
    )) return false;
    if (normalizedUserEmailFilter && !item.email.toLocaleLowerCase().includes(normalizedUserEmailFilter)) return false;
    if (normalizedUserPhoneFilter && !(item.phone ?? "").toLocaleLowerCase().includes(normalizedUserPhoneFilter)) return false;
    if (userRoleFilter === "admin" && !item.is_admin) return false;
    if (userRoleFilter === "user" && item.is_admin) return false;
    if (userRegistrationFromTimestamp !== null && item.created_at < userRegistrationFromTimestamp) return false;
    if (userRegistrationToTimestamp !== null && item.created_at >= userRegistrationToTimestamp) return false;
    if (userLastLoginFromTimestamp !== null && (!item.last_login_at || item.last_login_at < userLastLoginFromTimestamp)) return false;
    if (userLastLoginToTimestamp !== null && (!item.last_login_at || item.last_login_at >= userLastLoginToTimestamp)) return false;
    if (userLoginRegionFilter === "all") return true;
    if (!item.last_login_ip) return false;
    return userLoginRegionFilter === "domestic"
      ? isDomesticLoginIp(item.last_login_ip)
      : !isDomesticLoginIp(item.last_login_ip);
  });
  const selectedUserIdSet = new Set(selectedUserIds);
  const allVisibleUsersSelected = filteredUsers.length > 0 && filteredUsers.every((item) => selectedUserIdSet.has(item.id));
  const filteredClients = clients.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.client_id,
    item.client_name,
    item.organization_name,
    item.scopes.join(" ")
  ));
  const applicationByOidcClientId = new Map(
    applications.flatMap((application) =>
      application.client_bindings.map((binding) => [binding.id, application] as const)
    )
  );
  const filteredIapApplications = iapApplications.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.name,
    item.slug,
    item.external_host,
    item.description
  ));
  const filteredOrganizations = organizations.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.name,
    item.slug,
    item.description,
    item.allowed_email_domains.join(" ")
  ));
  const filteredInvitations = invitations.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.code_type,
    item.login_code_level,
    item.allowed_client_ids?.join(" "),
    item.organization_id,
    item.organization_role,
    item.code_prefix,
    item.description,
    item.authorized_email,
    item.authorized_username
  ));
  const filteredProviders = providers.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.display_name,
    item.slug,
    item.issuer,
    item.email_domains.join(" ")
  ));
  const filteredLdapProviders = ldapProviders.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.display_name,
    item.slug,
    item.url,
    item.base_dn
  ));
  const filteredRoles = roles.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.name,
    item.description,
    item.permissions.join(" ")
  ));
  const filteredGroups = groups.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.name,
    item.description
  ));
  const filteredAuditWebhooks = auditWebhooks.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.name,
    item.url,
    item.actions.join(" "),
    item.last_error
  ));
  const filteredAuditEvents = auditEvents.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.action,
    item.target_kind,
    item.target_id,
    item.actor_user_id,
    item.actor_client_id,
    item.details
  ));
  const searchableTabs: Tab[] = [
    "users",
    "applications",
    "clients",
    "iap",
    "organizations",
    "invitations",
    "providers",
    "security"
  ];
  const searchEnabled = searchableTabs.includes(tab);
  const activeUserCount = overview?.active_users ?? 0;
  const totalUserCount = overview?.users ?? 0;
  const activeClientCount = overview?.active_clients ?? 0;
  const totalClientCount = overview?.clients ?? 0;
  const activeUserRate = totalUserCount > 0 ? Math.round((activeUserCount / totalUserCount) * 100) : 0;
  const activeClientRate = totalClientCount > 0 ? Math.round((activeClientCount / totalClientCount) * 100) : 0;
  const selectedManagedUsers = users.filter((item) => selectedUserIdSet.has(item.id));
  const selectedUsersAreCurrent = selectedManagedUsers.length === selectedUserIds.length;
  const selectedLifecycleState = selectedManagedUsers.length > 0
    ? lifecycleStateForUser(selectedManagedUsers[0])
    : null;
  const selectedUsersShareLifecycleState = Boolean(
    selectedUsersAreCurrent
    && selectedLifecycleState
    && selectedManagedUsers.every((item) => lifecycleStateForUser(item) === selectedLifecycleState)
  );
  const sharedLifecycleBulkActions: BulkUserAction[] = selectedUsersShareLifecycleState
    ? selectedManagedUsers.reduce<BulkUserAction[] | null>((shared, item) => {
      if (!shared) return null;
      const available = availableUserActions(item, user?.id);
      return shared.filter((action) => action !== "reset_mfa" && available.includes(action));
    }, availableUserActions(selectedManagedUsers[0], user?.id).filter((action) => action !== "reset_mfa")) ?? []
    : [];
  // MFA reset is not a lifecycle transition. It remains available for any
  // selection whose individual row actions all expose it (active/disabled),
  // while lifecycle buttons themselves remain hidden for mixed selections.
  const canBulkResetMfa = selectedUsersAreCurrent
    && selectedManagedUsers.length > 0
    && selectedManagedUsers.every((item) => availableUserActions(item, user?.id).includes("reset_mfa"));
  const availableBulkUserActions: BulkUserAction[] = [
    ...sharedLifecycleBulkActions,
    ...(canBulkResetMfa ? ["reset_mfa" as const] : [])
  ];

  function resetUserFilters() {
    setUserFilter("live");
    setUserOrganizationFilter("");
    setUserFiltersExpanded(false);
    setUserEmailFilter("");
    setUserRoleFilter("all");
    setUserRegistrationFrom("");
    setUserRegistrationTo("");
    setUserLastLoginFrom("");
    setUserLastLoginTo("");
    setUserPhoneFilter("");
    setUserLoginRegionFilter("all");
    setUserLinkedIdentityFilter("all");
    setSelectedUserIds([]);
  }

  function toggleUserSelection(id: string) {
    setSelectedUserIds((current) => current.includes(id)
      ? current.filter((item) => item !== id)
      : [...current, id]);
  }

  function toggleVisibleUserSelection(selected: boolean) {
    const visibleIds = filteredUsers.map((item) => item.id);
    setSelectedUserIds((current) => selected
      ? [...new Set([...current, ...visibleIds])]
      : current.filter((id) => !visibleIds.includes(id)));
  }

  function bulkUserActionTitle(action: BulkUserAction): string {
    switch (action) {
      case "enable": return t("bulkEnable");
      case "disable": return t("bulkDisable");
      case "archive": return t("bulkArchive");
      case "delete": return t("bulkDelete");
      case "reset_mfa": return t("bulkResetMfa");
    }
  }

  function requestBulkUserAction(action: BulkUserAction) {
    if (!availableBulkUserActions.includes(action)) return;
    const targetIds = selectedManagedUsers.map((item) => item.id);
    if (targetIds.length === 0 || targetIds.length !== selectedUserIds.length) return;
    const title = bulkUserActionTitle(action);
    requestConfirmation(async () => {
      for (const id of targetIds) {
        const path = action === "enable"
          ? `/api/admin/users/${id}/enable`
          : action === "reset_mfa"
            ? `/api/admin/users/${id}/mfa/reset`
            : `/api/admin/users/${id}`;
        await api(path, { method: action === "enable" || action === "reset_mfa" ? "POST" : "DELETE" });
      }
      setSelectedUserIds((current) => current.filter((id) => !targetIds.includes(id)));
      await loadAdminData("users");
      setVerificationMessage(t("bulkActionCompleted"));
    }, title);
  }

  if (initialLoadError) {
    return (
      <main className="load-error" role="alert">
        <Shield size={34} />
        <h1>Signet</h1>
        <p>{initialLoadError}</p>
        <button type="button" className="primary compact-action" onClick={() => void initialize()}>
          <RefreshCw size={16} />{t("retry")}
        </button>
      </main>
    );
  }

  if (user === undefined || !bootstrap) {
    return <div className="loading" role="status" aria-live="polite"><span className="loading-spinner" aria-hidden="true" />{t("loading")}</div>;
  }

  if (authCanCompleteWithCurrentUser) {
    return <div className="loading" role="status" aria-live="polite"><span className="loading-spinner" aria-hidden="true" />{t("loading")}</div>;
  }

  const hasRegistrationAuthorizationCode = Boolean(registerForm.authorization_code.trim());
  const registrationCodeMode = registrationCodeInspection?.mode;
  const registrationCodeRequired = bootstrap.has_users
    && authMode === "register"
    && bootstrap.registration.require_invitation;
  // An application can require its own enrollment code even while platform
  // registration remains open. OIDC return context is the safe signal to
  // offer a code field without making an app policy a browser-controlled
  // value.
  const registrationCodeVisible = registrationCodeRequired || Boolean(authReturnTo);
  const isTrialEnrollmentRegistration = registrationCodeMode === "trial_enrollment";
  const registrationCodeAccepted = registrationCodeMode === "registration"
    || registrationCodeMode === "trial_enrollment";
  const registrationFieldsVisible = !isTrialEnrollmentRegistration
    && (!registrationCodeRequired || registrationCodeAccepted);
  const registrationCodeBlocksSubmit = registrationCodeRequired
    && (!hasRegistrationAuthorizationCode || registrationCodeInspecting || !registrationCodeAccepted);
  const registrationCodeHint = registrationCodeInspecting
    ? t("authorizationCodeChecking")
    : registrationCodeMode === "trial_enrollment"
      ? t("authorizationCodeTrialHint")
      : registrationCodeMode === "registration"
        ? registrationCodeInspection?.email_requirement === "must_match_code"
          ? t("authorizationCodeBoundEmailHint")
          : t("authorizationCodeRegistrationHint")
        : registrationCodeMode === "sign_in_only"
          ? t("authorizationCodeSignInHint")
          : registrationCodeMode === "unavailable"
            ? t("authorizationCodeUnavailableHint")
            : "";
  const passwordRegistrationUnavailable =
    bootstrap.has_users
    && authMode === "register"
    && !registrationCodeRequired
    && !bootstrap.registration.allow_password_registration
    && !hasRegistrationAuthorizationCode;
  const loginExternalProviders = bootstrap.external_oidc_providers.filter((provider) => provider.allow_login);
  const registerExternalProviders = bootstrap.external_oidc_providers.filter((provider) => provider.allow_registration);
  const visibleExternalProviders =
    authMode === "register" || !bootstrap.has_users
        ? registerExternalProviders
        : authMode === "login"
          ? loginExternalProviders
          : [];
  const loginDomainProvider = findProviderForEmail(loginExternalProviders, authEmail);
  const registerDomainProvider = findProviderForEmail(registerExternalProviders, authEmail);
  const hasExternalProviderRow = authFormsVisible
    && authMode !== "reset"
    && visibleExternalProviders.length > 0;
  const unifiedAuthTitle = !bootstrap.has_users
    ? t("firstAdmin")
    : t("loginOrRegisterAccount");

  if (!user || authAccountSwitch || initialAuth.isAuthPage || initialAuth.selectAccount || (authReturnTo && initialAuth.forceLogin)) {
    return (
      <main className="unified-auth-page">
        <header className="unified-auth-header">
          <div className="unified-auth-header-brand" aria-label="Signet">
            <span className="auth-logo auth-product-logo" aria-hidden="true">
              <Shield size={18} />
              {bootstrap.login.brand_logo_url && (
                <img
                  src={bootstrap.login.brand_logo_url}
                  alt=""
                  referrerPolicy="no-referrer"
                  onLoad={(event) => { event.currentTarget.dataset.loaded = "true"; }}
                  onError={(event) => { event.currentTarget.hidden = true; }}
                />
              )}
            </span>
            <span>Signet</span>
            {browserAccountsContext?.client_name && (
              <>
                <span className="unified-auth-logo-separator" aria-hidden="true" />
                <span
                  className="auth-logo auth-client-logo"
                  role="img"
                  aria-label={browserAccountsContext.client_name}
                  title={browserAccountsContext.client_name}
                >
                  <Globe2 size={18} aria-hidden="true" />
                  {browserAccountsContext.client_logo_uri && (
                    <img
                      src={browserAccountsContext.client_logo_uri}
                      alt=""
                      referrerPolicy="no-referrer"
                      onLoad={(event) => { event.currentTarget.dataset.loaded = "true"; }}
                      onError={(event) => { event.currentTarget.hidden = true; }}
                    />
                  )}
                </span>
              </>
            )}
          </div>
          <div className="auth-toolbar">
            <TopLanguage locale={locale} supportedLocales={bootstrap.supported_locales} switchLocale={switchLocale} label={t("language")} />
            <button
              className="icon-button"
              type="button"
              onClick={() => setTheme((current) => current === "dark" ? "light" : "dark")}
              title={theme === "dark" ? t("lightMode") : t("darkMode")}
              aria-label={theme === "dark" ? t("lightMode") : t("darkMode")}
            >
              {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
            </button>
          </div>
        </header>
        <section className={`unified-auth-main${authFormsVisible ? " auth-form-mode" : ""}`}>
          <div className="unified-auth-content">
          <section className="unified-auth-title">
            <h1 ref={authModeHeadingRef} tabIndex={-1}>{unifiedAuthTitle}</h1>
          </section>
          {error && <div className="error" role="alert">{error}</div>}
          {authAccountSwitch && <div className="info">{t("authAccountSwitch")}</div>}
          {verificationMessage && <div className="info" role="status" aria-live="polite">{verificationMessage}</div>}
          {!authFormsVisible && selectedBrowserAccount && (
            <section className="unified-auth-selection" aria-label={`${t("useAccount")}: ${selectedBrowserAccount.user.email}`}>
              <span className="account-switcher-avatar" aria-hidden="true">
                {browserAccountShortName(selectedBrowserAccount).slice(0, 1).toLocaleUpperCase()}
              </span>
              {browserAccountsContext?.client_name && (
                <p>{t("selectAccountForApplication")} · {browserAccountsContext.client_name}</p>
              )}
              <h2>{browserAccountShortName(selectedBrowserAccount)}</h2>
              <p className="unified-auth-selection-email">{selectedBrowserAccount.user.email}</p>
              <div className="unified-auth-selection-meta">
                {selectedBrowserAccount.current && (
                  <StatusBadge tone="success">{t("currentAccount")}</StatusBadge>
                )}
                {(selectedBrowserAccount.session_kind === "trial_enrollment"
                  || selectedBrowserAccount.user.login_code_level === "trial_enrollment") && (
                  <StatusBadge tone="warning">{t("trialEnrollmentSessionBadge")}</StatusBadge>
                )}
                {(selectedBrowserAccount.session_kind === "temporary_authorization_code"
                  || selectedBrowserAccount.user.login_code_level === "account_recovery") && (
                  <StatusBadge tone="warning">{t("temporaryRecoverySessionBadge")}</StatusBadge>
                )}
                <small>{t("lastLogin")}: {formatTime(selectedBrowserAccount.last_login_at, locale)}</small>
              </div>
              <div className="unified-auth-selection-actions">
                <button
                  className="primary"
                  type="button"
                  disabled={browserAccountContinuing || !continueWithBrowserAccount}
                  onClick={() => void continueSelectedBrowserAccount()}
                >
                  <KeyRound size={16} />
                  {browserAccountContinuing ? t("loading") : t("signIn")}
                </button>
              </div>
            </section>
          )}
          {authFormsVisible && (
            <div className="unified-auth-forms">
              {hasExternalProviderRow && (
                <div className="auth-external-providers" role="group" aria-label={t("externalLogin")}>
                  {visibleExternalProviders.map((provider) => (
                    <a
                      key={provider.slug}
                      className="auth-provider-button"
                      href={oidcStartUrl(
                        provider.start_url,
                        authEmail,
                        authMode === "login" ? "login" : "register",
                        effectiveAccountFlow
                      )}
                    >
                      <Link2 size={16} aria-hidden="true" />
                      <span>{provider.display_name}</span>
                    </a>
                  ))}
                </div>
              )}
              {hasExternalProviderRow && (
                <div className="auth-method-divider">
                  <span>{t("orContinueWith")}</span>
                </div>
              )}
          {authFormsVisible && authMode === "login" && bootstrap.has_users && (
            <>
              <LoginMethodSwitcher
                value={loginMethod}
                onChange={changeLoginMethod}
                disabled={busy}
                label={t("loginMethod")}
                passwordLabel={t("passwordLogin")}
                authorizationCodeLabel={t("authorizationCodeLogin")}
              />
              {loginMethod === "password" ? (
                <form aria-busy={busy} onSubmit={handleLogin}>
                  <EmailField
                    label={t("email")}
                    value={authEmail}
                    onChange={setSharedAuthEmail}
                    domains={bootstrap.login.email_domains}
                    customDomain={loginCustomDomain}
                    onCustomDomainChange={setLoginCustomDomain}
                    customLabel={t("customDomain")}
                    applyLabel={t("applySuffix")}
                  />
                  {loginDomainProvider && (
                    <a className="secondary-link" href={oidcStartUrl(loginDomainProvider.start_url, authEmail, "login", effectiveAccountFlow)}>
                      <Link2 size={16} />
                      {t("domainSsoLogin")} · {loginDomainProvider.display_name}
                    </a>
                  )}
                  <Field label={t("password")} type="password" autoComplete="current-password" value={loginPassword} onChange={setLoginPassword} />
                  {loginMfaChallengeId && (
                    <>
                      <Field label={t("mfaCode")} autoComplete="one-time-code" value={loginMfaCode} onChange={setLoginMfaCode} />
                      <small role="status" aria-live="polite">{t("mfaRequired")}{loginRecoveryAvailable ? ` · ${t("recoveryCodes")}` : ""}</small>
                    </>
                  )}
                  {loginCaptchaChallengeId && (
                    <>
                      <Field label={`${t("captchaAnswer")} · ${loginCaptchaPrompt}`} value={loginCaptchaAnswer} onChange={setLoginCaptchaAnswer} />
                      <small role="status" aria-live="polite">{t("captchaRequired")}</small>
                    </>
                  )}
                  <button className="primary" type="submit" disabled={busy}>
                    {t("signIn")}
                  </button>
                  <button className="link-button" type="button" onClick={handlePasskeyLogin} disabled={busy}>
                    <KeyRound size={14} />
                    {t("passkeyLogin")}
                  </button>
                </form>
              ) : (
                <>
                  <div className="info authorization-code-purpose" role="note">
                    <strong>{t("authorizationCodeLoginPurposeTitle")}</strong>
                    <p>{t("authorizationCodeLoginPurposeHint")}</p>
                    {browserAccountsContext?.client_name && (
                      <small>{t("authorizationCodeLoginScopeHint").replace("{client}", browserAccountsContext.client_name)}</small>
                    )}
                  </div>
                  <AuthorizationCodeLoginForm
                    email={authorizationCodeLoginForm.email}
                    authorizationCode={authorizationCodeLoginForm.authorization_code}
                    onAuthorizationCodeChange={(value) => setAuthorizationCodeLoginForm((current) => ({ ...current, authorization_code: value }))}
                    onEmailChange={(value) => setAuthorizationCodeLoginForm((current) => ({ ...current, email: value }))}
                    onSubmit={handleAuthorizationCodeLogin}
                    busy={busy}
                    emailLabel={t("email")}
                    authorizationCodeLabel={t("loginAuthorizationCode")}
                    hint={t("loginAuthorizationCodeHint")}
                    submitLabel={t("authorizationCodeLogin")}
                  />
                </>
              )}
              <div className="auth-secondary-actions">
                <span>
                  {t("noAccountPrompt")} {" "}
                  <button type="button" onClick={() => setAuthMode("register")} disabled={busy}>{t("createAccount")}</button>
                </span>
                <span>
                  {t("forgotPasswordPrompt")} {" "}
                  <button type="button" onClick={() => setAuthMode("reset")} disabled={busy}>{t("resetPasswordAction")}</button>
                </span>
              </div>
            </>
          )}
          {authFormsVisible && authMode === "reset" && bootstrap.has_users && (
            <form aria-busy={busy} onSubmit={handlePasswordReset}>
              <EmailField
                label={t("email")}
                value={authEmail}
                onChange={setSharedAuthEmail}
                domains={bootstrap.login.email_domains}
                customDomain={resetCustomDomain}
                onCustomDomainChange={setResetCustomDomain}
                customLabel={t("customDomain")}
                applyLabel={t("applySuffix")}
              />
              <InlineCode
                icon={<Mail size={16} />}
                label={t("resetPasswordCode")}
                button={t("sendResetCode")}
                value={passwordResetForm.code}
                onChange={(value) => setPasswordResetForm({ ...passwordResetForm, code: value })}
                onSend={sendPasswordResetCode}
                disabled={busy}
              />
              <Field label={t("newPassword")} type="password" autoComplete="new-password" value={passwordResetForm.password} onChange={(value) => setPasswordResetForm({ ...passwordResetForm, password: value })} />
              <button className="primary" type="submit" disabled={busy}>
                {t("completePasswordReset")}
              </button>
            </form>
          )}
          {authFormsVisible && (authMode === "register" || !bootstrap.has_users) && (
            <form aria-busy={busy} onSubmit={handleRegister}>
              <EmailField
                label={t("email")}
                value={authEmail}
                onChange={setSharedAuthEmail}
                domains={bootstrap.login.email_domains}
                customDomain={registerCustomDomain}
                onCustomDomainChange={setRegisterCustomDomain}
                customLabel={t("customDomain")}
                applyLabel={t("applySuffix")}
              />
              {registrationCodeVisible && (
                <>
                  <Field
                    label={t("registrationAuthorizationCode")}
                    value={registerForm.authorization_code}
                    onChange={(value) => setRegisterForm({ ...registerForm, authorization_code: value })}
                    required={registrationCodeRequired}
                  />
                  {hasRegistrationAuthorizationCode && registrationCodeHint && (
                    <div
                      className={`authorization-code-hint ${registrationCodeMode ?? "checking"}`}
                      role="status"
                      aria-live="polite"
                    >
                      {registrationCodeHint}
                    </div>
                  )}
                </>
              )}
              {!isTrialEnrollmentRegistration && registrationFieldsVisible && (
                <>
                  {registerDomainProvider && (
                    <a className="secondary-link" href={oidcStartUrl(registerDomainProvider.start_url, authEmail, "register", effectiveAccountFlow)}>
                      <Link2 size={16} />
                      {t("domainSsoRegister")} · {registerDomainProvider.display_name}
                    </a>
                  )}
                  <div className="email-actions">
                    <button type="button" onClick={generateRegisterEmail}>
                      <Shuffle size={14} />
                      {t("randomEmail")}
                    </button>
                    <button type="button" onClick={copyRegisterEmail}>
                      <Copy size={14} />
                      {t("copyEmail")}
                    </button>
                  </div>
                  {passwordRegistrationUnavailable && (
                    <div className="info">{t("passwordRegistrationUnavailable")}</div>
                  )}
                  {bootstrap.registration.require_email_verification && bootstrap.has_users && (
                    <InlineCode
                      icon={<Mail size={16} />}
                      label={t("emailCode")}
                      button={t("sendEmailCode")}
                      value={registerForm.email_code}
                      onChange={(value) => setRegisterForm({ ...registerForm, email_code: value })}
                      onSend={() => sendVerification("email")}
                      disabled={busy}
                    />
                  )}
                  {bootstrap.registration.require_phone_verification && (
                    <>
                      <Field label={t("phone")} type="tel" autoComplete="tel" value={registerForm.phone} onChange={(value) => setRegisterForm({ ...registerForm, phone: value })} required />
                      <InlineCode
                        icon={<Phone size={16} />}
                        label={t("phoneCode")}
                        button={t("sendPhoneCode")}
                        value={registerForm.phone_code}
                        onChange={(value) => setRegisterForm({ ...registerForm, phone_code: value })}
                        onSend={() => sendVerification("phone")}
                        disabled={busy}
                      />
                    </>
                  )}
                  <Field label={t("username")} autoComplete="username" value={registerForm.username} onChange={(value) => setRegisterForm({ ...registerForm, username: value })} />
                  <Field label={t("password")} type="password" autoComplete="new-password" value={registerForm.password} onChange={(value) => setRegisterForm({ ...registerForm, password: value })} required />
                </>
              )}
              <button className="primary" type="submit" disabled={busy || passwordRegistrationUnavailable || registrationCodeBlocksSubmit}>
                {t("register")}
              </button>
            </form>
          )}
          {authFormsVisible && authMode !== "login" && bootstrap.has_users && (
            <div className="auth-secondary-actions auth-secondary-actions-single">
              <button type="button" onClick={() => setAuthMode("login")} disabled={busy}>{t("openLogin")}</button>
            </div>
          )}
          {authFormsVisible && bootstrap.ldap_providers.length > 0 && (authMode !== "login" || loginMethod === "password") && (
            <div className="external-list">
              <span>{t("directoryLogin")}</span>
              {bootstrap.ldap_providers.map((provider) => (
                <span key={provider.slug} className="secondary-link">
                  <Users size={16} />
                  {provider.display_name}
                </span>
              ))}
            </div>
          )}
            </div>
          )}
          <QuickJump links={bootstrap.login.quick_links} />
          </div>
        </section>
        <AccountChooser
          returnTo={authReturnTo ?? "/"}
          locale={locale}
          t={t}
          selectedAccountRef={selectedBrowserAccount?.account_ref ?? null}
          selectionMode={initialAuth.selectAccount ? "select" : "activate"}
          onAccountSelected={selectBrowserAccount}
          onAccountsLoaded={handleBrowserAccountsLoaded}
          onLoginAnother={openAnotherAccountLogin}
        />
      </main>
    );
  }

  return (
    <div className="app-shell">
      <button
        type="button"
        className={`sidebar-scrim ${sidebarOpen ? "visible" : ""}`}
        aria-label={t("closeNavigation")}
        aria-hidden={!sidebarOpen}
        tabIndex={sidebarOpen ? 0 : -1}
        onClick={() => setSidebarOpen(false)}
      />
      <aside
        id="admin-navigation"
        ref={sidebarRef}
        className={sidebarOpen ? "sidebar-open" : ""}
        aria-label={t("adminConsole")}
      >
        <div className="brand-row compact">
          <span className="brand-mark"><Shield size={22} /></span>
          <div>
            <h1>Signet</h1>
          </div>
        </div>
        <TopLanguage locale={locale} supportedLocales={bootstrap.supported_locales} switchLocale={switchLocale} label={t("language")} compact />
        <nav aria-label={t("adminConsole")}>
          {navigationGroups.map((group) => (
            <div className="nav-group" key={group.id}>
              <p className="nav-group-label">{group.label}</p>
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    type="button"
                    key={item.id}
                    className={tab === item.id ? "active" : ""}
                    onClick={() => navigateToTab(item.id)}
                    aria-current={tab === item.id ? "page" : undefined}
                    aria-label={item.label}
                    title={item.label}
                  >
                    <Icon size={18} />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <button
            className={`account-card ${tab === "account" ? "active" : ""}`}
            type="button"
            onClick={() => navigateToTab("account")}
            aria-label={t("account")}
            aria-current={tab === "account" ? "page" : undefined}
            aria-describedby="account-tooltip"
          >
            <UserRound size={18} />
            <span className="account-card-copy">
              <strong>{user.username}</strong>
              <small>{user.email}</small>
            </span>
            <span id="account-tooltip" className="account-tooltip" role="tooltip">
              <strong>{t("account")}</strong>
              <span>{t("email")}: {user.email}</span>
              <span>{t("username")}: {user.username}</span>
              <span>{t("role")}: {user.is_admin ? t("admin") : t("normalUser")}</span>
            </span>
          </button>
          <button
            className="ghost account-switch-button"
            type="button"
            onClick={openAccountSwitcher}
            title={t("switchAccount")}
            aria-label={t("switchAccount")}
            disabled={busy}
          >
            <ArrowLeftRight size={18} />
          </button>
          <button className="ghost logout-button" type="button" onClick={handleLogout} title={t("logout")} aria-label={t("logout")} disabled={busy}>
            <LogOut size={18} />
          </button>
        </div>
      </aside>
      <main className="content">
        <header className="page-header">
          <button
            ref={mobileMenuButtonRef}
            className="icon-button mobile-menu-button"
            type="button"
            onClick={() => setSidebarOpen(true)}
            title={t("openNavigation")}
            aria-label={t("openNavigation")}
            aria-controls="admin-navigation"
            aria-expanded={sidebarOpen}
          >
            <Menu size={19} />
          </button>
          <div className="page-heading">
            {activeNavigationGroup && <span className="page-heading-context">{activeNavigationGroup.label}</span>}
            <h2>{tabs.find((item) => item.id === tab)?.label}</h2>
            {activeNavigationGroup && <small className="page-heading-hint">{activeNavigationGroup.hint}</small>}
            {user && (
              <span className="page-heading-context current-enterprise-context" aria-live="polite">
                <Building2 size={13} aria-hidden="true" />
                {t("enterprise")} · {organizationContext?.name ?? t("noEnterprise")}
              </span>
            )}
          </div>
          {user && (
            <div className="enterprise-switcher">
              <Building2 size={16} aria-hidden="true" />
              <select
                aria-label={t("switchEnterprise")}
                value={organizationContext?.id ?? ""}
                onChange={(event) => void switchEnterprise(event.target.value)}
                disabled={busy || myOrganizations.length === 0}
              >
                {myOrganizations.length === 0 && <option value="">{t("noEnterprise")}</option>}
                {myOrganizations.map((organization) => (
                  <option key={organization.id} value={organization.id}>
                    {organization.name}{organization.kind === "system" ? ` · ${t("systemEnterprise")}` : ""}
                  </option>
                ))}
              </select>
              <button className="icon-button" type="button" onClick={() => { setEnterpriseForm(emptyEnterpriseForm); setEnterpriseFormBaseline(emptyEnterpriseForm); setEditor("enterprise"); }} title={t("createEnterprise")} aria-label={t("createEnterprise")} disabled={busy}>
                <Plus size={16} />
              </button>
            </div>
          )}
          <div className="header-actions">
            {searchEnabled && (
              <SearchField
                value={searchQuery}
                onChange={setSearchQuery}
                placeholder={t("searchCurrentPage")}
                clearLabel={t("clearSearch")}
              />
            )}
            <button
              className="icon-button"
              type="button"
              onClick={() => setTheme((current) => current === "dark" ? "light" : "dark")}
              title={theme === "dark" ? t("lightMode") : t("darkMode")}
              aria-label={theme === "dark" ? t("lightMode") : t("darkMode")}
            >
              {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            <button className="icon-button" type="button" onClick={refreshCurrentTab} title={t("refresh")} aria-label={t("refresh")} disabled={refreshing}>
              <RefreshCw className={refreshing ? "spin" : ""} size={18} />
            </button>
          </div>
        </header>
        {editor === "enterprise" && (
          <Modal title={t("createEnterprise")} closeLabel={t("close")} error={error} dismissible={!busy} onClose={closeEditor}>
            <form className="panel" onSubmit={saveEnterprise}>
              <p className="muted">{t("createEnterpriseHint")}</p>
              <Field label={t("enterpriseSlug")} value={enterpriseForm.slug} onChange={(value) => setEnterpriseForm({ ...enterpriseForm, slug: value })} />
              <Field label={t("enterpriseName")} value={enterpriseForm.name} onChange={(value) => setEnterpriseForm({ ...enterpriseForm, name: value })} />
              <Field label={t("enterpriseDescription")} value={enterpriseForm.description} onChange={(value) => setEnterpriseForm({ ...enterpriseForm, description: value })} textarea />
              <Field label={t("enterpriseEmailDomains")} value={enterpriseForm.allowed_email_domains} onChange={(value) => setEnterpriseForm({ ...enterpriseForm, allowed_email_domains: value })} textarea />
              <FormActions
                submitLabel={t("createEnterprise")}
                cancelLabel={t("cancel")}
                onCancel={closeEditor}
                busy={busy}
                dirty={enterpriseFormIsDirty()}
                statusLabel={enterpriseFormIsDirty() ? t("unsavedChanges") : undefined}
                savingLabel={t("saving")}
              />
            </form>
          </Modal>
        )}
        {adminLoading && <div className="loading-bar" role="progressbar" aria-label={t("loading")} />}
        {error && !editor && !pendingConfirmation && <div className="error" role="alert">{error}</div>}
        {isRestrictedLoginCodeSession && (
          <div className="info temporary-session-banner" role="status" aria-live="polite">
            <Shield size={17} aria-hidden="true" />
            <span>{t(isTrialEnrollmentSession ? "trialEnrollmentAccountReady" : "temporaryAccountReady")}</span>
          </div>
        )}
        {verificationMessage && <div className="toast" role="status" aria-live="polite">{verificationMessage}</div>}
        {!canAdmin && tab !== "account" && tab !== "billing" ? <div className="empty">{t("noUserAdminOnly")}</div> : null}
        {tab === "account" && (
          <section className="account-layout">
            <div className="client-list">
              <div className="panel">
                <h3>{t("account")}</h3>
                <div className="detail-grid">
                  <div className="info-cell">
                    <span>{t("email")}</span>
                    <strong>{user.email}</strong>
                  </div>
                  <div className="info-cell">
                    <span>{t("username")}</span>
                    <strong>{user.username}</strong>
                  </div>
                  <div className="info-cell">
                    <span>{t("displayName")}</span>
                    <strong>{user.display_name ?? "-"}</strong>
                  </div>
                  <div className="info-cell">
                    <span>{t("phone")}</span>
                    <strong>{user.phone ?? "-"}</strong>
                  </div>
                  <div className="info-cell">
                    <span>{t("role")}</span>
                    <strong>{user.is_admin ? t("admin") : t("normalUser")}</strong>
                  </div>
                  <div className="info-cell">
                    <span>{t("status")}</span>
                    <strong>{user.archived_at ? t("archived") : user.is_active ? t("active") : t("disabled")}</strong>
                  </div>
                  <div className="info-cell">
                    <span>{t("registeredAt")}</span>
                    <strong>{formatTime(user.created_at, locale)}</strong>
                  </div>
                  <div className="info-cell">
                    <span>{t("lastLogin")}</span>
                    <strong>{formatTime(user.last_login_at, locale)}</strong>
                  </div>
                  <div className="info-cell">
                    <span>{t("lastIp")}</span>
                    <strong>{user.last_login_ip ?? "-"}</strong>
                  </div>
                  <div className="info-cell">
                    <span>{t("lastClient")}</span>
                    <strong>{user.last_oidc_client_id ?? "-"}</strong>
                  </div>
                </div>
                {user.archived_at && <p className="muted">{t("archivedReadOnly")}</p>}
              </div>
              <div className="panel">
                <h3>{t("mfaSettings")}</h3>
                <p className="muted">
                  {mfaStatus?.enabled ? t("active") : t("disabled")} · {t("recoveryCodesRemaining")}: {mfaStatus?.recovery_codes_remaining ?? 0}/{mfaStatus?.recovery_codes_total ?? 0}
                </p>
                {canMutateAccount && (
                  <div className="actions">
                    <button type="button" onClick={startTotpSetup} disabled={busy}><KeyRound size={14} />{t("startTotpSetup")}</button>
                    {mfaStatus?.enabled && <button type="button" onClick={() => requestConfirmation(rotateRecoveryCodes, t("rotateRecoveryCodes"), t("rotateRecoveryCodesDescription"))} disabled={busy}>{t("rotateRecoveryCodes")}</button>}
                    {mfaStatus?.enabled && <button type="button" onClick={() => requestConfirmation(disableMfa, t("disableMfa"), t("disableMfaDescription"))} disabled={busy}>{t("disableMfa")}</button>}
                  </div>
                )}
                {totpSetup && canMutateAccount && (
                  <div className="mfa-setup">
                    <label htmlFor="account-totp-secret">{t("totpSecret")}</label>
                    <textarea id="account-totp-secret" readOnly value={totpSetup.secret} />
                    <label htmlFor="account-otpauth-uri">{t("otpauthUri")}</label>
                    <textarea id="account-otpauth-uri" readOnly value={totpSetup.otpauth_uri} />
                    <Field label={t("mfaCode")} value={totpSetupCode} onChange={setTotpSetupCode} />
                    <div className="actions">
                      <button type="button" onClick={confirmTotpSetup} disabled={busy}><Save size={14} />{t("confirmTotp")}</button>
                    </div>
                  </div>
                )}
                {newRecoveryCodes.length > 0 && (
                  <div className="info">
                    <strong>{t("recoveryCodes")}</strong>
                    <p>{t("recoveryCodesOnce")}</p>
                    <div className="token-list">
                      {newRecoveryCodes.map((code) => <span key={code}>{code}</span>)}
                    </div>
                  </div>
                )}
              </div>
              <div className="panel">
                <h3>{t("passkeys")}</h3>
                {canMutateAccount && (
                  <div className="inline-code">
                    <Field label={t("passkeyName")} value={passkeyName} onChange={setPasskeyName} />
                    <button type="button" onClick={registerPasskey} disabled={busy}>
                      <KeyRound size={14} />
                      {t("registerPasskey")}
                    </button>
                  </div>
                )}
                <table>
                  <thead>
                    <tr>
                      <th>{t("passkeyName")}</th>
                      <th>{t("credentialId")}</th>
                      <th>{t("lastUsed")}</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {passkeys.map((passkey) => (
                      <tr key={passkey.id}>
                        <td>
                          {passkey.name}
                          <br />
                          <small>{formatTime(passkey.created_at, locale)}</small>
                        </td>
                        <td><code>{shortSessionId(passkey.credential_id)}</code></td>
                        <td>{formatTime(passkey.last_used_at, locale)}</td>
                        <td className="actions">
                          {canMutateAccount && (
                            <button type="button" onClick={() => requestConfirmation(() => deletePasskey(passkey.id))} disabled={busy}>
                              <Trash2 size={14} />
                              {t("delete")}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {passkeys.length === 0 && <div className="empty">{t("noPasskeys")}</div>}
              </div>
            </div>
            <div className="client-list">
              <div className="table-panel">
                <h3>{t("activeSessions")}</h3>
                <table>
                  <thead>
                    <tr>
                      <th>{t("sessionId")}</th>
                      <th>{t("device")}</th>
                      <th>{t("authMethod")}</th>
                      <th>{t("createdAt")}</th>
                      <th>{t("expiresAt")}</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {mySessions.map((session) => (
                      <tr key={session.id}>
                        <td>
                          <code>{shortSessionId(session.id)}</code>
                          {session.current && (
                            <>
                              <br />
                              <small>{t("currentSession")}</small>
                            </>
                          )}
                        </td>
                        <td>
                          <div className="session-device">
                            <strong>{session.ip_address ?? "-"}</strong>
                            <small>{session.user_agent ?? "-"}</small>
                          </div>
                        </td>
                        <td>{session.login_method ?? "-"}</td>
                        <td>{formatTime(session.created_at, locale)}</td>
                        <td>{formatTime(session.expires_at, locale)}</td>
                        <td className="actions">
                          {canMutateAccount && !session.current && (
                            <button type="button" onClick={() => requestConfirmation(() => revokeMySession(session.id))} disabled={busy}>
                              <LogOut size={14} />
                              {t("revokeSession")}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {mySessions.length === 0 && <div className="empty">{t("noActiveSessions")}</div>}
              </div>
              <div className="table-panel">
                <h3>{t("authorizedApplications")}</h3>
                <table>
                  <thead>
                    <tr>
                      <th>{t("clientName")}</th>
                      <th>{t("grantedScopes")}</th>
                      <th>{t("grantedAt")}</th>
                      <th>{t("updatedAt")}</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {myConsents.map((consent) => (
                      <tr key={consent.client_id}>
                        <td>
                          {consent.client_name ?? consent.client_id}
                          <br />
                          <small>{consent.client_id}</small>
                        </td>
                        <td>
                          <div className="token-list">
                            {consent.granted_scopes.map((scope) => <span key={scope}>{scope}</span>)}
                          </div>
                        </td>
                        <td>{formatTime(consent.granted_at, locale)}</td>
                        <td>{formatTime(consent.updated_at, locale)}</td>
                        <td className="actions">
                          {canMutateAccount && (
                            <button type="button" onClick={() => requestConfirmation(() => revokeMyConsent(consent.client_id))} disabled={busy}>
                              <Ban size={14} />
                              {t("revoke")}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {myConsents.length === 0 && <div className="empty">{t("noAuthorizedApplications")}</div>}
              </div>
            </div>
          </section>
        )}
        {tab === "billing" && user && !isRestrictedLoginCodeSession && (
          <WalletWorkspace locale={locale} t={t} orderReference={billingOrderReference} />
        )}
        {canAdmin && tab === "overview" && (
          <section className="dashboard">
            <article className="welcome-card">
              <div>
                <StatusBadge tone="success"><Activity size={13} />{t("serviceHealthy")}</StatusBadge>
                <h3>{t("welcomeBack")}，{user.username}</h3>
                <p>{t("overviewIntro")}</p>
              </div>
              <div className="quick-actions" role="group" aria-label={t("quickActions")}>
                {canReadUsers && <button type="button" onClick={() => navigateToTab("users")}><Users size={16} />{t("users")}</button>}
                {canReadClients && <button type="button" onClick={() => navigateToTab("clients")}><KeyRound size={16} />{t("clients")}</button>}
                {canManageSecurity && <button type="button" onClick={() => navigateToTab("security")}><Shield size={16} />{t("security")}</button>}
              </div>
            </article>
            <div className="metrics-grid">
              <Metric label={t("usersMetric")} value={totalUserCount} detail={`${activeUserCount} ${t("active")}`} />
              <Metric label={t("activeRate")} value={`${activeUserRate}%`} detail={`${activeUserCount}/${totalUserCount} ${t("users")}`} />
              <Metric label={t("clientsMetric")} value={totalClientCount} detail={`${activeClientCount} ${t("active")} · ${activeClientRate}%`} />
              <Metric label={t("database")} value={overview?.database_kind ?? "-"} detail={t("settings")} />
            </div>
            <div className="overview-bottom-grid">
              <article className="panel overview-status-card">
                <div className="overview-card-heading">
                  <div>
                    <StatusBadge tone="success"><Activity size={13} />{t("serviceHealthy")}</StatusBadge>
                    <h3>{t("overviewStatus")}</h3>
                  </div>
                  <Shield size={22} aria-hidden="true" />
                </div>
                <div className="overview-fact-grid">
                  <Info label={t("issuerLabel")} value={overview?.issuer ?? bootstrap.issuer} />
                  <Info label={t("database")} value={overview?.database_kind ?? "-"} />
                  <Info label={t("usersMetric")} value={`${activeUserCount}/${totalUserCount} ${t("active")}`} />
                  <Info label={t("clientsMetric")} value={`${activeClientCount}/${totalClientCount} ${t("active")}`} />
                </div>
              </article>
              <article className="panel overview-workspace-card">
                <div className="overview-card-heading">
                  <div>
                    <h3>{t("overviewWorkspace")}</h3>
                    <p className="muted">{t("overviewIntro")}</p>
                  </div>
                </div>
                <div className="overview-nav-grid">
                  {canReadUsers && <button type="button" onClick={() => navigateToTab("users")}><Users size={17} /><span>{t("users")}</span><ExternalLink size={14} /></button>}
                  {canReadClients && <button type="button" onClick={() => navigateToTab("clients")}><KeyRound size={17} /><span>{t("clients")}</span><ExternalLink size={14} /></button>}
                  {canReadOrganizations && <button type="button" onClick={() => navigateToTab("organizations")}><Building2 size={17} /><span>{t("organizations")}</span><ExternalLink size={14} /></button>}
                  {canManageSecurity && <button type="button" onClick={() => navigateToTab("security")}><Shield size={17} /><span>{t("security")}</span><ExternalLink size={14} /></button>}
                </div>
              </article>
            </div>
          </section>
        )}
        {canReadUsers && tab === "users" && (
          <section className="users-layout">
            {canManageUsers && editor === "user" && (
              <Modal title={userForm.id ? t("updateUser") : t("createUser")} closeLabel={t("close")} error={error} dismissible={!busy} onClose={closeEditor}>
              <form className="panel" onSubmit={saveUser}>
                <Field label={t("email")} value={userForm.email} onChange={(value) => setUserForm({ ...userForm, email: value })} />
                <Field label={t("username")} value={userForm.username} onChange={(value) => setUserForm({ ...userForm, username: value })} />
                <Field label={t("displayName")} value={userForm.display_name} onChange={(value) => setUserForm({ ...userForm, display_name: value })} />
                <Field label={t("phone")} value={userForm.phone} onChange={(value) => setUserForm({ ...userForm, phone: value })} />
                <Field label={t("password")} type="password" value={userForm.password} onChange={(value) => setUserForm({ ...userForm, password: value })} />
                <Check label={t("admin")} checked={userForm.is_admin} onChange={(value) => setUserForm({ ...userForm, is_admin: value })} />
                {!userForm.id && <Check label={t("active")} checked={userForm.is_active} onChange={(value) => setUserForm({ ...userForm, is_active: value })} />}
                <FormActions
                  submitLabel={t("save")}
                  cancelLabel={t("cancel")}
                  onCancel={closeEditor}
                  busy={busy}
                  dirty={userFormIsDirty()}
                  statusLabel={userFormIsDirty() ? t("unsavedChanges") : undefined}
                  savingLabel={t("saving")}
                />
              </form>
              </Modal>
            )}
            {canManageUsers && bulkImportOpen && (
              <Modal
                title={t("bulkUserImport")}
                closeLabel={t("close")}
                error={bulkImportError}
                dismissible={!busy}
                onClose={closeBulkUserImport}
                wide
              >
                <form className="panel bulk-import-panel" onSubmit={submitBulkUserImport}>
                  <div className="info bulk-import-intro">
                    <strong>{t("bulkImportAtomicTitle")}</strong>
                    <p>{t("bulkImportAtomicDescription")}</p>
                  </div>
                  <div className="field">
                    <label htmlFor="bulk-user-import-file">{t("bulkImportFile")}</label>
                    <input
                      id="bulk-user-import-file"
                      type="file"
                      accept=".csv,text/csv"
                      onChange={(event) => void readBulkUserImportFile(event)}
                    />
                    <small className="field-description">
                      {bulkImportFileName ? `${t("bulkImportSelectedFile")}: ${bulkImportFileName}` : t("bulkImportFileHint")}
                    </small>
                  </div>
                  <Field
                    label={t("bulkImportCsv")}
                    textarea
                    value={bulkImportCsv}
                    onChange={(value) => {
                      setBulkImportCsv(value);
                      setBulkImportFileName("");
                      setBulkImportResult(null);
                    }}
                    description={t("bulkImportCsvHint")}
                  />
                  <div className="bulk-import-template">
                    <code>{BULK_USER_IMPORT_TEMPLATE}</code>
                    <button
                      type="button"
                      onClick={() => {
                        setBulkImportCsv(BULK_USER_IMPORT_TEMPLATE);
                        setBulkImportFileName("");
                        setBulkImportResult(null);
                        setBulkImportError("");
                      }}
                    >
                      <FileUp size={14} />
                      {t("bulkImportUseTemplate")}
                    </button>
                  </div>
                  <Check
                    label={t("bulkImportDryRun")}
                    checked={bulkImportDryRun}
                    onChange={(value) => {
                      setBulkImportDryRun(value);
                      if (value) setBulkImportCommitConfirmed(false);
                    }}
                  />
                  {bulkImportDryRun ? (
                    <div className="info">{t("bulkImportDryRunHint")}</div>
                  ) : (
                    <div className="error bulk-import-commit-warning" role="alert">
                      <strong>{t("bulkImportCommitWarning")}</strong>
                      <Check
                        label={t("bulkImportCommitConfirmation")}
                        checked={bulkImportCommitConfirmed}
                        onChange={setBulkImportCommitConfirmed}
                      />
                    </div>
                  )}
                  <div className="actions bulk-import-actions">
                    <button type="button" onClick={resetBulkUserImport} disabled={busy}>{t("clear")}</button>
                    <button className="primary compact-primary" type="submit" disabled={busy}>
                      <FileUp size={16} />
                      {bulkImportDryRun ? t("bulkImportRunDryRun") : t("bulkImportCommit")}
                    </button>
                  </div>
                  {bulkImportResult && (
                    <section className="bulk-import-results" aria-live="polite" aria-label={t("bulkImportResults")}>
                      <div className="bulk-import-result-header">
                        <h4>{t("bulkImportResults")}</h4>
                        <StatusBadge tone={bulkImportResult.committed ? "success" : bulkImportResult.summary.invalid > 0 ? "danger" : "info"}>
                          {bulkImportResult.committed ? t("bulkImportCommitted") : bulkImportResult.dry_run ? t("bulkImportDryRunResult") : t("bulkImportNotCommitted")}
                        </StatusBadge>
                      </div>
                      <div className="bulk-import-summary">
                        <span><strong>{bulkImportResult.summary.total}</strong>{t("bulkImportTotal")}</span>
                        <span><strong>{bulkImportResult.summary.created}</strong>{t("bulkImportCreated")}</span>
                        <span><strong>{bulkImportResult.summary.would_create}</strong>{t("bulkImportWouldCreate")}</span>
                        <span><strong>{bulkImportResult.summary.invalid}</strong>{t("bulkImportInvalid")}</span>
                      </div>
                      <div className="bulk-import-result-table">
                        <table>
                          <thead>
                            <tr>
                              <th>{t("bulkImportRow")}</th>
                              <th>{t("email")}</th>
                              <th>{t("username")}</th>
                              <th>{t("status")}</th>
                              <th>{t("bulkImportUserId")}</th>
                              <th>{t("bulkImportError")}</th>
                            </tr>
                          </thead>
                          <tbody>
                            {bulkImportResult.rows.map((row) => (
                              <tr key={`${row.row}-${row.email ?? ""}-${row.username ?? ""}`}>
                                <td>{row.row}</td>
                                <td>{row.email ?? "-"}</td>
                                <td>{row.username ?? "-"}</td>
                                <td>
                                  <StatusBadge tone={bulkImportOutcomeTone(row.outcome)}>
                                    {t(
                                      row.outcome === "created"
                                        ? "bulkImportOutcomeCreated"
                                        : row.outcome === "would_create"
                                          ? "bulkImportOutcomeWouldCreate"
                                          : row.outcome === "not_committed"
                                            ? "bulkImportOutcomeNotCommitted"
                                            : "bulkImportOutcomeInvalid"
                                    )}
                                  </StatusBadge>
                                </td>
                                <td><code>{row.user_id ?? "-"}</code></td>
                                <td>{row.error ?? "-"}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </section>
                  )}
                </form>
              </Modal>
            )}
            <div className="table-panel users-table-panel">
              <div className="table-toolbar users-toolbar">
                <div className="users-toolbar-actions">
                  {canManageUsers && <button type="button" onClick={() => { setUserForm(emptyUserForm); setUserFormBaseline(emptyUserForm); setEditor("user"); }}><Plus size={14} />{t("createUser")}</button>}
                  {canManageUsers && <button type="button" onClick={openBulkUserImport}><FileUp size={14} />{t("bulkUserImport")}</button>}
                </div>
                <label className="filter-control">
                  <span>{t("userFilter")}</span>
                  <select value={userFilter} onChange={(event) => setUserFilter(event.target.value as UserFilter)}>
                    <option value="live">{t("liveUsers")}</option>
                    <option value="active">{t("activeUsers")}</option>
                    <option value="disabled">{t("disabledUsers")}</option>
                    <option value="archived">{t("archivedUsers")}</option>
                    <option value="authorization_code">{t("authorizationCodeUsers")}</option>
                    <option value="all">{t("allUsers")}</option>
                  </select>
                </label>
              </div>
              <section className="user-filter-panel" aria-label={t("userFilters")}>
                <div className="user-filter-heading">
                  <div>
                    <Filter size={16} aria-hidden="true" />
                    <strong>{t("userFilters")}</strong>
                  </div>
                  <button
                    className="text-button"
                    type="button"
                    aria-expanded={userFiltersExpanded}
                    onClick={() => setUserFiltersExpanded((value) => !value)}
                  >
                    {userFiltersExpanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
                    {userFiltersExpanded ? t("userFiltersLess") : t("userFiltersMore")}
                  </button>
                </div>
                <div className="user-filter-grid user-filter-grid-common">
                  <label className="user-filter-field">
                    <span>{t("filterEmail")}</span>
                    <input value={userEmailFilter} onChange={(event) => setUserEmailFilter(event.target.value)} />
                  </label>
                  <label className="user-filter-field">
                    <span>{t("filterRole")}</span>
                    <select value={userRoleFilter} onChange={(event) => setUserRoleFilter(event.target.value as UserRoleFilter)}>
                      <option value="all">{t("allRoles")}</option>
                      <option value="admin">{t("admin")}</option>
                      <option value="user">{t("normalUser")}</option>
                    </select>
                  </label>
                  <div className="user-filter-field">
                    <span>{t("filterRegistrationDate")}</span>
                    <div className="user-date-range">
                      <input aria-label={`${t("filterRegistrationDate")} ${t("filterDateFrom")}`} type="date" value={userRegistrationFrom} onChange={(event) => setUserRegistrationFrom(event.target.value)} />
                      <span aria-hidden="true">–</span>
                      <input aria-label={`${t("filterRegistrationDate")} ${t("filterDateTo")}`} type="date" value={userRegistrationTo} onChange={(event) => setUserRegistrationTo(event.target.value)} />
                    </div>
                  </div>
                  <div className="user-filter-field">
                    <span>{t("filterLastLoginDate")}</span>
                    <div className="user-date-range">
                      <input aria-label={`${t("filterLastLoginDate")} ${t("filterDateFrom")}`} type="date" value={userLastLoginFrom} onChange={(event) => setUserLastLoginFrom(event.target.value)} />
                      <span aria-hidden="true">–</span>
                      <input aria-label={`${t("filterLastLoginDate")} ${t("filterDateTo")}`} type="date" value={userLastLoginTo} onChange={(event) => setUserLastLoginTo(event.target.value)} />
                    </div>
                  </div>
                </div>
                {userFiltersExpanded && (
                  <div className="user-filter-grid user-filter-grid-advanced">
                    <label className="user-filter-field">
                      <span>{t("filterPhone")}</span>
                      <input value={userPhoneFilter} onChange={(event) => setUserPhoneFilter(event.target.value)} />
                    </label>
                    <label className="user-filter-field">
                      <span>{t("filterLoginRegion")}</span>
                      <select value={userLoginRegionFilter} onChange={(event) => setUserLoginRegionFilter(event.target.value as UserLoginRegionFilter)}>
                        <option value="all">{t("allLoginRegions")}</option>
                        <option value="domestic">{t("domestic")}</option>
                        <option value="overseas">{t("overseas")}</option>
                      </select>
                    </label>
                    <label className="user-filter-field">
                      <span>{t("filterOrganization")}</span>
                      <select value={userOrganizationFilter} onChange={(event) => setUserOrganizationFilter(event.target.value)}>
                        <option value="">{t("allOrganizations")}</option>
                        {userOrganizationFilter && !organizationOptions.some((organization) => organization.id === userOrganizationFilter) && (
                          <option value={userOrganizationFilter}>{userOrganizationFilter}</option>
                        )}
                        {organizationOptions.map((organization) => (
                          <option key={organization.id} value={organization.id}>
                            {organization.name} · {organization.slug}{organization.is_active ? "" : ` · ${t("disabled")}`}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="user-filter-field">
                      <span>{t("filterLinkedIdentity")}</span>
                      <select value={userLinkedIdentityFilter} onChange={(event) => setUserLinkedIdentityFilter(event.target.value as UserLinkedIdentityFilter)}>
                        <option value="all">{t("allIdentityStates")}</option>
                        <option value="linked">{t("linkedIdentityOnly")}</option>
                        <option value="unlinked">{t("unlinkedIdentityOnly")}</option>
                      </select>
                    </label>
                  </div>
                )}
                <div className="user-filter-footer">
                  <button className="text-button" type="button" onClick={resetUserFilters}>{t("resetFilters")}</button>
                </div>
              </section>
              {canManageUsers && selectedUserIds.length > 0 && (
                <div className="bulk-user-actions" aria-live="polite">
                  <strong>{t("selectedUsers").replace("{count}", String(selectedUserIds.length))}</strong>
                  <div className="actions">
                    {availableBulkUserActions.includes("enable") && <button type="button" onClick={() => requestBulkUserAction("enable")} disabled={busy}>
                      <RotateCcw size={14} />{t("bulkEnable")}
                    </button>}
                    {availableBulkUserActions.includes("disable") && <button type="button" onClick={() => requestBulkUserAction("disable")} disabled={busy}>
                      <Ban size={14} />{t("bulkDisable")}
                    </button>}
                    {availableBulkUserActions.includes("archive") && <button type="button" onClick={() => requestBulkUserAction("archive")} disabled={busy}>
                      <Archive size={14} />{t("bulkArchive")}
                    </button>}
                    {availableBulkUserActions.includes("delete") && <button type="button" onClick={() => requestBulkUserAction("delete")} disabled={busy}>
                      <Trash2 size={14} />{t("bulkDelete")}
                    </button>}
                    {availableBulkUserActions.includes("reset_mfa") && <button type="button" onClick={() => requestBulkUserAction("reset_mfa")} disabled={busy}>
                      <KeyRound size={14} />{t("bulkResetMfa")}
                    </button>}
                    <button type="button" onClick={() => setSelectedUserIds([])} disabled={busy}>{t("clearSelection")}</button>
                  </div>
                </div>
              )}
              <table className="user-table">
                <caption className="sr-only">{t("users")}</caption>
                <thead>
                  <tr>
                    {canManageUsers && (
                      <th className="user-selection-column">
                        <input
                          type="checkbox"
                          aria-label={t("selectAllUsers")}
                          checked={allVisibleUsersSelected}
                          onChange={(event) => toggleVisibleUserSelection(event.target.checked)}
                        />
                      </th>
                    )}
                    <th>{t("email")}</th>
                    <th>{t("role")}</th>
                    <th>{t("registeredAt")}</th>
                    <th>{t("lastLogin")}</th>
                    <th>{t("status")}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map((item) => (
                    <tr key={item.id}>
                      {canManageUsers && (
                        <td className="user-selection-column">
                          <input
                            type="checkbox"
                            aria-label={`${t("email")}: ${item.email}`}
                            checked={selectedUserIdSet.has(item.id)}
                            onChange={() => toggleUserSelection(item.id)}
                          />
                        </td>
                      )}
                      <td className="user-summary">{item.email}<br /><small>{item.username}</small></td>
                      <td className="user-role">{item.is_admin ? t("admin") : t("normalUser")}</td>
                      <td className="user-registration">{formatTime(item.created_at, locale)}</td>
                      <td className="user-last-login">{formatTime(item.last_login_at, locale)}</td>
                      <td className="user-status">
                        <div className="user-status-stack">
                          <StatusBadge tone={item.archived_at !== null ? "neutral" : item.is_active ? "success" : "warning"}>
                            {item.archived_at !== null ? t("archived") : item.is_active ? t("active") : t("disabled")}
                          </StatusBadge>
                          {item.registration_source === "authorization_code" && (
                            <StatusBadge tone="info">{t("authorizationCodeRegistered")}</StatusBadge>
                          )}
                        </div>
                        {item.archived_at !== null && <><br /><small>{formatTime(item.archived_at, locale)}</small></>}
                      </td>
                      <td className="actions user-actions">
                        {canManageUsers && item.archived_at === null && (
                          <button type="button" onClick={() => {
                            const nextForm = {
                              id: item.id,
                              email: item.email,
                              username: item.username,
                              display_name: item.display_name ?? "",
                              phone: item.phone ?? "",
                              password: "",
                              is_admin: item.is_admin,
                              is_active: item.is_active
                            };
                            setUserForm(nextForm);
                            setUserFormBaseline(nextForm);
                            setEditor("user");
                          }}>{t("edit")}</button>
                        )}
                        <button type="button" onClick={() => void showUserDetails(item.id)} disabled={busy}>{t("details")}</button>
                        {canManageUsers && availableUserActions(item, user?.id).includes("reset_mfa") && (
                          <button type="button" onClick={() => requestConfirmation(() => resetUserMfa(item.id))}>
                            <KeyRound size={14} />
                            {t("resetMfa")}
                          </button>
                        )}
                        {canManageUsers && availableUserActions(item, user?.id).includes("disable") && (
                          <button type="button" onClick={() => requestConfirmation(() => advanceUserLifecycle(item.id))}>
                            <Ban size={14} />
                            {t("disable")}
                          </button>
                        )}
                        {canManageUsers && availableUserActions(item, user?.id).includes("enable") && (
                          <button type="button" onClick={() => void enableUser(item.id)} disabled={busy}>
                            <RotateCcw size={14} />
                            {t("enable")}
                          </button>
                        )}
                        {canManageUsers && availableUserActions(item, user?.id).includes("archive") && (
                          <button type="button" onClick={() => requestConfirmation(() => advanceUserLifecycle(item.id))}>
                            <Archive size={14} />
                            {t("archive")}
                          </button>
                        )}
                        {canManageUsers && availableUserActions(item, user?.id).includes("delete") && (
                          <button type="button" onClick={() => requestConfirmation(() => advanceUserLifecycle(item.id))}>
                            <Trash2 size={14} />
                            {t("delete")}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!adminLoading && filteredUsers.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} icon={<Users size={22} />} />}
              {selectedUser && <Modal title={t("userDetails")} closeLabel={t("close")} onClose={() => setSelectedUser(null)} wide className="user-detail-modal"><UserDetailPanel detail={selectedUser} locale={locale} t={t} /></Modal>}
            </div>
          </section>
        )}
        {canReadOrganizations && tab === "organizations" && (
          <section className="management-list">
            {canManageOrganizations && editor === "organization" && (
              <Modal title={organizationForm.id ? t("updateOrganization") : t("createOrganization")} closeLabel={t("close")} error={error} dismissible={!busy} onClose={closeEditor}>
              <form className="panel" onSubmit={saveOrganization}>
                <Field label={t("organizationSlug")} value={organizationForm.slug} onChange={(value) => setOrganizationForm({ ...organizationForm, slug: value })} />
                <Field label={t("organizationName")} value={organizationForm.name} onChange={(value) => setOrganizationForm({ ...organizationForm, name: value })} />
                <Field label={t("description")} value={organizationForm.description} onChange={(value) => setOrganizationForm({ ...organizationForm, description: value })} textarea />
                <Field label={t("allowedEmailDomains")} value={organizationForm.allowed_email_domains} onChange={(value) => setOrganizationForm({ ...organizationForm, allowed_email_domains: value })} textarea />
                <Check label={t("active")} checked={organizationForm.is_active} onChange={(value) => setOrganizationForm({ ...organizationForm, is_active: value })} />
                <label>{t("organizationMembers")}</label>
                {organizationMembersLoading ? (
                  <div className="info" role="status">{t("loading")}</div>
                ) : (
                  <div className="checkbox-grid tall">
                    {users.map((item) => {
                      const role = organizationMemberRoles[item.id] ?? "";
                      return (
                        <div key={item.id} className="member-row">
                          <Check
                            label={`${item.email} · ${item.username}`}
                            checked={Boolean(role)}
                            onChange={(selected) => setOrganizationMemberRole(item.id, selected ? "member" : null)}
                          />
                          {role && (
                            <select
                              aria-label={`${item.email} · ${t("role")}`}
                              value={role}
                              onChange={(event) => setOrganizationMemberRole(item.id, event.target.value)}
                            >
                              <option value="member">member</option>
                              <option value="admin">admin</option>
                              <option value="owner">owner</option>
                            </select>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
                <FormActions
                  submitLabel={organizationForm.id ? t("save") : t("create")}
                  cancelLabel={t("cancel")}
                  onCancel={closeEditor}
                  busy={busy || organizationMembersLoading}
                  dirty={organizationFormIsDirty()}
                  statusLabel={organizationFormIsDirty() ? t("unsavedChanges") : undefined}
                  savingLabel={t("saving")}
                />
              </form>
              </Modal>
            )}
            <div className="table-panel">
              <div className="table-toolbar"><h3>{t("organizations")}</h3>{canManageOrganizations && <button type="button" onClick={() => { organizationMembersLoadId.current += 1; setOrganizationForm(emptyOrganizationForm); setOrganizationFormBaseline(emptyOrganizationForm); setOrganizationMemberRoles({}); setOrganizationMemberRolesBaseline({}); setOrganizationMembersLoading(false); setEditor("organization"); }}><Plus size={14} />{t("createOrganization")}</button>}</div>
              <table>
                <thead>
                  <tr>
                    <th>{t("organizationName")}</th>
                    <th>{t("memberCount")}</th>
                    <th>{t("status")}</th>
                    <th>{t("updatedAt")}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredOrganizations.map((organization) => (
                    <tr key={organization.id}>
                      <td className="organization-name-cell">
                        <div className="organization-name-summary">
                          <strong>{organization.name}</strong>
                          <span className="organization-slug">{organization.slug}</span>
                          {organization.allowed_email_domains.length > 0 && (
                            <span
                              className="organization-domains"
                              title={organization.allowed_email_domains.map((domain) => `@${domain}`).join(", ")}
                            >
                              @{organization.allowed_email_domains[0]}
                              {organization.allowed_email_domains.length > 1 && ` +${organization.allowed_email_domains.length - 1}`}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="organization-member-count">{organization.member_count}</td>
                      <td><StatusBadge tone={organization.is_active ? "success" : "warning"}>{organization.is_active ? t("active") : t("disabled")}</StatusBadge></td>
                      <td>{formatTime(organization.updated_at, locale)}</td>
                      <td className="actions">
                        {canReadUsers && <button type="button" onClick={() => {
                          setUserOrganizationFilter(organization.id);
                          navigateToTab("users");
                        }}>{t("viewMembers")}</button>}
                        {canManageOrganizations && <button type="button" onClick={() => void editOrganization(organization)}>{t("edit")}</button>}
                        {canManageOrganizations && <button type="button" onClick={() => requestConfirmation(() => deleteOrganization(organization.id))}>{t("delete")}</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!adminLoading && filteredOrganizations.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} icon={<Building2 size={22} />} />}
            </div>
          </section>
        )}
        {canManageActiveOrganization && tab === "applications" && (
          <>
            {editor === "application" && (
              <Modal
                title={applicationForm.id ? t("updateApplication") : t("createApplication")}
                closeLabel={t("close")}
                error={error}
                dismissible={!busy}
                onClose={closeEditor}
              >
                <form className="panel application-basics-form" onSubmit={saveApplication}>
                  <div className="application-form-intro">
                    <span className="application-hero-avatar"><Globe2 size={22} /></span>
                    <div><strong>{t("websiteApplication")}</strong><p>{t("websiteApplicationHint")}</p></div>
                  </div>
                  <Field label={t("applicationSlug")} value={applicationForm.slug} onChange={(value) => setApplicationForm({ ...applicationForm, slug: value })} required />
                  <Field label={t("applicationName")} value={applicationForm.name} onChange={(value) => setApplicationForm({ ...applicationForm, name: value })} required />
                  <Field label={t("websiteUrl")} type="url" value={applicationForm.website_url} onChange={(value) => setApplicationForm({ ...applicationForm, website_url: value })} />
                  <Field label={t("description")} value={applicationForm.description} onChange={(value) => setApplicationForm({ ...applicationForm, description: value })} textarea />
                  <SelectField label={t("applicationAccountSelection")} value={applicationForm.account_selection_mode} onChange={(value) => setApplicationForm({ ...applicationForm, account_selection_mode: value as typeof applicationForm.account_selection_mode })}>
                    <option value="optional">{t("accountSelectionOptional")}</option>
                    <option value="required">{t("accountSelectionRequired")}</option>
                  </SelectField>
                  <Check label={t("active")} checked={applicationForm.is_active} onChange={(value) => setApplicationForm({ ...applicationForm, is_active: value })} />
                  <div className="form-actions">
                    <span className="form-actions-status" aria-live="polite">{applicationFormIsDirty() ? t("unsavedChanges") : ""}</span>
                    <div className="actions"><button type="submit" disabled={busy}><Save size={14} />{applicationForm.id ? t("save") : t("create")}</button></div>
                  </div>
                </form>
              </Modal>
            )}
            <ApplicationWorkspace
              applications={applications}
              clients={clients}
              providers={providers}
              ldapProviders={ldapProviders}
              locale={locale}
              canManage={canManageActiveOrganization}
              onCreateApplication={() => {
                setApplicationForm(emptyApplicationForm);
                setApplicationFormBaseline(emptyApplicationForm);
                setEditor("application");
              }}
              onEditApplication={(application) => void editApplication(application)}
              onDeleteApplication={(id) => requestConfirmation(() => deleteApplication(id), t("delete"), t("deleteApplicationDescription"))}
              onApplicationModuleChanged={updateApplicationModuleInState}
              initialApplicationId={applicationNavigationId}
              initialSection={applicationNavigationSection}
              onNavigationChange={(applicationId, section) => navigateToTab("applications", { applicationId, applicationSection: section })}
              onDirtyChange={setApplicationWorkspaceDirty}
              onRequestConfirmation={requestConfirmation}
            />
          </>
        )}
        {canReadClients && tab === "clients" && (
          <section className="management-list">
            {canManageClients && editor === "client" && (
              <Modal title={clientForm.id ? t("save") : t("createClient")} closeLabel={t("close")} error={error} dismissible={!busy} onClose={closeEditor} wide>
              <form className="panel" onSubmit={saveClient}>
                <FormErrorSummary title={t("fixFormErrors")} errors={clientFormErrors} />
                <SettingsSection title={t("clientBasics")} description={t("clientBasicsHint")} collapsible={false}>
                  <Field label={t("clientId")} value={clientForm.client_id} onChange={(value) => setClientForm({ ...clientForm, client_id: value })} error={clientFieldErrors.client_id} required />
                  <Field label={t("clientName")} value={clientForm.client_name} onChange={(value) => setClientForm({ ...clientForm, client_name: value })} error={clientFieldErrors.client_name} required />
                  <Field label={t("clientLogoUri")} type="url" value={clientForm.logo_uri} onChange={(value) => setClientForm({ ...clientForm, logo_uri: value })} />
                  <div className="info client-enterprise-lock" role="status">
                    <strong>{t("clientOrganization")}</strong>
                    <span>{organizationContext?.name ?? t("noEnterprise")}</span>
                    <small>{t("clientOrganizationFixed")}</small>
                  </div>
                  <SecretField
                    label={t("clientSecret")}
                    value={clientForm.client_secret}
                    onChange={(value) => setClientForm({ ...clientForm, client_secret: value })}
                    description={clientForm.id ? t("clientSecretHint") : undefined}
                    revealLabel={t("revealSecret")}
                    hideLabel={t("hideSecret")}
                  />
                </SettingsSection>
                <SettingsSection title={t("clientRedirects")} description={t("clientRedirectsHint")}>
                  <ListField
                    label={t("redirectUris")}
                    value={clientForm.redirect_uris}
                    onChange={(value) => setClientForm({ ...clientForm, redirect_uris: value })}
                    error={clientFieldErrors.redirect_uris}
                    addLabel={t("addItem")}
                    removeLabel={t("removeItem")}
                    type="url"
                    description={t("clientRedirectListHint")}
                  />
                  <ListField
                    label={t("postLogoutUris")}
                    value={clientForm.post_logout_redirect_uris}
                    onChange={(value) => setClientForm({ ...clientForm, post_logout_redirect_uris: value })}
                    error={clientFieldErrors.post_logout_redirect_uris}
                    addLabel={t("addItem")}
                    removeLabel={t("removeItem")}
                    type="url"
                  />
                  <Field label={t("backchannelLogoutUri")} type="url" value={clientForm.backchannel_logout_uri} onChange={(value) => setClientForm({ ...clientForm, backchannel_logout_uri: value })} />
                  <Field label={t("frontchannelLogoutUri")} type="url" value={clientForm.frontchannel_logout_uri} onChange={(value) => setClientForm({ ...clientForm, frontchannel_logout_uri: value })} />
                  <div className="check-grid-inline">
                    <Check label={t("backchannelLogoutSessionRequired")} checked={clientForm.backchannel_logout_session_required} onChange={(value) => setClientForm({ ...clientForm, backchannel_logout_session_required: value })} />
                    <Check label={t("frontchannelLogoutSessionRequired")} checked={clientForm.frontchannel_logout_session_required} onChange={(value) => setClientForm({ ...clientForm, frontchannel_logout_session_required: value })} />
                  </div>
                </SettingsSection>
                <SettingsSection title={t("clientProtocol")} description={t("clientProtocolHint")}>
                  <div className="form-grid-2">
                    <Field label={t("scopes")} value={clientForm.scopes} onChange={(value) => setClientForm({ ...clientForm, scopes: value })} />
                    <Field label={t("grantTypes")} value={clientForm.grant_types} onChange={(value) => setClientForm({ ...clientForm, grant_types: value })} />
                    <Field label={t("responseTypes")} value={clientForm.response_types} onChange={(value) => setClientForm({ ...clientForm, response_types: value })} />
                    <SelectField label={t("tokenAuthMethod")} value={clientForm.token_endpoint_auth_method} onChange={(value) => setClientForm({ ...clientForm, token_endpoint_auth_method: value })}>
                      <option value="client_secret_basic">client_secret_basic</option>
                      <option value="client_secret_post">client_secret_post</option>
                      <option value="client_secret_jwt">client_secret_jwt</option>
                      <option value="private_key_jwt">private_key_jwt</option>
                      <option value="none">none</option>
                    </SelectField>
                    <SelectField label={t("subjectType")} value={clientForm.subject_type} onChange={(value) => setClientForm({ ...clientForm, subject_type: value })}>
                      <option value="public">public</option>
                      <option value="pairwise">pairwise</option>
                    </SelectField>
                    <Field label={t("sectorIdentifierUri")} type="url" value={clientForm.sector_identifier_uri} onChange={(value) => setClientForm({ ...clientForm, sector_identifier_uri: value })} />
                  </div>
                </SettingsSection>
                <SettingsSection title={t("clientSecurity")} description={t("clientSecurityHint")}>
                  <div className="check-grid-inline">
                    <Check label={t("requirePkce")} checked={clientForm.require_pkce} onChange={(value) => setClientForm({ ...clientForm, require_pkce: value })} />
                    <Check label={t("requireS256Pkce")} checked={clientForm.require_s256_pkce} error={clientFieldErrors.require_s256_pkce} onChange={(value) => setClientForm({ ...clientForm, require_s256_pkce: value, require_pkce: value ? true : clientForm.require_pkce })} />
                    <Check label={t("requireClientMfa")} checked={clientForm.require_mfa} onChange={(value) => setClientForm({ ...clientForm, require_mfa: value })} />
                    <Check label={t("requirePar")} checked={clientForm.require_pushed_authorization_requests} onChange={(value) => setClientForm({ ...clientForm, require_pushed_authorization_requests: value })} />
                    <Check label={t("requireConfidentialClient")} checked={clientForm.require_confidential_client} onChange={(value) => setClientForm({ ...clientForm, require_confidential_client: value })} />
                    <Check label={t("requireDpop")} checked={clientForm.require_dpop} onChange={(value) => setClientForm({ ...clientForm, require_dpop: value })} />
                    <Check label={t("requireAccountSelection")} checked={clientForm.require_account_selection} onChange={(value) => setClientForm({ ...clientForm, require_account_selection: value })} />
                    <Check label={t("trustEmailVerified")} checked={clientForm.trust_email_verified} onChange={(value) => setClientForm({ ...clientForm, trust_email_verified: value })} />
                  </div>
                </SettingsSection>
                <SettingsSection title={t("clientExtensions")} description={t("clientExtensionsHint")}>
                  <Field label={t("jwksUri")} type="url" value={clientForm.jwks_uri} onChange={(value) => setClientForm({ ...clientForm, jwks_uri: value })} />
                  <Field label={t("jwks")} value={clientForm.jwks} onChange={(value) => setClientForm({ ...clientForm, jwks: value })} textarea />
                  <Field label={t("authorizationDetailsTypes")} textarea value={clientForm.authorization_details_types} onChange={(value) => setClientForm({ ...clientForm, authorization_details_types: value })} />
                  <Check label={t("serviceAccount")} checked={clientForm.service_account_enabled} onChange={(value) => setClientForm({ ...clientForm, service_account_enabled: value })} />
                  {clientForm.service_account_enabled && <Field label={t("serviceAccountPermissions")} textarea value={clientForm.service_account_permissions} onChange={(value) => setClientForm({ ...clientForm, service_account_permissions: value })} />}
                  <Check label={t("active")} checked={clientForm.is_active} onChange={(value) => setClientForm({ ...clientForm, is_active: value })} />
                </SettingsSection>
                <SettingsSection title={t("clientClaims")} description={t("clientClaimsHint")}>
                  <div className="mapper-list">
                    <div className="mapper-heading">
                      <h4>{t("claimMappers")}</h4>
                      <button type="button" onClick={addClientClaimMapper}>
                        <Plus size={14} />
                        {t("addClaimMapper")}
                      </button>
                    </div>
                    {clientForm.claim_mappers.length === 0 && <p className="muted">{t("noData")}</p>}
                    {clientForm.claim_mappers.map((mapper, index) => (
                      <div className="mapper-card" key={index}>
                        <div className="mapper-grid">
                          <Field label={t("claimName")} value={mapper.claim_name} onChange={(value) => updateClientClaimMapper(index, { claim_name: value })} />
                          <SelectField label={t("claimSource")} value={mapper.source} onChange={(value) => updateClientClaimMapper(index, { source: value })}>
                            <option value="user_field">{t("userField")}</option>
                            <option value="static">{t("staticValue")}</option>
                            <option value="scope">{t("scopeFlag")}</option>
                            <option value="client">{t("clientField")}</option>
                          </SelectField>
                          <Field label={t("sourceValue")} value={mapper.source_value} onChange={(value) => updateClientClaimMapper(index, { source_value: value })} />
                          <SelectField label={t("valueType")} value={mapper.value_type} onChange={(value) => updateClientClaimMapper(index, { value_type: value })}>
                            <option value="string">string</option>
                            <option value="bool">bool</option>
                            <option value="number">number</option>
                            <option value="json">json</option>
                          </SelectField>
                        </div>
                        <div className="mapper-targets">
                          <Check label={t("includeIdToken")} checked={mapper.include_in_id_token} onChange={(value) => updateClientClaimMapper(index, { include_in_id_token: value })} />
                          <Check label={t("includeAccessToken")} checked={mapper.include_in_access_token} onChange={(value) => updateClientClaimMapper(index, { include_in_access_token: value })} />
                          <Check label={t("includeUserInfo")} checked={mapper.include_in_userinfo} onChange={(value) => updateClientClaimMapper(index, { include_in_userinfo: value })} />
                          <Check label={t("active")} checked={mapper.is_active} onChange={(value) => updateClientClaimMapper(index, { is_active: value })} />
                          <button type="button" onClick={() => removeClientClaimMapper(index)}>
                            <Trash2 size={14} />
                            {t("delete")}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </SettingsSection>
                <FormActions
                  submitLabel={t("save")}
                  cancelLabel={t("cancel")}
                  onCancel={() => closeEditor()}
                  busy={busy}
                  dirty={clientDraftIsDirty()}
                  statusLabel={clientDraftIsDirty() ? t("unsavedChanges") : undefined}
                  savingLabel={t("saving")}
                />
              </form>
              </Modal>
            )}
            <div className="client-list oidc-client-list">
              {canManageClients && <div className="table-toolbar"><button type="button" onClick={() => openClientEditor({ ...emptyClientForm, organization_id: organizationContext?.id ?? "" })}><Plus size={14} />{t("createClient")}</button></div>}
              {filteredClients.map((client) => (
                <article className="client-card" key={client.id}>
                  <div>
                    <h3>{client.client_name}</h3>
                    <p>{client.client_id} · {client.subject_type} · {client.organization_name ?? t("noOrganization")}</p>
                  </div>
                  <div className="tag-row">{client.scopes.map((scope) => <span key={scope}>{scope}</span>)}</div>
                  {(() => {
                    const application = applicationByOidcClientId.get(client.id);
                    return application ? (
                      <div className="application-connection-summary">
                        <span>{t("applicationConnection")}</span>
                        <strong>{application.name}</strong>
                        {canManageActiveOrganization && (
                          <button className="text-button" type="button" onClick={() => navigateToTab("applications", { applicationId: application.id, applicationSection: "authorization" })}>
                            <Link2 size={14} />
                            {t("openApplicationPolicy")}
                          </button>
                        )}
                      </div>
                    ) : (
                      <p className="muted application-connection-summary">{t("applicationConnectionUnlinked")}</p>
                    );
                  })()}
                  {client.require_mfa && <div className="tag-row"><span>{t("requireClientMfa")}</span></div>}
                  {(client.require_pushed_authorization_requests || client.require_s256_pkce || client.require_confidential_client || client.require_dpop || client.require_account_selection || client.trust_email_verified) && (
                    <div className="tag-row">
                      {client.require_pushed_authorization_requests && <span>{t("requirePar")}</span>}
                      {client.require_s256_pkce && <span>{t("requireS256Pkce")}</span>}
                      {client.require_confidential_client && <span>{t("requireConfidentialClient")}</span>}
                      {client.require_dpop && <span>{t("requireDpop")}</span>}
                      {client.require_account_selection && <span>{t("requireAccountSelection")}</span>}
                      {client.trust_email_verified && <span>{t("trustEmailVerified")}</span>}
                    </div>
                  )}
                  {client.service_account_enabled && (
                    <div className="tag-row">
                      <span>{t("serviceAccount")}</span>
                      {client.service_account_permissions.map((permission) => <span key={permission}>{permission}</span>)}
                    </div>
                  )}
                  {client.authorization_details_types.length > 0 && (
                    <div className="tag-row">
                      <span>{t("authorizationDetailsTypes")}</span>
                      {client.authorization_details_types.map((type) => <span key={type}>{type}</span>)}
                    </div>
                  )}
                  {client.claim_mappers.length > 0 && (
                    <div className="tag-row">
                      {client.claim_mappers.map((mapper) => <span key={mapper.id}>{mapper.claim_name}</span>)}
                    </div>
                  )}
                  <small>{client.redirect_uris.join(", ")}</small>
                  {canManageClients && (
                    <div className="actions client-card-actions">
                      <button type="button" onClick={() => openClientEditor({
                        id: client.id,
                        client_id: client.client_id,
                        client_name: client.client_name,
                        logo_uri: client.logo_uri,
                        organization_id: client.organization_id ?? "",
                        client_secret: "",
                        redirect_uris: client.redirect_uris.join("\n"),
                        post_logout_redirect_uris: client.post_logout_redirect_uris.join("\n"),
                        scopes: joinList(client.scopes),
                        grant_types: joinList(client.grant_types),
                        response_types: joinList(client.response_types),
                        token_endpoint_auth_method: client.token_endpoint_auth_method,
                        require_pkce: client.require_pkce,
                        require_mfa: client.require_mfa,
                        require_pushed_authorization_requests: client.require_pushed_authorization_requests,
                        require_s256_pkce: client.require_s256_pkce,
                        require_confidential_client: client.require_confidential_client,
                        require_dpop: client.require_dpop,
                        require_account_selection: client.require_account_selection,
                        trust_email_verified: client.trust_email_verified,
                        authorization_details_types: joinList(client.authorization_details_types),
                        subject_type: client.subject_type,
                        sector_identifier_uri: client.sector_identifier_uri,
                        jwks_uri: client.jwks_uri,
                        jwks: client.jwks,
                        backchannel_logout_uri: client.backchannel_logout_uri,
                        backchannel_logout_session_required: client.backchannel_logout_session_required,
                        frontchannel_logout_uri: client.frontchannel_logout_uri,
                        frontchannel_logout_session_required: client.frontchannel_logout_session_required,
                        service_account_enabled: client.service_account_enabled,
                        service_account_permissions: client.service_account_permissions.join("\n"),
                        is_active: client.is_active,
                        claim_mappers: client.claim_mappers.map((mapper, index) => ({
                          claim_name: mapper.claim_name,
                          source: mapper.source,
                          source_value: mapper.source_value,
                          value_type: mapper.value_type,
                          include_in_id_token: mapper.include_in_id_token,
                          include_in_access_token: mapper.include_in_access_token,
                          include_in_userinfo: mapper.include_in_userinfo,
                          is_active: mapper.is_active,
                          sort_order: mapper.sort_order ?? index
                        }))
                      })}>{t("edit")}</button>
                      <button className="danger-button" type="button" onClick={() => requestConfirmation(() => deleteClient(client.id))} disabled={busy}>
                        <Trash2 size={14} />
                        {t("delete")}
                      </button>
                    </div>
                  )}
                </article>
              ))}
              {!adminLoading && filteredClients.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} icon={<KeyRound size={22} />} />}
            </div>
          </section>
        )}
        {canReadIap && tab === "iap" && (
          <section className="management-list">
            {canManageIap && editor === "iap" && (
              <Modal title={iapApplicationForm.id ? t("updateIapApplication") : t("createIapApplication")} closeLabel={t("close")} error={error} dismissible={!busy} onClose={closeEditor}>
              <form className="panel" onSubmit={saveIapApplication}>
                <Field label={t("slug")} value={iapApplicationForm.slug} onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, slug: value })} />
                <Field label={t("iapApplication")} value={iapApplicationForm.name} onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, name: value })} />
                <Field label={t("description")} value={iapApplicationForm.description} onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, description: value })} textarea />
                <Field label={t("externalHost")} value={iapApplicationForm.external_host} onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, external_host: value })} />
                <Field label={t("pathPrefix")} value={iapApplicationForm.path_prefix} onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, path_prefix: value })} />
                <SelectField label={t("requiredOrganization")} value={iapApplicationForm.required_organization_id} onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, required_organization_id: value })}>
                  <option value="">{t("noOrganization")}</option>
                  {organizationOptions.map((organization) => (
                    <option key={organization.id} value={organization.id}>
                      {organization.name} · {organization.slug}{organization.is_active ? "" : ` · ${t("disabled")}`}
                    </option>
                  ))}
                </SelectField>
                <label>{t("requiredOrganizationRoles")}</label>
                <div className="checkbox-grid">
                  {["owner", "admin", "member"].map((role) => (
                    <Check
                      key={role}
                      label={role}
                      checked={iapApplicationForm.required_organization_roles.includes(role)}
                      onChange={() => setIapApplicationForm({
                        ...iapApplicationForm,
                        required_organization_roles: toggleValue(iapApplicationForm.required_organization_roles, role)
                      })}
                    />
                  ))}
                </div>
                <Field
                  label={t("requiredPermissions")}
                  textarea
                  value={iapApplicationForm.required_permissions}
                  onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, required_permissions: value })}
                />
                <Check label={t("active")} checked={iapApplicationForm.is_active} onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, is_active: value })} />
                <FormActions
                  submitLabel={iapApplicationForm.id ? t("save") : t("create")}
                  cancelLabel={t("cancel")}
                  onCancel={closeEditor}
                  busy={busy}
                  dirty={iapApplicationFormIsDirty()}
                  statusLabel={iapApplicationFormIsDirty() ? t("unsavedChanges") : undefined}
                  savingLabel={t("saving")}
                />
              </form>
              </Modal>
            )}
            <div className="client-list">
              {canManageIap && <div className="table-toolbar"><button type="button" onClick={() => { setIapApplicationForm(emptyIapApplicationForm); setIapApplicationFormBaseline(emptyIapApplicationForm); setEditor("iap"); }}><Plus size={14} />{t("createIapApplication")}</button></div>}
              {filteredIapApplications.map((application) => {
                const organization = organizationOptions.find((item) => item.id === application.required_organization_id);
                return (
                  <article className="client-card" key={application.id}>
                    <div>
                      <h3>{application.name}</h3>
                      <p>{application.external_host}{application.path_prefix} · {application.is_active ? t("active") : t("disabled")}</p>
                    </div>
                    <small>{application.description ?? "-"}</small>
                    <div className="tag-row">
                      <span>{t("forwardAuthEndpoint")}: /api/iap/forward-auth</span>
                    </div>
                    <div className="tag-row">
                      <span>{t("slug")}: {application.slug}</span>
                      {organization && <span>{organization.name}</span>}
                      {application.required_organization_roles.map((role) => <span key={role}>{role}</span>)}
                    </div>
                    {application.required_permissions.length > 0 && (
                      <div className="tag-row">
                        {application.required_permissions.map((permission) => <span key={permission}>{permission}</span>)}
                      </div>
                    )}
                    <small>{t("updatedAt")}: {formatTime(application.updated_at, locale)}</small>
                    {canManageIap && (
                      <div className="actions">
                        <button type="button" onClick={() => { editIapApplication(application); setEditor("iap"); }}>{t("edit")}</button>
                        <button type="button" onClick={() => requestConfirmation(() => deleteIapApplication(application.id))}>{t("delete")}</button>
                      </div>
                    )}
                  </article>
                );
              })}
              {!adminLoading && filteredIapApplications.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} icon={<Shield size={22} />} />}
            </div>
          </section>
        )}
        {canManageAuthorizationCodes && tab === "invitations" && (
          <section className="management-list">
            {editor === "invitation" && (
              <Modal
                title={invitationForm.id ? t("updateInvitation") : t("createInvitation")}
                closeLabel={t("close")}
                error={error}
                dismissible={!busy}
                onClose={() => {
                  if (closeEditor()) setLastInvitationCode("");
                }}
                wide
              >
                <form className="panel" onSubmit={saveInvitation}>
              <SelectField
                label={t("authorizationCodeType")}
                value={invitationForm.code_type}
                disabled={Boolean(invitationForm.id)}
                description={invitationForm.id ? t("authorizationCodeTypeLocked") : undefined}
                onChange={(value) => {
                  const codeType = value as AuthorizationCodeType;
                  setInvitationForm({
                    ...invitationForm,
                    code_type: codeType,
                    authorized_email: codeType === "login" ? "" : invitationForm.authorized_email,
                    authorized_display_name: codeType === "login" ? "" : invitationForm.authorized_display_name,
                    allowed_client_ids: codeType === "registration" ? [] : invitationForm.allowed_client_ids,
                    organization_id: codeType === "registration" ? "" : invitationForm.organization_id,
                    organization_role: codeType === "registration" ? "member" : invitationForm.organization_role
                  });
                }}
              >
                <option value="registration">{t("registrationAuthorizationCodeType")}</option>
                <option value="login">{t("loginAuthorizationCodeType")}</option>
              </SelectField>
              {invitationForm.code_type === "login" && (
                <SelectField
                  label={t("loginCodeLevel")}
                  value={invitationForm.login_code_level}
                  disabled={Boolean(invitationForm.id)}
                  description={invitationForm.id
                    ? t("loginCodeLevelLocked")
                    : t(
                      invitationForm.login_code_level === "admin_universal"
                        ? "adminUniversalCodeHint"
                        : invitationForm.login_code_level === "trial_enrollment"
                          ? "trialEnrollmentCodeHint"
                          : "accountRecoveryCodeHint"
                    )}
                  onChange={(value) => {
                    const level = value as LoginAuthorizationCodeLevel;
                    const applicationBound = level === "trial_enrollment" || level === "admin_universal";
                    setInvitationForm({
                      ...invitationForm,
                      login_code_level: level,
                      authorized_username: applicationBound ? "" : invitationForm.authorized_username,
                      authorized_display_name: applicationBound ? "" : invitationForm.authorized_display_name,
                      allowed_client_ids: applicationBound ? invitationForm.allowed_client_ids : [],
                      organization_id: level === "trial_enrollment" ? invitationForm.organization_id : "",
                      organization_role: level === "trial_enrollment" ? invitationForm.organization_role : "member"
                    });
                  }}
                >
                  <option value="account_recovery">{t("accountRecoveryCode")}</option>
                  <option value="trial_enrollment">{t("trialEnrollmentCode")}</option>
                  <option value="admin_universal" disabled={!user?.is_admin}>{t("adminUniversalCode")}</option>
                </SelectField>
              )}
              <Field label={t("description")} value={invitationForm.description} onChange={(value) => setInvitationForm({ ...invitationForm, description: value })} />
              {invitationForm.code_type === "registration" && (
                <Field label={t("authorizedEmail")} value={invitationForm.authorized_email} onChange={(value) => setInvitationForm({ ...invitationForm, authorized_email: value })} />
              )}
              {(invitationForm.code_type === "registration" || invitationForm.login_code_level === "account_recovery") && (
                <Field
                  label={invitationForm.code_type === "login" ? t("username") : t("authorizedUsername")}
                  value={invitationForm.authorized_username}
                  onChange={(value) => setInvitationForm({ ...invitationForm, authorized_username: value })}
                  required={invitationForm.code_type === "login"}
                  disabled={Boolean(invitationForm.id) && invitationForm.code_type === "login"}
                  description={invitationForm.code_type === "login"
                    ? t(invitationForm.id ? "boundAccountLocked" : "loginCodeUsernameHint")
                    : undefined}
                />
              )}
              {invitationForm.code_type === "registration" && (
                <Field
                  label={t("authorizedDisplayName")}
                  value={invitationForm.authorized_display_name}
                  onChange={(value) => setInvitationForm({ ...invitationForm, authorized_display_name: value })}
                />
              )}
              {invitationForm.code_type === "login" && (invitationForm.login_code_level === "admin_universal" || invitationForm.login_code_level === "trial_enrollment") && (
                <>
                  {invitationForm.login_code_level === "admin_universal" ? (
                    <div className="error" role="alert">{t("adminUniversalCodeRisk")}</div>
                  ) : (
                    <div className="info" role="status">{t("trialEnrollmentCodeScope")}</div>
                  )}
                  <div role="group" aria-label={t("allowedApplications")}>
                    <label>{t("allowedApplications")}</label>
                    {invitationForm.id && <small className="field-description">{t(invitationForm.login_code_level === "trial_enrollment" ? "trialEnrollmentScopeLocked" : "allowedApplicationsLocked")}</small>}
                    {clients.length > 0 ? (
                      <div className="checkbox-grid">
                        {clients.map((client) => (
                          <Check
                            key={client.client_id}
                            label={`${client.client_name} · ${client.client_id}${client.is_active ? "" : ` · ${t("disabled")}`}`}
                            checked={invitationForm.allowed_client_ids.includes(client.client_id)}
                            disabled={Boolean(invitationForm.id)}
                            onChange={() => setInvitationForm({
                              ...invitationForm,
                              allowed_client_ids: toggleValue(invitationForm.allowed_client_ids, client.client_id)
                            })}
                          />
                        ))}
                      </div>
                    ) : (
                      <div className="info">{t("noOidcClients")}</div>
                    )}
                  </div>
                </>
              )}
              {invitationForm.code_type === "login" && invitationForm.login_code_level === "trial_enrollment" && (
                <div className="enrollment-code-scope">
                  {!canManageOrganizations && <div className="error" role="alert">{t("trialEnrollmentOrganizationManageRequired")}</div>}
                  <SelectField
                    label={t("enrollmentOrganization")}
                    value={invitationForm.organization_id}
                    disabled={Boolean(invitationForm.id)}
                    description={invitationForm.id ? t("trialEnrollmentScopeLocked") : t("trialEnrollmentOrganizationHint")}
                    onChange={(value) => setInvitationForm({ ...invitationForm, organization_id: value })}
                  >
                    <option value="">{t("selectOrganization")}</option>
                    {organizationOptions.map((organization) => (
                      <option key={organization.id} value={organization.id} disabled={!organization.is_active}>
                        {organization.name} · {organization.slug}{organization.is_active ? "" : ` · ${t("disabled")}`}
                      </option>
                    ))}
                  </SelectField>
                  {organizationOptions.length === 0 && <div className="error" role="alert">{t("trialEnrollmentOrganizationUnavailable")}</div>}
                  <SelectField
                    label={t("enrollmentOrganizationRole")}
                    value={invitationForm.organization_role}
                    disabled={Boolean(invitationForm.id)}
                    description={invitationForm.id ? t("trialEnrollmentScopeLocked") : t("trialEnrollmentRoleHint")}
                    onChange={(value) => setInvitationForm({ ...invitationForm, organization_role: value as OrganizationMemberRole })}
                  >
                    <option value="member">{t("organizationRoleMember")}</option>
                    <option value="admin">{t("organizationRoleAdmin")}</option>
                    <option value="owner">{t("organizationRoleOwner")}</option>
                  </SelectField>
                </div>
              )}
              <Field
                label={t("expiresAt")}
                type="datetime-local"
                value={invitationForm.expires_at}
                onChange={(value) => setInvitationForm({ ...invitationForm, expires_at: value })}
                required={invitationForm.code_type === "login" && invitationForm.login_code_level === "trial_enrollment"}
                description={invitationForm.code_type === "login" && invitationForm.login_code_level === "trial_enrollment" ? t("trialEnrollmentExpiryHint") : undefined}
              />
              <Field
                label={t("maxUses")}
                type="number"
                min={1}
                step={1}
                value={invitationForm.max_uses}
                onChange={(value) => setInvitationForm({ ...invitationForm, max_uses: value })}
                required={invitationForm.code_type === "login" && invitationForm.login_code_level === "trial_enrollment"}
                description={invitationForm.code_type === "login" && invitationForm.login_code_level === "trial_enrollment" ? t("trialEnrollmentUsesHint") : undefined}
              />
              <Check label={t("active")} checked={invitationForm.is_active} onChange={(value) => setInvitationForm({ ...invitationForm, is_active: value })} />
              <FormActions
                submitLabel={t("save")}
                cancelLabel={t("cancel")}
                onCancel={closeEditor}
                busy={busy}
                dirty={invitationFormIsDirty()}
                statusLabel={invitationFormIsDirty() ? t("unsavedChanges") : undefined}
                savingLabel={t("saving")}
              />
              {lastInvitationCode && (
                <div className="info">
                  {t("createdInvitation")}: <strong>{lastInvitationCode}</strong>
                  <button className="link-button" type="button" onClick={copyLastInvitationCode}>
                    <Copy size={14} />
                    {t("copyAuthorizationCode")}
                  </button>
                </div>
              )}
                </form>
              </Modal>
            )}
            {revealedInvitation && (
              <Modal
                title={t("authorizationCodeRevealTitle")}
                closeLabel={t("close")}
                error={invitationRevealError}
                onClose={closeInvitationReveal}
                className="invitation-reveal-modal"
              >
                <div className="invitation-reveal-content">
                  <p>{t("authorizationCodeRevealHint")}</p>
                  {revealingInvitationId === revealedInvitation.id ? (
                    <div className="muted">{t("loading")}</div>
                  ) : revealedInvitationCode ? (
                    <div className="invitation-secret-value">
                      <code>{revealedInvitationCode}</code>
                      <button
                        className="link-button"
                        type="button"
                        onClick={() => void copyTextToClipboard(
                          revealedInvitationCode,
                          "authorizationCodeCopied",
                          "copyAuthorizationCodeUnavailable"
                        )}
                      >
                        <Copy size={14} />
                        {t("copyAuthorizationCode")}
                      </button>
                    </div>
                  ) : null}
                </div>
              </Modal>
            )}
            {redemptionsInvitation && (
              <Modal
                title={t("authorizationCodeRedemptionsTitle")}
                closeLabel={t("close")}
                error={invitationRedemptionsError}
                onClose={closeInvitationRedemptions}
                className="invitation-redemptions-modal"
              >
                <div className="invitation-redemptions-content">
                  <div className="invitation-redemptions-summary">
                    <code>{redemptionsInvitation.code_prefix}...</code>
                    <span>{redemptionsInvitation.uses_count}/{redemptionsInvitation.max_uses ?? t("unlimited")}</span>
                  </div>
                  {invitationRedemptionsLoading && invitationRedemptions.length === 0 ? (
                    <div className="muted">{t("loading")}</div>
                  ) : invitationRedemptions.length === 0 ? (
                    <EmptyState title={t("noAuthorizationCodeRedemptions")} icon={<Ticket size={22} />} />
                  ) : (
                    <div className="invitation-redemption-list">
                      {invitationRedemptions.map((redemption) => (
                        <article className="invitation-redemption-row" key={redemption.id}>
                          <strong>{redemption.user_email ?? redemption.user_username ?? redemption.user_id}</strong>
                          <span>{formatTime(redemption.redeemed_at, locale)}</span>
                        </article>
                      ))}
                    </div>
                  )}
                  {invitationRedemptionsNextCursor && (
                    <button
                      type="button"
                      onClick={() => void loadInvitationRedemptions(
                        redemptionsInvitation,
                        invitationRedemptionsNextCursor
                      )}
                      disabled={invitationRedemptionsLoading}
                    >
                      {invitationRedemptionsLoading ? t("loading") : t("loadMore")}
                    </button>
                  )}
                </div>
              </Modal>
            )}
            <div className="table-panel">
              <div className="table-toolbar">
                <h3>{t("invitations")}</h3>
                <button type="button" onClick={() => {
                  setInvitationForm(emptyInvitationForm);
                  setInvitationFormBaseline(emptyInvitationForm);
                  setLastInvitationCode("");
                  setEditor("invitation");
                }}>
                  <Plus size={14} />
                  {t("createInvitation")}
                </button>
              </div>
              <table className="authorization-codes-table">
                <thead><tr><th>{t("authorizationCodePrefix")}</th><th>{t("authorizationCodeType")}</th><th>{t("description")}</th><th>{t("authorizedIdentity")}</th><th>{t("expiresAt")}</th><th>{t("used")}</th><th>{t("status")}</th><th></th></tr></thead>
                <tbody>
                  {filteredInvitations.map((item) => (
                    <tr key={item.id}>
                      <td className="authorization-code-prefix-cell">
                        <code>{item.code_prefix}...</code>
                        <button
                          className="icon-button compact-icon-button"
                          type="button"
                          aria-label={item.can_reveal ? t("revealAuthorizationCode") : t("authorizationCodeRevealUnavailable")}
                          title={item.can_reveal ? t("revealAuthorizationCode") : t("authorizationCodeRevealUnavailable")}
                          disabled={!item.can_reveal || revealingInvitationId === item.id}
                          onClick={() => void revealInvitationCode(item)}
                        >
                          <Eye size={15} />
                        </button>
                      </td>
                      <td>
                        <div className="invitation-type-badges">
                          <StatusBadge tone={item.code_type === "login" ? "info" : "neutral"}>
                            {t(item.code_type === "login" ? "loginAuthorizationCodeType" : "registrationAuthorizationCodeType")}
                          </StatusBadge>
                          {item.code_type === "login" && (
                            <StatusBadge tone={item.login_code_level === "admin_universal" ? "danger" : item.login_code_level === "trial_enrollment" ? "success" : "neutral"}>
                              {t(
                                item.login_code_level === "admin_universal"
                                  ? "adminUniversalCode"
                                  : item.login_code_level === "trial_enrollment"
                                    ? "trialEnrollmentCode"
                                    : "accountRecoveryCode"
                              )}
                            </StatusBadge>
                          )}
                        </div>
                      </td>
                      <td>{item.description ?? "-"}</td>
                      <td>
                        {item.code_type === "login" && item.login_code_level === "trial_enrollment" ? (
                          <div className="token-list">
                            <span>{organizationOptions.find((organization) => organization.id === item.organization_id)?.name ?? item.organization_id ?? "-"}</span>
                            <span>{t("enrollmentOrganizationRole")}: {t(
                              item.organization_role === "owner"
                                ? "organizationRoleOwner"
                                : item.organization_role === "admin"
                                  ? "organizationRoleAdmin"
                                  : "organizationRoleMember"
                            )}</span>
                            {(item.allowed_client_ids ?? []).map((clientId) => (
                              <span key={clientId}>
                                {clients.find((client) => client.client_id === clientId)?.client_name ?? clientId}
                              </span>
                            ))}
                          </div>
                        ) : item.code_type === "login" && item.login_code_level === "admin_universal" ? (
                          <div className="token-list">
                            {(item.allowed_client_ids ?? []).map((clientId) => (
                              <span key={clientId}>
                                {clients.find((client) => client.client_id === clientId)?.client_name ?? clientId}
                              </span>
                            ))}
                            {(item.allowed_client_ids ?? []).length === 0 && <span>-</span>}
                          </div>
                        ) : (
                          item.authorized_email ?? item.authorized_username ?? "-"
                        )}
                      </td>
                      <td>{item.expires_at ? formatTime(item.expires_at, locale) : t("permanent")}</td>
                      <td className="invitation-usage-cell">
                        <span>{item.uses_count}/{item.max_uses ?? t("unlimited")}</span>
                        <button type="button" className="link-button" onClick={() => openInvitationRedemptions(item)}>
                          <Clock3 size={14} />
                          {t("viewRedemptions")}
                        </button>
                      </td>
                      <td>{item.is_active ? t("active") : t("disabled")}</td>
                      <td className="actions">
                        <button type="button" onClick={() => {
                          const nextForm = {
                            id: item.id,
                            code_type: item.code_type,
                            login_code_level: item.login_code_level ?? "account_recovery",
                            allowed_client_ids: item.allowed_client_ids ?? [],
                            organization_id: item.organization_id ?? "",
                            organization_role: item.organization_role ?? "member",
                            description: item.description ?? "",
                            authorized_email: item.authorized_email ?? "",
                            authorized_username: item.authorized_username ?? "",
                            authorized_display_name: item.authorized_display_name ?? "",
                            expires_at: toDatetimeLocalValue(item.expires_at),
                            max_uses: item.max_uses ? String(item.max_uses) : "",
                            is_active: item.is_active
                          };
                          setInvitationForm(nextForm);
                          setInvitationFormBaseline(nextForm);
                          setLastInvitationCode("");
                          setEditor("invitation");
                        }}>{t("edit")}</button>
                        <button type="button" onClick={() => requestConfirmation(() => deleteInvitation(item.id))}>{t("delete")}</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!adminLoading && filteredInvitations.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} icon={<Ticket size={22} />} />}
            </div>
          </section>
        )}
        {canManageSettings && tab === "registration" && registrationSettings && (
          <form className="panel narrow configuration-form" onSubmit={saveRegistrationSettings}>
            <h3>{t("registrationSettings")}</h3>
            <p className="muted">{t("registrationPolicyHint")}</p>
            <SettingsSection title={t("registrationSettings")} description={t("registrationPolicyHint")} collapsible={false}>
              <Check label={t("passwordRegistration")} checked={registrationSettings.allow_password_registration} onChange={(value) => setRegistrationSettings({ ...registrationSettings, allow_password_registration: value })} />
              <Check label={t("requireEmailVerification")} checked={registrationSettings.require_email_verification} onChange={(value) => setRegistrationSettings({ ...registrationSettings, require_email_verification: value })} />
              <Check label={t("requirePhoneVerification")} checked={registrationSettings.require_phone_verification} onChange={(value) => setRegistrationSettings({ ...registrationSettings, require_phone_verification: value })} />
              <Check label={t("allowExternalOidc")} checked={registrationSettings.allow_external_oidc_registration} onChange={(value) => setRegistrationSettings({ ...registrationSettings, allow_external_oidc_registration: value })} />
              <Check label={t("requireInvitation")} checked={registrationSettings.require_invitation} onChange={(value) => setRegistrationSettings({ ...registrationSettings, require_invitation: value })} />
            </SettingsSection>
            <SettingsSection title={t("firstUserAdmin")} description={t("firstUserAdminHint")}>
              <Check label={t("firstUserAdmin")} checked={registrationSettings.first_user_direct_admin} onChange={(value) => setRegistrationSettings({ ...registrationSettings, first_user_direct_admin: value })} />
              <Check label={t("defaultUserActive")} checked={registrationSettings.default_user_active} onChange={(value) => setRegistrationSettings({ ...registrationSettings, default_user_active: value })} />
            </SettingsSection>
            <FormActions
              submitLabel={t("save")}
              busy={busy}
              dirty={registrationSettingsIsDirty()}
              statusLabel={registrationSettingsIsDirty() ? t("unsavedChanges") : undefined}
              savingLabel={t("saving")}
            />
          </form>
        )}
        {canManageProviders && tab === "providers" && (
          <section className="management-list identity-sources-page">
            {editor === "provider" && (
              <Modal
                title={providerForm.id ? t("updateProvider") : t("createProvider")}
                closeLabel={t("close")}
                error={error}
                dismissible={!busy}
                onClose={closeEditor}
                wide
              >
                <form className="panel" onSubmit={saveProvider}>
                  <SettingsSection title={t("providerBasics")} description={t("providerBasicsHint")} collapsible={false}>
                    {providerTemplates.length > 0 && (
                      <>
                        <SelectField label={t("providerTemplate")} value={providerTemplateId} onChange={setProviderTemplateId}>
                          <option value="">-</option>
                          {providerTemplates.map((template) => (
                            <option key={template.id} value={template.id}>{template.display_name}</option>
                          ))}
                        </SelectField>
                        <div className="actions">
                          <button type="button" onClick={applyProviderTemplate} disabled={busy || !providerTemplateId}>
                            <Plus size={14} />
                            {t("applyTemplate")}
                          </button>
                        </div>
                      </>
                    )}
                    <Field label={t("slug")} value={providerForm.slug} onChange={(value) => setProviderForm({ ...providerForm, slug: value, redirect_path: providerRedirectPath(value) })} />
                    <Field label={t("displayName")} value={providerForm.display_name} onChange={(value) => setProviderForm({ ...providerForm, display_name: value })} />
                    {canManagePlatformProviders && (
                      <SelectField label={t("clientOrganization")} value={providerForm.organization_id} onChange={(value) => setProviderForm({ ...providerForm, organization_id: value })}>
                        <option value="">{t("noOrganization")}</option>
                        {organizationOptions.map((organization) => (
                          <option key={organization.id} value={organization.id}>
                            {organization.name} · {organization.slug}{organization.is_active ? "" : ` · ${t("disabled")}`}
                          </option>
                        ))}
                      </SelectField>
                    )}
                  </SettingsSection>
                  <SettingsSection title={t("providerConnection")} description={t("providerConnectionHint")}>
                    <Field label={t("issuer")} type="url" value={providerForm.issuer} onChange={(value) => setProviderForm({ ...providerForm, issuer: value })} />
                    <div className="actions">
                      <button type="button" onClick={() => void discoverProviderEndpoints()} disabled={busy || !providerForm.issuer.trim()}>
                        <RefreshCw size={14} />
                        {t("discoverProvider")}
                      </button>
                    </div>
                    <Field label={t("clientId")} value={providerForm.client_id} onChange={(value) => setProviderForm({ ...providerForm, client_id: value })} />
                    <SecretField
                      label={t("clientSecret")}
                      value={providerForm.client_secret}
                      onChange={(value) => setProviderForm({ ...providerForm, client_secret: value, clear_client_secret: false })}
                      description={providerForm.id ? t("secretLeaveBlank") : undefined}
                      revealLabel={t("revealSecret")}
                      hideLabel={t("hideSecret")}
                    />
                    {providerForm.id && (
                      <Check
                        label={t("clearClientSecret")}
                        checked={providerForm.clear_client_secret}
                        onChange={(value) => setProviderForm({ ...providerForm, clear_client_secret: value, client_secret: value ? "" : providerForm.client_secret })}
                      />
                    )}
                    <div className="form-grid-2">
                      <Field label={t("authorizationEndpoint")} type="url" value={providerForm.authorization_endpoint} onChange={(value) => setProviderForm({ ...providerForm, authorization_endpoint: value })} />
                      <Field label={t("tokenEndpoint")} type="url" value={providerForm.token_endpoint} onChange={(value) => setProviderForm({ ...providerForm, token_endpoint: value })} />
                      <Field label={t("userinfoEndpoint")} type="url" value={providerForm.userinfo_endpoint} onChange={(value) => setProviderForm({ ...providerForm, userinfo_endpoint: value })} />
                      <Field label={t("redirectPath")} value={providerForm.redirect_path} onChange={(value) => setProviderForm({ ...providerForm, redirect_path: value })} />
                    </div>
                    <Field label={t("scopes")} value={providerForm.scopes} onChange={(value) => setProviderForm({ ...providerForm, scopes: value })} />
                    <Field label={t("providerEmailDomains")} value={providerForm.email_domains} onChange={(value) => setProviderForm({ ...providerForm, email_domains: value })} textarea />
                  </SettingsSection>
                  <SettingsSection title={t("providerAccess")} description={t("providerAccessHint")}>
                    <Check label={t("active")} checked={providerForm.is_active} onChange={(value) => setProviderForm({ ...providerForm, is_active: value })} />
                    <Check label={t("allowLogin")} checked={providerForm.allow_login} onChange={(value) => setProviderForm({ ...providerForm, allow_login: value })} />
                    <Check label={t("allowRegistration")} checked={providerForm.allow_registration} onChange={(value) => setProviderForm({ ...providerForm, allow_registration: value })} />
                  </SettingsSection>
                  <FormActions
                    submitLabel={t("save")}
                    cancelLabel={t("cancel")}
                    onCancel={closeEditor}
                    busy={busy}
                    dirty={providerFormIsDirty()}
                    statusLabel={providerFormIsDirty() ? t("unsavedChanges") : undefined}
                    savingLabel={t("saving")}
                  />
                </form>
              </Modal>
            )}
            <section className="identity-source-section">
              <div className="table-toolbar identity-source-toolbar">
                <div>
                  <h3>{t("providers")}</h3>
                  <p className="muted">{t("externalLogin")}</p>
                </div>
                <button type="button" onClick={() => {
                  setProviderForm(emptyProviderForm);
                  setProviderFormBaseline(emptyProviderForm);
                  setProviderTemplateId("");
                  setEditor("provider");
                }}><Plus size={14} />{t("createProvider")}</button>
              </div>
              <div className="client-list identity-source-list">
              {filteredProviders.map((provider) => (
                <article className="client-card" key={provider.id}>
                  {(() => {
                    const organization = organizationOptions.find((item) => item.id === provider.organization_id)
                      ?? (provider.organization_id === organizationContext?.id ? organizationContext : undefined);
                    return (
                      <>
                  <h3>{provider.display_name}</h3>
                  <p>{provider.slug} · {provider.is_active ? t("active") : t("disabled")} · {organization?.name ?? t("noOrganization")}</p>
                  <small>{provider.issuer}</small>
                  {provider.email_domains.length > 0 && (
                    <div className="tag-row">
                      {provider.email_domains.map((domain) => <span key={domain}>@{domain}</span>)}
                    </div>
                  )}
                  <div className="tag-row">
                    {provider.allow_login && <span>{t("allowLogin")}</span>}
                    {provider.allow_registration && <span>{t("allowRegistration")}</span>}
                  </div>
                  <div className="actions">
                    <button type="button" onClick={() => {
                      const nextForm = {
                        id: provider.id,
                        slug: provider.slug,
                        display_name: provider.display_name,
                        organization_id: provider.organization_id ?? "",
                        issuer: provider.issuer,
                        client_id: provider.client_id,
                        client_secret: "",
                        clear_client_secret: false,
                        authorization_endpoint: provider.authorization_endpoint,
                        token_endpoint: provider.token_endpoint,
                        userinfo_endpoint: provider.userinfo_endpoint,
                        redirect_path: provider.redirect_path,
                        scopes: joinList(provider.scopes),
                        email_domains: joinList(provider.email_domains),
                        is_active: provider.is_active,
                        allow_login: provider.allow_login,
                        allow_registration: provider.allow_registration
                      };
                      setProviderForm(nextForm);
                      setProviderFormBaseline(nextForm);
                      setProviderTemplateId("");
                      setEditor("provider");
                    }}>{t("edit")}</button>
                    <button type="button" onClick={() => requestConfirmation(() => deleteProvider(provider.id))}>{t("delete")}</button>
                  </div>
                      </>
                    );
                  })()}
                </article>
              ))}
              {!adminLoading && filteredProviders.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} icon={<Link2 size={22} />} />}
              </div>
            </section>
            {canManagePlatformProviders && editor === "ldap" && (
              <Modal
                title={ldapProviderForm.id ? t("updateLdapProvider") : t("createLdapProvider")}
                closeLabel={t("close")}
                error={error}
                dismissible={!busy}
                onClose={closeEditor}
                wide
              >
                <form className="panel" onSubmit={saveLdapProvider}>
                  <SettingsSection title={t("providerBasics")} description={t("providerBasicsHint")} collapsible={false}>
                    <Field label={t("slug")} value={ldapProviderForm.slug} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, slug: value })} />
                    <Field label={t("displayName")} value={ldapProviderForm.display_name} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, display_name: value })} />
                    {canManagePlatformProviders && (
                      <SelectField label={t("clientOrganization")} value={ldapProviderForm.organization_id} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, organization_id: value })}>
                        <option value="">{t("noOrganization")}</option>
                        {organizationOptions.map((organization) => (
                          <option key={organization.id} value={organization.id}>
                            {organization.name} · {organization.slug}{organization.is_active ? "" : ` · ${t("disabled")}`}
                          </option>
                        ))}
                      </SelectField>
                    )}
                  </SettingsSection>
                  <SettingsSection title={t("directoryConnection")} description={t("directoryConnectionHint")}>
                    <Field label={t("ldapUrl")} value={ldapProviderForm.url} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, url: value })} />
                    <Check label={t("startTls")} checked={ldapProviderForm.starttls} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, starttls: value })} />
                    <Field label={t("bindDn")} value={ldapProviderForm.bind_dn} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, bind_dn: value })} />
                    <SecretField
                      label={t("bindPassword")}
                      value={ldapProviderForm.bind_password}
                      onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, bind_password: value })}
                      revealLabel={t("revealSecret")}
                      hideLabel={t("hideSecret")}
                    />
                    {ldapProviderForm.id && (
                      <Check label={t("clearBindPassword")} checked={ldapProviderForm.clear_bind_password} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, clear_bind_password: value })} />
                    )}
                    <Field label={t("baseDn")} value={ldapProviderForm.base_dn} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, base_dn: value })} />
                    <Field label={t("ldapUserFilter")} value={ldapProviderForm.user_filter} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, user_filter: value })} textarea />
                  </SettingsSection>
                  <SettingsSection title={t("directoryMapping")} description={t("directoryMappingHint")}>
                    <div className="form-grid-2">
                      <Field label={t("userIdAttribute")} value={ldapProviderForm.user_id_attribute} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, user_id_attribute: value })} />
                      <Field label={t("emailAttribute")} value={ldapProviderForm.email_attribute} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, email_attribute: value })} />
                      <Field label={t("usernameAttribute")} value={ldapProviderForm.username_attribute} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, username_attribute: value })} />
                      <Field label={t("displayNameAttribute")} value={ldapProviderForm.display_name_attribute} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, display_name_attribute: value })} />
                      <Field label={t("phoneAttribute")} value={ldapProviderForm.phone_attribute} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, phone_attribute: value })} />
                    </div>
                  </SettingsSection>
                  <SettingsSection title={t("providerAccess")} description={t("providerAccessHint")}>
                    <Check label={t("active")} checked={ldapProviderForm.is_active} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, is_active: value })} />
                    <Check label={t("allowLogin")} checked={ldapProviderForm.allow_login} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, allow_login: value })} />
                    <Check label={t("allowRegistration")} checked={ldapProviderForm.allow_registration} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, allow_registration: value })} />
                  </SettingsSection>
                  <FormActions
                    submitLabel={t("save")}
                    cancelLabel={t("cancel")}
                    onCancel={closeEditor}
                    busy={busy}
                    dirty={ldapProviderFormIsDirty()}
                    statusLabel={ldapProviderFormIsDirty() ? t("unsavedChanges") : undefined}
                    savingLabel={t("saving")}
                  />
                </form>
              </Modal>
            )}
            {canManagePlatformProviders && (
            <section className="identity-source-section">
              <div className="table-toolbar identity-source-toolbar">
                <div>
                  <h3>{t("ldapProviders")}</h3>
                  <p className="muted">{t("directoryLogin")}</p>
                </div>
                <button type="button" onClick={() => {
                  setLdapProviderForm(emptyLdapProviderForm);
                  setLdapProviderFormBaseline(emptyLdapProviderForm);
                  setEditor("ldap");
                }}><Plus size={14} />{t("createLdapProvider")}</button>
              </div>
              <div className="client-list identity-source-list">
              {filteredLdapProviders.map((provider) => (
                <article className="client-card" key={provider.id}>
                  <h3>{provider.display_name}</h3>
                  <p>{provider.slug} · {provider.is_active ? t("active") : t("disabled")}</p>
                  <small>{provider.url} · {provider.base_dn}</small>
                  <div className="tag-row">
                    {provider.allow_login && <span>{t("allowLogin")}</span>}
                    {provider.allow_registration && <span>{t("allowRegistration")}</span>}
                    {provider.starttls && <span>{t("startTls")}</span>}
                    {provider.has_bind_password && <span>{t("hasSecret")}</span>}
                  </div>
                  <div className="tag-row">
                    <span>{provider.user_id_attribute}</span>
                    <span>{provider.email_attribute}</span>
                    <span>{provider.username_attribute}</span>
                  </div>
                  <small>{provider.user_filter}</small>
                  <div className="actions">
                    <button type="button" onClick={() => editLdapProvider(provider)}>{t("edit")}</button>
                    <button type="button" onClick={() => requestConfirmation(() => deleteLdapProvider(provider.id))}>{t("delete")}</button>
                  </div>
                </article>
              ))}
              {!adminLoading && filteredLdapProviders.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} icon={<Users size={22} />} />}
            </div>
          </section>
            )}
          </section>
        )}
        {canManageSettings && tab === "portal" && loginSettings && (
          <section className="split wide">
            <form className="panel configuration-form" onSubmit={saveLoginSettings}>
              <h3>{t("loginSettings")}</h3>
              <p className="muted">{t("loginSettingsHint")}</p>
              <SettingsSection title={t("loginSettings")} description={t("loginSettingsHint")} collapsible={false}>
                <Field
                  label={t("brandLogoUrl")}
                  type="url"
                  autoComplete="url"
                  value={loginSettingsDraft.brand_logo_url}
                  onChange={(value) => setLoginSettingsDraft({ ...loginSettingsDraft, brand_logo_url: value })}
                />
                <Field
                  label={t("companyEmailDomains")}
                  textarea
                  value={loginSettingsDraft.email_domains}
                  onChange={(value) => setLoginSettingsDraft({ ...loginSettingsDraft, email_domains: value })}
                />
              </SettingsSection>
              <FormActions
                submitLabel={t("save")}
                busy={busy}
                dirty={loginSettingsIsDirty()}
                statusLabel={loginSettingsIsDirty() ? t("unsavedChanges") : undefined}
                savingLabel={t("saving")}
              />
            </form>
            <form
              className="table-panel"
              onSubmit={(event) => {
                event.preventDefault();
                void saveQuickLinkDraft();
              }}
            >
              <h3>{quickLinkForm.id ? t("updateQuickLink") : t("createQuickLink")}</h3>
              <SettingsSection title={t("quickLinks")} description={t("loginSettingsHint")} collapsible={false}>
                <Field label={t("linkLabel")} value={quickLinkForm.label} onChange={(value) => setQuickLinkForm({ ...quickLinkForm, label: value })} />
                <Field label={t("linkUrl")} type="url" value={quickLinkForm.url} onChange={(value) => setQuickLinkForm({ ...quickLinkForm, url: value })} />
                <Check label={t("active")} checked={quickLinkForm.is_active} onChange={(value) => setQuickLinkForm({ ...quickLinkForm, is_active: value })} />
                <div className="actions">
                  <button type="submit" disabled={busy}>
                    <Plus size={14} />
                    {quickLinkForm.id ? t("save") : t("create")}
                  </button>
                  {quickLinkForm.id && (
                    <button type="button" onClick={() => setQuickLinkForm(emptyQuickLinkForm)} disabled={busy}>{t("refresh")}</button>
                  )}
                </div>
              </SettingsSection>
              <table>
                <thead><tr><th>{t("linkLabel")}</th><th>{t("linkUrl")}</th><th>{t("status")}</th><th></th></tr></thead>
                <tbody>
                  {loginSettingsDraft.quick_links.map((link) => (
                    <tr key={link.id}>
                      <td>{link.label}</td>
                      <td>{link.url}</td>
                      <td>{link.is_active ? t("active") : t("disabled")}</td>
                      <td className="actions">
                        <button type="button" onClick={() => editQuickLink(link)} disabled={busy}>{t("edit")}</button>
                        <button type="button" onClick={() => requestConfirmation(() => removeQuickLink(link.id))} disabled={busy}>{t("delete")}</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </form>
          </section>
        )}
        {(canManageSecurity || canReadAudit) && tab === "security" && (
          <section className="security-page wide">
            {canManageSecurity && (
              <>
                <div className="security-overview-grid">
                  <section className="panel security-card security-mfa-card" aria-labelledby="security-mfa-heading">
                    <div className="security-card-heading">
                      <div className="security-card-title">
                        <span className="security-card-icon" aria-hidden="true"><Shield size={18} /></span>
                        <div>
                          <h3 id="security-mfa-heading">{t("mfaSettings")}</h3>
                          <p>{t("recoveryCodesRemaining")}: {mfaStatus?.recovery_codes_remaining ?? 0}/{mfaStatus?.recovery_codes_total ?? 0}</p>
                        </div>
                      </div>
                      <StatusBadge tone={mfaStatus?.enabled ? "success" : "neutral"}>
                        <Shield size={13} aria-hidden="true" />
                        {mfaStatus?.enabled ? t("active") : t("disabled")}
                      </StatusBadge>
                    </div>
                    <div className="actions security-card-actions">
                      <button className="security-action-primary" type="button" onClick={startTotpSetup} disabled={busy}><KeyRound size={14} />{t("startTotpSetup")}</button>
                      {mfaStatus?.enabled && <button type="button" onClick={() => requestConfirmation(rotateRecoveryCodes, t("rotateRecoveryCodes"), t("rotateRecoveryCodesDescription"))} disabled={busy}>{t("rotateRecoveryCodes")}</button>}
                      {mfaStatus?.enabled && <button className="danger-button" type="button" onClick={() => requestConfirmation(disableMfa, t("disableMfa"), t("disableMfaDescription"))} disabled={busy}>{t("disableMfa")}</button>}
                    </div>
                    {totpSetup && (
                      <div className="mfa-setup security-mfa-setup">
                        <label htmlFor="security-totp-secret">{t("totpSecret")}</label>
                        <textarea id="security-totp-secret" readOnly value={totpSetup.secret} />
                        <label htmlFor="security-otpauth-uri">{t("otpauthUri")}</label>
                        <textarea id="security-otpauth-uri" readOnly value={totpSetup.otpauth_uri} />
                        <Field label={t("mfaCode")} value={totpSetupCode} onChange={setTotpSetupCode} />
                        <div className="actions">
                          <button className="security-action-primary" type="button" onClick={confirmTotpSetup} disabled={busy}><Save size={14} />{t("confirmTotp")}</button>
                        </div>
                      </div>
                    )}
                    {newRecoveryCodes.length > 0 && (
                      <div className="info security-recovery-codes">
                        <strong>{t("recoveryCodes")}</strong>
                        <p>{t("recoveryCodesOnce")}</p>
                        <div className="token-list">
                          {newRecoveryCodes.map((code) => <span key={code}>{code}</span>)}
                        </div>
                      </div>
                    )}
                  </section>

                  <section className="table-panel security-card security-signing-card" aria-labelledby="security-signing-keys-heading">
                    <div className="security-card-heading">
                      <div className="security-card-title">
                        <span className="security-card-icon" aria-hidden="true"><KeyRound size={18} /></span>
                        <div>
                          <h3 id="security-signing-keys-heading">{t("signingKeys")}</h3>
                          <p>{t("keyId")}</p>
                        </div>
                      </div>
                      <StatusBadge tone={signingKeys.some((key) => key.is_active) ? "success" : "warning"}>
                        {signingKeys.some((key) => key.is_active) ? t("activeSigningKey") : t("retiredSigningKey")}
                      </StatusBadge>
                    </div>
                    <div className="security-key-controls">
                      <Field label={t("keyId")} value={signingKeyKid} onChange={setSigningKeyKid} />
                      <button className="security-action-primary" type="button" onClick={() => requestConfirmation(rotateSigningKey)} disabled={busy}><RotateCcw size={14} />{t("rotateSigningKey")}</button>
                    </div>
                    <table className="security-signing-table">
                      <thead><tr><th>{t("keyId")}</th><th>{t("status")}</th><th>{t("registeredAt")}</th><th>{t("activatedAt")}</th><th>{t("retiredAt")}</th></tr></thead>
                      <tbody>
                        {signingKeys.map((key) => (
                          <tr key={key.id}>
                            <td>{key.kid}</td>
                            <td>{key.is_active ? t("activeSigningKey") : t("retiredSigningKey")}</td>
                            <td>{formatTime(key.created_at, locale)}</td>
                            <td>{formatTime(key.activated_at, locale)}</td>
                            <td>{formatTime(key.retired_at, locale)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {signingKeys.length === 0 && <div className="empty">{t("noData")}</div>}
                  </section>
                </div>

                {securityPolicy && (
                  <form className="panel security-policy-panel" onSubmit={saveSecurityPolicy}>
                    <div className="security-policy-header">
                      <div className="security-card-title">
                        <span className="security-card-icon" aria-hidden="true"><Shield size={18} /></span>
                        <div>
                          <h3>{t("securityPolicy")}</h3>
                          <p>{t("passwordPolicy")} · {t("accessRiskRules")}</p>
                        </div>
                      </div>
                      <span className="security-policy-status" aria-live="polite">
                        {securityPolicyIsDirty() ? t("unsavedChanges") : t("changesSaved")}
                      </span>
                    </div>
                    <div className="security-policy-sections">
                      <section className="security-policy-section" aria-labelledby="security-password-policy-heading">
                        <h4 id="security-password-policy-heading">{t("passwordPolicy")}</h4>
                        <Field
                          label={t("minPasswordLength")}
                          type="number"
                          value={String(securityPolicy.password_min_length)}
                          onChange={(value) => setSecurityPolicy({ ...securityPolicy, password_min_length: Number(value) })}
                        />
                        <div className="security-check-grid">
                          <Check label={t("requireUppercase")} checked={Boolean(securityPolicy.password_require_uppercase)} onChange={(value) => setSecurityPolicy({ ...securityPolicy, password_require_uppercase: value ? 1 : 0 })} />
                          <Check label={t("requireLowercase")} checked={Boolean(securityPolicy.password_require_lowercase)} onChange={(value) => setSecurityPolicy({ ...securityPolicy, password_require_lowercase: value ? 1 : 0 })} />
                          <Check label={t("requireDigit")} checked={Boolean(securityPolicy.password_require_digit)} onChange={(value) => setSecurityPolicy({ ...securityPolicy, password_require_digit: value ? 1 : 0 })} />
                          <Check label={t("requireSymbol")} checked={Boolean(securityPolicy.password_require_symbol)} onChange={(value) => setSecurityPolicy({ ...securityPolicy, password_require_symbol: value ? 1 : 0 })} />
                          <Check label={t("rejectUserInfo")} checked={Boolean(securityPolicy.password_reject_user_info)} onChange={(value) => setSecurityPolicy({ ...securityPolicy, password_reject_user_info: value ? 1 : 0 })} />
                        </div>
                      </section>

                      <section className="security-policy-section" aria-labelledby="security-login-protection-heading">
                        <h4 id="security-login-protection-heading">{t("loginLockout")}</h4>
                        <Check label={t("active")} checked={Boolean(securityPolicy.login_lockout_enabled)} onChange={(value) => setSecurityPolicy({ ...securityPolicy, login_lockout_enabled: value ? 1 : 0 })} />
                        <div className="security-field-grid security-compact-fields">
                          <Field
                            label={t("maxFailedAttempts")}
                            type="number"
                            value={String(securityPolicy.max_failed_login_attempts)}
                            onChange={(value) => setSecurityPolicy({ ...securityPolicy, max_failed_login_attempts: Number(value) })}
                          />
                          <Field
                            label={t("failureWindowSeconds")}
                            type="number"
                            value={String(securityPolicy.failure_window_seconds)}
                            onChange={(value) => setSecurityPolicy({ ...securityPolicy, failure_window_seconds: Number(value) })}
                          />
                          <Field
                            label={t("lockoutSeconds")}
                            type="number"
                            value={String(securityPolicy.lockout_seconds)}
                            onChange={(value) => setSecurityPolicy({ ...securityPolicy, lockout_seconds: Number(value) })}
                          />
                        </div>
                        <div className="security-policy-subsection">
                          <h5>{t("captchaPolicy")}</h5>
                          <Check
                            label={t("active")}
                            checked={securityPolicy.captcha_enabled}
                            onChange={(value) => setSecurityPolicy({ ...securityPolicy, captcha_enabled: value })}
                          />
                          <div className="security-field-grid">
                            <Field
                              label={t("captchaAfterFailedAttempts")}
                              type="number"
                              value={String(securityPolicy.captcha_after_failed_attempts)}
                              onChange={(value) => setSecurityPolicy({ ...securityPolicy, captcha_after_failed_attempts: Number(value) })}
                            />
                            <Field
                              label={t("captchaTtlSeconds")}
                              type="number"
                              value={String(securityPolicy.captcha_ttl_seconds)}
                              onChange={(value) => setSecurityPolicy({ ...securityPolicy, captcha_ttl_seconds: Number(value) })}
                            />
                          </div>
                        </div>
                      </section>

                      <section className="security-policy-section security-policy-section-wide" aria-labelledby="security-trusted-networks-heading">
                        <h4 id="security-trusted-networks-heading">{t("trustedNetworks")}</h4>
                        <div className="security-network-grid">
                          <ListField
                            label={t("trustedIpCidrs")}
                            value={joinList(securityPolicy.trusted_ip_cidrs)}
                            onChange={(value) => setSecurityPolicy({ ...securityPolicy, trusted_ip_cidrs: splitList(value) })}
                            addLabel={t("addItem")}
                            removeLabel={t("removeItem")}
                          />
                          <div className="security-network-option">
                            <Check
                              label={t("requireMfaOutsideTrustedNetworks")}
                              checked={securityPolicy.require_mfa_outside_trusted_networks}
                              onChange={(value) => setSecurityPolicy({ ...securityPolicy, require_mfa_outside_trusted_networks: value })}
                            />
                          </div>
                        </div>
                      </section>

                      <section className="security-policy-section security-policy-section-wide" aria-labelledby="security-risk-rules-heading">
                        <h4 id="security-risk-rules-heading">{t("accessRiskRules")}</h4>
                        <div className="security-risk-grid">
                          <ListField
                            label={t("allowedIpCidrs")}
                            value={joinList(securityPolicy.allowed_ip_cidrs)}
                            onChange={(value) => setSecurityPolicy({ ...securityPolicy, allowed_ip_cidrs: splitList(value) })}
                            addLabel={t("addItem")}
                            removeLabel={t("removeItem")}
                          />
                          <ListField
                            label={t("blockedIpCidrs")}
                            value={joinList(securityPolicy.blocked_ip_cidrs)}
                            onChange={(value) => setSecurityPolicy({ ...securityPolicy, blocked_ip_cidrs: splitList(value) })}
                            addLabel={t("addItem")}
                            removeLabel={t("removeItem")}
                          />
                          <ListField
                            label={t("allowedEmailDomains")}
                            value={joinList(securityPolicy.allowed_email_domains)}
                            onChange={(value) => setSecurityPolicy({ ...securityPolicy, allowed_email_domains: splitList(value).map(normalizeDomain) })}
                            addLabel={t("addItem")}
                            removeLabel={t("removeItem")}
                          />
                          <ListField
                            label={t("blockedEmailDomains")}
                            value={joinList(securityPolicy.blocked_email_domains)}
                            onChange={(value) => setSecurityPolicy({ ...securityPolicy, blocked_email_domains: splitList(value).map(normalizeDomain) })}
                            addLabel={t("addItem")}
                            removeLabel={t("removeItem")}
                          />
                        </div>
                      </section>
                    </div>
                    <FormActions
                      className="security-form-actions"
                      submitLabel={t("save")}
                      busy={busy}
                      dirty={securityPolicyIsDirty()}
                      statusLabel={securityPolicyIsDirty() ? t("unsavedChanges") : undefined}
                      savingLabel={t("saving")}
                    />
                  </form>
                )}

                {editor === "role" && <Modal title={roleForm.id ? t("updateRole") : t("createRole")} closeLabel={t("close")} error={error} dismissible={!busy} onClose={closeEditor}>
                  <form className="panel" onSubmit={saveRole}>
                    <Field label={t("roleName")} value={roleForm.name} onChange={(value) => setRoleForm({ ...roleForm, name: value })} />
                    <Field label={t("description")} value={roleForm.description} onChange={(value) => setRoleForm({ ...roleForm, description: value })} textarea />
                    <label>{t("rolePermissions")}</label>
                    <div className="checkbox-grid">
                      {permissionCatalog.map((permission) => (
                        <Check
                          key={permission.key}
                          label={`${permission.key} · ${permission.category}`}
                          checked={roleForm.permissions.includes(permission.key)}
                          onChange={() => setRoleForm({ ...roleForm, permissions: toggleValue(roleForm.permissions, permission.key) })}
                        />
                      ))}
                    </div>
                    <FormActions
                      submitLabel={roleForm.id ? t("save") : t("create")}
                      cancelLabel={t("cancel")}
                      onCancel={closeEditor}
                      busy={busy}
                      dirty={roleFormIsDirty()}
                      statusLabel={roleFormIsDirty() ? t("unsavedChanges") : undefined}
                      savingLabel={t("saving")}
                    />
                  </form>
                </Modal>}

                {editor === "group" && <Modal title={groupForm.id ? t("updateGroup") : t("createGroup")} closeLabel={t("close")} error={error} dismissible={!busy} onClose={closeEditor}>
                  <form className="panel" onSubmit={saveGroup}>
                    <Field label={t("groupName")} value={groupForm.name} onChange={(value) => setGroupForm({ ...groupForm, name: value })} />
                    <Field label={t("description")} value={groupForm.description} onChange={(value) => setGroupForm({ ...groupForm, description: value })} textarea />
                    <label>{t("groupRoles")}</label>
                    <div className="checkbox-grid">
                      {roles.map((role) => (
                        <Check
                          key={role.id}
                          label={role.name}
                          checked={groupForm.role_ids.includes(role.id)}
                          onChange={() => setGroupForm({ ...groupForm, role_ids: toggleValue(groupForm.role_ids, role.id) })}
                        />
                      ))}
                    </div>
                    <label>{t("groupMembers")}</label>
                    <div className="checkbox-grid tall">
                      {users.map((item) => (
                        <Check
                          key={item.id}
                          label={`${item.email} · ${item.username}`}
                          checked={groupForm.user_ids.includes(item.id)}
                          onChange={() => setGroupForm({ ...groupForm, user_ids: toggleValue(groupForm.user_ids, item.id) })}
                        />
                      ))}
                    </div>
                    <FormActions
                      submitLabel={groupForm.id ? t("save") : t("create")}
                      cancelLabel={t("cancel")}
                      onCancel={closeEditor}
                      busy={busy}
                      dirty={groupFormIsDirty()}
                      statusLabel={groupFormIsDirty() ? t("unsavedChanges") : undefined}
                      savingLabel={t("saving")}
                    />
                  </form>
                </Modal>}

                <div className="security-management-grid">
                  <section className="table-panel security-roles-panel">
                    <div className="table-toolbar"><h3>{t("roles")}</h3><button type="button" onClick={() => { setRoleForm(emptyRoleForm); setRoleFormBaseline(emptyRoleForm); setEditor("role"); }}><Plus size={14} />{t("createRole")}</button></div>
                    <table>
                      <thead><tr><th>{t("role")}</th><th>{t("permissions")}</th><th>{t("status")}</th><th></th></tr></thead>
                      <tbody>
                        {filteredRoles.map((role) => (
                          <tr key={role.id}>
                            <td>{role.name}<br /><small>{role.description ?? "-"}</small></td>
                            <td><div className="token-list">{role.permissions.map((permission) => <span key={permission}>{permission}</span>)}</div></td>
                            <td>{role.is_system ? t("systemRole") : t("customRole")}</td>
                            <td className="actions">
                              {!role.is_system && <button type="button" onClick={() => { editRole(role); setEditor("role"); }}>{t("edit")}</button>}
                              {!role.is_system && <button type="button" onClick={() => requestConfirmation(() => deleteRole(role.id))}>{t("delete")}</button>}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {!adminLoading && filteredRoles.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} />}
                  </section>

                  <section className="panel security-user-access-panel">
                    <h3>{t("userAccess")}</h3>
                    <SelectField
                      label={t("selectUser")}
                      value={selectedAccessUserId}
                      disabled={busy}
                      onChange={(value) => void runUiAction(() => loadUserAccess(value))}
                    >
                      <option value="">-</option>
                      {users.map((item) => (
                        <option key={item.id} value={item.id}>{item.email}</option>
                      ))}
                    </SelectField>
                    {userAccess && (
                      <>
                        <label>{t("directRoles")}</label>
                        <div className="checkbox-grid">
                          {roles.map((role) => {
                            const selected = userAccess.direct_roles.some((item) => item.id === role.id);
                            return (
                              <Check
                                key={role.id}
                                label={role.name}
                                checked={selected}
                                onChange={() => setUserAccess({
                                  ...userAccess,
                                  direct_roles: selected
                                    ? userAccess.direct_roles.filter((item) => item.id !== role.id)
                                    : [...userAccess.direct_roles, role]
                                })}
                              />
                            );
                          })}
                        </div>
                        <div className="actions">
                          <button className="security-action-primary" type="button" onClick={() => void saveUserRoles()} disabled={busy}><Save size={14} />{t("save")}</button>
                        </div>
                        <label>{t("groups")}</label>
                        <div className="token-list security-access-token-list">{userAccess.groups.map((group) => <span key={group.id}>{group.name}</span>)}</div>
                        <label>{t("effectivePermissions")}</label>
                        <div className="token-list security-access-token-list">{userAccess.effective_permissions.map((permission) => <span key={permission}>{permission}</span>)}</div>
                      </>
                    )}
                  </section>

                  <section className="table-panel security-groups-panel">
                    <div className="table-toolbar"><h3>{t("groups")}</h3><button type="button" onClick={() => { setGroupForm(emptyGroupForm); setGroupFormBaseline(emptyGroupForm); setEditor("group"); }}><Plus size={14} />{t("createGroup")}</button></div>
                    <table>
                      <thead><tr><th>{t("groups")}</th><th>{t("groupRoles")}</th><th>{t("groupMembers")}</th><th></th></tr></thead>
                      <tbody>
                        {filteredGroups.map((group) => (
                          <tr key={group.id}>
                            <td>{group.name}<br /><small>{group.description ?? "-"}</small></td>
                            <td><div className="token-list">{(group.roles ?? []).map((role) => <span key={role.id}>{role.name}</span>)}</div></td>
                            <td><div className="token-list">{(group.members ?? []).map((member) => <span key={member.id}>{member.email}</span>)}</div></td>
                            <td className="actions">
                              <button type="button" onClick={() => { editGroup(group); setEditor("group"); }}>{t("edit")}</button>
                              <button type="button" onClick={() => requestConfirmation(() => deleteGroup(group.id))}>{t("delete")}</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {!adminLoading && filteredGroups.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} />}
                  </section>
                </div>
              </>
            )}

            <div className="security-audit-layout">
              {canManageSecurity && (
                <form className="panel security-webhook-form" onSubmit={saveAuditWebhook}>
                  <h3>{auditWebhookForm.id ? t("updateAuditWebhook") : t("createAuditWebhook")}</h3>
                  <SettingsSection title={t("providerBasics")} description={t("auditWebhooks")} collapsible={false}>
                    <Field label={t("webhookName")} value={auditWebhookForm.name} onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, name: value })} />
                    <Field label={t("webhookUrl")} type="url" value={auditWebhookForm.url} onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, url: value })} />
                    <SecretField
                      label={t("webhookSecret")}
                      value={auditWebhookForm.secret}
                      onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, secret: value, clear_secret: false })}
                      description={auditWebhookForm.id ? t("secretLeaveBlank") : undefined}
                      revealLabel={t("revealSecret")}
                      hideLabel={t("hideSecret")}
                    />
                    {auditWebhookForm.id && (
                      <Check label={t("clearWebhookSecret")} checked={auditWebhookForm.clear_secret} onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, clear_secret: value, secret: value ? "" : auditWebhookForm.secret })} />
                    )}
                  </SettingsSection>
                  <SettingsSection title={t("webhookActions")} description={t("webhookActions")}>
                    <ListField
                      label={t("webhookActions")}
                      value={auditWebhookForm.actions}
                      onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, actions: value })}
                      addLabel={t("addItem")}
                      removeLabel={t("removeItem")}
                    />
                    <Field
                      label={t("webhookTimeout")}
                      type="number"
                      value={String(auditWebhookForm.timeout_seconds)}
                      onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, timeout_seconds: Number(value) })}
                    />
                    <Check label={t("active")} checked={auditWebhookForm.is_active} onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, is_active: value })} />
                  </SettingsSection>
                  <FormActions
                    submitLabel={auditWebhookForm.id ? t("save") : t("create")}
                    busy={busy}
                    dirty={auditWebhookFormIsDirty()}
                    statusLabel={auditWebhookFormIsDirty() ? t("unsavedChanges") : undefined}
                    savingLabel={t("saving")}
                    cancelLabel={auditWebhookForm.id ? t("clear") : undefined}
                    onCancel={auditWebhookForm.id ? () => {
                      setAuditWebhookForm(emptyAuditWebhookForm);
                      setAuditWebhookFormBaseline(emptyAuditWebhookForm);
                    } : undefined}
                  />
                </form>
              )}
              {(canReadAudit || canManageSecurity) && (
                <section className="table-panel security-webhooks-panel">
                  <h3>{t("auditWebhooks")}</h3>
                  <table>
                    <thead>
                      <tr>
                        <th>{t("webhookName")}</th>
                        <th>{t("webhookActions")}</th>
                        <th>{t("deliveryStatus")}</th>
                        <th>{t("status")}</th>
                        <th></th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAuditWebhooks.map((webhook) => (
                        <tr key={webhook.id}>
                          <td>
                            {webhook.name}<br />
                            <a href={webhook.url} target="_blank" rel="noreferrer"><ExternalLink size={12} /> {webhook.url}</a>
                          </td>
                          <td>
                            <div className="token-list">
                              {(webhook.actions.length > 0 ? webhook.actions : ["*"]).map((action) => <span key={action}>{action}</span>)}
                              {webhook.has_secret && <span>{t("hasSecret")}</span>}
                            </div>
                          </td>
                          <td>
                            {webhook.last_status_code ?? "-"}<br />
                            <small>{webhook.last_error ?? formatTime(webhook.last_delivered_at, locale)}</small>
                          </td>
                          <td>{webhook.is_active ? t("active") : t("disabled")}</td>
                          <td className="actions">
                            {canManageSecurity && <button type="button" onClick={() => editAuditWebhook(webhook)}>{t("edit")}</button>}
                            {canManageSecurity && <button type="button" onClick={() => requestConfirmation(() => deleteAuditWebhook(webhook.id))}>{t("delete")}</button>}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {!adminLoading && filteredAuditWebhooks.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} />}
                </section>
              )}
            </div>

            {canReadAudit && (
              <section className="table-panel security-audit-events-panel">
                <h3>{t("auditEvents")}</h3>
                <table>
                  <thead><tr><th>{t("action")}</th><th>{t("actor")}</th><th>{t("target")}</th><th>{t("outcome")}</th><th>{t("registeredAt")}</th></tr></thead>
                  <tbody>
                    {filteredAuditEvents.map((event) => (
                      <tr key={event.id}>
                        <td>{event.action}<br /><small>{event.details}</small></td>
                        <td>{event.actor_user_id ?? event.actor_client_id ?? "-"}</td>
                        <td>{event.target_kind}<br /><small>{event.target_id ?? "-"}</small></td>
                        <td>{event.outcome}</td>
                        <td>{formatTime(event.created_at, locale)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!adminLoading && filteredAuditEvents.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} />}
              </section>
            )}
          </section>
        )}
        {canManageSettings && tab === "settings" && settings && runtimeSettings && (
          <section className="split wide">
            <form className="panel configuration-form" onSubmit={saveRuntimeSettings}>
              <h3>{t("runtimeSettings")}</h3>
              <p className="muted">{t("runtimeSettingsHint")}</p>
              <SettingsSection title={t("runtimeSettings")} description={t("runtimeSettingsHint")} collapsible={false}>
                <Field label={t("publicBaseUrl")} type="url" value={runtimeSettings.public_base_url} onChange={(value) => setRuntimeSettings({ ...runtimeSettings, public_base_url: value })} required />
                <Field label={t("issuer")} type="url" value={runtimeSettings.issuer} onChange={(value) => setRuntimeSettings({ ...runtimeSettings, issuer: value })} />
                <Check label={t("trustProxyHeaders")} checked={runtimeSettings.trust_proxy_headers} onChange={(value) => setRuntimeSettings({ ...runtimeSettings, trust_proxy_headers: value })} />
                <div className="info">
                  <strong>{t("effectivePublicBaseUrl")}:</strong> {runtimeSettings.effective_public_base_url}<br />
                  <strong>{t("effectiveIssuer")}:</strong> {runtimeSettings.effective_issuer}
                </div>
              </SettingsSection>
              <FormActions
                submitLabel={t("save")}
                busy={busy}
                dirty={runtimeSettingsIsDirty()}
                statusLabel={runtimeSettingsIsDirty() ? t("unsavedChanges") : undefined}
                savingLabel={t("saving")}
              />
            </form>
            <div className="panel diagnostics-panel">
              <h3>{t("diagnostics")}</h3>
              <p className="muted">{t("diagnosticsHint")}</p>
              <SettingsSection title={t("diagnosticsRuntime")} collapsible={false}>
                <div className="settings-grid diagnostics-grid">
                  <div className="setting-row"><span>{t("effectivePublicBaseUrl")}</span><strong>{runtimeSettings.effective_public_base_url}</strong></div>
                  <div className="setting-row"><span>{t("effectiveIssuer")}</span><strong>{runtimeSettings.effective_issuer}</strong></div>
                  <div className="setting-row"><span>{t("publicBaseUrl")}</span><strong>{settings.runtime_public_base_url}</strong></div>
                  <div className="setting-row"><span>{t("trustProxyHeaders")}</span><strong>{formatDiagnosticValue(settings.runtime_trust_proxy_headers, t)}</strong></div>
                </div>
              </SettingsSection>
              <SettingsSection title={t("diagnosticsOidc")}>
                <div className="settings-grid diagnostics-grid">
                  <div className="setting-row"><span>{t("issuer")}</span><strong>{settings.config_issuer}</strong></div>
                  <div className="setting-row"><span>{t("scopes")}</span><strong>{formatDiagnosticValue(settings.supported_scopes, t)}</strong></div>
                  <div className="setting-row"><span>{t("accessTokenTtl")}</span><strong>{settings.access_token_ttl_seconds}s</strong></div>
                  <div className="setting-row"><span>{t("idTokenTtl")}</span><strong>{settings.id_token_ttl_seconds}s</strong></div>
                  <div className="setting-row"><span>{t("refreshTokenTtl")}</span><strong>{settings.refresh_token_ttl_seconds}s</strong></div>
                </div>
              </SettingsSection>
              <SettingsSection title={t("diagnosticsStorage")}>
                <div className="settings-grid diagnostics-grid">
                  <div className="setting-row"><span>{t("database")}</span><strong>{settings.database_kind}</strong></div>
                  <div className="setting-row"><span>{t("databasePoolSize")}</span><strong>{settings.database_pool_size}</strong></div>
                  <div className="setting-row"><span>{t("runMigrations")}</span><strong>{formatDiagnosticValue(settings.run_migrations, t)}</strong></div>
                </div>
              </SettingsSection>
              <SettingsSection title={t("diagnosticsSecurity")}>
                <div className="settings-grid diagnostics-grid">
                  <div className="setting-row"><span>{t("cookieSecure")}</span><strong>{formatDiagnosticValue(settings.cookie_secure, t)}</strong></div>
                  <div className="setting-row"><span>{t("cookieSameSite")}</span><strong>{settings.cookie_same_site}</strong></div>
                  <div className="setting-row"><span>{t("corsAllowedOrigins")}</span><strong>{formatDiagnosticValue(settings.cors_allowed_origins, t)}</strong></div>
                </div>
              </SettingsSection>
            </div>
          </section>
        )}
      </main>
      {pendingConfirmation && (
        <Modal
          title={pendingConfirmation.title}
          closeLabel={t("close")}
          error={error}
          dismissible={!busy}
          onClose={() => {
            setPendingConfirmation(null);
            setError("");
          }}
        >
          <div className="confirm-dialog">
            <div className="confirm-icon"><Trash2 size={22} /></div>
            <p>{pendingConfirmation.description}</p>
            <div className="actions confirm-actions">
              <button type="button" onClick={() => { setPendingConfirmation(null); setError(""); }} disabled={busy}>{t("cancel")}</button>
              <button type="button" className="danger-button" onClick={() => void runPendingConfirmation()} disabled={busy}>
                {t("continue")}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

function TopLanguage({
  locale,
  supportedLocales,
  switchLocale,
  label,
  compact = false
}: {
  locale: Locale;
  supportedLocales: string[];
  switchLocale: (locale: Locale) => void;
  label: string;
  compact?: boolean;
}) {
  return (
    <div className={compact ? "language-row compact-language" : "language-row"} role="group" aria-label={label}>
      <Globe2 size={16} />
      <span>{label}</span>
      {supportedLocales.includes("zh-CN") && <button type="button" className={locale === "zh-CN" ? "active" : ""} aria-pressed={locale === "zh-CN"} onClick={() => switchLocale("zh-CN")}>中文</button>}
      {supportedLocales.includes("en-US") && <button type="button" className={locale === "en-US" ? "active" : ""} aria-pressed={locale === "en-US"} onClick={() => switchLocale("en-US")}>EN</button>}
    </div>
  );
}

function Metric({ label, value, detail }: { label: string; value: string | number; detail: string }) {
  const text = String(value);
  const compact = text.length > 12;
  const schemeBoundary = typeof value === "string" && /^https?:\/\//.test(value)
    ? value.indexOf("//") + 2
    : 0;
  return (
    <Card as="article" className="metric">
      <span>{label}</span>
      <strong className={compact ? "metric-compact" : undefined}>
        {schemeBoundary ? <>{text.slice(0, schemeBoundary)}<wbr />{text.slice(schemeBoundary)}</> : value}
      </strong>
      <p>{detail}</p>
    </Card>
  );
}

function EmailField({
  label,
  value,
  onChange,
  domains,
  customDomain,
  onCustomDomainChange,
  customLabel,
  applyLabel,
  required = true
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  domains: string[];
  customDomain: string;
  onCustomDomainChange: (value: string) => void;
  customLabel: string;
  applyLabel: string;
  required?: boolean;
}) {
  const customSuffix = usableEmailDomain(customDomain);
  return (
    <div className="email-field">
      <Field label={label} value={value} onChange={onChange} type="email" autoComplete="email" required={required} />
      {domains.length > 0 && (
        <div className="domain-pills" role="group" aria-label={label}>
          {domains.map((domain) => (
            <button type="button" key={domain} onClick={() => onChange(applyEmailDomain(value, domain))}>
              @{domain}
            </button>
          ))}
        </div>
      )}
      <div className="custom-domain">
        <input aria-label={customLabel} autoComplete="off" value={customDomain} placeholder={customLabel} onChange={(event) => onCustomDomainChange(event.target.value)} />
        <button type="button" disabled={!customSuffix} onClick={() => onChange(applyEmailDomain(value, customSuffix))}>
          <AtSign size={14} />
          {applyLabel}
        </button>
      </div>
    </div>
  );
}

function QuickJump({ links }: { links: QuickLink[] }) {
  if (links.length === 0) return null;
  return (
    <div className="quick-jump">
      {links.map((link) => <QuickJumpLink key={`${link.id}:${link.url}`} link={link} />)}
    </div>
  );
}

function QuickJumpLink({ link }: { link: QuickLink }) {
  const faviconUrl = quickLinkFaviconUrl(link.url);
  const [faviconState, setFaviconState] = useState<"loading" | "loaded" | "failed">(
    faviconUrl ? "loading" : "failed"
  );

  return (
    <a className="quick-jump-link" href={link.url} target="_blank" rel="noreferrer" title={link.label} aria-label={link.label}>
      <span className={`quick-jump-icon${faviconState === "loaded" ? " has-favicon" : ""}`} aria-hidden="true">
        <span className="quick-jump-fallback">{quickLinkInitial(link.label)}</span>
        {faviconUrl && (
          <img
            src={faviconUrl}
            alt=""
            referrerPolicy="no-referrer"
            onLoad={() => setFaviconState("loaded")}
            onError={() => setFaviconState("failed")}
          />
        )}
      </span>
    </a>
  );
}

function quickLinkFaviconUrl(url: string): string | null {
  try {
    const target = new URL(url);
    return new URL("/favicon.ico", target.origin).toString();
  } catch {
    return null;
  }
}

function quickLinkInitial(label: string): string {
  return Array.from(label.trim())[0]?.toLocaleUpperCase() ?? "?";
}

function InlineCode({
  icon,
  label,
  button,
  value,
  onChange,
  onSend,
  disabled = false
}: {
  icon: React.ReactNode;
  label: string;
  button: string;
  value: string;
  onChange: (value: string) => void;
  onSend: () => void;
  disabled?: boolean;
}) {
  return (
    <div className="inline-code">
      <Field label={label} value={value} onChange={onChange} autoComplete="one-time-code" />
      <button type="button" onClick={onSend} disabled={disabled}>{icon}{button}</button>
    </div>
  );
}

function UserDetailPanel({
  detail,
  locale,
  t
}: {
  detail: UserDetail;
  locale: Locale;
  t: (key: TranslationKey) => string;
}) {
  return (
    <section className="detail-panel modal-detail-panel">
      <div className="detail-grid">
        <Info label={t("email")} value={`${detail.user.email} · ${detail.user.email_verified_at ? t("verified") : t("unverified")}`} />
        <Info label={t("phone")} value={`${detail.user.phone ?? "-"} · ${detail.user.phone_verified_at ? t("verified") : t("unverified")}`} />
        <Info label={t("status")} value={detail.user.archived_at !== null ? t("archived") : detail.user.is_active ? t("active") : t("disabled")} />
        <Info
          label={t("registrationSource")}
          value={detail.user.registration_source === "authorization_code" ? t("authorizationCodeRegistered") : t("localRegistration")}
        />
        <Info label={t("archivedAt")} value={formatTime(detail.user.archived_at, locale)} />
        <Info label={t("registeredAt")} value={formatTime(detail.user.created_at, locale)} />
        <Info label={t("lastLogin")} value={formatTime(detail.user.last_login_at, locale)} />
        <Info label={t("lastIp")} value={detail.user.last_login_ip ?? "-"} />
        <Info label={t("lastClient")} value={detail.user.last_oidc_client_id ?? "-"} />
        <Info label={t("loginMethod")} value={detail.user.last_login_method ?? "-"} />
      </div>
      {detail.user.archived_at !== null && <p className="muted">{t("archivedReadOnly")}</p>}
      <h4>{t("organizations")}</h4>
      {detail.organizations.length === 0 ? <p className="muted">{t("noData")}</p> : detail.organizations.map((organization) => (
        <div className="event-row" key={organization.id}>
          <strong>{organization.name}</strong>
          <span>{organization.slug} · {organization.role} · {organization.is_active ? t("active") : t("disabled")}</span>
        </div>
      ))}
      <h4>{t("linkedIdentities")}</h4>
      {detail.linked_identities.length === 0 ? <p className="muted">{t("noData")}</p> : detail.linked_identities.map((item) => (
        <div className="event-row" key={item.id}>
          <strong>{item.provider_slug}</strong>
          <span>{item.external_email ?? item.external_subject}</span>
        </div>
      ))}
      <h4>{t("loginEvents")}</h4>
      {detail.login_events.length === 0 ? <p className="muted">{t("noData")}</p> : (
        <ol className="login-event-list">
          {detail.login_events.map((event) => {
            const clientOrProvider = event.oidc_client_id ?? event.external_provider;
            const clientOrProviderLabel = event.oidc_client_id
              ? t("lastClient")
              : t("linkedIdentities");
            return (
              <li className="login-event" key={event.id}>
                <span className="login-event-marker" aria-hidden="true"><Activity size={16} /></span>
                <div className="login-event-content">
                  <div className="login-event-heading">
                    <div className="login-event-method">
                      <KeyRound size={16} aria-hidden="true" />
                      <strong>{event.method || "-"}</strong>
                    </div>
                    <time dateTime={new Date(event.login_at * 1000).toISOString()}>
                      <Clock3 size={15} aria-hidden="true" />
                      <span>{formatTime(event.login_at, locale)}</span>
                    </time>
                  </div>
                  <dl className="login-event-meta">
                    <div>
                      <dt><Globe2 size={14} aria-hidden="true" />{t("lastIp")}</dt>
                      <dd>{event.ip_address ?? "-"}</dd>
                    </div>
                    {clientOrProvider && (
                      <div>
                        <dt><Link2 size={14} aria-hidden="true" />{clientOrProviderLabel}</dt>
                        <dd>{clientOrProvider}</dd>
                      </div>
                    )}
                    {event.user_agent && (
                      <div className="login-event-device" title={event.user_agent}>
                        <dt><Monitor size={14} aria-hidden="true" />{t("userAgent")}</dt>
                        <dd>{event.user_agent}</dd>
                      </div>
                    )}
                  </dl>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="info-cell">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
