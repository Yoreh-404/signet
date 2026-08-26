import {
  Activity,
  Archive,
  AtSign,
  Ban,
  Building2,
  ChevronDown,
  ChevronUp,
  Clock3,
  Coins,
  ExternalLink,
  FileUp,
  Filter,
  Globe2,
  KeyRound,
  Link2,
  LogOut,
  Mail,
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
import { ChangeEvent, FormEvent, lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
import {
  Card,
  Check,
  EmptyState,
  Field,
  FormActions,
  FormErrorSummary,
  ListField,
  Modal,
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
import {
  EnterpriseAuthWorkspace
} from "./features/auth/EnterpriseAuthWorkspace";
import { InvitationsWorkspace } from "./features/invitations/InvitationsWorkspace";
import { useInvitationRedemptions } from "./features/invitations/useInvitationRedemptions";
import { useAccountController } from "./features/admin/use-account-controller";
import { useApplicationController } from "./features/admin/use-application-controller";
import { useAdminDataLoader } from "./features/admin/use-admin-data-loader";
import { useLatestRequest } from "./features/admin/use-latest-request";
import { useInvitationController } from "./features/admin/use-invitation-controller";
import { deriveAdminPermissions } from "./features/admin/admin-permissions";
import { useAdminNavigation } from "./features/navigation/useAdminNavigation";
import { AdminSidebar } from "./features/navigation/AdminSidebar";
import type { AdminSidebarNavigationGroup } from "./features/navigation/AdminSidebar";
import { AdminHeader } from "./features/navigation/AdminHeader";
import type { AdminHeaderTab } from "./features/navigation/AdminHeader";
import { useOrganizationController } from "./features/admin/use-organization-controller";
import { useRoleController } from "./features/admin/use-role-controller";
import { useSettingsController } from "./features/admin/use-settings-controller";
import { useSessionController } from "./features/session/useSessionController";
import { PortalWorkspace } from "./features/settings/PortalWorkspace";
import { RegistrationSettingsPanel } from "./features/settings/RegistrationSettingsPanel";
import { SettingsWorkspace } from "./features/settings/SettingsWorkspace";
import { AccountWorkspace } from "./features/account/AccountWorkspace";
import { SecurityWorkspace } from "./features/security/SecurityWorkspace";
import { ProvidersWorkspace } from "./features/providers/ProvidersWorkspace";
import { useUserDirectoryCursor } from "./features/users/use-user-directory";
import { useUserSelection } from "./features/users/use-user-selection";
import { UserEditorModal } from "./features/users/UserEditorModal";
import { BulkUserImportModal } from "./features/users/BulkUserImportModal";
import { UserTable } from "./features/users/UserTable";
import { OrganizationsWorkspace } from "./features/organizations/OrganizationsWorkspace";
import type { OrganizationFormState } from "./features/organizations/OrganizationWorkspace";
import type { BulkUserImportFormState } from "./features/users/BulkUserImportModal";
import {
  availableUserActions,
  BULK_USER_IMPORT_TEMPLATE,
  isBulkUserImportResult,
  lifecycleStateForUser
} from "./features/users/user-lifecycle";
import type { BulkUserAction, UserLifecycleState } from "./features/users/user-lifecycle";
import { isDirtyDomain } from "./features/admin/stable-domain-comparator";
import { confirmDiscardChanges } from "./features/admin/confirm-discard-changes";
import { useUserController } from "./features/admin/use-user-controller";
import * as adminApi from "./lib/api/admin";
import * as accountApi from "./lib/api/account";
import type { WalletWorkspaceHandle } from "./features/billing/WalletWorkspace";
import { translations } from "./i18n";
import type { TranslationKey } from "./i18n";
import {
  api,
  ApiError
} from "./lib/api";
import * as applicationApi from "./lib/api/applications";
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
  emptyGroupForm,
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
  browserAccountShortName,
  formatDiagnosticValue,
  inlineAccountLoginFlow,
  matchesHttpUrl
} from "./app-helpers";
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
  AuditEvent,
  AuditWebhook,
  BrowserAccount,
  BrowserAccountsContext,
  AuthorizationCodeInspection,
  AuthMode,
  BulkUserImportResult,
  Client,
  ExternalProvider,
  ExternalProviderDiscovery,
  ExternalProviderTemplate,
  Invitation,
  LdapProvider,
  Locale,
  LoginMethod,
  LoginResponse,
  LoginSettings,
  LoginSettingsDraft,
  LogoutResponse,
  Organization,
  OrganizationMember,
  OrganizationOption,
  OidcContinuationLoginResponse,
  Overview,
  PendingConfirmation,
  PermissionInfo,
  QuickLink,
  RegistrationSettings,
  Role,
  SecurityPolicy,
  SigningKey,
  Tab,
  Theme,
  TenantApplication,
  User,
  UserAccess,
  UserDetail,
  UserFilter,
  UserOption,
} from "./types";

const ApplicationWorkspace = lazy(() =>
  import("./features/applications/ApplicationWorkspace").then(({ ApplicationWorkspace }) => ({
    default: ApplicationWorkspace
  }))
);
const WalletWorkspace = lazy(() =>
  import("./features/billing/WalletWorkspace").then(({ WalletWorkspace }) => ({
    default: WalletWorkspace
  }))
);

type UserRoleFilter = "all" | "admin" | "user";
type UserLoginRegionFilter = "all" | "domestic" | "overseas";
type UserLinkedIdentityFilter = "all" | "linked" | "unlinked";
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

  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const sidebarRef = useRef<HTMLElement | null>(null);
  const mobileMenuButtonRef = useRef<HTMLButtonElement | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const applicationCreateMutationRef = useRef<{
    fingerprint: string;
    key: string;
  } | null>(null);
  const applicationDeleteMutationRef = useRef<{
    applicationId: string;
    organizationId: string | null;
    scopeKey: string | null;
    key: string;
  } | null>(null);
  const bulkLifecycleMutationRef = useRef<{
    action: adminApi.UserLifecycleBatchAction;
    userIds: string[];
    key: string;
  } | null>(null);
  const walletWorkspaceRef = useRef<WalletWorkspaceHandle | null>(null);
  const [initialLoadError, setInitialLoadError] = useState("");
  const accountController = useAccountController({
    initialAuth,
    initialError: authContextError(initialAuth, t)
  });
  const {
    mfaStatus,
    setMfaStatus,
    totpSetup,
    setTotpSetup,
    totpSetupCode,
    setTotpSetupCode,
    newRecoveryCodes,
    setNewRecoveryCodes,
    passkeys,
    setPasskeys,
    passkeyName,
    setPasskeyName,
    myConsents,
    setMyConsents,
    mySessions,
    setMySessions,
    signingKeyKid,
    setSigningKeyKid,
    accountLoadId,
    accountAbortController,
    registerForm,
    setRegisterForm,
    registrationCodeInspection,
    setRegistrationCodeInspection,
    registrationCodeInspecting,
    setRegistrationCodeInspecting,
    passwordResetForm,
    setPasswordResetForm,
    authEmail,
    setAuthEmail,
    loginMethod,
    setLoginMethod,
    authorizationCodeLoginForm,
    setAuthorizationCodeLoginForm,
    loginPassword,
    setLoginPassword,
    loginMfaChallengeId,
    setLoginMfaChallengeId,
    loginMfaCode,
    setLoginMfaCode,
    loginRecoveryAvailable,
    setLoginRecoveryAvailable,
    loginCaptchaChallengeId,
    setLoginCaptchaChallengeId,
    loginCaptchaPrompt,
    setLoginCaptchaPrompt,
    loginCaptchaAnswer,
    setLoginCaptchaAnswer,
    loginCustomDomain,
    setLoginCustomDomain,
    registerCustomDomain,
    setRegisterCustomDomain,
    resetCustomDomain,
    setResetCustomDomain,
    authMode,
    setAuthMode,
    authReturnTo,
    accountLoginExpanded,
    setAccountLoginExpanded,
    accountLoginFlow,
    setAccountLoginFlow,
    browserAccountsContext,
    setBrowserAccountsContext,
    selectedBrowserAccount,
    setSelectedBrowserAccount,
    continueWithBrowserAccount,
    setContinueWithBrowserAccount,
    browserAccountContinuing,
    setBrowserAccountContinuing,
    lastInvitationCode,
    setLastInvitationCode,
    verificationMessage,
    setVerificationMessage,
    error,
    setError,
    busy,
    setBusy,
    authModeHeadingRef,
    pendingConfirmation,
    setPendingConfirmation
  } = accountController;

  const {
    selectedUser,
    setSelectedUser,
    userFilter,
    setUserFilter,
    userOrganizationFilter,
    setUserOrganizationFilter,
    userFiltersExpanded,
    setUserFiltersExpanded,
    userEmailFilter,
    setUserEmailFilter,
    userRoleFilter,
    setUserRoleFilter,
    userRegistrationFrom,
    setUserRegistrationFrom,
    userRegistrationTo,
    setUserRegistrationTo,
    userLastLoginFrom,
    setUserLastLoginFrom,
    userLastLoginTo,
    setUserLastLoginTo,
    userPhoneFilter,
    setUserPhoneFilter,
    userLoginRegionFilter,
    setUserLoginRegionFilter,
    userLinkedIdentityFilter,
    setUserLinkedIdentityFilter,
    userDirectoryPage,
    setUserDirectoryPage,
    userDirectoryPageSize,
    userDirectoryCursorHistory,
    setUserDirectoryCursorHistory,
    selectedUserIds,
    setSelectedUserIds,
    userForm,
    setUserForm,
    userFormBaseline,
    setUserFormBaseline,
    bulkImportOpen,
    setBulkImportOpen,
    bulkImportCsv,
    setBulkImportCsv,
    bulkImportFileName,
    setBulkImportFileName,
    bulkImportDryRun,
    setBulkImportDryRun,
    bulkImportCommitConfirmed,
    setBulkImportCommitConfirmed,
    bulkImportResult,
    setBulkImportResult,
    bulkImportError,
    setBulkImportError
  } = useUserController();

  const {
    applicationForm,
    setApplicationForm,
    applicationFormBaseline,
    setApplicationFormBaseline
  } = useApplicationController();
  const organizationController = useOrganizationController();
  const {
    enterpriseForm,
    setEnterpriseForm,
    enterpriseFormBaseline,
    setEnterpriseFormBaseline,
    enterpriseMemberEmail,
    setEnterpriseMemberEmail,
    enterpriseMemberRole,
    setEnterpriseMemberRole,
    organizationMemberInvitationForm,
    setOrganizationMemberInvitationForm,
    revealedOrganizationMemberInvitation,
    setRevealedOrganizationMemberInvitation,
    organizationForm,
    setOrganizationForm,
    organizationFormBaseline,
    setOrganizationFormBaseline,
    organizationMemberRolesBaseline,
    setOrganizationMemberRolesBaseline,
    organizationMemberRoles,
    setOrganizationMemberRoles,
    organizationMembers,
    setOrganizationMembers,
    organizationMemberInvitations,
    setOrganizationMemberInvitations,
    organizationMembersLoading,
    setOrganizationMembersLoading,
    organizationMembersLoadId
  } = organizationController;
  const {
    invitationForm,
    setInvitationForm,
    invitationFormBaseline,
    setInvitationFormBaseline,
    revealedInvitation,
    setRevealedInvitation,
    revealedInvitationCode,
    setRevealedInvitationCode,
    revealingInvitationId,
    setRevealingInvitationId,
    invitationRevealError,
    setInvitationRevealError
  } = useInvitationController();
  const {
    roleForm,
    setRoleForm,
    roleFormBaseline,
    setRoleFormBaseline,
    groupForm,
    setGroupForm,
    groupFormBaseline,
    setGroupFormBaseline,
    selectedAccessUserId,
    setSelectedAccessUserId,
    userAccess,
    setUserAccess
  } = useRoleController();
  const selectedInvitationClientIds = useMemo(
    () => new Set(invitationForm.allowed_client_ids),
    [invitationForm.allowed_client_ids]
  );
  const selectedDirectRoleIds = useMemo(
    () => new Set(userAccess?.direct_roles.map((role) => role.id) ?? []),
    [userAccess?.direct_roles]
  );
  const {
    providerForm,
    setProviderForm,
    providerFormBaseline,
    setProviderFormBaseline,
    providerTemplateId,
    setProviderTemplateId,
    ldapProviderForm,
    setLdapProviderForm,
    ldapProviderFormBaseline,
    setLdapProviderFormBaseline,
    auditWebhookForm,
    setAuditWebhookForm,
    auditWebhookFormBaseline,
    setAuditWebhookFormBaseline,
    editor,
    setEditor,
    loginSettingsDraft,
    setLoginSettingsDraft,
    quickLinkForm,
    setQuickLinkForm,
    quickLinkFormBaseline,
    setQuickLinkFormBaseline,
    providerDiscoveryRequest
  } = useSettingsController();

  const userDetailsRequest = useLatestRequest();
  const userAccessRequest = useLatestRequest();

  const session = useSessionController({ returnTo: authReturnTo });
  const {
    bootstrap,
    user,
    myOrganizations,
    organizationContext,
    cacheScope,
    organizationContextReady: enterpriseContextReady,
    initialize: initializeSession,
    loadBootstrap: loadSessionBootstrap,
    loadOrganizationContext: loadSessionOrganizationContext,
    switchOrganization: switchSessionOrganization,
    transitionToAuthenticated,
    transitionToAnonymous
  } = session;
  const invitationRedemptions = useInvitationRedemptions();
  const invitationRedemptionsError = invitationRedemptions.error
    ? messageOr(invitationRedemptions.error, "loadAuthorizationCodeRedemptionsFailed")
    : "";

  const {
    tab,
    applicationId: applicationNavigationId,
    applicationSection: applicationNavigationSection,
    billingOrder: billingOrderReference,
    dirtyNavigation,
    navigateToTab
  } = useAdminNavigation({
    initialState: initialNavigationState,
    confirmNavigation: () => confirmDiscardChanges(t),
    onAccepted: () => {
      resetUserDirectoryQueryState();
      setSearchQuery("");
      setSidebarOpen(false);
    }
  });

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
  const {
    hasGlobalConsolePermission,
    canAdmin,
    canReadUsers,
    canManageUsers,
    canManageActiveOrganization,
    canReadOrganizations,
    canManageOrganizations,
    canManageAuthorizationCodes,
    canManageSettings,
    canManagePlatformProviders,
    canManageProviders,
    canReadAudit,
    canManageSecurity
  } = deriveAdminPermissions({
    permissions: userPermissions,
    organization: organizationContext,
    restrictedLoginCodeSession: isRestrictedLoginCodeSession
  });

  const {
    overview,
    setOverview,
    userOptions,
    setUserOptions,
    clients,
    setClients,
    applications,
    setApplications,
    invitations,
    setInvitations,
    registrationSettings,
    setRegistrationSettings,
    registrationSettingsBaseline,
    setRegistrationSettingsBaseline,
    providers,
    setProviders,
    providerTemplates,
    setProviderTemplates,
    ldapProviders,
    setLdapProviders,
    auditEvents,
    setAuditEvents,
    auditWebhooks,
    setAuditWebhooks,
    permissionCatalog,
    setPermissionCatalog,
    roles,
    setRoles,
    groups,
    setGroups,
    organizations,
    setOrganizations,
    organizationOptions,
    setOrganizationOptions,
    signingKeys,
    setSigningKeys,
    settings,
    setSettings,
    runtimeSettings,
    setRuntimeSettings,
    runtimeSettingsBaseline,
    setRuntimeSettingsBaseline,
    loginSettings,
    setLoginSettings,
    loginSettingsBaseline,
    setLoginSettingsBaseline,
    securityPolicy,
    setSecurityPolicy,
    securityPolicyBaseline,
    setSecurityPolicyBaseline,
    adminLoading,
    loadAdminData,
    invalidateAdminLoad
  } = useAdminDataLoader({
    tab,
    session: session.controller,
    scopeKey: cacheScope,
    onLoginSettingsLoaded: setLoginSettingsDraft,
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
  });

  const userDirectoryFilterKey = useMemo(() => JSON.stringify({
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
  }), [
    searchQuery,
    userEmailFilter,
    userFilter,
    userLastLoginFrom,
    userLastLoginTo,
    userLinkedIdentityFilter,
    userLoginRegionFilter,
    userOrganizationFilter,
    userPhoneFilter,
    userRegistrationFrom,
    userRegistrationTo,
    userRoleFilter
  ]);
  const previousUserDirectoryFilterKey = useRef(userDirectoryFilterKey);
  const userDirectoryFilterTransition = previousUserDirectoryFilterKey.current !== userDirectoryFilterKey;
  useEffect(() => {
    previousUserDirectoryFilterKey.current = userDirectoryFilterKey;
  }, [userDirectoryFilterKey]);

  const userDirectoryQuery = useMemo(() => ({
    // Filter changes are reconciled by the following effect, but the query
    // must switch to the first keyset page during the same render. Otherwise
    // the cursor from the previous filter set can issue one stale request.
    page: userDirectoryFilterTransition ? 1 : userDirectoryPage,
    page_size: userDirectoryPageSize,
    cursor: userDirectoryFilterTransition
      ? undefined
      : userDirectoryCursorHistory[userDirectoryPage - 1] ?? undefined,
    status: userFilter,
    search: searchQuery,
    organization_id: userOrganizationFilter,
    linked_identity: userLinkedIdentityFilter === "all" ? undefined : userLinkedIdentityFilter,
    email: userEmailFilter,
    phone: userPhoneFilter,
    role: userRoleFilter === "all" ? undefined : userRoleFilter,
    registration_from: userRegistrationFrom,
    registration_to: userRegistrationTo,
    last_login_from: userLastLoginFrom,
    last_login_to: userLastLoginTo,
    login_region: userLoginRegionFilter === "all" ? undefined : userLoginRegionFilter
  }), [
    searchQuery,
    userDirectoryCursorHistory,
    userDirectoryFilterKey,
    userDirectoryFilterTransition,
    userDirectoryPage,
    userEmailFilter,
    userFilter,
    userLastLoginFrom,
    userLastLoginTo,
    userLinkedIdentityFilter,
    userLoginRegionFilter,
    userOrganizationFilter,
    userPhoneFilter,
    userRegistrationFrom,
    userRegistrationTo,
    userRoleFilter
  ]);
  const userDirectory = useUserDirectoryCursor({
    endpoint: "/api/admin/users/cursor",
    query: userDirectoryQuery,
    enabled: canAdmin && canReadUsers && !initialAuth.isAuthPage && tab === "users",
    scopeKey: cacheScope
  });

  // The cursor query is the sole owner of the visible page. Keeping a second
  // controller-owned users/next-cursor mirror creates a stale render window
  // whenever a filter, account, or organization scope changes.
  const users = userDirectory.data?.items ?? [];
  const userDirectoryNextCursor = userDirectory.data?.next_cursor ?? null;

  useEffect(() => {
    if (userDirectory.data?.items.length === 0 && userDirectoryPage > 1) {
      // A mutation can remove the only row on the current cursor page. Go
      // back to the retained predecessor instead of leaving a dead end.
      setUserDirectoryPage((page) => Math.max(1, page - 1));
    }
    if (tab === "users" && userDirectory.data) setError("");
  }, [setError, tab, userDirectory.data, userDirectoryPage]);

  useEffect(() => {
    if (tab !== "users") return;
    if (userDirectory.error) setError(messageOr(userDirectory.error, "loadFailed"));
  }, [tab, userDirectory.error, userDirectory.loading]);

  const adminViewLoading = adminLoading || userDirectory.loading;

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
    // Session ownership lives in the controller. Loading the organization
    // context here also closes the old login path where a newly authenticated
    // account retained the previous account's enterprise/cache scope.
    void transitionToAuthenticated(nextUser).catch(() => undefined);
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
    const next = await loadSessionBootstrap(authReturnTo);
    if (!localStorage.getItem("gpt-sso-locale") && next.default_locale === "en-US") {
      setLocale("en-US");
    }
    if (!next.has_users) {
      setAuthMode("register");
    }
  }

  async function loadEnterpriseContext(userId?: string) {
    return loadSessionOrganizationContext(userId);
  }

  function invalidateAccountLoad() {
    accountLoadId.current += 1;
    accountAbortController.current?.abort();
    accountAbortController.current = null;
  }

  async function loadAccountData() {
    const requestId = ++accountLoadId.current;
    accountAbortController.current?.abort();
    const controller = new AbortController();
    accountAbortController.current = controller;
    const started = session.controller.getSnapshot();
    const startedUserId = started.user?.id ?? null;
    const startedOrganizationId = started.organizationContext?.id ?? null;
    const startedScope = started.cacheScope;
    const startedSessionGeneration = session.controller.getGeneration();
    const isCurrent = () => {
      const current = session.controller.getSnapshot();
      return accountLoadId.current === requestId
        && !controller.signal.aborted
        && session.controller.getGeneration() === startedSessionGeneration
        && current.cacheScope === startedScope
        && (current.user?.id ?? null) === startedUserId
        && (current.organizationContext?.id ?? null) === startedOrganizationId;
    };

    try {
      if (!started.user) {
        if (!isCurrent()) return;
        setMfaStatus(null);
        setPasskeys([]);
        setMyConsents([]);
        setMySessions([]);
        return;
      }
      const [nextMfaStatus, nextPasskeys, nextConsents, nextSessions] = await Promise.all([
        accountApi.getMfaStatus({ signal: controller.signal }),
        accountApi.listPasskeys({ signal: controller.signal }),
        accountApi.listConsents({ signal: controller.signal }),
        accountApi.listSessions({ signal: controller.signal })
      ]);
      if (!isCurrent()) return;
      setMfaStatus(nextMfaStatus);
      setPasskeys(nextPasskeys);
      setMyConsents(nextConsents);
      setMySessions(nextSessions);
    } catch (error) {
      // A request that belongs to an older account, organization, or session
      // is expected to lose the race; it must not surface as a new-page error.
      if (!isCurrent()) return;
      throw error;
    } finally {
      if (accountAbortController.current === controller) accountAbortController.current = null;
    }
  }

  // Admin read lifecycle is owned by useAdminDataLoader. App only composes
  // the read model with form state and mutation commands.
  async function initialize() {
    setInitialLoadError("");
    try {
      const next = await initializeSession({ returnTo: authReturnTo });
      if (!localStorage.getItem("gpt-sso-locale") && next.bootstrap?.default_locale === "en-US") {
        setLocale("en-US");
      }
      if (!next.bootstrap?.has_users) setAuthMode("register");
    } catch (err) {
      transitionToAnonymous();
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
    if (initialAuth.isAuthPage) {
      invalidateAccountLoad();
      return;
    }
    void loadAccountData().catch((err) => setError(messageOr(err, "loadFailed")));
    return () => {
      invalidateAccountLoad();
    };
  }, [initialAuth.isAuthPage, user?.id, cacheScope]);

  useEffect(() => {
    // Clear data immediately when the scope changes. The render-time guard
    // above prevents in-flight responses from repopulating this cleared view.
    setOrganizationMembers([]);
    setOrganizationMemberInvitations([]);
    setSelectedUser(null);
    setSelectedUserIds([]);
    setUserAccess(null);
  }, [cacheScope, setOrganizationMemberInvitations, setOrganizationMembers]);

  useEffect(() => {
    if (!canAdmin || initialAuth.isAuthPage || tab === "account" || tab === "billing" || (tab === "overview" && !hasGlobalConsolePermission)) {
      invalidateAdminLoad();
      return;
    }
    const loadScope = cacheScope;
    loadAdminData(tab).catch((err) => {
      if (cacheScope === loadScope) setError(messageOr(err, "loadFailed"));
    });
    return () => invalidateAdminLoad();
  }, [
    canAdmin,
    canManageActiveOrganization,
    hasGlobalConsolePermission,
    initialAuth.isAuthPage,
    tab,
    organizationContext?.id,
    cacheScope,
    loadAdminData,
    invalidateAdminLoad
  ]);

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
    userDirectoryPage,
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

  // Cursor positions belong to one exact filter set. A filter change starts a
  // fresh keyset walk instead of reusing a position from another result set.
  useEffect(() => {
    setUserDirectoryPage(1);
    setUserDirectoryCursorHistory([null]);
  }, [
    searchQuery,
    userEmailFilter,
    userFilter,
    userLastLoginFrom,
    userLastLoginTo,
    userLinkedIdentityFilter,
    userLoginRegionFilter,
    userOrganizationFilter,
    userPhoneFilter,
    userRegistrationFrom,
    userRegistrationTo,
    userRoleFilter
  ]);

  useEffect(() => {
    setUserDirectoryPage(1);
    setUserDirectoryCursorHistory([null]);
    setSelectedUserIds([]);
  }, [cacheScope]);

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
      const start = await accountApi.startPasskeyAuthentication(email, effectiveAccountFlow);
      const credential = await navigator.credentials.get(passkeyRequestOptions(start.public_key));
      if (!credential || credential.type !== "public-key") {
        throw new Error(t("passkeyLoginFailed"));
      }
      const result = await accountApi.finishPasskeyAuthentication<
        { user: User } | OidcContinuationLoginResponse
      >({
        challengeId: start.challenge_id,
        credential: authenticationCredentialJson(credential as PublicKeyCredential),
        accountFlow: effectiveAccountFlow
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
      transitionToAnonymous();
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
      const body = {
        email: userForm.email,
        username: userForm.username,
        display_name: userForm.display_name || null,
        phone: userForm.phone || null,
        password: userForm.password || null,
        is_admin: userForm.is_admin,
        is_active: userForm.is_active
      };
      if (userForm.id) {
        await adminApi.updateAdminUser(userForm.id, body);
      } else {
        await adminApi.createAdminUser(body);
      }
      setUserForm(emptyUserForm);
      setUserFormBaseline(null);
      setEditor(null);
      setVerificationMessage(t("changesSaved"));
      await userDirectory.reload();
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
      const result = await adminApi.importAdminUsersCsv(bulkImportCsv, bulkImportDryRun);
      setBulkImportResult(result);
      if (result.committed) {
        setVerificationMessage(t("bulkImportCompleted"));
        await userDirectory.reload();
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
      const request = userDetailsRequest.begin();
      try {
        const detail = await adminApi.getAdminUserDetail(id, {
          signal: request.signal,
          force: true
        });
        if (request.isCurrent()) setSelectedUser(detail);
      } catch (error) {
        // A newer account selection owns the error surface. Abort and stale
        // responses must not overwrite the current modal or global error.
        if (request.isCurrent()) throw error;
      }
    });
  }

  async function enableUser(id: string) {
    const completed = await runUiAction(async () => {
      await adminApi.enableAdminUser(id);
      await userDirectory.reload();
      if (selectedUser?.user.id === id) setSelectedUser(null);
    });
    if (completed) setVerificationMessage(t("operationCompleted"));
  }

  async function advanceUserLifecycle(id: string) {
    await adminApi.advanceAdminUserLifecycle(id);
    setSelectedUserIds((current) => current.filter((selectedId) => selectedId !== id));
    await userDirectory.reload();
    if (selectedUser?.user.id === id) setSelectedUser(null);
    if (userForm.id === id) {
      setUserForm(emptyUserForm);
      setUserFormBaseline(null);
    }
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
    const creatingApplication = !applicationForm.id;
    setBusy(true);
    setError("");
    try {
      const input = {
        slug: applicationForm.slug,
        name: applicationForm.name,
        website_url: applicationForm.website_url.trim() || null,
        description: applicationForm.description || null,
        account_selection_mode: applicationForm.account_selection_mode,
        unique_identity_factors: applicationForm.unique_identity_factors,
        is_active: applicationForm.is_active
      };
      let application: TenantApplication;
      if (applicationForm.id) {
        application = await applicationApi.updateApplication(applicationForm.id, input);
        const currentProtocolModule = application.modules?.find((module) => module.module_key === "protocols");
        const currentProtocolConfig = currentProtocolModule?.config ?? {};
        await applicationApi.updateApplicationModule(application.id, "protocols", {
          config: {
            ...(currentProtocolConfig && typeof currentProtocolConfig === "object" ? currentProtocolConfig : {}),
            website_url: applicationForm.website_url
          },
          is_enabled: currentProtocolModule?.is_enabled ?? Boolean(application.client_bindings.length)
        });
      } else {
        const fingerprint = JSON.stringify(input);
        const existingMutation = applicationCreateMutationRef.current;
        const idempotencyKey = existingMutation?.fingerprint === fingerprint
          ? existingMutation.key
          : `ui-application-create-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;
        applicationCreateMutationRef.current = { fingerprint, key: idempotencyKey };
        application = await applicationApi.createApplication(input, { idempotencyKey });
        applicationCreateMutationRef.current = null;
        // Creation and the initial protocols module commit atomically on the
        // server. There is no second module request to partially fail.
        setApplicationForm((current) => ({ ...current, id: application.id }));
      }
      setApplicationForm(emptyApplicationForm);
      setApplicationFormBaseline(null);
      setEditor(null);
      setVerificationMessage(t("changesSaved"));
      await loadAdminData("applications", { force: true });
    } catch (err) {
      // The first write may already have committed even when a later phase or
      // the response failed. Reconcile the collection before exposing the
      // error so a newly created application is visible and can be retried.
      if (
        creatingApplication
        && err instanceof ApiError
        && (err.code === "network_error" || err.status >= 500)
      ) {
        try {
          const recoveredApplications = await applicationApi.listApplications({ force: true });
          const recovered = recoveredApplications.find((candidate) => (
            candidate.organization_id === organizationContext?.id
            && candidate.slug === applicationForm.slug.trim()
            && candidate.name === applicationForm.name.trim()
          ));
          if (recovered) {
            setApplicationForm((current) => ({ ...current, id: recovered.id }));
          }
        } catch {
          // The normal collection reconciliation below remains the fallback.
        }
      }
      try {
        await loadAdminData("applications", { force: true });
      } catch {
        // Preserve the original mutation error when reconciliation is also
        // unavailable.
      }
      setError(messageOr(err, "saveApplicationFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function deleteApplication(id: string) {
    const organizationId = organizationContext?.id ?? null;
    const scopeKey = cacheScope;
    const target = applications.find((application) => application.id === id);
    if (target && organizationId && target.organization_id !== organizationId) {
      throw new Error("application does not belong to the active organization");
    }
    const existingMutation = applicationDeleteMutationRef.current;
    const idempotencyKey = existingMutation
      && existingMutation.applicationId === id
      && existingMutation.organizationId === organizationId
      && existingMutation.scopeKey === scopeKey
      ? existingMutation.key
      : `ui-application-delete-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;
    applicationDeleteMutationRef.current = {
      applicationId: id,
      organizationId,
      scopeKey,
      key: idempotencyKey
    };

    const clearDeletedApplication = () => {
      setApplications((current) => current.filter((application) => application.id !== id));
      if (applicationForm.id === id) {
        setApplicationForm(emptyApplicationForm);
        setApplicationFormBaseline(null);
        setEditor(null);
      }
      if (applicationNavigationId === id) {
        navigateToTab("applications", { applicationId: null, applicationSection: null });
      }
    };

    try {
      await applicationApi.deleteApplication(id, { idempotencyKey });
      clearDeletedApplication();
      await loadAdminData("applications", { force: true });
      applicationDeleteMutationRef.current = null;
    } catch (error) {
      // A lost response must not make the operator repeat a destructive
      // command with a new key. Reconcile the scoped collection first; if the
      // target is gone, the original delete committed and is safe to treat as
      // success even when the refresh endpoint itself failed afterward.
      try {
        const recovered = await applicationApi.listApplications({ force: true });
        setApplications(recovered);
        if (!recovered.some((application) => application.id === id)) {
          clearDeletedApplication();
          applicationDeleteMutationRef.current = null;
          return;
        }
      } catch {
        // Keep the original error and the stable idempotency key for retry.
      }
      throw error;
    }
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

  function updateApplicationOidcClientsInState(applicationId: string, nextClients: Client[]) {
    const previousApplicationClientIds = new Set(
      applications
        .find((application) => application.id === applicationId)
        ?.client_bindings
        .filter((binding) => binding.protocol === "oidc")
        .map((binding) => binding.id) ?? []
    );
    setClients((current) => {
      // `nextClients` is the complete application projection. Remove the
      // previous projection first so a deleted client cannot remain in the
      // global read model and reappear in invitation selectors.
      const retained = current.filter((client) => !previousApplicationClientIds.has(client.id));
      return [...retained, ...nextClients];
    });
    setApplications((current) => current.map((application) => {
      if (application.id !== applicationId) return application;
      const previousOidcBindings = application.client_bindings.filter((binding) => binding.protocol === "oidc");
      const oidcBindings = nextClients.map((client) => {
        const previous = previousOidcBindings.find((binding) => binding.id === client.id);
        return {
          ...client,
          protocol: "oidc",
          authorization_profile_id: previous?.authorization_profile_id ?? "default",
          auth_domain_id: previous?.auth_domain_id ?? `auth-domain:${applicationId}`
        };
      });
      return {
        ...application,
        client_bindings: [
          ...application.client_bindings.filter((binding) => binding.protocol !== "oidc"),
          ...oidcBindings
        ]
      };
    }));
  }

  async function addEnterpriseMember() {
    if (!organizationContext || !enterpriseMemberEmail.trim()) return;
    setBusy(true);
    setError("");
    try {
      await adminApi.addAdminOrganizationMember(organizationContext.id, {
        email: enterpriseMemberEmail.trim(),
        role: enterpriseMemberRole
      });
      setOrganizationMembers(await adminApi.listAdminOrganizationMembers(organizationContext.id));
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
      const created = await adminApi.createAdminOrganizationInvitation(organizationContext.id, {
        email: organizationMemberInvitationForm.email.trim(),
        display_name: organizationMemberInvitationForm.display_name || null,
        description: organizationMemberInvitationForm.description || null,
        expires_at: expiresAt,
        organization_role: organizationMemberInvitationForm.organization_role,
        is_active: organizationMemberInvitationForm.is_active
      });
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
    await adminApi.deleteAdminOrganizationInvitation(organizationContext.id, invitationId);
    setOrganizationMemberInvitations((current) => current.filter((invitation) => invitation.id !== invitationId));
    setRevealedOrganizationMemberInvitation((current) =>
      current?.invitation.id === invitationId ? null : current
    );
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
      const body = {
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
      };
      if (invitationForm.id) {
        await adminApi.updateAdminAuthorizationCode(invitationForm.id, body);
      } else {
        const result = await adminApi.createAdminAuthorizationCode(body);
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
    await adminApi.deleteAdminAuthorizationCode(id);
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
      const result = await adminApi.revealAdminAuthorizationCode(invitation.id);
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

  async function saveRole(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = {
        name: roleForm.name,
        description: roleForm.description || null,
        permissions: roleForm.permissions
      };
      if (roleForm.id) {
        await adminApi.updateAdminRole(roleForm.id, body);
      } else {
        await adminApi.createAdminRole(body);
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
    await adminApi.deleteAdminRole(id);
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
      const body = {
        name: groupForm.name,
        description: groupForm.description || null
      };
      const group = groupForm.id
        ? await adminApi.updateAdminGroup(groupForm.id, body)
        : await adminApi.createAdminGroup(body);
      await adminApi.updateAdminGroupRoles(group.id, groupForm.role_ids);
      await adminApi.updateAdminGroupMembers(group.id, groupForm.user_ids);
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
    await adminApi.deleteAdminGroup(id);
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
      const body = {
        slug: organizationForm.slug,
        name: organizationForm.name,
        description: organizationForm.description || null,
        allowed_email_domains: splitList(organizationForm.allowed_email_domains).map(normalizeDomain),
        is_active: organizationForm.is_active
      };
      const organization = organizationForm.id
        ? await adminApi.updateAdminOrganization(organizationForm.id, body)
        : await adminApi.createAdminOrganization(body);
      await adminApi.replaceAdminOrganizationMembers(organization.id, {
        members: Object.entries(organizationMemberRoles).map(([user_id, role]) => ({ user_id, role }))
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
      const members = await adminApi.listAdminOrganizationMembers(organization.id);
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
    await adminApi.deleteAdminOrganization(id);
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
    const request = userAccessRequest.begin();
    setSelectedAccessUserId(id);
    setUserAccess(null);
    if (!id) {
      return;
    }
    try {
      const access = await adminApi.getAdminUserAccess(id, {
        signal: request.signal,
        force: true
      });
      if (request.isCurrent()) setUserAccess(access);
    } catch (error) {
      if (request.isCurrent()) throw error;
    }
  }

  async function saveUserRoles() {
    if (!selectedAccessUserId || !userAccess) return;
    const completed = await runUiAction(async () => {
      const updated = await adminApi.updateAdminUserRoles(
        selectedAccessUserId,
        userAccess.direct_roles.map((role) => role.id)
      );
      setUserAccess(updated);
      await loadAdminData();
    });
    if (completed) setVerificationMessage(t("changesSaved"));
  }

  async function startTotpSetup() {
    setNewRecoveryCodes([]);
    setTotpSetupCode("");
    await runUiAction(async () => {
      setTotpSetup(await accountApi.startTotpSetup());
    }, "startMfaSetupFailed");
  }

  async function confirmTotpSetup() {
    if (!totpSetup) return;
    await runUiAction(async () => {
      const result = await accountApi.confirmTotpSetup(totpSetup.setup_id, totpSetupCode);
      setMfaStatus(result.status);
      setNewRecoveryCodes(result.recovery_codes);
      setTotpSetup(null);
      setTotpSetupCode("");
      await loadAccountData();
    }, "confirmMfaSetupFailed");
  }

  async function rotateRecoveryCodes() {
    await runUiAction(async () => {
      const result = await accountApi.rotateRecoveryCodes();
      setMfaStatus(result.status);
      setNewRecoveryCodes(result.recovery_codes);
      await loadAccountData();
    }, "rotateRecoveryCodesFailed");
  }

  async function disableMfa() {
    setError("");
    try {
      const result = await accountApi.disableMfa();
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
      const start = await accountApi.startPasskeyRegistration(passkeyName || null);
      const credential = await navigator.credentials.create(passkeyCreationOptions(start.public_key));
      if (!credential || credential.type !== "public-key") {
        throw new Error(t("registerPasskeyFailed"));
      }
      const created = await accountApi.finishPasskeyRegistration({
        challengeId: start.challenge_id,
        name: passkeyName || null,
        credential: registrationCredentialJson(credential as PublicKeyCredential)
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
      await accountApi.deletePasskey(id);
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
      await accountApi.revokeConsent(clientId);
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
      await accountApi.revokeSession(sessionId);
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
    await adminApi.resetAdminUserMfa(id);
    await loadAdminData();
  }

  async function saveSecurityPolicy(event: FormEvent) {
    event.preventDefault();
    if (!securityPolicy) return;
    setBusy(true);
    setError("");
    try {
      const updated = await adminApi.updateAdminSecurityPolicy({
          password_min_length: Number(securityPolicy.password_min_length),
          password_require_uppercase: Number(Boolean(securityPolicy.password_require_uppercase)),
          password_require_lowercase: Number(Boolean(securityPolicy.password_require_lowercase)),
          password_require_digit: Number(Boolean(securityPolicy.password_require_digit)),
          password_require_symbol: Number(Boolean(securityPolicy.password_require_symbol)),
          password_reject_user_info: Number(Boolean(securityPolicy.password_reject_user_info)),
          login_lockout_enabled: Number(Boolean(securityPolicy.login_lockout_enabled)),
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
      await adminApi.rotateAdminSigningKey(signingKeyKid.trim() || null);
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
      const updated = await adminApi.updateAdminRegistrationSettings(registrationSettings);
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
      const updated = await adminApi.updateAdminRuntimeSettings({
        public_base_url: runtimeSettings.public_base_url,
        issuer: runtimeSettings.issuer || runtimeSettings.public_base_url,
        trust_proxy_headers: runtimeSettings.trust_proxy_headers
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
      const updated = await adminApi.updateAdminLoginSettings({
        brand_logo_url: draft.brand_logo_url,
        email_domains: splitList(draft.email_domains).map(normalizeDomain),
        quick_links: draft.quick_links
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

  function resetQuickLinkForm() {
    const empty = { ...emptyQuickLinkForm };
    setQuickLinkForm(empty);
    setQuickLinkFormBaseline(empty);
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
    if (saved) resetQuickLinkForm();
  }

  function editQuickLink(link: QuickLink) {
    const nextForm = {
      id: link.id,
      label: link.label,
      url: link.url,
      is_active: link.is_active
    };
    setQuickLinkForm(nextForm);
    setQuickLinkFormBaseline(nextForm);
  }

  async function removeQuickLink(id: string) {
    const saved = await persistLoginSettings({
      ...loginSettingsDraft,
      quick_links: loginSettingsDraft.quick_links.filter((item) => item.id !== id)
    });
    if (!saved) throw new Error(t("saveLoginSettingsFailed"));
    if (quickLinkForm.id === id) resetQuickLinkForm();
  }

  function providerRedirectPath(slug: string): string {
    return `/api/register/oidc/${slug.trim() || "provider"}/callback`;
  }

  function applyProviderTemplate() {
    const template = providerTemplates.find((item) => item.id === providerTemplateId);
    if (!template) return;
    providerDiscoveryRequest.cancel();
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
    const requestedIssuer = providerForm.issuer.trim();
    if (!requestedIssuer) return;
    const request = providerDiscoveryRequest.begin();
    setBusy(true);
    setError("");
    try {
      const discovered = await adminApi.discoverAdminExternalOidcProvider(requestedIssuer, { signal: request.signal });
      setProviderForm((current) => {
        // Discovery is a patch for the issuer that was requested. Preserve
        // every field edited while the network call was in flight and ignore
        // a response that belongs to an older issuer/request.
        if (!request.isCurrent() || current.issuer.trim() !== requestedIssuer) {
          return current;
        }
        return {
          ...current,
          issuer: discovered.issuer,
          authorization_endpoint: discovered.authorization_endpoint,
          token_endpoint: discovered.token_endpoint,
          userinfo_endpoint: discovered.userinfo_endpoint,
          scopes: joinList(discovered.scopes)
        };
      });
    } catch (err) {
      if (request.isCurrent()) {
        setError(messageOr(err, "discoverProviderFailed"));
      }
    } finally {
      if (request.isCurrent()) setBusy(false);
    }
  }

  async function saveProvider(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = {
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
      };
      if (providerForm.id) {
        await adminApi.updateAdminExternalOidcProvider(providerForm.id, body);
      } else {
        await adminApi.createAdminExternalOidcProvider(body);
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
    await adminApi.deleteAdminExternalOidcProvider(id);
    await loadAdminData();
    await loadBootstrap();
  }

  async function saveLdapProvider(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = {
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
      };
      if (ldapProviderForm.id) {
        await adminApi.updateAdminLdapProvider(ldapProviderForm.id, body);
      } else {
        await adminApi.createAdminLdapProvider(body);
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
    await adminApi.deleteAdminLdapProvider(id);
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
      const body = {
        name: auditWebhookForm.name,
        url: auditWebhookForm.url,
        secret: auditWebhookForm.secret || null,
        clear_secret: auditWebhookForm.clear_secret,
        actions: splitList(auditWebhookForm.actions),
        is_active: auditWebhookForm.is_active,
        timeout_seconds: Number(auditWebhookForm.timeout_seconds)
      };
      if (auditWebhookForm.id) {
        await adminApi.updateAdminAuditWebhook(auditWebhookForm.id, body);
      } else {
        await adminApi.createAdminAuditWebhook(body);
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
    await adminApi.deleteAdminAuditWebhook(id);
    setAuditWebhookForm((current) => (current.id === id ? emptyAuditWebhookForm : current));
    setAuditWebhookFormBaseline((current) => (current.id === id ? emptyAuditWebhookForm : current));
    await loadAdminData();
  }

  async function refreshCurrentTab() {
    setError("");
    setRefreshing(true);
    try {
      if (tab === "billing") {
        await walletWorkspaceRef.current?.reload();
      } else if (tab === "account") {
        await loadAccountData();
      } else if (tab === "users") {
        await userDirectory.reload();
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
    if (configurationFormsDirty() && !confirmDiscardChanges(t)) {
      return;
    }
    setBusy(true);
    setError("");
    try {
      await switchSessionOrganization(organizationId);
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

  function providerFormIsDirty(): boolean {
    return providerFormBaseline !== null
      && isDirtyDomain(providerForm, providerFormBaseline);
  }

  function ldapProviderFormIsDirty(): boolean {
    return ldapProviderFormBaseline !== null
      && isDirtyDomain(ldapProviderForm, ldapProviderFormBaseline);
  }

  function auditWebhookFormIsDirty(): boolean {
    return isDirtyDomain(auditWebhookForm, auditWebhookFormBaseline);
  }

  function registrationSettingsIsDirty(): boolean {
    return registrationSettingsBaseline !== null
      && registrationSettings !== null
      && isDirtyDomain(registrationSettings, registrationSettingsBaseline);
  }

  function runtimeSettingsIsDirty(): boolean {
    return runtimeSettingsBaseline !== null
      && runtimeSettings !== null
      && isDirtyDomain(runtimeSettings, runtimeSettingsBaseline);
  }

  function loginSettingsIsDirty(): boolean {
    return loginSettingsBaseline !== null
      && isDirtyDomain(loginSettingsDraft, loginSettingsBaseline);
  }

  function quickLinkFormIsDirty(): boolean {
    return isDirtyDomain(quickLinkForm, quickLinkFormBaseline);
  }

  function applicationFormIsDirty(): boolean {
    return applicationFormBaseline !== null
      && isDirtyDomain(applicationForm, applicationFormBaseline);
  }

  function securityPolicyIsDirty(): boolean {
    return securityPolicyBaseline !== null
      && securityPolicy !== null
      && isDirtyDomain(securityPolicy, securityPolicyBaseline);
  }

  function userFormIsDirty(): boolean {
    return userFormBaseline !== null
      && isDirtyDomain(userForm, userFormBaseline);
  }

  function enterpriseFormIsDirty(): boolean {
    return enterpriseFormBaseline !== null
      && isDirtyDomain(enterpriseForm, enterpriseFormBaseline);
  }

  function invitationFormIsDirty(): boolean {
    return invitationFormBaseline !== null
      && isDirtyDomain(invitationForm, invitationFormBaseline);
  }

  function roleFormIsDirty(): boolean {
    return roleFormBaseline !== null
      && isDirtyDomain(roleForm, roleFormBaseline);
  }

  function groupFormIsDirty(): boolean {
    return groupFormBaseline !== null
      && isDirtyDomain(groupForm, groupFormBaseline);
  }

  function organizationFormIsDirty(): boolean {
    const formDirty = organizationFormBaseline !== null
      && isDirtyDomain(organizationForm, organizationFormBaseline);
    const membersDirty = organizationMemberRolesBaseline !== null
      && isDirtyDomain(organizationMemberRoles, organizationMemberRolesBaseline);
    return formDirty || membersDirty;
  }

  function configurationFormsDirty(): boolean {
    return userFormIsDirty()
      || enterpriseFormIsDirty()
      || organizationFormIsDirty()
      || providerFormIsDirty()
      || ldapProviderFormIsDirty()
      || applicationFormIsDirty()
      || invitationFormIsDirty()
      || roleFormIsDirty()
      || groupFormIsDirty()
      || auditWebhookFormIsDirty()
      || registrationSettingsIsDirty()
      || runtimeSettingsIsDirty()
      || loginSettingsIsDirty()
      || quickLinkFormIsDirty()
      || securityPolicyIsDirty();
  }

  function closeEditor(force = false): boolean {
    const editorDirty =
      editor === "application" ? applicationFormIsDirty()
      : editor === "user" ? userFormIsDirty()
      : editor === "enterprise" ? enterpriseFormIsDirty()
      : editor === "organization" ? organizationFormIsDirty()
      : editor === "invitation" ? invitationFormIsDirty()
      : editor === "role" ? roleFormIsDirty()
      : editor === "group" ? groupFormIsDirty()
      : editor === "provider" ? providerFormIsDirty()
      : editor === "ldap" ? ldapProviderFormIsDirty()
      : false;
    if (!force && editorDirty && !confirmDiscardChanges(t)) {
      return false;
    }
    if (editor === "organization") {
      organizationMembersLoadId.current += 1;
      setOrganizationMembersLoading(false);
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
      applicationCreateMutationRef.current = null;
      applicationDeleteMutationRef.current = null;
      setApplicationForm(emptyApplicationForm);
      setApplicationFormBaseline(null);
    }
    if (editor === "provider") {
      setProviderForm(emptyProviderForm);
      setProviderFormBaseline(null);
      setProviderTemplateId("");
      providerDiscoveryRequest.cancel();
    }
    if (editor === "ldap") {
      setLdapProviderForm(emptyLdapProviderForm);
      setLdapProviderFormBaseline(null);
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
        ids: ["applications"] as Tab[]
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
    dirtyNavigation.setSource("app", configurationFormsDirty());
  }, [
    dirtyNavigation.setSource,
    userForm,
    userFormBaseline,
    enterpriseForm,
    enterpriseFormBaseline,
    organizationForm,
    organizationFormBaseline,
    organizationMemberRoles,
    organizationMemberRolesBaseline,
    providerForm,
    providerFormBaseline,
    ldapProviderForm,
    ldapProviderFormBaseline,
    auditWebhookForm,
    auditWebhookFormBaseline,
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
    quickLinkForm,
    quickLinkFormBaseline,
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
  // The invitation/provider tables resolve these references for every row.
  // Build indexes once per read-model change instead of scanning the full
  // client/organization collections inside each rendered cell.
  const clientsByClientId = useMemo(
    () => new Map(clients.map((client) => [client.client_id, client])),
    [clients]
  );
  const organizationOptionsById = useMemo(
    () => new Map(organizationOptions.map((organization) => [organization.id, organization])),
    [organizationOptions]
  );
  // The directory endpoint is the single owner of user filtering, sorting,
  // and pagination. Filtering this page again in React makes server totals and
  // visible rows disagree when the two implementations drift.
  const filteredUsers = users;
  const activeUserDirectoryPage = userDirectoryQuery.page;
  const userPageStart = filteredUsers.length === 0
    ? 0
    : (activeUserDirectoryPage - 1) * userDirectoryPageSize + 1;
  const userPageEnd = userPageStart === 0
    ? 0
    : userPageStart + filteredUsers.length - 1;
  const {
    selectedIdSet: selectedUserIdSet,
    selectedUsers: selectedManagedUsers,
    selectedIdsAreCurrent: selectedUsersAreCurrent,
    allVisibleSelected: allVisibleUsersSelected,
    toggle: toggleUserSelection,
    toggleVisible: toggleVisibleUserSelection
  } = useUserSelection({
    users,
    visibleUsers: filteredUsers,
    selectedIds: selectedUserIds,
    setSelectedIds: setSelectedUserIds
  });
  const filteredOrganizations = useMemo(() => organizations.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.name,
    item.slug,
    item.description,
    item.allowed_email_domains.join(" ")
  )), [normalizedSearchQuery, organizations]);
  const filteredApplications = useMemo(() => applications.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.name,
    item.slug,
    item.description
  )), [applications, normalizedSearchQuery]);
  const filteredInvitations = useMemo(() => invitations.filter((item) => matchesSearch(
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
  )), [invitations, normalizedSearchQuery]);
  const filteredProviders = useMemo(() => providers.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.display_name,
    item.slug,
    item.issuer,
    item.email_domains.join(" ")
  )), [normalizedSearchQuery, providers]);
  const filteredLdapProviders = useMemo(() => ldapProviders.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.display_name,
    item.slug,
    item.url,
    item.base_dn
  )), [ldapProviders, normalizedSearchQuery]);
  const filteredRoles = useMemo(() => roles.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.name,
    item.description,
    item.permissions.join(" ")
  )), [normalizedSearchQuery, roles]);
  const filteredGroups = useMemo(() => groups.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.name,
    item.description
  )), [groups, normalizedSearchQuery]);
  const filteredAuditWebhooks = useMemo(() => auditWebhooks.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.name,
    item.url,
    item.actions.join(" "),
    item.last_error
  )), [auditWebhooks, normalizedSearchQuery]);
  const filteredAuditEvents = useMemo(() => auditEvents.filter((item) => matchesSearch(
    normalizedSearchQuery,
    item.action,
    item.target_kind,
    item.target_id,
    item.actor_user_id,
    item.actor_client_id,
    item.details
  )), [auditEvents, normalizedSearchQuery]);
  const searchableTabs: Tab[] = [
    "users",
    "applications",
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

  function resetUserDirectoryQueryState() {
    setUserDirectoryPage(1);
    setUserDirectoryCursorHistory([null]);
    setSelectedUserIds([]);
  }

  function resetUserFilters() {
    resetUserDirectoryQueryState();
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
    const targetIdSet = new Set(targetIds);
    const title = bulkUserActionTitle(action);
    const existingMutation = bulkLifecycleMutationRef.current;
    const idempotencyKey = existingMutation
      && existingMutation.action === action
      && existingMutation.userIds.length === targetIds.length
      && existingMutation.userIds.every((id) => targetIdSet.has(id))
      ? existingMutation.key
      : `ui-bulk-lifecycle-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`}`;
    bulkLifecycleMutationRef.current = { action, userIds: [...targetIds], key: idempotencyKey };
    requestConfirmation(async () => {
      await adminApi.applyAdminUserLifecycle(action, targetIds, { idempotencyKey });
      setSelectedUserIds((current) => current.filter((id) => !targetIdSet.has(id)));
      await userDirectory.reload();
      setVerificationMessage(t("bulkActionCompleted"));
      bulkLifecycleMutationRef.current = null;
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
    return <EnterpriseAuthWorkspace
      bootstrap={bootstrap}
      locale={locale}
      supportedLocales={bootstrap.supported_locales}
      switchLocale={switchLocale}
      theme={theme}
      onToggleTheme={() => setTheme((current) => current === "dark" ? "light" : "dark")}
      title={unifiedAuthTitle}
      headingRef={authModeHeadingRef}
      error={error}
      verificationMessage={verificationMessage}
      authAccountSwitch={authAccountSwitch}
      authFormsVisible={authFormsVisible}
      authMode={authMode}
      onAuthModeChange={setAuthMode}
      busy={busy}
      authEmail={authEmail}
      onAuthEmailChange={setSharedAuthEmail}
      browserAccountsContext={browserAccountsContext}
      selectedBrowserAccount={selectedBrowserAccount}
      browserAccountContinuing={browserAccountContinuing}
      continueWithBrowserAccount={Boolean(continueWithBrowserAccount)}
      onContinueSelectedBrowserAccount={() => void continueSelectedBrowserAccount()}
      authReturnTo={authReturnTo}
      selectAccount={initialAuth.selectAccount}
      onBrowserAccountSelected={selectBrowserAccount}
      onBrowserAccountsLoaded={handleBrowserAccountsLoaded}
      onLoginAnother={openAnotherAccountLogin}
      visibleExternalProviders={visibleExternalProviders}
      hasExternalProviderRow={hasExternalProviderRow}
      accountFlow={effectiveAccountFlow}
      loginDomainProvider={loginDomainProvider}
      registerDomainProvider={registerDomainProvider}
      loginMethod={loginMethod}
      onLoginMethodChange={changeLoginMethod}
      loginPassword={loginPassword}
      onLoginPasswordChange={setLoginPassword}
      loginMfaChallengeId={loginMfaChallengeId}
      loginMfaCode={loginMfaCode}
      onLoginMfaCodeChange={setLoginMfaCode}
      loginRecoveryAvailable={loginRecoveryAvailable}
      loginCaptchaChallengeId={loginCaptchaChallengeId}
      loginCaptchaPrompt={loginCaptchaPrompt}
      loginCaptchaAnswer={loginCaptchaAnswer}
      onLoginCaptchaAnswerChange={setLoginCaptchaAnswer}
      loginCustomDomain={loginCustomDomain}
      onLoginCustomDomainChange={setLoginCustomDomain}
      registerCustomDomain={registerCustomDomain}
      onRegisterCustomDomainChange={setRegisterCustomDomain}
      resetCustomDomain={resetCustomDomain}
      onResetCustomDomainChange={setResetCustomDomain}
      registerForm={registerForm}
      onRegisterFormChange={setRegisterForm}
      passwordResetForm={passwordResetForm}
      onPasswordResetFormChange={setPasswordResetForm}
      authorizationCodeLoginForm={authorizationCodeLoginForm}
      onAuthorizationCodeLoginFormChange={setAuthorizationCodeLoginForm}
      registrationCodeVisible={registrationCodeVisible}
      registrationCodeRequired={registrationCodeRequired}
      registrationCodeMode={registrationCodeMode}
      registrationCodeHint={registrationCodeHint}
      registrationCodeInspecting={registrationCodeInspecting}
      registrationFieldsVisible={registrationFieldsVisible}
      registrationCodeBlocksSubmit={registrationCodeBlocksSubmit}
      passwordRegistrationUnavailable={passwordRegistrationUnavailable}
      onLogin={handleLogin}
      onPasskeyLogin={handlePasskeyLogin}
      onAuthorizationCodeLogin={handleAuthorizationCodeLogin}
      onPasswordReset={handlePasswordReset}
      onRegister={handleRegister}
      onSendVerification={sendVerification}
      onSendPasswordResetCode={sendPasswordResetCode}
      onGenerateRegisterEmail={generateRegisterEmail}
      onCopyRegisterEmail={copyRegisterEmail}
      quickLinks={bootstrap.login.quick_links}
      t={t}
    />;
  }

  return (
    <div className="app-shell">
      <AdminSidebar
        open={sidebarOpen}
        sidebarRef={sidebarRef}
        tab={tab}
        user={user}
        navigationGroups={navigationGroups.map<AdminSidebarNavigationGroup>((group) => ({
          id: group.id,
          label: group.label,
          items: group.items.map((item) => ({
            id: item.id,
            label: item.label,
            icon: item.icon
          }))
        }))}
        languageControl={<TopLanguage locale={locale} supportedLocales={bootstrap.supported_locales} switchLocale={switchLocale} label={t("language")} compact />}
        labels={{
          closeNavigation: t("closeNavigation"),
          adminConsole: t("adminConsole"),
          account: t("account"),
          email: t("email"),
          username: t("username"),
          role: t("role"),
          admin: t("admin"),
          normalUser: t("normalUser"),
          switchAccount: t("switchAccount"),
          logout: t("logout")
        }}
        busy={busy}
        onClose={() => setSidebarOpen(false)}
        onNavigate={(nextTab) => navigateToTab(nextTab)}
        onSwitchAccount={() => void openAccountSwitcher()}
        onLogout={() => void handleLogout()}
      />
      <main className="content">
        <AdminHeader
          mobileMenuButtonRef={mobileMenuButtonRef}
          sidebarOpen={sidebarOpen}
          activeNavigationGroup={activeNavigationGroup
            ? { label: activeNavigationGroup.label, hint: activeNavigationGroup.hint }
            : undefined}
          tab={tab}
          tabs={tabs.map<AdminHeaderTab>((item) => ({ id: item.id, label: item.label }))}
          organizationContext={organizationContext}
          myOrganizations={myOrganizations}
          searchEnabled={searchEnabled}
          searchQuery={searchQuery}
          theme={theme}
          refreshing={refreshing}
          busy={busy}
          labels={{
            openNavigation: t("openNavigation"),
            enterprise: t("enterprise"),
            noEnterprise: t("noEnterprise"),
            switchEnterprise: t("switchEnterprise"),
            systemEnterprise: t("systemEnterprise"),
            createEnterprise: t("createEnterprise"),
            searchCurrentPage: t("searchCurrentPage"),
            clearSearch: t("clearSearch"),
            lightMode: t("lightMode"),
            darkMode: t("darkMode"),
            refresh: t("refresh")
          }}
          onOpenSidebar={() => setSidebarOpen(true)}
          onNavigateSearch={(value) => {
            resetUserDirectoryQueryState();
            setSearchQuery(value);
          }}
          onToggleTheme={() => setTheme((current) => current === "dark" ? "light" : "dark")}
          onRefresh={() => void refreshCurrentTab()}
          onSwitchEnterprise={(organizationId) => void switchEnterprise(organizationId)}
          onCreateEnterprise={() => {
            setEnterpriseForm(emptyEnterpriseForm);
            setEnterpriseFormBaseline(emptyEnterpriseForm);
            setEditor("enterprise");
          }}
        />
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
        {adminViewLoading && <div className="loading-bar" role="progressbar" aria-label={t("loading")} />}
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
          <AccountWorkspace
            user={user}
            locale={locale}
            mfaStatus={mfaStatus}
            totpSetup={totpSetup}
            totpSetupCode={totpSetupCode}
            recoveryCodes={newRecoveryCodes}
            passkeyName={passkeyName}
            passkeys={passkeys}
            mySessions={mySessions}
            myConsents={myConsents}
            busy={busy}
            canMutateAccount={canMutateAccount}
            translate={t}
            onStartTotpSetup={startTotpSetup}
            onConfirmTotpSetup={confirmTotpSetup}
            onRotateRecoveryCodes={() => requestConfirmation(rotateRecoveryCodes, t("rotateRecoveryCodes"), t("rotateRecoveryCodesDescription"))}
            onDisableMfa={() => requestConfirmation(disableMfa, t("disableMfa"), t("disableMfaDescription"))}
            onTotpSetupCodeChange={setTotpSetupCode}
            onPasskeyNameChange={setPasskeyName}
            onRegisterPasskey={registerPasskey}
            onDeletePasskey={(id) => requestConfirmation(() => deletePasskey(id))}
            onRevokeSession={(id) => requestConfirmation(() => revokeMySession(id))}
            onRevokeConsent={(clientId) => requestConfirmation(() => revokeMyConsent(clientId))}
          />
        )}
        {tab === "billing" && user && !isRestrictedLoginCodeSession && (
          <Suspense fallback={<div className="loading-state">{t("loading")}</div>}>
            <WalletWorkspace ref={walletWorkspaceRef} locale={locale} t={t} orderReference={billingOrderReference} />
          </Suspense>
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
              <UserEditorModal
                form={userForm}
                busy={busy}
                error={error}
                dirty={userFormIsDirty()}
                translate={t}
                onChange={setUserForm}
                onSubmit={saveUser}
                onClose={closeEditor}
              />
            )}
            {canManageUsers && (
              <BulkUserImportModal
                open={bulkImportOpen}
                form={{
                  csv: bulkImportCsv,
                  fileName: bulkImportFileName,
                  dryRun: bulkImportDryRun,
                  commitConfirmed: bulkImportCommitConfirmed,
                  result: bulkImportResult
                } satisfies BulkUserImportFormState}
                busy={busy}
                error={bulkImportError}
                translate={t}
                onClose={closeBulkUserImport}
                onSubmit={submitBulkUserImport}
                onFileChange={readBulkUserImportFile}
                onCsvChange={(value) => {
                  setBulkImportCsv(value);
                  setBulkImportFileName("");
                  setBulkImportResult(null);
                }}
                onUseTemplate={() => {
                  setBulkImportCsv(BULK_USER_IMPORT_TEMPLATE);
                  setBulkImportFileName("");
                  setBulkImportResult(null);
                  setBulkImportError("");
                }}
                onDryRunChange={(value) => {
                  setBulkImportDryRun(value);
                  if (value) setBulkImportCommitConfirmed(false);
                }}
                onCommitConfirmedChange={setBulkImportCommitConfirmed}
                onReset={resetBulkUserImport}
              />
            )}
            <div className="table-panel users-table-panel">
              <div className="table-toolbar users-toolbar">
                <div className="users-toolbar-actions">
                  {canManageUsers && <button type="button" onClick={() => { setUserForm(emptyUserForm); setUserFormBaseline(emptyUserForm); setEditor("user"); }}><Plus size={14} />{t("createUser")}</button>}
                  {canManageUsers && <button type="button" onClick={openBulkUserImport}><FileUp size={14} />{t("bulkUserImport")}</button>}
                </div>
                <label className="filter-control">
                  <span>{t("userFilter")}</span>
                  <select value={userFilter} onChange={(event) => {
                    resetUserDirectoryQueryState();
                    setUserFilter(event.target.value as UserFilter);
                  }}>
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
                    <input value={userEmailFilter} onChange={(event) => {
                      resetUserDirectoryQueryState();
                      setUserEmailFilter(event.target.value);
                    }} />
                  </label>
                  <label className="user-filter-field">
                    <span>{t("filterRole")}</span>
                    <select value={userRoleFilter} onChange={(event) => {
                      resetUserDirectoryQueryState();
                      setUserRoleFilter(event.target.value as UserRoleFilter);
                    }}>
                      <option value="all">{t("allRoles")}</option>
                      <option value="admin">{t("admin")}</option>
                      <option value="user">{t("normalUser")}</option>
                    </select>
                  </label>
                  <div className="user-filter-field">
                    <span>{t("filterRegistrationDate")}</span>
                    <div className="user-date-range">
                      <input aria-label={`${t("filterRegistrationDate")} ${t("filterDateFrom")}`} type="date" value={userRegistrationFrom} onChange={(event) => {
                        resetUserDirectoryQueryState();
                        setUserRegistrationFrom(event.target.value);
                      }} />
                      <span aria-hidden="true">–</span>
                      <input aria-label={`${t("filterRegistrationDate")} ${t("filterDateTo")}`} type="date" value={userRegistrationTo} onChange={(event) => {
                        resetUserDirectoryQueryState();
                        setUserRegistrationTo(event.target.value);
                      }} />
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
                      <input value={userPhoneFilter} onChange={(event) => {
                        resetUserDirectoryQueryState();
                        setUserPhoneFilter(event.target.value);
                      }} />
                    </label>
                    <label className="user-filter-field">
                      <span>{t("filterLoginRegion")}</span>
                      <select value={userLoginRegionFilter} onChange={(event) => {
                        resetUserDirectoryQueryState();
                        setUserLoginRegionFilter(event.target.value as UserLoginRegionFilter);
                      }}>
                        <option value="all">{t("allLoginRegions")}</option>
                        <option value="domestic">{t("domestic")}</option>
                        <option value="overseas">{t("overseas")}</option>
                      </select>
                    </label>
                    <label className="user-filter-field">
                      <span>{t("filterOrganization")}</span>
                      <select value={userOrganizationFilter} onChange={(event) => {
                        resetUserDirectoryQueryState();
                        setUserOrganizationFilter(event.target.value);
                      }}>
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
                      <select value={userLinkedIdentityFilter} onChange={(event) => {
                        resetUserDirectoryQueryState();
                        setUserLinkedIdentityFilter(event.target.value as UserLinkedIdentityFilter);
                      }}>
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
              <UserTable
                users={filteredUsers}
                canManageUsers={canManageUsers}
                currentUserId={user?.id}
                selectedUserIdSet={selectedUserIdSet}
                allVisibleSelected={allVisibleUsersSelected}
                busy={busy}
                locale={locale}
                translate={t}
                onToggleVisibleSelection={toggleVisibleUserSelection}
                onToggleSelection={toggleUserSelection}
                onEditUser={(item) => {
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
                }}
                onShowDetails={(id) => void showUserDetails(id)}
                onResetMfa={resetUserMfa}
                onAdvanceLifecycle={advanceUserLifecycle}
                onEnableUser={enableUser}
                onRequestConfirmation={requestConfirmation}
              />
              <div className="user-pagination" aria-label={t("users")}>
                <span>
                  {t("cursorPageSummary")
                    .replace("{page}", String(activeUserDirectoryPage))
                    .replace("{from}", String(userPageStart))
                    .replace("{to}", String(userPageEnd))}
                </span>
                <div className="actions">
                  <button
                    type="button"
                    className="text-button"
                    aria-label={t("previousPage")}
                    onClick={() => {
                      setSelectedUserIds([]);
                      setUserDirectoryPage((page) => Math.max(1, page - 1));
                    }}
                    disabled={adminViewLoading || activeUserDirectoryPage <= 1}
                  >{t("previousPage")}</button>
                  <button
                    type="button"
                    className="text-button"
                    aria-label={t("nextPage")}
                    onClick={() => {
                      setSelectedUserIds([]);
                      const nextCursor = userDirectoryNextCursor;
                      if (!nextCursor) return;
                      setUserDirectoryCursorHistory((history) => {
                        const nextPage = activeUserDirectoryPage + 1;
                        const nextHistory = history.slice(0, nextPage);
                        nextHistory[nextPage - 1] = nextCursor;
                        return nextHistory;
                      });
                      setUserDirectoryPage((page) => page + 1);
                    }}
                    disabled={adminViewLoading || !userDirectoryNextCursor}
                  >{t("nextPage")}</button>
                </div>
              </div>
              {!adminViewLoading && filteredUsers.length === 0 && <EmptyState title={searchQuery ? t("noSearchResults") : t("noData")} icon={<Users size={22} />} />}
              {selectedUser && <Modal title={t("userDetails")} closeLabel={t("close")} onClose={() => setSelectedUser(null)} wide className="user-detail-modal"><UserDetailPanel detail={selectedUser} locale={locale} t={t} /></Modal>}
            </div>
          </section>
        )}
        {canReadOrganizations && tab === "organizations" && (
          <OrganizationsWorkspace
            organizationForm={organizationForm as OrganizationFormState}
            organizationMemberRoles={organizationMemberRoles}
            userOptions={userOptions}
            filteredOrganizations={filteredOrganizations}
            permissions={{ canManageOrganizations, canReadUsers }}
            busy={busy}
            loading={adminViewLoading}
            membersLoading={organizationMembersLoading}
            error={error}
            dirty={organizationFormIsDirty()}
            locale={locale}
            translate={t}
            editorOpen={editor === "organization"}
            searchActive={Boolean(searchQuery)}
            onCreate={() => {
              organizationMembersLoadId.current += 1;
              setOrganizationForm(emptyOrganizationForm);
              setOrganizationFormBaseline(emptyOrganizationForm);
              setOrganizationMemberRoles({});
              setOrganizationMemberRolesBaseline({});
              setOrganizationMembersLoading(false);
              setEditor("organization");
            }}
            onEdit={(organization) => void editOrganization(organization)}
            onDelete={(id) => requestConfirmation(() => deleteOrganization(id))}
            onSave={saveOrganization}
            onViewMembers={(organization) => {
              setUserOrganizationFilter(organization.id);
              navigateToTab("users");
            }}
            onClose={closeEditor}
            onSetForm={setOrganizationForm}
            onSetRole={setOrganizationMemberRole}
          />
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
            <Suspense fallback={<div className="loading-state">{t("loading")}</div>}>
              <ApplicationWorkspace
                applications={filteredApplications}
                providers={providers}
                ldapProviders={ldapProviders}
                organizationOptions={organizationOptions}
                locale={locale}
                canManage={canManageActiveOrganization}
                onCreateApplication={() => {
                  applicationCreateMutationRef.current = null;
                  setApplicationForm(emptyApplicationForm);
                  setApplicationFormBaseline(emptyApplicationForm);
                  setEditor("application");
                }}
                onEditApplication={(application) => void editApplication(application)}
                onDeleteApplication={(id) => requestConfirmation(() => deleteApplication(id), t("delete"), t("deleteApplicationDescription"))}
                onApplicationModuleChanged={updateApplicationModuleInState}
                onApplicationOidcClientsChanged={updateApplicationOidcClientsInState}
                initialApplicationId={applicationNavigationId}
                initialSection={applicationNavigationSection}
                onNavigationChange={(applicationId, section) => navigateToTab("applications", { applicationId, applicationSection: section })}
                dirtyNavigation={dirtyNavigation.controller}
                onRequestConfirmation={requestConfirmation}
              />
            </Suspense>
          </>
        )}
        {canManageAuthorizationCodes && tab === "invitations" && (
          <InvitationsWorkspace
              open={editor === "invitation"}
              form={invitationForm}
              clients={clients}
              organizations={organizationOptions}
              filteredInvitations={filteredInvitations}
              canManageOrganizations={canManageOrganizations}
              isAdmin={Boolean(user?.is_admin)}
              busy={busy}
              error={error}
              dirty={invitationFormIsDirty()}
              adminViewLoading={adminViewLoading}
              searchQuery={searchQuery}
              locale={locale}
              lastInvitationCode={lastInvitationCode}
              revealingInvitationId={revealingInvitationId}
              translate={t}
              onChange={setInvitationForm}
              onSubmit={saveInvitation}
              onClose={() => {
                if (closeEditor()) setLastInvitationCode("");
              }}
              onCreate={() => {
                setInvitationForm(emptyInvitationForm);
                setInvitationFormBaseline(emptyInvitationForm);
                setLastInvitationCode("");
                setEditor("invitation");
              }}
              onEdit={(item) => {
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
              }}
              onDelete={(id) => requestConfirmation(() => deleteInvitation(id))}
              onReveal={(item) => void revealInvitationCode(item)}
              onOpenRedemptions={invitationRedemptions.open}
              onCopyLastInvitationCode={copyLastInvitationCode}
              onCloseReveal={closeInvitationReveal}
              onCopyRevealedInvitationCode={() => void copyTextToClipboard(
                revealedInvitationCode,
                "authorizationCodeCopied",
                "copyAuthorizationCodeUnavailable"
              )}
              revealedInvitation={revealedInvitation}
              revealedInvitationCode={revealedInvitationCode}
              invitationRevealError={invitationRevealError}
              redemptions={invitationRedemptions}
              redemptionsError={invitationRedemptionsError}
          />
        )}
        {canManageSettings && tab === "registration" && registrationSettings && (
          <RegistrationSettingsPanel
            value={registrationSettings}
            busy={busy}
            dirty={registrationSettingsIsDirty()}
            translate={t}
            onChange={setRegistrationSettings}
            onSubmit={saveRegistrationSettings}
          />
        )}
        {canManageProviders && tab === "providers" && (
          <ProvidersWorkspace
            state={{
              editor: editor === "provider" || editor === "ldap" ? editor : null,
              providerForm,
              providerTemplateId,
              ldapProviderForm,
              providerTemplates,
              providers: filteredProviders,
              ldapProviders: filteredLdapProviders,
              organizationOptions,
              organizationOptionsById,
              organizationContext,
              loading: adminViewLoading,
              searchActive: Boolean(searchQuery),
              error,
              providerDirty: providerFormIsDirty(),
              ldapDirty: ldapProviderFormIsDirty()
            }}
            actions={{
              updateProviderForm: (next) => {
                if (next.issuer !== providerForm.issuer) providerDiscoveryRequest.cancel();
                setProviderForm(next);
              },
              updateProviderTemplateId: setProviderTemplateId,
              applyProviderTemplate,
              discoverProvider: () => void discoverProviderEndpoints(),
              saveProvider,
              createProvider: () => {
                providerDiscoveryRequest.cancel();
                setProviderForm(emptyProviderForm);
                setProviderFormBaseline(emptyProviderForm);
                setProviderTemplateId("");
                setEditor("provider");
              },
              editProvider: (provider) => {
                providerDiscoveryRequest.cancel();
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
              },
              deleteProvider: (id) => requestConfirmation(() => deleteProvider(id)),
              updateLdapProviderForm: setLdapProviderForm,
              saveLdapProvider,
              createLdapProvider: () => {
                setLdapProviderForm(emptyLdapProviderForm);
                setLdapProviderFormBaseline(emptyLdapProviderForm);
                setEditor("ldap");
              },
              editLdapProvider,
              deleteLdapProvider: (id) => requestConfirmation(() => deleteLdapProvider(id)),
              closeEditor,
              providerRedirectPath
            }}
            access={{ busy, canManagePlatformProviders }}
            i18n={{ t }}
          />
        )}
        {tab === "portal" && loginSettings && (
          <PortalWorkspace
            state={{
              loginSettingsDraft,
              quickLinkForm
            }}
            actions={{
              updateLoginSettingsDraft: setLoginSettingsDraft,
              updateQuickLinkForm: setQuickLinkForm,
              persistLoginSettings,
              saveQuickLinkDraft,
              editQuickLink,
              deleteQuickLink: (id) => requestConfirmation(() => removeQuickLink(id)),
              resetQuickLinkForm
            }}
            access={{
              busy,
              canManageSettings
            }}
            i18n={{ t }}
            dirty={{
              loginSettings: loginSettingsIsDirty(),
              quickLinkForm: quickLinkFormIsDirty()
            }}
          />
        )}
        {(canManageSecurity || canReadAudit) && tab === "security" && (
          <SecurityWorkspace
            canManageSecurity={canManageSecurity}
            canReadAudit={canReadAudit}
            canMutateAccount={canMutateAccount}
            busy={busy}
            error={error}
            locale={locale}
            translate={t}
            searchQuery={searchQuery}
            adminViewLoading={adminViewLoading}
            mfaStatus={mfaStatus}
            totpSetup={totpSetup}
            totpSetupCode={totpSetupCode}
            newRecoveryCodes={newRecoveryCodes}
            signingKeys={signingKeys}
            signingKeyKid={signingKeyKid}
            securityPolicy={securityPolicy}
            roleForm={roleForm}
            groupForm={groupForm}
            permissionCatalog={permissionCatalog}
            roles={roles}
            filteredRoles={filteredRoles}
            groups={groups}
            filteredGroups={filteredGroups}
            userOptions={userOptions}
            selectedAccessUserId={selectedAccessUserId}
            userAccess={userAccess}
            auditWebhookForm={auditWebhookForm}
            filteredAuditWebhooks={filteredAuditWebhooks}
            filteredAuditEvents={filteredAuditEvents}
            editor={editor}
            roleDirty={roleFormIsDirty()}
            groupDirty={groupFormIsDirty()}
            securityPolicyDirty={securityPolicyIsDirty()}
            auditWebhookDirty={auditWebhookFormIsDirty()}
            onStartTotpSetup={startTotpSetup}
            onConfirmTotpSetup={confirmTotpSetup}
            onDisableMfa={() => requestConfirmation(disableMfa, t("disableMfa"), t("disableMfaDescription"))}
            onRotateRecoveryCodes={() => requestConfirmation(rotateRecoveryCodes, t("rotateRecoveryCodes"), t("rotateRecoveryCodesDescription"))}
            onTotpSetupCodeChange={setTotpSetupCode}
            onSigningKeyKidChange={setSigningKeyKid}
            onRotateSigningKey={() => requestConfirmation(rotateSigningKey)}
            onSecurityPolicyChange={setSecurityPolicy}
            onSaveSecurityPolicy={saveSecurityPolicy}
            onRoleChange={setRoleForm}
            onGroupChange={setGroupForm}
            onRoleSubmit={saveRole}
            onGroupSubmit={saveGroup}
            onCloseEditor={closeEditor}
            onCreateRole={() => { setRoleForm(emptyRoleForm); setRoleFormBaseline(emptyRoleForm); setEditor("role"); }}
            onEditRole={(role) => { editRole(role); setEditor("role"); }}
            onDeleteRole={(role) => requestConfirmation(() => deleteRole(role.id))}
            onSelectUser={(value) => void runUiAction(() => loadUserAccess(value))}
            onToggleUserRole={(role) => {
              if (!userAccess) return;
              const selected = selectedDirectRoleIds.has(role.id);
              setUserAccess({
                ...userAccess,
                direct_roles: selected
                  ? userAccess.direct_roles.filter((item) => item.id !== role.id)
                  : [...userAccess.direct_roles, role]
              });
            }}
            onSaveUserRoles={saveUserRoles}
            onCreateGroup={() => { setGroupForm(emptyGroupForm); setGroupFormBaseline(emptyGroupForm); setEditor("group"); }}
            onEditGroup={(group) => { editGroup(group); setEditor("group"); }}
            onDeleteGroup={(group) => requestConfirmation(() => deleteGroup(group.id))}
            onAuditWebhookChange={setAuditWebhookForm}
            onSaveAuditWebhook={saveAuditWebhook}
            onCancelAuditWebhook={() => { setAuditWebhookForm(emptyAuditWebhookForm); setAuditWebhookFormBaseline(emptyAuditWebhookForm); }}
            onEditAuditWebhook={editAuditWebhook}
            onDeleteAuditWebhook={(webhook) => requestConfirmation(() => deleteAuditWebhook(webhook.id))}
          />
        )}
        {canManageSettings && tab === "settings" && settings && runtimeSettings && (
          <SettingsWorkspace
            settings={settings}
            runtimeSettings={runtimeSettings}
            busy={busy}
            dirty={runtimeSettingsIsDirty()}
            translate={t}
            onRuntimeSettingsChange={setRuntimeSettings}
            onRuntimeSettingsSubmit={saveRuntimeSettings}
          />
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
