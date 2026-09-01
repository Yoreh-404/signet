import {
  Archive,
  AtSign,
  Ban,
  Building2,
  Coins,
  FileUp,
  Globe2,
  KeyRound,
  Link2,
  LogOut,
  Mail,
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
import { FormEvent, lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
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
import { useBrowserAccountFlow } from "./features/auth/use-browser-account-flow";
import { usePasskeyLogin } from "./features/auth/use-passkey-login";
import { useAuthVerificationActions } from "./features/auth/use-auth-verification-actions";
import { useAuthorizationCodeLogin } from "./features/auth/use-authorization-code-login";
import { usePasswordLogin } from "./features/auth/use-password-login";
import { useRegistrationSubmit } from "./features/auth/use-registration-submit";
import { useRegistrationCodeInspection } from "./features/auth/use-registration-code-inspection";
import { useAuthBootstrapActions } from "./features/auth/use-auth-bootstrap-actions";
import { clearLoginChallengeState } from "./features/auth/login-challenge-state";
import {
  EnterpriseAuthWorkspace
} from "./features/auth/EnterpriseAuthWorkspace";
import { InvitationsWorkspace } from "./features/invitations/InvitationsWorkspace";
import { useInvitationRedemptions } from "./features/invitations/useInvitationRedemptions";
import { useAccountController } from "./features/admin/use-account-controller";
import { useApplicationController } from "./features/admin/use-application-controller";
import { useApplicationAdminStateActions } from "./features/admin/use-application-admin-state-actions";
import { useAdminUserActions } from "./features/admin/use-admin-user-actions";
import { useAdminAccessActions } from "./features/admin/use-admin-access-actions";
import { useAdminDataLoader } from "./features/admin/use-admin-data-loader";
import { useAdminSearchProjections } from "./features/admin/use-admin-search-projections";
import { useAdminDirtyState } from "./features/admin/use-admin-dirty-state";
import { useAdminRefresh } from "./features/admin/use-admin-refresh";
import { useAdminSettingsActions } from "./features/admin/use-admin-settings-actions";
import { useApplicationActions } from "./features/admin/use-application-actions";
import { useBulkUserImportActions } from "./features/admin/use-bulk-user-import-actions";
import { useUserAccessLoader } from "./features/admin/use-user-access-loader";
import { useInvitationActions } from "./features/admin/use-invitation-actions";
import { useEnterpriseActions } from "./features/admin/use-enterprise-actions";
import { useAccountSecurityActions } from "./features/account/use-account-security-actions";
import { useUiAction } from "./features/admin/use-ui-action";
import { useLatestRequest } from "./features/admin/use-latest-request";
import { useInvitationController } from "./features/admin/use-invitation-controller";
import { useOrganizationMemberActions } from "./features/admin/use-organization-member-actions";
import { useOrganizationEditorActions } from "./features/admin/use-organization-editor-actions";
import { useOrganizationAdminActions } from "./features/admin/use-organization-admin-actions";
import { useEditorLifecycle } from "./features/admin/use-editor-lifecycle";
import { useConfirmationActions } from "./features/admin/use-confirmation-actions";
import { useProviderAdminActions } from "./features/admin/use-provider-admin-actions";
import { useLoginSettingsActions } from "./features/admin/use-login-settings-actions";
import { deriveAdminPermissions } from "./features/admin/admin-permissions";
import { useAdminNavigation } from "./features/navigation/useAdminNavigation";
import { AdminSidebar } from "./features/navigation/AdminSidebar";
import type { AdminSidebarNavigationGroup } from "./features/navigation/AdminSidebar";
import { AdminHeader } from "./features/navigation/AdminHeader";
import type { AdminHeaderTab } from "./features/navigation/AdminHeader";
import { AdminFeedbackStack } from "./features/navigation/AdminFeedbackStack";
import { useAdminTabModel } from "./features/navigation/use-admin-tab-model";
import { useMobileSidebarFocusTrap } from "./features/navigation/use-mobile-sidebar-focus-trap";
import { QuickJump } from "./features/navigation/QuickJump";
import { TopLanguage } from "./features/navigation/TopLanguage";
import { EmailField, InlineCode } from "./features/auth/AuthFields";
import { AdminOverview } from "./features/overview/AdminOverview";
import { useOrganizationController } from "./features/admin/use-organization-controller";
import { useRoleController } from "./features/admin/use-role-controller";
import { useSettingsController } from "./features/admin/use-settings-controller";
import { useSessionController } from "./features/session/useSessionController";
import { useDocumentPreferences } from "./features/preferences/use-document-preferences";
import { PortalWorkspace } from "./features/settings/PortalWorkspace";
import { RegistrationSettingsPanel } from "./features/settings/RegistrationSettingsPanel";
import { SettingsWorkspace } from "./features/settings/SettingsWorkspace";
import { AccountWorkspace } from "./features/account/AccountWorkspace";
import { useAccountDataLoader } from "./features/account/use-account-data-loader";
import { SecurityWorkspace } from "./features/security/SecurityWorkspace";
import { ProvidersWorkspace } from "./features/providers/ProvidersWorkspace";
import { useUserDirectoryCursor } from "./features/users/use-user-directory";
import { useUserSelection } from "./features/users/use-user-selection";
import { useUserDirectoryQuery } from "./features/users/use-user-directory-query";
import { useUserBulkActions } from "./features/users/use-user-bulk-actions";
import { UserDirectoryFilterPanel } from "./features/users/UserDirectoryFilterPanel";
import type {
  UserLinkedIdentityFilter,
  UserLoginRegionFilter,
  UserRoleFilter,
} from "./features/users/user-directory-filter-types";
import { UserEditorModal } from "./features/users/UserEditorModal";
import { UserDetailPanel } from "./features/users/UserDetailPanel";
import { BulkUserImportModal } from "./features/users/BulkUserImportModal";
import { UserTable } from "./features/users/UserTable";
import { OrganizationsWorkspace } from "./features/organizations/OrganizationsWorkspace";
import type { OrganizationFormState } from "./features/organizations/OrganizationWorkspace";
import type { BulkUserImportFormState } from "./features/users/BulkUserImportModal";
import { BULK_USER_IMPORT_TEMPLATE } from "./features/users/user-lifecycle";
import type { BulkUserAction, UserLifecycleState } from "./features/users/user-lifecycle";
import { confirmDiscardChanges } from "./features/admin/confirm-discard-changes";
import { useUserController } from "./features/admin/use-user-controller";
import * as adminApi from "./lib/api/admin";
import type { WalletWorkspaceHandle } from "./features/billing/WalletWorkspace";
import { translations } from "./i18n";
import type { TranslationKey } from "./i18n";
import {
  api,
  ApiError
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
  toggleValue
} from "./lib/collection-utils";
import {
  joinList,
  shortSessionId,
  splitList,
  toDatetimeLocalValue,
  toTimestamp
} from "./lib/formatters";
import {
  emptyAuditWebhookForm,
  emptyAuthorizationCodeLoginForm,
  emptyApplicationForm,
  emptyGroupForm,
  emptyEnterpriseForm,
  emptyInvitationForm,
  emptyLdapProviderForm,
  emptyOrganizationForm,
  emptyPasswordResetForm,
  emptyProviderForm,
  emptyRegisterForm,
  emptyRoleForm,
  emptyUserForm
} from "./lib/form-defaults";
import { initialNavigation, initialTheme } from "./lib/navigation";
import {
  browserAccountShortName,
  formatDiagnosticValue,
  matchesHttpUrl
} from "./app-helpers";
import type {
  AuditEvent,
  AuthMode,
  Client,
  Invitation,
  Locale,
  LoginMethod,
  LoginResponse,
  LoginSettings,
  LogoutResponse,
  Organization,
  OrganizationOption,
  OidcContinuationLoginResponse,
  Overview,
  PendingConfirmation,
  PermissionInfo,
  SigningKey,
  Tab,
  Theme,
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

export function App() {
  const initialAuth = useMemo(initialAuthContext, []);
  const initialNavigationState = useMemo(() => initialNavigation(), []);
  const [locale, setLocale] = useState<Locale>(() => {
    const saved = localStorage.getItem("gpt-sso-locale");
    return saved === "en-US" ? "en-US" : "zh-CN";
  });
  const t = (key: TranslationKey) => translations[locale][key];
  const messageOr = useMemo(() => (err: unknown, fallback: TranslationKey) => {
    if (err instanceof ApiError && err.code === "network_error") return t("networkError");
    if (err instanceof ApiError && err.code === "csrf_failed") return t("sessionExpired");
    if (err instanceof ApiError && err.status >= 500) return t("serverError");
    if (err instanceof ApiError && (err.status === 401 || err.status === 403)) return t(fallback);
    return err instanceof Error ? err.message : t(fallback);
  }, [locale]);

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
    registerForm,
    setRegisterForm,
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
    editOrganization,
    setOrganizationMemberRole
  } = useOrganizationEditorActions({
    organizationMembersLoadId,
    setOrganizationForm,
    setOrganizationFormBaseline,
    setOrganizationMemberRoles,
    setOrganizationMemberRolesBaseline,
    setOrganizationMembersLoading,
    openOrganizationEditor: () => setEditor("organization"),
    setError,
    messageOr
  });
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
  const { initialize, loadBootstrap } = useAuthBootstrapActions({
    returnTo: authReturnTo,
    autoInitialize: true,
    loadSessionBootstrap,
    initializeSession,
    transitionToAnonymous,
    setLocale,
    setAuthMode,
    setInitialLoadError,
    formatError: messageOr
  });
  const { inspection: registrationCodeInspection, inspecting: registrationCodeInspecting } =
    useRegistrationCodeInspection({
      hasUsers: bootstrap?.has_users ?? false,
      authMode,
      authorizationCode: registerForm.authorization_code
    });
  const { load: loadAccountData } = useAccountDataLoader({
    controller: session.controller,
    scopeKey: cacheScope,
    enabled: !initialAuth.isAuthPage,
    onError: useMemo(
      () => (error: unknown) => setError(messageOr(error, "loadFailed")),
      [messageOr]
    ),
    setMfaStatus,
    setPasskeys,
    setMyConsents,
    setMySessions
  });
  const invitationRedemptions = useInvitationRedemptions();
  const invitationRedemptionsError = invitationRedemptions.error
    ? messageOr(invitationRedemptions.error, "loadAuthorizationCodeRedemptionsFailed")
    : "";
  const {
    addEnterpriseMember,
    createOrganizationMemberInvitation,
    deleteOrganizationMemberInvitation
  } = useOrganizationMemberActions({
    organizationContext,
    enterpriseMemberEmail,
    enterpriseMemberRole,
    setEnterpriseMemberEmail,
    setEnterpriseMemberRole,
    setOrganizationMembers,
    organizationMemberInvitationForm,
    setOrganizationMemberInvitationForm,
    setOrganizationMemberInvitations,
    setRevealedOrganizationMemberInvitation,
    setBusy,
    setError,
    setVerificationMessage,
    messageOr,
    translate: t,
    toTimestamp
  });

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
  const adminPermissions = deriveAdminPermissions({
    permissions: userPermissions,
    organization: organizationContext,
    restrictedLoginCodeSession: isRestrictedLoginCodeSession
  });
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
  } = adminPermissions;

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
    loadAdminData
  } = useAdminDataLoader({
    tab,
    session: session.controller,
    scopeKey: cacheScope,
    enabled: canAdmin
      && !initialAuth.isAuthPage
      && tab !== "account"
      && tab !== "billing"
      && !(tab === "overview" && !hasGlobalConsolePermission),
    onError: useMemo(
      () => (error: unknown) => setError(messageOr(error, "loadFailed")),
      [messageOr]
    ),
    onLoginSettingsLoaded: setLoginSettingsDraft,
    permissions: adminPermissions
  });
  const {
    updateApplicationModuleInState,
    updateApplicationOidcClientsInState
  } = useApplicationAdminStateActions({ applications, setApplications, setClients });

  const {
    userForm: userFormDirty,
    enterpriseForm: enterpriseFormDirty,
    organizationForm: organizationFormDirty,
    providerForm: providerFormDirty,
    ldapProviderForm: ldapProviderFormDirty,
    applicationForm: applicationFormDirty,
    invitationForm: invitationFormDirty,
    roleForm: roleFormDirty,
    groupForm: groupFormDirty,
    auditWebhookForm: auditWebhookFormDirty,
    registrationSettings: registrationSettingsDirty,
    runtimeSettings: runtimeSettingsDirty,
    loginSettings: loginSettingsDirty,
    quickLinkForm: quickLinkFormDirty,
    securityPolicy: securityPolicyDirty,
    configurationFormsDirty,
    editorDirty
  } = useAdminDirtyState({
    editor,
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
    applicationForm,
    applicationFormBaseline,
    invitationForm,
    invitationFormBaseline,
    roleForm,
    roleFormBaseline,
    groupForm,
    groupFormBaseline,
    auditWebhookForm,
    auditWebhookFormBaseline,
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
  });
  const runUiAction = useUiAction({ setBusy, setError, formatError: messageOr });
  const {
    saveSecurityPolicy,
    rotateSigningKey,
    saveRegistrationSettings,
    saveRuntimeSettings,
    saveAuditWebhook,
    editAuditWebhook,
    deleteAuditWebhook
  } = useAdminSettingsActions({
    securityPolicy,
    setSecurityPolicy,
    setSecurityPolicyBaseline,
    signingKeyKid,
    setSigningKeyKid,
    registrationSettings,
    setRegistrationSettings,
    setRegistrationSettingsBaseline,
    runtimeSettings,
    setRuntimeSettings,
    setRuntimeSettingsBaseline,
    auditWebhookForm,
    setAuditWebhookForm,
    setAuditWebhookFormBaseline,
    setBusy,
    setError,
    setVerificationMessage,
    loadAdminData,
    loadBootstrap,
    translate: t,
    formatError: messageOr
  });
  const { saveOrganization, deleteOrganization } = useOrganizationAdminActions({
    organizationForm,
    organizationMemberRoles,
    organizationMembersLoading,
    organizationMembersLoadId,
    setOrganizationForm,
    setOrganizationFormBaseline,
    setOrganizationMemberRoles,
    setOrganizationMemberRolesBaseline,
    setOrganizationMembersLoading,
    setEditor,
    runUiAction,
    loadAdminData,
    setVerificationMessage,
    changesSavedMessage: t("changesSaved")
  });
  const closeEditor = useEditorLifecycle({
    editor,
    editorDirty,
    confirmDiscard: () => confirmDiscardChanges(t),
    setEditor,
    setError,
    organizationMembersLoadId,
    setOrganizationMembersLoading,
    setUserForm,
    setUserFormBaseline,
    setEnterpriseForm,
    setEnterpriseFormBaseline,
    setOrganizationForm,
    setOrganizationFormBaseline,
    setOrganizationMemberRoles,
    setOrganizationMemberRolesBaseline,
    applicationCreateMutationRef,
    applicationDeleteMutationRef,
    setApplicationForm,
    setApplicationFormBaseline,
    setProviderForm,
    setProviderFormBaseline,
    setProviderTemplateId,
    providerDiscoveryRequest,
    setLdapProviderForm,
    setLdapProviderFormBaseline,
    setInvitationForm,
    setInvitationFormBaseline,
    setLastInvitationCode,
    setRoleForm,
    setRoleFormBaseline,
    setGroupForm,
    setGroupFormBaseline
  });
  const {
    editApplication,
    saveApplication,
    deleteApplication
  } = useApplicationActions({
    applicationForm,
    setApplicationForm,
    setApplicationFormBaseline,
    applications,
    setApplications,
    applicationCreateMutationRef,
    applicationDeleteMutationRef,
    organizationId: organizationContext?.id ?? null,
    scopeKey: cacheScope,
    applicationNavigationId,
    openEditor: () => setEditor("application"),
    closeEditor: () => setEditor(null),
    navigateToTab,
    setBusy,
    setError,
    setVerificationMessage,
    loadAdminData,
    translate: t,
    formatError: messageOr
  });
  const {
    saveInvitation,
    deleteInvitation,
    copyLastInvitationCode: copyInvitationCode,
    revealInvitationCode,
    closeInvitationReveal
  } = useInvitationActions({
    invitationForm,
    setInvitationForm,
    setInvitationFormBaseline,
    setLastInvitationCode,
    setEditor: (nextEditor) => setEditor(nextEditor),
    setRevealedInvitation,
    setRevealedInvitationCode,
    setRevealingInvitationId,
    setInvitationRevealError,
    canManageOrganizations,
    user: user ?? null,
    setBusy,
    setError,
    loadAdminData,
    copyText: copyTextToClipboard,
    translate: t,
    formatError: messageOr
  });
  const { switchEnterprise, saveEnterprise } = useEnterpriseActions({
    enterpriseForm,
    setEnterpriseForm,
    setEnterpriseFormBaseline,
    currentOrganizationId: organizationContext?.id ?? null,
    currentUserId: user?.id ?? null,
    formsDirty: configurationFormsDirty,
    confirmDiscard: () => confirmDiscardChanges(t),
    switchOrganization: switchSessionOrganization,
    clearScopedData: () => {
      setApplications([]);
      setClients([]);
      setOrganizationMembers([]);
    },
    loadOrganizationContext: loadSessionOrganizationContext,
    navigateToTab,
    setEditor: (nextEditor) => setEditor(nextEditor),
    setBusy,
    setError,
    setVerificationMessage,
    translate: t,
    formatError: messageOr
  });
  const { requestConfirmation, runPendingConfirmation } = useConfirmationActions({
    pendingConfirmation,
    setPendingConfirmation,
    setBusy,
    setError,
    setVerificationMessage,
    formatError: messageOr,
    confirmActionTitle: t("confirmAction"),
    confirmActionDescription: t("confirmActionDescription"),
    operationCompletedMessage: t("operationCompleted")
  });
  const {
    providerRedirectPath,
    applyProviderTemplate,
    discoverProviderEndpoints,
    saveProvider,
    deleteProvider,
    saveLdapProvider,
    deleteLdapProvider,
    editLdapProvider
  } = useProviderAdminActions({
    providerForm,
    providerTemplates,
    providerTemplateId,
    setProviderForm,
    setProviderFormBaseline,
    providerDiscoveryRequest,
    ldapProviderForm,
    setLdapProviderForm,
    setLdapProviderFormBaseline,
    setEditor,
    setBusy,
    setError,
    setVerificationMessage,
    loadAdminData,
    loadBootstrap,
    messageOr,
    changesSavedMessage: t("changesSaved")
  });
  const {
    persistLoginSettings,
    resetQuickLinkForm,
    saveQuickLinkDraft,
    editQuickLink,
    removeQuickLink
  } = useLoginSettingsActions({
    loginSettingsDraft,
    quickLinkForm,
    setLoginSettings,
    setLoginSettingsDraft,
    setLoginSettingsBaseline,
    setQuickLinkForm,
    setQuickLinkFormBaseline,
    setBusy,
    setError,
    setVerificationMessage,
    loadBootstrap,
    messageOr,
    changesSavedMessage: t("changesSaved"),
    saveLoginSettingsFailedMessage: t("saveLoginSettingsFailed")
  });
  const {
    sendVerification,
    sendPasswordResetCode,
    handlePasswordReset
  } = useAuthVerificationActions({
    authEmail,
    registerPhone: registerForm.phone,
    passwordResetForm,
    setRegisterForm,
    setPasswordResetForm,
    setAuthMode,
    setVerificationMessage,
    runUiAction,
    setBusy,
    setError,
    formatError: messageOr,
    translate: t,
    request: api
  });
  const handlePasskeyLogin = usePasskeyLogin({
    email: authEmail,
    accountFlow: effectiveAccountFlow,
    setBusy,
    setError,
    setLoginMfaChallengeId,
    setLoginMfaCode,
    setLoginRecoveryAvailable,
    setLoginCaptchaChallengeId,
    setLoginCaptchaPrompt,
    setLoginCaptchaAnswer,
    translate: t,
    formatError: messageOr,
    finishInteractiveAuth,
    loadBootstrap
  });
  const handleAuthorizationCodeLogin = useAuthorizationCodeLogin({
    form: authorizationCodeLoginForm,
    returnTo: authReturnTo,
    accountFlow: effectiveAccountFlow,
    setForm: setAuthorizationCodeLoginForm,
    setBusy,
    setError,
    translate: t,
    formatError: messageOr,
    finishInteractiveAuth,
    loadBootstrap,
    request: api
  });
  const handleLogin = usePasswordLogin({
    email: authEmail,
    password: loginPassword,
    mfaChallengeId: loginMfaChallengeId,
    mfaCode: loginMfaCode,
    captchaChallengeId: loginCaptchaChallengeId,
    captchaAnswer: loginCaptchaAnswer,
    returnTo: authReturnTo,
    accountFlow: effectiveAccountFlow,
    setBusy,
    setError,
    setMfaChallengeId: setLoginMfaChallengeId,
    setMfaCode: setLoginMfaCode,
    setRecoveryAvailable: setLoginRecoveryAvailable,
    setCaptchaChallengeId: setLoginCaptchaChallengeId,
    setCaptchaPrompt: setLoginCaptchaPrompt,
    setCaptchaAnswer: setLoginCaptchaAnswer,
    translate: t,
    formatError: messageOr,
    finishInteractiveAuth,
    loadBootstrap,
    request: api
  });
  const handleRegister = useRegistrationSubmit({
    bootstrap,
    form: registerForm,
    email: authEmail,
    returnTo: authReturnTo,
    accountFlow: effectiveAccountFlow,
    trialEnrollment: registrationCodeInspection?.mode === "trial_enrollment",
    setForm: setRegisterForm,
    setAuthMode,
    setBusy,
    setError,
    translate: t,
    formatError: messageOr,
    finishInteractiveAuth,
    loadBootstrap,
    request: api
  });
  const {
    registerPasskey,
    deletePasskey,
    revokeMyConsent,
    revokeMySession,
    startTotpSetup,
    confirmTotpSetup,
    rotateRecoveryCodes,
    disableMfa
  } = useAccountSecurityActions({
    passkeyName,
    setPasskeyName,
    setPasskeys,
    totpSetup,
    totpSetupCode,
    setTotpSetup,
    setTotpSetupCode,
    setMfaStatus,
    setNewRecoveryCodes,
    setError,
    loadAccountData,
    runUiAction,
    formatError: messageOr
  });

  const userDirectoryQueryModel = useUserDirectoryQuery(
    {
      searchQuery,
      userFilter,
      userOrganizationFilter,
      userEmailFilter,
      userRoleFilter,
      userRegistrationFrom,
      userRegistrationTo,
      userLastLoginFrom,
      userLastLoginTo,
      userPhoneFilter,
      userLoginRegionFilter,
      userLinkedIdentityFilter,
    },
    {
      userDirectoryPage,
      userDirectoryPageSize,
      userDirectoryCursorHistory,
      setUserDirectoryPage,
      setUserDirectoryCursorHistory,
      setSelectedUserIds,
    },
  );
  const userDirectoryQuery = userDirectoryQueryModel.query;
  const resetUserDirectoryQueryState = userDirectoryQueryModel.resetQueryState;
  const userDirectoryFilters = {
    searchQuery,
    userFilter,
    userOrganizationFilter,
    userEmailFilter,
    userRoleFilter,
    userRegistrationFrom,
    userRegistrationTo,
    userLastLoginFrom,
    userLastLoginTo,
    userPhoneFilter,
    userLoginRegionFilter,
    userLinkedIdentityFilter,
  };
  const userDirectory = useUserDirectoryCursor({
    endpoint: "/api/admin/users/cursor",
    query: userDirectoryQuery,
    enabled: canAdmin && canReadUsers && !initialAuth.isAuthPage && tab === "users",
    scopeKey: cacheScope
  });
  const {
    openBulkUserImport,
    closeBulkUserImport,
    resetBulkUserImport,
    readBulkUserImportFile,
    submitBulkUserImport
  } = useBulkUserImportActions({
    busy,
    csv: bulkImportCsv,
    dryRun: bulkImportDryRun,
    commitConfirmed: bulkImportCommitConfirmed,
    setOpen: setBulkImportOpen,
    setCsv: setBulkImportCsv,
    setFileName: setBulkImportFileName,
    setDryRun: setBulkImportDryRun,
    setCommitConfirmed: setBulkImportCommitConfirmed,
    setResult: setBulkImportResult,
    setImportError: setBulkImportError,
    setBusy,
    setError,
    setVerificationMessage,
    reloadUsers: userDirectory.reload,
    translate: t,
    formatError: messageOr
  });
  const loadUserAccess = useUserAccessLoader({
    setSelectedAccessUserId,
    setUserAccess
  });
  const {
    saveUser,
    enableUser,
    advanceUserLifecycle
  } = useAdminUserActions({
    userForm,
    setUserForm,
    setUserFormBaseline,
    selectedUser,
    setSelectedUser,
    setSelectedUserIds,
    reloadUsers: userDirectory.reload,
    runUiAction,
    clearEditor: () => setEditor(null),
    setVerificationMessage,
    translate: t
  });
  const {
    saveRole,
    deleteRole,
    saveGroup,
    deleteGroup,
    saveUserRoles,
    editRole,
    editGroup
  } = useAdminAccessActions({
    roleForm,
    setRoleForm,
    setRoleFormBaseline,
    groupForm,
    setGroupForm,
    setGroupFormBaseline,
    selectedAccessUserId,
    userAccess,
    setUserAccess,
    loadAdminData,
    loadUserAccess,
    runUiAction,
    clearEditor: () => setEditor(null),
    setVerificationMessage,
    translate: t
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

  const {
    setSharedAuthEmail,
    selectBrowserAccount,
    handleBrowserAccountsLoaded,
    continueSelectedBrowserAccount,
    openAnotherAccountLogin,
  } = useBrowserAccountFlow({
    accountLoginFlow,
    accountLoginExpanded,
    authReturnTo,
    selectedBrowserAccount,
    continueWithBrowserAccount,
    setAccountLoginFlow,
    setAccountLoginExpanded,
    setSelectedBrowserAccount,
    setContinueWithBrowserAccount,
    setBrowserAccountsContext,
    setBrowserAccountContinuing,
    setAuthMode,
    setLoginMethod,
    setLoginPassword,
    setAuthorizationCodeLoginForm,
    setLoginMfaChallengeId,
    setLoginMfaCode,
    setLoginRecoveryAvailable,
    setLoginCaptchaChallengeId,
    setLoginCaptchaPrompt,
    setLoginCaptchaAnswer,
    setAuthEmail,
    setError,
    setVerificationMessage,
    t,
  });

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

  useDocumentPreferences(locale, theme);

  useEffect(() => {
    if (authCanCompleteWithCurrentUser && authReturnTo) {
      window.location.assign(authReturnTo);
    }
  }, [authCanCompleteWithCurrentUser, authReturnTo]);

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
    if (userOrganizationFilter) setUserFiltersExpanded(true);
  }, [userOrganizationFilter]);

  useEffect(() => {
    setUserDirectoryPage(1);
    setUserDirectoryCursorHistory([null]);
    setSelectedUserIds([]);
  }, [cacheScope]);

  useMobileSidebarFocusTrap({
    open: sidebarOpen,
    sidebarRef,
    mobileMenuButtonRef,
    setOpen: setSidebarOpen
  });

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
    clearLoginChallengeState({
      setMfaChallengeId: setLoginMfaChallengeId,
      setMfaCode: setLoginMfaCode,
      setRecoveryAvailable: setLoginRecoveryAvailable,
      setCaptchaChallengeId: setLoginCaptchaChallengeId,
      setCaptchaPrompt: setLoginCaptchaPrompt,
      setCaptchaAnswer: setLoginCaptchaAnswer
    });
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

  async function resetUserMfa(id: string) {
    await adminApi.resetAdminUserMfa(id);
    await loadAdminData();
  }

  const refreshCurrentTab = useAdminRefresh({
    tab,
    setRefreshing,
    setError,
    setVerificationMessage,
    formatError: messageOr,
    translate: t,
    reloadBilling: async () => {
      await walletWorkspaceRef.current?.reload();
    },
    reloadAccount: loadAccountData,
    reloadUsers: userDirectory.reload,
    reloadAdmin: loadAdminData
  });

  const { tabs, navigationGroups } = useAdminTabModel({
    locale,
    translate: t,
    user: user ?? null,
    isRestrictedLoginCodeSession,
    canAdmin,
    hasGlobalConsolePermission,
    canReadUsers,
    canManageActiveOrganization,
    canReadOrganizations,
    canManageAuthorizationCodes,
    canManageSettings,
    canManageProviders,
    canManageSecurity,
    canReadAudit
  });
  const activeNavigationGroup = navigationGroups.find((group) => group.items.some((item) => item.id === tab));

  useEffect(() => {
    if (!user || !enterpriseContextReady) return;
    if (!tabs.some((item) => item.id === tab)) {
      navigateToTab("account");
    }
  }, [enterpriseContextReady, tab, tabs, user]);

  useEffect(() => {
    dirtyNavigation.setSource("app", configurationFormsDirty);
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
  const activeUserDirectoryPage = userDirectoryQuery.page ?? userDirectoryPage;
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
  const {
    filteredOrganizations,
    filteredApplications,
    filteredInvitations,
    filteredProviders,
    filteredLdapProviders,
    filteredRoles,
    filteredGroups,
    filteredAuditWebhooks,
    filteredAuditEvents
  } = useAdminSearchProjections(searchQuery, {
    organizations,
    applications,
    invitations,
    providers,
    ldapProviders,
    roles,
    groups,
    auditWebhooks,
    auditEvents
  });
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
  const { availableActions: availableBulkUserActions } = useUserBulkActions(
    selectedManagedUsers,
    user?.id,
    selectedUsersAreCurrent
  );

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
                dirty={enterpriseFormDirty}
                statusLabel={enterpriseFormDirty ? t("unsavedChanges") : undefined}
                savingLabel={t("saving")}
              />
            </form>
          </Modal>
        )}
        <AdminFeedbackStack
          loading={adminViewLoading}
          error={error}
          editorOpen={Boolean(editor)}
          confirmationOpen={Boolean(pendingConfirmation)}
          restrictedLoginCodeSession={isRestrictedLoginCodeSession}
          trialEnrollmentSession={isTrialEnrollmentSession}
          verificationMessage={verificationMessage}
          t={t}
        />
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
          <AdminOverview
            username={user.username}
            overview={overview}
            issuer={bootstrap.issuer}
            canReadUsers={canReadUsers}
            canReadOrganizations={canReadOrganizations}
            canManageSecurity={canManageSecurity}
            activeUserCount={activeUserCount}
            totalUserCount={totalUserCount}
            activeClientCount={activeClientCount}
            totalClientCount={totalClientCount}
            translate={t}
            navigateToTab={navigateToTab}
          />
        )}
        {canReadUsers && tab === "users" && (
          <section className="users-layout">
            {canManageUsers && editor === "user" && (
              <UserEditorModal
                form={userForm}
                busy={busy}
                error={error}
                dirty={userFormDirty}
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
              </div>
                <UserDirectoryFilterPanel
                  filters={userDirectoryFilters}
                  expanded={userFiltersExpanded}
                  organizationOptions={organizationOptions}
                  t={t}
                  onToggleExpanded={() => setUserFiltersExpanded((value) => !value)}
                  onChange={(field, value) => {
                    resetUserDirectoryQueryState();
                    switch (field) {
                      case "userFilter": setUserFilter(value as UserFilter); break;
                      case "userEmailFilter": setUserEmailFilter(value as string); break;
                      case "userRoleFilter": setUserRoleFilter(value as UserRoleFilter); break;
                      case "userRegistrationFrom": setUserRegistrationFrom(value as string); break;
                      case "userRegistrationTo": setUserRegistrationTo(value as string); break;
                      case "userLastLoginFrom": setUserLastLoginFrom(value as string); break;
                      case "userLastLoginTo": setUserLastLoginTo(value as string); break;
                      case "userPhoneFilter": setUserPhoneFilter(value as string); break;
                      case "userLoginRegionFilter": setUserLoginRegionFilter(value as UserLoginRegionFilter); break;
                      case "userOrganizationFilter": setUserOrganizationFilter(value as string); break;
                      case "userLinkedIdentityFilter": setUserLinkedIdentityFilter(value as UserLinkedIdentityFilter); break;
                      case "searchQuery": setSearchQuery(value as string); break;
                    }
                  }}
                  onReset={resetUserFilters}
                />
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
            dirty={organizationFormDirty}
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
                    <span className="form-actions-status" aria-live="polite">{applicationFormDirty ? t("unsavedChanges") : ""}</span>
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
              dirty={invitationFormDirty}
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
                onCopyLastInvitationCode={() => void copyInvitationCode(lastInvitationCode)}
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
            dirty={registrationSettingsDirty}
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
              providerDirty: providerFormDirty,
              ldapDirty: ldapProviderFormDirty
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
              loginSettings: loginSettingsDirty,
              quickLinkForm: quickLinkFormDirty
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
            roleDirty={roleFormDirty}
            groupDirty={groupFormDirty}
            securityPolicyDirty={securityPolicyDirty}
            auditWebhookDirty={auditWebhookFormDirty}
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
            dirty={runtimeSettingsDirty}
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
