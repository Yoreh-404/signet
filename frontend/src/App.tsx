import {
  Archive,
  AtSign,
  Ban,
  Bot,
  Building2,
  Copy,
  ExternalLink,
  Globe2,
  KeyRound,
  Link2,
  LogOut,
  Mail,
  Phone,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Settings,
  Shield,
  Shuffle,
  Trash2,
  Ticket,
  UserRound,
  Users
} from "lucide-react";
import { FormEvent, useEffect, useMemo, useState } from "react";

type Locale = "zh-CN" | "en-US";
type AuthMode = "login" | "register" | "reset";

type User = {
  id: string;
  email: string;
  username: string;
  display_name: string | null;
  phone: string | null;
  email_verified_at: number | null;
  phone_verified_at: number | null;
  is_admin: boolean;
  is_active: boolean;
  archived_at: number | null;
  last_login_at: number | null;
  last_login_ip: string | null;
  last_oidc_client_id: string | null;
  last_login_method: string | null;
  created_at: number;
  updated_at: number;
  permissions?: string[];
};

type LoginEvent = {
  id: string;
  user_id: string;
  login_at: number;
  ip_address: string | null;
  user_agent: string | null;
  method: string;
  oidc_client_id: string | null;
  external_provider: string | null;
};

type AuditEvent = {
  id: string;
  actor_user_id: string | null;
  actor_client_id: string | null;
  action: string;
  target_kind: string;
  target_id: string | null;
  outcome: string;
  ip_address: string | null;
  user_agent: string | null;
  details: string;
  created_at: number;
};

type AuditWebhook = {
  id: string;
  name: string;
  url: string;
  has_secret: boolean;
  actions: string[];
  is_active: boolean;
  timeout_seconds: number;
  last_delivered_at: number | null;
  last_status_code: number | null;
  last_error: string | null;
  created_at: number;
  updated_at: number;
};

type Role = {
  id: string;
  name: string;
  description: string | null;
  is_system: number;
  permissions: string[];
  created_at: number;
  updated_at: number;
};

type AccessGroup = {
  id: string;
  name: string;
  description: string | null;
  roles?: Role[];
  members?: User[];
  created_at: number;
  updated_at: number;
};

type OrganizationMember = {
  organization_id: string;
  user_id: string;
  role: string;
  email: string;
  username: string;
  display_name: string | null;
  is_active: boolean;
  archived_at: number | null;
  created_at: number;
  updated_at: number;
};

type Organization = {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  allowed_email_domains: string[];
  is_active: boolean;
  members: OrganizationMember[];
  created_at: number;
  updated_at: number;
};

type UserOrganization = {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  is_active: number;
  role: string;
  membership_created_at: number;
  membership_updated_at: number;
};

type PermissionInfo = {
  key: string;
  category: string;
  label: string;
};

type UserAccess = {
  direct_roles: Role[];
  groups: AccessGroup[];
  effective_permissions: string[];
};

type LoginResponse = {
  user: User | null;
  mfa_required: boolean;
  mfa_challenge_id: string | null;
  recovery_available: boolean;
  captcha_required: boolean;
  captcha_challenge_id: string | null;
  captcha_prompt: string | null;
  captcha_expires_at: number | null;
};

type MfaStatus = {
  enabled: boolean;
  totp_enabled: boolean;
  recovery_codes_remaining: number;
  recovery_codes_total: number;
};

type TotpSetup = {
  setup_id: string;
  secret: string;
  otpauth_uri: string;
  expires_at: number;
};

type MfaConfirmResponse = {
  status: MfaStatus;
  recovery_codes: string[];
};

type Passkey = {
  id: string;
  name: string;
  credential_id: string;
  last_used_at: number | null;
  created_at: number;
  updated_at: number;
};

type WebauthnCreationPublicKeyJson = Omit<PublicKeyCredentialCreationOptions, "challenge" | "excludeCredentials" | "user"> & {
  challenge: string;
  excludeCredentials?: Array<Omit<PublicKeyCredentialDescriptor, "id"> & { id: string }>;
  user: Omit<PublicKeyCredentialUserEntity, "id"> & { id: string };
};

type WebauthnCreationResponseJson = {
  publicKey: WebauthnCreationPublicKeyJson;
};

type WebauthnRequestPublicKeyJson = Omit<PublicKeyCredentialRequestOptions, "allowCredentials" | "challenge"> & {
  allowCredentials?: Array<Omit<PublicKeyCredentialDescriptor, "id"> & { id: string }>;
  challenge: string;
};

type WebauthnRequestResponseJson = {
  publicKey: WebauthnRequestPublicKeyJson;
  mediation?: CredentialMediationRequirement;
};

type PasskeyRegistrationStart = {
  challenge_id: string;
  public_key: WebauthnCreationResponseJson;
  expires_at: number;
};

type PasskeyAuthenticationStart = {
  challenge_id: string;
  public_key: WebauthnRequestResponseJson;
  expires_at: number;
};

type SecurityPolicy = {
  id: string;
  password_min_length: number;
  password_require_uppercase: number;
  password_require_lowercase: number;
  password_require_digit: number;
  password_require_symbol: number;
  password_reject_user_info: number;
  login_lockout_enabled: number;
  max_failed_login_attempts: number;
  failure_window_seconds: number;
  lockout_seconds: number;
  trusted_ip_cidrs: string[];
  require_mfa_outside_trusted_networks: boolean;
  allowed_ip_cidrs: string[];
  blocked_ip_cidrs: string[];
  allowed_email_domains: string[];
  blocked_email_domains: string[];
  captcha_enabled: boolean;
  captcha_after_failed_attempts: number;
  captcha_ttl_seconds: number;
  updated_at: number;
};

type SigningKey = {
  id: string;
  kid: string;
  is_active: boolean;
  created_at: number;
  activated_at: number | null;
  retired_at: number | null;
};

type MyConsent = {
  client_id: string;
  client_name: string | null;
  granted_scopes: string[];
  granted_at: number;
  updated_at: number;
};

type MySession = {
  id: string;
  current: boolean;
  ip_address: string | null;
  user_agent: string | null;
  login_method: string | null;
  expires_at: number;
  created_at: number;
};

type LinkedIdentity = {
  id: string;
  user_id: string;
  provider_slug: string;
  external_subject: string;
  external_email: string | null;
  created_at: number;
  updated_at: number;
};

type UserDetail = {
  user: User;
  login_events: LoginEvent[];
  linked_identities: LinkedIdentity[];
  organizations: UserOrganization[];
};

type Client = {
  id: string;
  client_id: string;
  client_name: string;
  organization_id: string | null;
  organization_slug: string | null;
  organization_name: string | null;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  scopes: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  require_pkce: boolean;
  require_mfa: boolean;
  require_pushed_authorization_requests: boolean;
  require_s256_pkce: boolean;
  require_confidential_client: boolean;
  require_dpop: boolean;
  require_account_selection: boolean;
  trust_email_verified: boolean;
  authorization_details_types: string[];
  subject_type: string;
  sector_identifier_uri: string;
  jwks_uri: string;
  jwks: string;
  backchannel_logout_uri: string;
  backchannel_logout_session_required: boolean;
  frontchannel_logout_uri: string;
  frontchannel_logout_session_required: boolean;
  service_account_enabled: boolean;
  service_account_permissions: string[];
  is_active: boolean;
  claim_mappers: ClientClaimMapper[];
  created_at: number;
  updated_at: number;
};

type LogoutFrame = {
  client_id: string;
  uri: string;
};

type LogoutResponse = {
  ok: boolean;
  frontchannel_logout_frames?: LogoutFrame[];
};

type ClientClaimMapper = {
  id: string;
  claim_name: string;
  source: string;
  source_value: string;
  value_type: string;
  include_in_id_token: boolean;
  include_in_access_token: boolean;
  include_in_userinfo: boolean;
  is_active: boolean;
  sort_order: number;
  created_at: number;
  updated_at: number;
};

type IapApplication = {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  external_host: string;
  path_prefix: string;
  required_organization_id: string | null;
  required_organization_roles: string[];
  required_permissions: string[];
  is_active: boolean;
  created_at: number;
  updated_at: number;
};

type ClientClaimMapperForm = {
  claim_name: string;
  source: string;
  source_value: string;
  value_type: string;
  include_in_id_token: boolean;
  include_in_access_token: boolean;
  include_in_userinfo: boolean;
  is_active: boolean;
  sort_order: number;
};

type Invitation = {
  id: string;
  code_prefix: string;
  description: string | null;
  authorized_email: string | null;
  authorized_username: string | null;
  authorized_display_name: string | null;
  expires_at: number | null;
  max_uses: number | null;
  uses_count: number;
  is_active: boolean;
  created_by: string | null;
  created_at: number;
  updated_at: number;
  redemptions: InvitationRedemption[];
};

type InvitationRedemption = {
  id: string;
  user_id: string;
  user_email: string | null;
  user_username: string | null;
  redeemed_at: number;
};

type QuickLink = {
  id: string;
  label: string;
  url: string;
  icon: string;
  is_active: boolean;
};

type LoginSettings = {
  email_domains: string[];
  quick_links: QuickLink[];
  updated_at: number;
};

type LoginSettingsDraft = {
  email_domains: string;
  quick_links: QuickLink[];
};

type RegistrationSettings = {
  allow_password_registration: boolean;
  require_email_verification: boolean;
  require_phone_verification: boolean;
  allow_external_oidc_registration: boolean;
  require_invitation: boolean;
  first_user_direct_admin: boolean;
  default_user_active: boolean;
};

type ExternalProvider = {
  id: string;
  slug: string;
  display_name: string;
  organization_id: string | null;
  issuer: string;
  client_id: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  redirect_path: string;
  scopes: string[];
  email_domains: string[];
  is_active: boolean;
  allow_login: boolean;
  allow_registration: boolean;
  created_at: number;
  updated_at: number;
};

type ExternalProviderSummary = {
  slug: string;
  display_name: string;
  start_url: string;
  email_domains: string[];
  allow_login: boolean;
  allow_registration: boolean;
};

type ExternalProviderTemplate = {
  id: string;
  slug: string;
  display_name: string;
  issuer: string;
  scopes: string[];
};

type ExternalProviderDiscovery = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  scopes: string[];
};

type LdapProvider = {
  id: string;
  slug: string;
  display_name: string;
  url: string;
  starttls: boolean;
  bind_dn: string;
  has_bind_password: boolean;
  base_dn: string;
  user_filter: string;
  user_id_attribute: string;
  email_attribute: string;
  username_attribute: string;
  display_name_attribute: string;
  phone_attribute: string;
  is_active: boolean;
  allow_login: boolean;
  allow_registration: boolean;
  created_at: number;
  updated_at: number;
};

type Bootstrap = {
  has_users: boolean;
  registration: RegistrationSettings;
  login: LoginSettings;
  default_locale: string;
  supported_locales: string[];
  external_oidc_providers: ExternalProviderSummary[];
  ldap_providers: Array<{ slug: string; display_name: string }>;
};

type Overview = {
  users: number;
  active_users: number;
  clients: number;
  active_clients: number;
  issuer: string;
  database_kind: string;
};

type SettingsSummary = Record<string, string | number | boolean | string[]>;

type RuntimeSettings = {
  public_base_url: string;
  issuer: string;
  trust_proxy_headers: boolean;
  effective_public_base_url: string;
  effective_issuer: string;
  updated_at: number;
};

type Tab = "account" | "overview" | "users" | "clients" | "iap" | "organizations" | "invitations" | "registration" | "providers" | "portal" | "security" | "settings";
type UserFilter = "live" | "active" | "disabled" | "archived" | "all";

const translations = {
  "zh-CN": {
    loading: "加载中",
    signIn: "登录",
    register: "注册",
    firstAdmin: "首次启动：注册第一个管理员",
    adminConsole: "管理控制台",
    email: "邮箱",
    phone: "手机号",
    password: "密码",
    newPassword: "新密码",
    username: "用户名",
    displayName: "显示名",
    invitationCode: "授权码",
    authorizationCodePrefix: "授权码",
    authAccountSwitch: "当前浏览器已登录其他账号，请使用授权方指定的邮箱继续。",
    emailCode: "邮箱验证码",
    phoneCode: "手机验证码",
    sendEmailCode: "发送邮箱验证码",
    sendPhoneCode: "发送手机验证码",
    forgotPassword: "忘记密码",
    resetPassword: "重置密码",
    resetPasswordCode: "重置验证码",
    sendResetCode: "发送重置验证码",
    completePasswordReset: "确认重置密码",
    passwordResetComplete: "密码已重置，请重新登录。",
    passwordRegistrationUnavailable: "密码注册已关闭，请使用授权码或第三方身份源。",
    temporaryAccountReady: "授权码临时账户已登录，可查阅信息。",
    createdInvitation: "新授权码",
    overview: "概览",
    users: "用户",
    clients: "OIDC 客户端",
    iap: "IAP 应用",
    invitations: "授权码",
    registration: "注册设置",
    providers: "身份源",
    portal: "登录入口",
    account: "账号",
    security: "安全",
    settings: "运行配置",
    logout: "退出",
    refresh: "刷新",
    create: "创建",
    save: "保存",
    edit: "编辑",
    enable: "启用",
    disable: "禁用",
    archive: "归档",
    delete: "删除",
    details: "详情",
    active: "启用",
    disabled: "禁用",
    archived: "归档",
    allUsers: "全部账户",
    liveUsers: "正常/禁用",
    activeUsers: "正常账户",
    disabledUsers: "禁用账户",
    archivedUsers: "归档账户",
    userFilter: "账户筛选",
    archivedAt: "归档时间",
    archivedReadOnly: "归档账户不可编辑，请先启用。",
    admin: "管理员",
    normalUser: "普通用户",
    role: "角色",
    status: "状态",
    registeredAt: "注册时间",
    lastLogin: "最近登录",
    lastIp: "最近 IP",
    lastClient: "最近 OIDC 客户端",
    loginMethod: "登录方式",
    verified: "已验证",
    unverified: "未验证",
    noUserAdminOnly: "当前账号不是管理员。",
    createUser: "创建用户",
    updateUser: "更新用户",
    userDetails: "用户详情",
    loginEvents: "登录事件",
    linkedIdentities: "绑定身份",
    createClient: "创建 OIDC 客户端",
    createIapApplication: "创建 IAP 应用",
    updateIapApplication: "更新 IAP 应用",
    iapApplication: "IAP 应用",
    externalHost: "外部 Host",
    pathPrefix: "路径前缀",
    requiredOrganization: "要求组织",
    requiredOrganizationRoles: "要求组织角色",
    requiredPermissions: "要求权限",
    forwardAuthEndpoint: "ForwardAuth 端点",
    clientId: "客户端 ID",
    clientName: "客户端名称",
    clientSecret: "客户端密钥",
    redirectUris: "回调地址",
    postLogoutUris: "退出回调地址",
    scopes: "Scopes",
    grantTypes: "Grant Types",
    responseTypes: "Response Types",
    tokenAuthMethod: "Token 认证方式",
    requirePkce: "要求 PKCE",
    requireClientMfa: "强制 MFA",
    requirePar: "强制 PAR",
    requireS256Pkce: "强制 S256 PKCE",
    requireConfidentialClient: "禁止 Public Client",
    requireDpop: "强制 DPoP",
    requireAccountSelection: "强制账号选择",
    trustEmailVerified: "信任邮箱已验证",
    authorizationDetailsTypes: "RAR 授权类型",
    serviceAccount: "机器身份",
    serviceAccountPermissions: "机器身份权限",
    subjectType: "Subject Type",
    sectorIdentifierUri: "Sector Identifier URI",
    jwksUri: "JWKS URI",
    jwks: "JWKS JSON",
    backchannelLogoutUri: "Back-Channel Logout URI",
    backchannelLogoutSessionRequired: "Logout Token 要求 sid",
    frontchannelLogoutUri: "Front-Channel Logout URI",
    frontchannelLogoutSessionRequired: "Iframe 通知要求 sid",
    claimMappers: "Claim 映射",
    claimName: "Claim 名称",
    claimSource: "来源",
    sourceValue: "来源值",
    valueType: "值类型",
    includeIdToken: "ID Token",
    includeAccessToken: "Access Token",
    includeUserInfo: "UserInfo",
    addClaimMapper: "添加 Claim",
    userField: "用户字段",
    staticValue: "固定值",
    scopeFlag: "Scope 标记",
    clientField: "客户端字段",
    createInvitation: "创建授权码",
    updateInvitation: "更新授权码",
    authorizedEmail: "授权邮箱",
    authorizedUsername: "授权用户名",
    authorizedDisplayName: "授权显示名",
    description: "描述",
    expiresAt: "过期时间",
    maxUses: "最大使用次数",
    used: "已使用",
    redemptions: "兑换记录",
    redeemedAt: "兑换时间",
    permanent: "永久",
    unlimited: "不限次数",
    registrationSettings: "注册策略",
    passwordRegistration: "允许密码注册",
    requireEmailVerification: "要求邮箱验证",
    requirePhoneVerification: "要求手机号验证",
    allowExternalOidc: "允许第三方 OIDC 注册",
    requireInvitation: "要求授权码",
    firstUserAdmin: "首个用户自动成为管理员",
    defaultUserActive: "注册后默认启用",
    createProvider: "创建第三方 OIDC",
    updateProvider: "更新第三方 OIDC",
    providerTemplate: "Provider 模板",
    applyTemplate: "套用模板",
    discoverProvider: "发现端点",
    ldapProviders: "LDAP/AD 目录",
    createLdapProvider: "创建 LDAP/AD",
    updateLdapProvider: "更新 LDAP/AD",
    slug: "标识",
    issuer: "Issuer",
    authorizationEndpoint: "授权端点",
    tokenEndpoint: "Token 端点",
    userinfoEndpoint: "Userinfo 端点",
    redirectPath: "回调路径",
    providerEmailDomains: "企业邮箱域名",
    allowRegistration: "允许注册",
    allowLogin: "允许登录",
    ldapUrl: "LDAP URL",
    startTls: "StartTLS",
    bindDn: "Bind DN",
    bindPassword: "Bind 密码",
    clearBindPassword: "清空 Bind 密码",
    baseDn: "Base DN",
    ldapUserFilter: "用户过滤器",
    userIdAttribute: "用户 ID 属性",
    emailAttribute: "邮箱属性",
    usernameAttribute: "用户名属性",
    displayNameAttribute: "显示名属性",
    phoneAttribute: "手机号属性",
    directoryLogin: "目录登录",
    externalLogin: "第三方登录/注册",
    domainSsoLogin: "使用公司 SSO 登录",
    domainSsoRegister: "使用公司 SSO 注册/登录",
    language: "语言",
    database: "数据库",
    issuerLabel: "Issuer",
    runtimeSettings: "外部访问设置",
    loginSettings: "登录入口设置",
    companyEmailDomains: "公司邮箱后缀",
    quickLinks: "快捷跳转",
    createQuickLink: "添加快捷跳转",
    updateQuickLink: "更新快捷跳转",
    linkLabel: "链接名称",
    linkUrl: "跳转链接",
    linkIcon: "图标",
    customDomain: "自定义后缀",
    applySuffix: "使用",
    randomEmail: "随机邮箱",
    copyEmail: "复制邮箱",
    copiedEmail: "邮箱已复制",
    copyEmailUnavailable: "浏览器不支持自动复制，请手动复制",
    copyAuthorizationCode: "复制授权码",
    authorizationCodeCopied: "授权码已复制",
    copyAuthorizationCodeUnavailable: "浏览器不支持自动复制，请手动复制授权码",
    companyEmailRequired: "请使用已配置的公司邮箱登录此应用",
    mfaCode: "二次验证码",
    mfaRequired: "需要二次验证",
    captcha: "安全验证",
    captchaAnswer: "验证答案",
    captchaRequired: "需要完成安全验证",
    mfaSettings: "二次验证",
    totpSetup: "TOTP 设置",
    startTotpSetup: "开始设置 TOTP",
    confirmTotp: "确认 TOTP",
    totpSecret: "TOTP Secret",
    otpauthUri: "Authenticator URI",
    recoveryCodes: "恢复码",
    recoveryCodesRemaining: "剩余恢复码",
    rotateRecoveryCodes: "重新生成恢复码",
    disableMfa: "关闭二次验证",
    resetMfa: "重置 MFA",
    recoveryCodesOnce: "恢复码只显示一次，请妥善保存。",
    passkeys: "Passkey",
    passkeyLogin: "使用 Passkey 登录",
    passkeyName: "Passkey 名称",
    registerPasskey: "注册 Passkey",
    noPasskeys: "暂无 Passkey",
    credentialId: "凭据 ID",
    lastUsed: "最近使用",
    securityPolicy: "安全策略",
    passwordPolicy: "密码策略",
    loginLockout: "登录锁定",
    minPasswordLength: "密码最小长度",
    requireUppercase: "要求大写字母",
    requireLowercase: "要求小写字母",
    requireDigit: "要求数字",
    requireSymbol: "要求符号",
    rejectUserInfo: "拒绝包含账号信息",
    maxFailedAttempts: "最大失败次数",
    failureWindowSeconds: "失败统计窗口（秒）",
    lockoutSeconds: "锁定时长（秒）",
    trustedNetworks: "可信网络",
    trustedIpCidrs: "可信 IP/CIDR",
    requireMfaOutsideTrustedNetworks: "外部网络强制 MFA",
    accessRiskRules: "登录/注册风险规则",
    allowedIpCidrs: "允许 IP/CIDR",
    blockedIpCidrs: "阻止 IP/CIDR",
    allowedEmailDomains: "允许邮箱域名",
    blockedEmailDomains: "阻止邮箱域名",
    captchaPolicy: "登录安全验证",
    captchaAfterFailedAttempts: "失败后要求验证次数",
    captchaTtlSeconds: "验证有效期（秒）",
    signingKeys: "签名密钥",
    keyId: "Key ID",
    activeSigningKey: "当前签名",
    retiredSigningKey: "已退役",
    rotateSigningKey: "轮换密钥",
    activatedAt: "启用时间",
    retiredAt: "退役时间",
    auditEvents: "审计事件",
    auditWebhooks: "审计 Webhook",
    createAuditWebhook: "创建审计 Webhook",
    updateAuditWebhook: "更新审计 Webhook",
    webhookName: "Webhook 名称",
    webhookUrl: "Webhook URL",
    webhookSecret: "签名密钥",
    webhookActions: "Action 过滤",
    webhookTimeout: "超时（秒）",
    clearWebhookSecret: "清除签名密钥",
    hasSecret: "已配置签名",
    lastDelivery: "最近投递",
    deliveryStatus: "投递状态",
    roles: "角色",
    groups: "用户组",
    organizations: "组织",
    clientOrganization: "所属组织",
    noOrganization: "无组织",
    permissions: "权限",
    roleName: "角色名",
    groupName: "组名",
    organizationName: "组织名称",
    organizationSlug: "组织标识",
    organizationMembers: "组织成员",
    organizationRole: "组织角色",
    createOrganization: "创建组织",
    updateOrganization: "更新组织",
    rolePermissions: "角色权限",
    groupRoles: "组角色",
    groupMembers: "组成员",
    userAccess: "用户授权",
    directRoles: "直接角色",
    effectivePermissions: "有效权限",
    selectUser: "选择用户",
    createRole: "创建角色",
    updateRole: "更新角色",
    createGroup: "创建用户组",
    updateGroup: "更新用户组",
    systemRole: "系统角色",
    customRole: "自定义角色",
    clear: "清空",
    actor: "操作者",
    action: "动作",
    target: "目标",
    outcome: "结果",
    detailsJson: "详情",
    publicBaseUrl: "公网 Base URL",
    effectivePublicBaseUrl: "当前生效 Base URL",
    effectiveIssuer: "当前生效 Issuer",
    trustProxyHeaders: "信任代理/穿透请求头",
    usersMetric: "用户数",
    clientsMetric: "客户端数",
    openRegister: "没有账号？注册",
    openLogin: "已有账号？登录",
    codeSent: "验证码已生成",
    copiedCodeHint: "开发模式验证码已显示，可直接填入。",
    authorizedApplications: "已授权应用",
    activeSessions: "登录会话",
    currentSession: "当前会话",
    revokeSession: "撤销会话",
    noActiveSessions: "暂无活跃会话",
    sessionId: "会话",
    device: "设备",
    ipAddress: "IP 地址",
    userAgent: "User-Agent",
    authMethod: "认证方式",
    createdAt: "创建时间",
    grantedScopes: "授权范围",
    grantedAt: "授权时间",
    updatedAt: "更新时间",
    revoke: "撤销",
    noAuthorizedApplications: "暂无已记住授权",
    noData: "暂无数据",
    loginFailed: "登录失败",
    registrationFailed: "注册失败",
    sendVerificationFailed: "发送验证码失败",
    sendResetCodeFailed: "发送重置验证码失败",
    resetPasswordFailed: "重置密码失败",
    saveUserFailed: "保存用户失败",
    saveClientFailed: "保存客户端失败",
    saveIapApplicationFailed: "保存 IAP 应用失败",
    saveInvitationFailed: "保存授权码失败",
    saveRoleFailed: "保存角色失败",
    saveGroupFailed: "保存用户组失败",
    saveOrganizationFailed: "保存组织失败",
    startMfaSetupFailed: "开始设置二次验证失败",
    confirmMfaSetupFailed: "确认二次验证失败",
    rotateRecoveryCodesFailed: "重新生成恢复码失败",
    disableMfaFailed: "关闭二次验证失败",
    registerPasskeyFailed: "注册 Passkey 失败",
    passkeyLoginFailed: "Passkey 登录失败",
    deletePasskeyFailed: "删除 Passkey 失败",
    revokeAuthorizationFailed: "撤销授权失败",
    revokeSessionFailed: "撤销会话失败",
    saveSecurityPolicyFailed: "保存安全策略失败",
    rotateSigningKeyFailed: "轮换签名密钥失败",
    saveRegistrationSettingsFailed: "保存注册策略失败",
    saveRuntimeSettingsFailed: "保存运行配置失败",
    saveLoginSettingsFailed: "保存登录入口设置失败",
    saveProviderFailed: "保存第三方 OIDC 失败",
    discoverProviderFailed: "发现 OIDC 端点失败",
    saveLdapProviderFailed: "保存 LDAP/AD 失败",
    saveAuditWebhookFailed: "保存审计 Webhook 失败",
    refreshFailed: "刷新失败"
  },
  "en-US": {
    loading: "Loading",
    signIn: "Sign in",
    register: "Register",
    firstAdmin: "First start: register the first administrator",
    adminConsole: "Admin console",
    email: "Email",
    phone: "Phone",
    password: "Password",
    newPassword: "New password",
    username: "Username",
    displayName: "Display name",
    invitationCode: "Authorization code",
    authorizationCodePrefix: "Code",
    authAccountSwitch: "A different account is signed in. Continue with the email requested by the application.",
    emailCode: "Email code",
    phoneCode: "Phone code",
    sendEmailCode: "Send email code",
    sendPhoneCode: "Send phone code",
    forgotPassword: "Forgot password",
    resetPassword: "Reset password",
    resetPasswordCode: "Reset code",
    sendResetCode: "Send reset code",
    completePasswordReset: "Reset password",
    passwordResetComplete: "Password reset. Sign in again.",
    passwordRegistrationUnavailable: "Password registration is disabled. Use an authorization code or an identity source.",
    temporaryAccountReady: "Temporary authorization-code account signed in for read-only access.",
    createdInvitation: "New authorization code",
    overview: "Overview",
    users: "Users",
    clients: "OIDC Clients",
    iap: "IAP apps",
    invitations: "Authorization codes",
    registration: "Registration",
    providers: "Identity sources",
    portal: "Login entry",
    account: "Account",
    security: "Security",
    settings: "Settings",
    logout: "Log out",
    refresh: "Refresh",
    create: "Create",
    save: "Save",
    edit: "Edit",
    enable: "Enable",
    disable: "Disable",
    archive: "Archive",
    delete: "Delete",
    details: "Details",
    active: "Active",
    disabled: "Disabled",
    archived: "Archived",
    allUsers: "All accounts",
    liveUsers: "Active/disabled",
    activeUsers: "Active accounts",
    disabledUsers: "Disabled accounts",
    archivedUsers: "Archived accounts",
    userFilter: "Account filter",
    archivedAt: "Archived at",
    archivedReadOnly: "Archived accounts are read-only. Enable first to edit.",
    admin: "Admin",
    normalUser: "User",
    role: "Role",
    status: "Status",
    registeredAt: "Registered",
    lastLogin: "Last login",
    lastIp: "Last IP",
    lastClient: "Last OIDC client",
    loginMethod: "Login method",
    verified: "Verified",
    unverified: "Unverified",
    noUserAdminOnly: "This account is not an administrator.",
    createUser: "Create user",
    updateUser: "Update user",
    userDetails: "User details",
    loginEvents: "Login events",
    linkedIdentities: "Linked identities",
    createClient: "Create OIDC client",
    createIapApplication: "Create IAP app",
    updateIapApplication: "Update IAP app",
    iapApplication: "IAP app",
    externalHost: "External host",
    pathPrefix: "Path prefix",
    requiredOrganization: "Required organization",
    requiredOrganizationRoles: "Required organization roles",
    requiredPermissions: "Required permissions",
    forwardAuthEndpoint: "ForwardAuth endpoint",
    clientId: "Client ID",
    clientName: "Client name",
    clientSecret: "Client secret",
    redirectUris: "Redirect URIs",
    postLogoutUris: "Post logout URIs",
    scopes: "Scopes",
    grantTypes: "Grant types",
    responseTypes: "Response types",
    tokenAuthMethod: "Token auth method",
    requirePkce: "Require PKCE",
    requireClientMfa: "Require MFA",
    requirePar: "Require PAR",
    requireS256Pkce: "Require S256 PKCE",
    requireConfidentialClient: "Disallow public client",
    requireDpop: "Require DPoP",
    requireAccountSelection: "Require account selection",
    trustEmailVerified: "Trust email as verified",
    authorizationDetailsTypes: "RAR authorization detail types",
    serviceAccount: "Service account",
    serviceAccountPermissions: "Service account permissions",
    subjectType: "Subject type",
    sectorIdentifierUri: "Sector identifier URI",
    jwksUri: "JWKS URI",
    jwks: "JWKS JSON",
    backchannelLogoutUri: "Back-Channel logout URI",
    backchannelLogoutSessionRequired: "Require sid in logout token",
    frontchannelLogoutUri: "Front-Channel logout URI",
    frontchannelLogoutSessionRequired: "Require sid in iframe notification",
    claimMappers: "Claim mappers",
    claimName: "Claim name",
    claimSource: "Source",
    sourceValue: "Source value",
    valueType: "Value type",
    includeIdToken: "ID Token",
    includeAccessToken: "Access Token",
    includeUserInfo: "UserInfo",
    addClaimMapper: "Add claim",
    userField: "User field",
    staticValue: "Static value",
    scopeFlag: "Scope flag",
    clientField: "Client field",
    createInvitation: "Create authorization code",
    updateInvitation: "Update authorization code",
    authorizedEmail: "Authorized email",
    authorizedUsername: "Authorized username",
    authorizedDisplayName: "Authorized display name",
    description: "Description",
    expiresAt: "Expires at",
    maxUses: "Max uses",
    used: "Used",
    redemptions: "Redemptions",
    redeemedAt: "Redeemed at",
    permanent: "Permanent",
    unlimited: "Unlimited",
    registrationSettings: "Registration policy",
    passwordRegistration: "Allow password registration",
    requireEmailVerification: "Require email verification",
    requirePhoneVerification: "Require phone verification",
    allowExternalOidc: "Allow external OIDC registration",
    requireInvitation: "Require authorization code",
    firstUserAdmin: "First user becomes admin",
    defaultUserActive: "Default user active",
    createProvider: "Create external OIDC",
    updateProvider: "Update external OIDC",
    providerTemplate: "Provider template",
    applyTemplate: "Apply template",
    discoverProvider: "Discover endpoints",
    ldapProviders: "LDAP/AD directories",
    createLdapProvider: "Create LDAP/AD",
    updateLdapProvider: "Update LDAP/AD",
    slug: "Slug",
    issuer: "Issuer",
    authorizationEndpoint: "Authorization endpoint",
    tokenEndpoint: "Token endpoint",
    userinfoEndpoint: "Userinfo endpoint",
    redirectPath: "Redirect path",
    providerEmailDomains: "Enterprise email domains",
    allowRegistration: "Allow registration",
    allowLogin: "Allow login",
    ldapUrl: "LDAP URL",
    startTls: "StartTLS",
    bindDn: "Bind DN",
    bindPassword: "Bind password",
    clearBindPassword: "Clear bind password",
    baseDn: "Base DN",
    ldapUserFilter: "User filter",
    userIdAttribute: "User ID attribute",
    emailAttribute: "Email attribute",
    usernameAttribute: "Username attribute",
    displayNameAttribute: "Display name attribute",
    phoneAttribute: "Phone attribute",
    directoryLogin: "Directory login",
    externalLogin: "External login/register",
    domainSsoLogin: "Use company SSO",
    domainSsoRegister: "Use company SSO",
    language: "Language",
    database: "Database",
    issuerLabel: "Issuer",
    runtimeSettings: "External access settings",
    loginSettings: "Login entry settings",
    companyEmailDomains: "Company email suffixes",
    quickLinks: "Quick links",
    createQuickLink: "Add quick link",
    updateQuickLink: "Update quick link",
    linkLabel: "Link label",
    linkUrl: "Link URL",
    linkIcon: "Icon",
    customDomain: "Custom suffix",
    applySuffix: "Apply",
    randomEmail: "Random email",
    copyEmail: "Copy email",
    copiedEmail: "Email copied",
    copyEmailUnavailable: "Clipboard is unavailable. Copy manually",
    copyAuthorizationCode: "Copy authorization code",
    authorizationCodeCopied: "Authorization code copied",
    copyAuthorizationCodeUnavailable: "Clipboard is unavailable. Copy the authorization code manually",
    companyEmailRequired: "Use a configured company email to sign in to this application",
    mfaCode: "MFA code",
    mfaRequired: "MFA required",
    mfaSettings: "Multi-factor authentication",
    totpSetup: "TOTP setup",
    startTotpSetup: "Start TOTP setup",
    confirmTotp: "Confirm TOTP",
    totpSecret: "TOTP secret",
    otpauthUri: "Authenticator URI",
    recoveryCodes: "Recovery codes",
    recoveryCodesRemaining: "Recovery codes remaining",
    rotateRecoveryCodes: "Rotate recovery codes",
    disableMfa: "Disable MFA",
    resetMfa: "Reset MFA",
    captcha: "Security check",
    captchaAnswer: "Security answer",
    captchaRequired: "Security check required",
    recoveryCodesOnce: "Recovery codes are shown only once. Store them now.",
    passkeys: "Passkeys",
    passkeyLogin: "Sign in with passkey",
    passkeyName: "Passkey name",
    registerPasskey: "Register passkey",
    noPasskeys: "No passkeys",
    credentialId: "Credential ID",
    lastUsed: "Last used",
    securityPolicy: "Security policy",
    passwordPolicy: "Password policy",
    loginLockout: "Login lockout",
    minPasswordLength: "Minimum password length",
    requireUppercase: "Require uppercase",
    requireLowercase: "Require lowercase",
    requireDigit: "Require digit",
    requireSymbol: "Require symbol",
    rejectUserInfo: "Reject account identifiers",
    maxFailedAttempts: "Max failed attempts",
    failureWindowSeconds: "Failure window (seconds)",
    lockoutSeconds: "Lockout duration (seconds)",
    trustedNetworks: "Trusted networks",
    trustedIpCidrs: "Trusted IP/CIDR",
    requireMfaOutsideTrustedNetworks: "Require MFA outside trusted networks",
    accessRiskRules: "Login/registration risk rules",
    allowedIpCidrs: "Allowed IP/CIDR",
    blockedIpCidrs: "Blocked IP/CIDR",
    allowedEmailDomains: "Allowed email domains",
    blockedEmailDomains: "Blocked email domains",
    captchaPolicy: "Login security check",
    captchaAfterFailedAttempts: "Require after failed attempts",
    captchaTtlSeconds: "Challenge TTL (seconds)",
    signingKeys: "Signing keys",
    keyId: "Key ID",
    activeSigningKey: "Active signer",
    retiredSigningKey: "Retired",
    rotateSigningKey: "Rotate key",
    activatedAt: "Activated",
    retiredAt: "Retired",
    auditEvents: "Audit events",
    auditWebhooks: "Audit webhooks",
    createAuditWebhook: "Create audit webhook",
    updateAuditWebhook: "Update audit webhook",
    webhookName: "Webhook name",
    webhookUrl: "Webhook URL",
    webhookSecret: "Signing secret",
    webhookActions: "Action filters",
    webhookTimeout: "Timeout (seconds)",
    clearWebhookSecret: "Clear signing secret",
    hasSecret: "Signing enabled",
    lastDelivery: "Last delivery",
    deliveryStatus: "Delivery status",
    roles: "Roles",
    groups: "Groups",
    organizations: "Organizations",
    clientOrganization: "Organization",
    noOrganization: "No organization",
    permissions: "Permissions",
    roleName: "Role name",
    groupName: "Group name",
    organizationName: "Organization name",
    organizationSlug: "Organization slug",
    organizationMembers: "Organization members",
    organizationRole: "Organization role",
    createOrganization: "Create organization",
    updateOrganization: "Update organization",
    rolePermissions: "Role permissions",
    groupRoles: "Group roles",
    groupMembers: "Group members",
    userAccess: "User access",
    directRoles: "Direct roles",
    effectivePermissions: "Effective permissions",
    selectUser: "Select user",
    createRole: "Create role",
    updateRole: "Update role",
    createGroup: "Create group",
    updateGroup: "Update group",
    systemRole: "System role",
    customRole: "Custom role",
    clear: "Clear",
    actor: "Actor",
    action: "Action",
    target: "Target",
    outcome: "Outcome",
    detailsJson: "Details",
    publicBaseUrl: "Public base URL",
    effectivePublicBaseUrl: "Effective base URL",
    effectiveIssuer: "Effective issuer",
    trustProxyHeaders: "Trust proxy/tunnel headers",
    usersMetric: "Users",
    clientsMetric: "Clients",
    openRegister: "Need an account? Register",
    openLogin: "Already have an account? Sign in",
    codeSent: "Verification code generated",
    copiedCodeHint: "Development code is shown and can be entered directly.",
    authorizedApplications: "Authorized applications",
    activeSessions: "Login sessions",
    currentSession: "Current session",
    revokeSession: "Revoke session",
    noActiveSessions: "No active sessions",
    sessionId: "Session",
    device: "Device",
    ipAddress: "IP address",
    userAgent: "User-Agent",
    authMethod: "Auth method",
    createdAt: "Created",
    grantedScopes: "Granted scopes",
    grantedAt: "Granted",
    updatedAt: "Updated",
    revoke: "Revoke",
    noAuthorizedApplications: "No remembered authorizations",
    noData: "No data",
    loginFailed: "Login failed",
    registrationFailed: "Registration failed",
    sendVerificationFailed: "Failed to send verification code",
    sendResetCodeFailed: "Failed to send reset code",
    resetPasswordFailed: "Failed to reset password",
    saveUserFailed: "Failed to save user",
    saveClientFailed: "Failed to save client",
    saveIapApplicationFailed: "Failed to save IAP app",
    saveInvitationFailed: "Failed to save authorization code",
    saveRoleFailed: "Failed to save role",
    saveGroupFailed: "Failed to save group",
    saveOrganizationFailed: "Failed to save organization",
    startMfaSetupFailed: "Failed to start MFA setup",
    confirmMfaSetupFailed: "Failed to confirm MFA setup",
    rotateRecoveryCodesFailed: "Failed to rotate recovery codes",
    disableMfaFailed: "Failed to disable MFA",
    registerPasskeyFailed: "Failed to register passkey",
    passkeyLoginFailed: "Passkey login failed",
    deletePasskeyFailed: "Failed to delete passkey",
    revokeAuthorizationFailed: "Failed to revoke authorization",
    revokeSessionFailed: "Failed to revoke session",
    saveSecurityPolicyFailed: "Failed to save security policy",
    rotateSigningKeyFailed: "Failed to rotate signing key",
    saveRegistrationSettingsFailed: "Failed to save registration settings",
    saveRuntimeSettingsFailed: "Failed to save runtime settings",
    saveLoginSettingsFailed: "Failed to save login settings",
    saveProviderFailed: "Failed to save provider",
    discoverProviderFailed: "Failed to discover OIDC endpoints",
    saveLdapProviderFailed: "Failed to save LDAP/AD",
    saveAuditWebhookFailed: "Failed to save audit webhook",
    refreshFailed: "Failed to refresh"
  }
};

type TranslationKey = keyof typeof translations["zh-CN"];

const DEFAULT_LOGIN_EMAIL = "admin@example.com";

const emptyUserForm = {
  id: "",
  email: "",
  username: "",
  display_name: "",
  phone: "",
  password: "",
  is_admin: false,
  is_active: true
};

const emptyRegisterForm = {
  username: "",
  display_name: "",
  phone: "",
  password: "",
  email_code: "",
  phone_code: "",
  authorization_code: ""
};

const emptyPasswordResetForm = {
  code: "",
  password: ""
};

const emptyClientForm = {
  id: "",
  client_id: "",
  client_name: "",
  organization_id: "",
  client_secret: "",
  redirect_uris: "http://localhost:3000/callback",
  post_logout_redirect_uris: "http://localhost:3000/",
  scopes: "openid profile email offline_access",
  grant_types: "authorization_code refresh_token",
  response_types: "code",
  token_endpoint_auth_method: "client_secret_basic",
  require_pkce: false,
  require_mfa: false,
  require_pushed_authorization_requests: false,
  require_s256_pkce: false,
  require_confidential_client: false,
  require_dpop: false,
  require_account_selection: false,
  trust_email_verified: false,
  authorization_details_types: "",
  subject_type: "public",
  sector_identifier_uri: "",
  jwks_uri: "",
  jwks: "",
  backchannel_logout_uri: "",
  backchannel_logout_session_required: false,
  frontchannel_logout_uri: "",
  frontchannel_logout_session_required: false,
  service_account_enabled: false,
  service_account_permissions: "",
  is_active: true,
  claim_mappers: [] as ClientClaimMapperForm[]
};

const emptyIapApplicationForm = {
  id: "",
  slug: "",
  name: "",
  description: "",
  external_host: "",
  path_prefix: "/",
  required_organization_id: "",
  required_organization_roles: [] as string[],
  required_permissions: "",
  is_active: true
};

function emptyClaimMapperForm(sortOrder: number): ClientClaimMapperForm {
  return {
    claim_name: "",
    source: "user_field",
    source_value: "username",
    value_type: "string",
    include_in_id_token: true,
    include_in_access_token: false,
    include_in_userinfo: true,
    is_active: true,
    sort_order: sortOrder
  };
}

const emptyInvitationForm = {
  id: "",
  description: "",
  authorized_email: "",
  authorized_username: "",
  authorized_display_name: "",
  expires_at: "",
  max_uses: "",
  is_active: true
};

const AUTHORIZATION_CODES_API = "/api/admin/authorization-codes";

const emptyQuickLinkForm = {
  id: "",
  label: "",
  url: "",
  icon: "link",
  is_active: true
};

const emptyRoleForm = {
  id: "",
  name: "",
  description: "",
  permissions: [] as string[]
};

const emptyGroupForm = {
  id: "",
  name: "",
  description: "",
  role_ids: [] as string[],
  user_ids: [] as string[]
};

const emptyOrganizationForm = {
  id: "",
  slug: "",
  name: "",
  description: "",
  allowed_email_domains: "",
  is_active: true
};

const emptyProviderForm = {
  id: "",
  slug: "",
  display_name: "",
  organization_id: "",
  issuer: "",
  client_id: "",
  client_secret: "",
  authorization_endpoint: "",
  token_endpoint: "",
  userinfo_endpoint: "",
  redirect_path: "/api/register/oidc/example/callback",
  scopes: "openid profile email",
  email_domains: "",
  is_active: false,
  allow_login: true,
  allow_registration: true
};

const emptyLdapProviderForm = {
  id: "",
  slug: "",
  display_name: "",
  url: "ldap://ldap.example.com",
  starttls: true,
  bind_dn: "",
  bind_password: "",
  clear_bind_password: false,
  base_dn: "dc=example,dc=com",
  user_filter: "(&(|(mail={login})(uid={login})(sAMAccountName={login}))(objectClass=person))",
  user_id_attribute: "dn",
  email_attribute: "mail",
  username_attribute: "uid",
  display_name_attribute: "cn",
  phone_attribute: "telephoneNumber",
  is_active: false,
  allow_login: true,
  allow_registration: true
};

const emptyAuditWebhookForm = {
  id: "",
  name: "",
  url: "",
  secret: "",
  clear_secret: false,
  actions: "",
  is_active: true,
  timeout_seconds: 5
};

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...options,
    credentials: "include",
    headers: {
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...(options.headers ?? {})
    }
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ message: response.statusText }));
    throw new Error(body.message ?? response.statusText);
  }
  return response.json() as Promise<T>;
}

function base64urlToBuffer(value: string): ArrayBuffer {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

function bufferSourceToBase64url(value: BufferSource | null): string | null {
  if (!value) return null;
  const bytes = value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function passkeyCreationOptions(value: WebauthnCreationResponseJson): CredentialCreationOptions {
  const publicKey = value.publicKey;
  return {
    publicKey: {
      ...publicKey,
      challenge: base64urlToBuffer(publicKey.challenge),
      excludeCredentials: publicKey.excludeCredentials?.map((credential) => ({
        ...credential,
        id: base64urlToBuffer(credential.id)
      })),
      user: {
        ...publicKey.user,
        id: base64urlToBuffer(publicKey.user.id)
      }
    }
  };
}

function passkeyRequestOptions(value: WebauthnRequestResponseJson): CredentialRequestOptions {
  const publicKey = value.publicKey;
  return {
    mediation: value.mediation,
    publicKey: {
      ...publicKey,
      allowCredentials: publicKey.allowCredentials?.map((credential) => ({
        ...credential,
        id: base64urlToBuffer(credential.id)
      })),
      challenge: base64urlToBuffer(publicKey.challenge)
    }
  };
}

function registrationCredentialJson(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAttestationResponse & {
    getTransports?: () => AuthenticatorTransport[];
  };
  return {
    id: credential.id,
    rawId: bufferSourceToBase64url(credential.rawId),
    response: {
      attestationObject: bufferSourceToBase64url(response.attestationObject),
      clientDataJSON: bufferSourceToBase64url(response.clientDataJSON),
      transports: response.getTransports?.()
    },
    type: credential.type,
    extensions: credential.getClientExtensionResults()
  };
}

function authenticationCredentialJson(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bufferSourceToBase64url(credential.rawId),
    response: {
      authenticatorData: bufferSourceToBase64url(response.authenticatorData),
      clientDataJSON: bufferSourceToBase64url(response.clientDataJSON),
      signature: bufferSourceToBase64url(response.signature),
      userHandle: bufferSourceToBase64url(response.userHandle)
    },
    type: credential.type,
    extensions: credential.getClientExtensionResults()
  };
}

function splitList(value: string): string[] {
  return value
    .split(/[\n, ]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function deliverFrontchannelLogout(frames: LogoutFrame[] = []) {
  frames.forEach((frame) => {
    if (!frame.uri) return;
    const iframe = document.createElement("iframe");
    iframe.src = frame.uri;
    iframe.title = frame.client_id || "frontchannel-logout";
    iframe.style.display = "none";
    iframe.width = "0";
    iframe.height = "0";
    document.body.appendChild(iframe);
    window.setTimeout(() => iframe.remove(), 2500);
  });
}

function joinList(value: string[]): string {
  return value.join(" ");
}

function formatTime(value: number | null | undefined, locale: Locale): string {
  if (!value) return "-";
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value * 1000));
}

function shortSessionId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 12)}...` : value;
}

function toTimestamp(value: string): number | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : Math.floor(date.getTime() / 1000);
}

function toDatetimeLocalValue(value: number | null | undefined): string {
  if (!value) return "";
  const date = new Date(value * 1000);
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function sortUsersForDisplay(value: User[]): User[] {
  const bucket = (item: User) => {
    if (item.archived_at) return 2;
    return item.is_active ? 0 : 1;
  };
  return [...value].sort((left, right) => {
    const bucketDiff = bucket(left) - bucket(right);
    if (bucketDiff !== 0) return bucketDiff;
    const leftTime = left.archived_at ?? left.created_at;
    const rightTime = right.archived_at ?? right.created_at;
    return rightTime - leftTime;
  });
}

function toggleValue(values: string[], value: string): string[] {
  return values.includes(value)
    ? values.filter((item) => item !== value)
    : [...values, value];
}

function normalizeDomain(value: string): string {
  return value.trim().replace(/^@+/, "").replace(/^\.+/, "").replace(/\.+$/, "").toLowerCase();
}

function usableEmailDomain(value: string): string {
  const domain = normalizeDomain(value);
  if (!domain || domain.includes("@") || domain.includes("/") || domain.includes("\\") || /\s/.test(domain) || domain.split(".").some((part) => !part)) return "";
  return domain;
}

function emailDomain(value: string): string {
  const [, domain = ""] = value.trim().toLowerCase().split("@").slice(-2);
  return usableEmailDomain(domain);
}

function domainMatchesRule(domain: string, rule: string): boolean {
  const normalizedRule = usableEmailDomain(rule);
  return Boolean(normalizedRule && (domain === normalizedRule || domain.endsWith(`.${normalizedRule}`)));
}

function findProviderForEmail(providers: ExternalProviderSummary[], email: string): ExternalProviderSummary | null {
  const domain = emailDomain(email);
  if (!domain) return null;
  let matched: { provider: ExternalProviderSummary; rule: string } | null = null;
  for (const provider of providers) {
    for (const rule of provider.email_domains) {
      const normalizedRule = usableEmailDomain(rule);
      if (!normalizedRule || !domainMatchesRule(domain, normalizedRule)) continue;
      if (!matched || normalizedRule.length > matched.rule.length) {
        matched = { provider, rule: normalizedRule };
      }
    }
  }
  return matched?.provider ?? null;
}

function applyEmailDomain(email: string, domain: string): string {
  const suffix = usableEmailDomain(domain);
  if (!suffix) return email;
  const local = email.split("@")[0]?.trim() || randomLocalPart();
  return `${local}@${suffix}`;
}

function randomLocalPart(): string {
  const time = Date.now().toString(36);
  const random = Math.random().toString(36).slice(2, 8);
  return `u${time}${random}`;
}

function currentLocalReturnTo(): string {
  const target = `${window.location.pathname}${window.location.search}${window.location.hash}` || "/";
  return localReturnTo(target) ?? "/";
}

function oidcStartUrl(startUrl: string, email: string, mode: "login" | "register"): string {
  const separator = startUrl.includes("?") ? "&" : "?";
  const params = [`return_to=${encodeURIComponent(currentLocalReturnTo())}`, `mode=${mode}`];
  const loginHint = normalizedAuthEmail(email);
  if (loginHint.includes("@")) {
    params.push(`login_hint=${encodeURIComponent(loginHint)}`);
  }
  return `${startUrl}${separator}${params.join("&")}`;
}

function localReturnTo(value: string | null): string | null {
  const target = value?.trim() ?? "";
  if (!target || target === "/" || !target.startsWith("/") || target.startsWith("//")) return null;
  if (target.includes("\\") || /[\r\n]/.test(target)) return null;
  return target;
}

function normalizedAuthEmail(value: string | null | undefined): string {
  return value?.trim().toLowerCase() ?? "";
}

function loginHintRequiresAccountSwitch(user: User | null | undefined, loginHint: string): boolean {
  const hint = normalizedAuthEmail(loginHint);
  if (!user || !hint.includes("@")) return false;
  return normalizedAuthEmail(user.email) !== hint;
}

function loginHintFromReturnTo(returnTo: string | null): string {
  if (!returnTo?.startsWith("/oauth2/authorize?")) return "";
  const query = returnTo.slice("/oauth2/authorize?".length).split("#", 1)[0];
  return new URLSearchParams(query).get("login_hint")?.trim() ?? "";
}

type InitialAuthContext = {
  mode: AuthMode;
  returnTo: string | null;
  loginHint: string;
  forceLogin: boolean;
  authError: string;
  authErrorCode: string;
  authErrorDetail: string;
};

function initialAuthContext(): InitialAuthContext {
  const params = new URLSearchParams(window.location.search);
  const modeParam = params.get("auth");
  const mode: AuthMode = modeParam === "register" || modeParam === "reset" ? modeParam : "login";
  const returnTo = localReturnTo(params.get("return_to"));
  const loginHint = params.get("login_hint")?.trim() || loginHintFromReturnTo(returnTo);
  const forceLogin = params.get("force_login") === "1";
  const authError = params.get("auth_error")?.trim() ?? "";
  const authErrorCode = params.get("auth_error_code")?.trim() ?? "";
  const authErrorDetail = params.get("auth_error_detail")?.trim() ?? "";
  return { mode, returnTo, loginHint, forceLogin, authError, authErrorCode, authErrorDetail };
}

function authContextError(
  context: InitialAuthContext,
  t: (key: TranslationKey) => string
): string {
  if (context.authError) return context.authError;
  if (context.authErrorCode === "company_email_required") {
    return context.authErrorDetail
      ? `${t("companyEmailRequired")}: ${context.authErrorDetail}`
      : t("companyEmailRequired");
  }
  return "";
}

function randomId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `link-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

export function App() {
  const initialAuth = useMemo(initialAuthContext, []);
  const [locale, setLocale] = useState<Locale>(() => {
    const saved = localStorage.getItem("gpt-sso-locale");
    return saved === "en-US" ? "en-US" : "zh-CN";
  });
  const t = (key: TranslationKey) => translations[locale][key];
  const messageOr = (err: unknown, fallback: TranslationKey) =>
    err instanceof Error ? err.message : t(fallback);

  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [tab, setTab] = useState<Tab>("account");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [iapApplications, setIapApplications] = useState<IapApplication[]>([]);
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [registrationSettings, setRegistrationSettings] = useState<RegistrationSettings | null>(null);
  const [providers, setProviders] = useState<ExternalProvider[]>([]);
  const [providerTemplates, setProviderTemplates] = useState<ExternalProviderTemplate[]>([]);
  const [ldapProviders, setLdapProviders] = useState<LdapProvider[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditWebhooks, setAuditWebhooks] = useState<AuditWebhook[]>([]);
  const [permissionCatalog, setPermissionCatalog] = useState<PermissionInfo[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [groups, setGroups] = useState<AccessGroup[]>([]);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
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
  const [loginSettings, setLoginSettings] = useState<LoginSettings | null>(null);
  const [selectedUser, setSelectedUser] = useState<UserDetail | null>(null);
  const [userFilter, setUserFilter] = useState<UserFilter>("live");
  const [userForm, setUserForm] = useState(emptyUserForm);
  const [registerForm, setRegisterForm] = useState(emptyRegisterForm);
  const [passwordResetForm, setPasswordResetForm] = useState(emptyPasswordResetForm);
  const [clientForm, setClientForm] = useState(emptyClientForm);
  const [iapApplicationForm, setIapApplicationForm] = useState(emptyIapApplicationForm);
  const [invitationForm, setInvitationForm] = useState(emptyInvitationForm);
  const [roleForm, setRoleForm] = useState(emptyRoleForm);
  const [groupForm, setGroupForm] = useState(emptyGroupForm);
  const [organizationForm, setOrganizationForm] = useState(emptyOrganizationForm);
  const [organizationMemberRoles, setOrganizationMemberRoles] = useState<Record<string, string>>({});
  const [selectedAccessUserId, setSelectedAccessUserId] = useState("");
  const [userAccess, setUserAccess] = useState<UserAccess | null>(null);
  const [providerForm, setProviderForm] = useState(emptyProviderForm);
  const [providerTemplateId, setProviderTemplateId] = useState("");
  const [ldapProviderForm, setLdapProviderForm] = useState(emptyLdapProviderForm);
  const [auditWebhookForm, setAuditWebhookForm] = useState(emptyAuditWebhookForm);
  const [loginSettingsDraft, setLoginSettingsDraft] = useState<LoginSettingsDraft>({
    email_domains: "",
    quick_links: []
  });
  const [quickLinkForm, setQuickLinkForm] = useState(emptyQuickLinkForm);
  const [authEmail, setAuthEmail] = useState(initialAuth.loginHint || DEFAULT_LOGIN_EMAIL);
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
  const [lastInvitationCode, setLastInvitationCode] = useState("");
  const [verificationMessage, setVerificationMessage] = useState("");
  const [error, setError] = useState(() => authContextError(initialAuth, t));
  const [busy, setBusy] = useState(false);

  const userPermissions = user?.permissions ?? [];
  const authAccountSwitch = Boolean(authReturnTo && loginHintRequiresAccountSwitch(user, initialAuth.loginHint));
  const authCanCompleteWithCurrentUser = Boolean(
    user && !user.archived_at && authReturnTo && !authAccountSwitch && !initialAuth.forceLogin
  );
  const hasPermission = (...permissions: string[]) =>
    Boolean(user?.is_admin || permissions.some((permission) => userPermissions.includes(permission)));
  const canAdmin = Boolean(user?.is_admin || userPermissions.length > 0);
  const canReadUsers = hasPermission("users.read", "users.manage", "organizations.manage", "security.manage");
  const canManageUsers = hasPermission("users.manage");
  const canReadClients = hasPermission("clients.read", "clients.manage");
  const canManageClients = hasPermission("clients.manage");
  const canReadIap = hasPermission("iap.read", "iap.manage");
  const canManageIap = hasPermission("iap.manage");
  const canReadOrganizations = hasPermission(
    "organizations.read",
    "organizations.manage",
    "clients.manage",
    "iap.read",
    "iap.manage"
  );
  const canManageOrganizations = hasPermission("organizations.manage");
  const canManageAuthorizationCodes = hasPermission("authorization_codes.manage");
  const canManageSettings = hasPermission("settings.manage");
  const canManageProviders = hasPermission("providers.manage");
  const canReadAudit = hasPermission("audit.read");
  const canManageSecurity = hasPermission("security.manage");

  function setSharedAuthEmail(value: string) {
    setAuthEmail(value);
  }

  function finishInteractiveAuth(nextUser: User): boolean {
    setUser(nextUser);
    if (!authReturnTo) return false;
    if (loginHintRequiresAccountSwitch(nextUser, initialAuth.loginHint)) {
      setSharedAuthEmail(initialAuth.loginHint);
      setError(t("authAccountSwitch"));
      return false;
    }
    if (nextUser.archived_at) {
      setVerificationMessage(t("temporaryAccountReady"));
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
    const next = await api<Bootstrap>("/api/public/bootstrap");
    setBootstrap(next);
    const defaultDomain = next.login.email_domains[0];
    if (defaultDomain) {
      setAuthEmail((current) => {
        if (current !== DEFAULT_LOGIN_EMAIL) return current;
        return applyEmailDomain("admin", defaultDomain);
      });
    }
    if (!next.has_users) {
      setAuthMode("register");
    }
  }

  async function loadMe() {
    const me = await api<User | null>("/api/me");
    setUser(me);
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

  async function loadAdminData() {
    if (!canAdmin) return;
    const [
      nextOverview,
      nextUsers,
      nextClients,
      nextIapApplications,
      nextInvitations,
      nextRegistration,
      nextProviders,
      nextProviderTemplates,
      nextLdapProviders,
      nextRuntime,
      nextLoginSettings,
      nextAuditEvents,
      nextAuditWebhooks,
      nextPermissionCatalog,
      nextRoles,
      nextGroups,
      nextOrganizations,
      nextSecurityPolicy,
      nextSigningKeys,
      nextSettings
    ] =
      await Promise.all([
        api<Overview>("/api/admin/overview"),
        canReadUsers ? api<User[]>(`/api/admin/users?status=${userFilter}`) : Promise.resolve([]),
        canReadClients ? api<Client[]>("/api/admin/clients") : Promise.resolve([]),
        canReadIap ? api<IapApplication[]>("/api/admin/iap-applications") : Promise.resolve([]),
        canManageAuthorizationCodes ? api<Invitation[]>(AUTHORIZATION_CODES_API) : Promise.resolve([]),
        canManageSettings ? api<RegistrationSettings>("/api/admin/registration-settings") : Promise.resolve(null),
        canManageProviders ? api<ExternalProvider[]>("/api/admin/external-oidc-providers") : Promise.resolve([]),
        canManageProviders ? api<ExternalProviderTemplate[]>("/api/admin/external-oidc-provider-templates") : Promise.resolve([]),
        canManageProviders ? api<LdapProvider[]>("/api/admin/ldap-providers") : Promise.resolve([]),
        canManageSettings ? api<RuntimeSettings>("/api/admin/runtime-settings") : Promise.resolve(null),
        canManageSettings ? api<LoginSettings>("/api/admin/login-settings") : Promise.resolve(null),
        canReadAudit ? api<AuditEvent[]>("/api/admin/audit-events") : Promise.resolve([]),
        (canReadAudit || canManageSecurity) ? api<AuditWebhook[]>("/api/admin/audit-webhooks") : Promise.resolve([]),
        canManageSecurity ? api<PermissionInfo[]>("/api/admin/access/permissions") : Promise.resolve([]),
        canManageSecurity ? api<Role[]>("/api/admin/access/roles") : Promise.resolve([]),
        canManageSecurity ? api<AccessGroup[]>("/api/admin/access/groups") : Promise.resolve([]),
        (canReadOrganizations || canManageProviders) ? api<Organization[]>("/api/admin/organizations") : Promise.resolve([]),
        canManageSecurity ? api<SecurityPolicy>("/api/admin/security-policy") : Promise.resolve(null),
        canManageSecurity ? api<SigningKey[]>("/api/admin/signing-keys") : Promise.resolve([]),
        canManageSettings ? api<SettingsSummary>("/api/admin/settings") : Promise.resolve(null)
      ]);
    setOverview(nextOverview);
    setUsers(sortUsersForDisplay(nextUsers));
    setClients(nextClients);
    setIapApplications(nextIapApplications);
    setInvitations(nextInvitations);
    setRegistrationSettings(nextRegistration);
    setProviders(nextProviders);
    setProviderTemplates(nextProviderTemplates);
    setLdapProviders(nextLdapProviders);
    setAuditEvents(nextAuditEvents);
    setAuditWebhooks(nextAuditWebhooks);
    setPermissionCatalog(nextPermissionCatalog);
    setRoles(nextRoles);
    setGroups(nextGroups);
    setOrganizations(nextOrganizations);
    setSecurityPolicy(nextSecurityPolicy);
    setSigningKeys(nextSigningKeys);
    setRuntimeSettings(nextRuntime);
    setLoginSettings(nextLoginSettings);
    if (nextLoginSettings) {
      setLoginSettingsDraft({
        email_domains: nextLoginSettings.email_domains.join("\n"),
        quick_links: nextLoginSettings.quick_links
      });
    } else {
      setLoginSettingsDraft({ email_domains: "", quick_links: [] });
    }
    setSettings(nextSettings);
  }

  useEffect(() => {
    Promise.all([loadBootstrap(), loadMe()]).catch(() => setUser(null));
  }, []);

  useEffect(() => {
    if (authCanCompleteWithCurrentUser && authReturnTo) {
      window.location.assign(authReturnTo);
    }
  }, [authCanCompleteWithCurrentUser, authReturnTo]);

  useEffect(() => {
    loadAccountData().catch((err) => setError(err.message));
  }, [user?.id]);

  useEffect(() => {
    loadAdminData().catch((err) => setError(err.message));
  }, [canAdmin, userFilter]);

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
          return_to: authReturnTo
        })
      });
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

  async function handlePasskeyLogin() {
    setBusy(true);
    setError("");
    try {
      if (!navigator.credentials?.get || !window.PublicKeyCredential) {
        throw new Error(t("passkeyLoginFailed"));
      }
      const start = await api<PasskeyAuthenticationStart>("/api/passkeys/authentication/start", {
        method: "POST",
        body: JSON.stringify({ email: authEmail })
      });
      const credential = await navigator.credentials.get(passkeyRequestOptions(start.public_key));
      if (!credential || credential.type !== "public-key") {
        throw new Error(t("passkeyLoginFailed"));
      }
      const result = await api<{ user: User }>("/api/passkeys/authentication/finish", {
        method: "POST",
        body: JSON.stringify({
          challenge_id: start.challenge_id,
          credential: authenticationCredentialJson(credential as PublicKeyCredential)
        })
      });
      setLoginMfaChallengeId("");
      setLoginMfaCode("");
      setLoginRecoveryAvailable(false);
      setLoginCaptchaChallengeId("");
      setLoginCaptchaPrompt("");
      setLoginCaptchaAnswer("");
      if (finishInteractiveAuth(result.user)) return;
      await loadBootstrap();
    } catch (err) {
      setError(messageOr(err, "passkeyLoginFailed"));
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
      const body: Record<string, string | null> = {
        display_name: registerForm.display_name || null,
        authorization_code: registerForm.authorization_code || null
      };
      if (!authorizationCodeRegistration || authEmail.trim()) {
        body.email = authEmail;
      }
      if (!authorizationCodeRegistration || registerForm.username.trim()) {
        body.username = registerForm.username;
      }
      if (!authorizationCodeRegistration) {
        body.phone = registerForm.phone || null;
        body.password = registerForm.password;
        body.email_code = registerForm.email_code || null;
        body.phone_code = registerForm.phone_code || null;
      }
      const result = await api<{ user: User; first_admin: boolean }>("/api/register", {
        method: "POST",
        body: JSON.stringify(body)
      });
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
    setError("");
    const target = channel === "email" ? authEmail : registerForm.phone;
    try {
      const result = await api<{ dev_code: string | null; expires_at: number }>("/api/register/verification/start", {
        method: "POST",
        body: JSON.stringify({ channel, target })
      });
      setVerificationMessage(
        `${t("codeSent")}${result.dev_code ? `: ${result.dev_code}. ${t("copiedCodeHint")}` : ""}`
      );
      if (channel === "email" && result.dev_code) {
        setRegisterForm({ ...registerForm, email_code: result.dev_code });
      }
      if (channel === "phone" && result.dev_code) {
        setRegisterForm({ ...registerForm, phone_code: result.dev_code });
      }
    } catch (err) {
      setError(messageOr(err, "sendVerificationFailed"));
    }
  }

  async function sendPasswordResetCode() {
    setError("");
    try {
      const result = await api<{ dev_code: string | null; expires_at: number }>("/api/password-reset/start", {
        method: "POST",
        body: JSON.stringify({ email: authEmail })
      });
      setVerificationMessage(
        `${t("codeSent")}${result.dev_code ? `: ${result.dev_code}. ${t("copiedCodeHint")}` : ""}`
      );
      if (result.dev_code) {
        setPasswordResetForm({ ...passwordResetForm, code: result.dev_code });
      }
    } catch (err) {
      setError(messageOr(err, "sendResetCodeFailed"));
    }
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

  async function handleLogout() {
    const result = await api<LogoutResponse>("/api/logout", { method: "POST" });
    deliverFrontchannelLogout(result.frontchannel_logout_frames);
    setUser(null);
    await loadBootstrap();
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
      await loadAdminData();
    } catch (err) {
      setError(messageOr(err, "saveUserFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function showUserDetails(id: string) {
    setSelectedUser(await api<UserDetail>(`/api/admin/users/${id}`));
  }

  async function enableUser(id: string) {
    await api(`/api/admin/users/${id}/enable`, { method: "POST" });
    await loadAdminData();
    if (selectedUser?.user.id === id) setSelectedUser(null);
  }

  async function advanceUserLifecycle(id: string) {
    await api(`/api/admin/users/${id}`, { method: "DELETE" });
    await loadAdminData();
    if (selectedUser?.user.id === id) setSelectedUser(null);
    if (userForm.id === id) setUserForm(emptyUserForm);
  }

  async function saveClient(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = JSON.stringify({
        client_id: clientForm.client_id,
        client_name: clientForm.client_name,
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
      await loadAdminData();
    } catch (err) {
      setError(messageOr(err, "saveClientFailed"));
    } finally {
      setBusy(false);
    }
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
  }

  async function deleteIapApplication(id: string) {
    await api(`/api/admin/iap-applications/${id}`, { method: "DELETE" });
    if (iapApplicationForm.id === id) setIapApplicationForm(emptyIapApplicationForm);
    await loadAdminData();
  }

  async function saveInvitation(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setLastInvitationCode("");
    try {
      const body = JSON.stringify({
        description: invitationForm.description || null,
        authorized_email: invitationForm.authorized_email || null,
        authorized_username: invitationForm.authorized_username || null,
        authorized_display_name: invitationForm.authorized_display_name || null,
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
  }

  async function deleteRole(id: string) {
    await api(`/api/admin/access/roles/${id}`, { method: "DELETE" });
    if (roleForm.id === id) setRoleForm(emptyRoleForm);
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
  }

  async function deleteGroup(id: string) {
    await api(`/api/admin/access/groups/${id}`, { method: "DELETE" });
    if (groupForm.id === id) setGroupForm(emptyGroupForm);
    await loadAdminData();
    if (selectedAccessUserId) await loadUserAccess(selectedAccessUserId);
  }

  async function saveOrganization(event: FormEvent) {
    event.preventDefault();
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
      setOrganizationForm(emptyOrganizationForm);
      setOrganizationMemberRoles({});
      await loadAdminData();
    } catch (err) {
      setError(messageOr(err, "saveOrganizationFailed"));
    } finally {
      setBusy(false);
    }
  }

  function editOrganization(organization: Organization) {
    setOrganizationForm({
      id: organization.id,
      slug: organization.slug,
      name: organization.name,
      description: organization.description ?? "",
      allowed_email_domains: organization.allowed_email_domains.join("\n"),
      is_active: organization.is_active
    });
    setOrganizationMemberRoles(
      Object.fromEntries(organization.members.map((member) => [member.user_id, member.role]))
    );
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
      setOrganizationForm(emptyOrganizationForm);
      setOrganizationMemberRoles({});
    }
    await loadAdminData();
  }

  async function loadUserAccess(id: string) {
    setSelectedAccessUserId(id);
    if (!id) {
      setUserAccess(null);
      return;
    }
    setUserAccess(await api<UserAccess>(`/api/admin/users/${id}/access`));
  }

  async function saveUserRoles() {
    if (!selectedAccessUserId || !userAccess) return;
    const updated = await api<UserAccess>(`/api/admin/users/${selectedAccessUserId}/roles`, {
      method: "PUT",
      body: JSON.stringify({ role_ids: userAccess.direct_roles.map((role) => role.id) })
    });
    setUserAccess(updated);
    await loadAdminData();
  }

  async function startTotpSetup() {
    setError("");
    setNewRecoveryCodes([]);
    setTotpSetupCode("");
    try {
      setTotpSetup(await api<TotpSetup>("/api/mfa/totp", { method: "POST" }));
    } catch (err) {
      setError(messageOr(err, "startMfaSetupFailed"));
    }
  }

  async function confirmTotpSetup() {
    if (!totpSetup) return;
    setError("");
    try {
      const result = await api<MfaConfirmResponse>("/api/mfa/totp/confirm", {
        method: "POST",
        body: JSON.stringify({ setup_id: totpSetup.setup_id, code: totpSetupCode })
      });
      setMfaStatus(result.status);
      setNewRecoveryCodes(result.recovery_codes);
      setTotpSetup(null);
      setTotpSetupCode("");
      await loadAccountData();
    } catch (err) {
      setError(messageOr(err, "confirmMfaSetupFailed"));
    }
  }

  async function rotateRecoveryCodes() {
    setError("");
    try {
      const result = await api<MfaConfirmResponse>("/api/mfa/recovery-codes/rotate", { method: "POST" });
      setMfaStatus(result.status);
      setNewRecoveryCodes(result.recovery_codes);
      await loadAccountData();
    } catch (err) {
      setError(messageOr(err, "rotateRecoveryCodesFailed"));
    }
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
      setError(messageOr(err, "disableMfaFailed"));
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
      setError(messageOr(err, "deletePasskeyFailed"));
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
      setError(messageOr(err, "revokeAuthorizationFailed"));
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
      setError(messageOr(err, "revokeSessionFailed"));
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
      setError(messageOr(err, "rotateSigningKeyFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function saveRegistrationSettings(event: FormEvent) {
    event.preventDefault();
    if (!registrationSettings) return;
    setBusy(true);
    try {
      const updated = await api<RegistrationSettings>("/api/admin/registration-settings", {
        method: "PUT",
        body: JSON.stringify({
          ...registrationSettings,
          first_user_direct_admin: true
        })
      });
      setRegistrationSettings(updated);
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
          email_domains: splitList(draft.email_domains).map(normalizeDomain),
          quick_links: draft.quick_links
        })
      });
      setLoginSettings(updated);
      setLoginSettingsDraft({
        email_domains: updated.email_domains.join("\n"),
        quick_links: updated.quick_links
      });
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
      id: quickLinkForm.id || randomId(),
      label: quickLinkForm.label.trim(),
      url: quickLinkForm.url.trim(),
      icon: quickLinkForm.icon.trim() || "link",
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
      icon: link.icon,
      is_active: link.is_active
    });
  }

  async function removeQuickLink(id: string) {
    const saved = await persistLoginSettings({
      ...loginSettingsDraft,
      quick_links: loginSettingsDraft.quick_links.filter((item) => item.id !== id)
    });
    if (saved && quickLinkForm.id === id) setQuickLinkForm(emptyQuickLinkForm);
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
    setLdapProviderForm({
      id: provider.id,
      slug: provider.slug,
      display_name: provider.display_name,
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
    });
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
      await loadAdminData();
    } catch (err) {
      setError(messageOr(err, "saveAuditWebhookFailed"));
    } finally {
      setBusy(false);
    }
  }

  function editAuditWebhook(webhook: AuditWebhook) {
    setAuditWebhookForm({
      id: webhook.id,
      name: webhook.name,
      url: webhook.url,
      secret: "",
      clear_secret: false,
      actions: webhook.actions.join("\n"),
      is_active: webhook.is_active,
      timeout_seconds: webhook.timeout_seconds
    });
  }

  async function deleteAuditWebhook(id: string) {
    await api(`/api/admin/audit-webhooks/${id}`, { method: "DELETE" });
    setAuditWebhookForm((current) => (current.id === id ? emptyAuditWebhookForm : current));
    await loadAdminData();
  }

  async function refreshCurrentTab() {
    setError("");
    try {
      if (tab === "account") {
        await loadAccountData();
      } else {
        await loadAdminData();
      }
    } catch (err) {
      setError(messageOr(err, "refreshFailed"));
    }
  }

  const tabs = useMemo(
    () => {
      const accountTab = { id: "account" as const, label: t("account"), icon: UserRound };
      const adminTabs = [
        { id: "overview" as const, label: t("overview"), icon: Shield },
        canReadUsers ? { id: "users" as const, label: t("users"), icon: Users } : null,
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
      return canAdmin ? [accountTab, ...adminTabs] : [accountTab];
    },
    [
      locale,
      canAdmin,
      canReadUsers,
      canReadClients,
      canReadIap,
      canReadOrganizations,
      canManageAuthorizationCodes,
      canManageSettings,
      canManageProviders,
      canManageSecurity,
      canReadAudit
    ]
  );

  useEffect(() => {
    if (!tabs.some((item) => item.id === tab)) {
      setTab("account");
    }
  }, [tab, tabs]);

  if (user === undefined || !bootstrap) {
    return <div className="loading">{t("loading")}</div>;
  }

  if (authCanCompleteWithCurrentUser) {
    return <div className="loading">{t("loading")}</div>;
  }

  const authorizationCodeRegistration =
    bootstrap.has_users
    && (
      Boolean(registerForm.authorization_code.trim())
      || bootstrap.registration.require_invitation
    );
  const passwordRegistrationUnavailable =
    bootstrap.has_users
    && authMode === "register"
    && !authorizationCodeRegistration
    && !bootstrap.registration.allow_password_registration;
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

  if (!user || authAccountSwitch || (authReturnTo && initialAuth.forceLogin)) {
    return (
      <main className="login-shell">
        <section className="login-panel">
          <TopLanguage locale={locale} switchLocale={switchLocale} label={t("language")} />
          <div className="brand-row">
            <Shield size={28} />
            <div>
              <h1>GPT SSO</h1>
              <p>{bootstrap.has_users ? t("adminConsole") : t("firstAdmin")}</p>
            </div>
          </div>
          <div className="segmented">
            <button type="button" className={authMode === "login" ? "active" : ""} onClick={() => setAuthMode("login")}>
              {t("signIn")}
            </button>
            <button type="button" className={authMode === "register" ? "active" : ""} onClick={() => setAuthMode("register")}>
              {t("register")}
            </button>
            {bootstrap.has_users && (
              <button type="button" className={authMode === "reset" ? "active" : ""} onClick={() => setAuthMode("reset")}>
                {t("resetPassword")}
              </button>
            )}
          </div>
          {error && <div className="error">{error}</div>}
          {authAccountSwitch && <div className="info">{t("authAccountSwitch")}</div>}
          {verificationMessage && <div className="info">{verificationMessage}</div>}
          {authMode === "login" && bootstrap.has_users && (
            <form onSubmit={handleLogin}>
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
                <a className="secondary-link" href={oidcStartUrl(loginDomainProvider.start_url, authEmail, "login")}>
                  <Link2 size={16} />
                  {t("domainSsoLogin")} · {loginDomainProvider.display_name}
                </a>
              )}
              <Field label={t("password")} type="password" value={loginPassword} onChange={setLoginPassword} />
              {loginMfaChallengeId && (
                <>
                  <Field label={t("mfaCode")} value={loginMfaCode} onChange={setLoginMfaCode} />
                  <small>{t("mfaRequired")}{loginRecoveryAvailable ? ` · ${t("recoveryCodes")}` : ""}</small>
                </>
              )}
              {loginCaptchaChallengeId && (
                <>
                  <Field label={`${t("captchaAnswer")} · ${loginCaptchaPrompt}`} value={loginCaptchaAnswer} onChange={setLoginCaptchaAnswer} />
                  <small>{t("captchaRequired")}</small>
                </>
              )}
              <button className="primary" type="submit" disabled={busy}>
                {t("signIn")}
              </button>
              <button className="link-button" type="button" onClick={handlePasskeyLogin} disabled={busy}>
                <KeyRound size={14} />
                {t("passkeyLogin")}
              </button>
              <button className="link-button" type="button" onClick={() => setAuthMode("register")}>
                {t("openRegister")}
              </button>
              <button className="link-button" type="button" onClick={() => setAuthMode("reset")}>
                {t("forgotPassword")}
              </button>
            </form>
          )}
          {authMode === "reset" && bootstrap.has_users && (
            <form onSubmit={handlePasswordReset}>
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
              />
              <Field label={t("newPassword")} type="password" value={passwordResetForm.password} onChange={(value) => setPasswordResetForm({ ...passwordResetForm, password: value })} />
              <button className="primary" type="submit" disabled={busy}>
                {t("completePasswordReset")}
              </button>
              <button className="link-button" type="button" onClick={() => setAuthMode("login")}>
                {t("openLogin")}
              </button>
            </form>
          )}
          {(authMode === "register" || !bootstrap.has_users) && (
            <form onSubmit={handleRegister}>
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
              {registerDomainProvider && (
                <a className="secondary-link" href={oidcStartUrl(registerDomainProvider.start_url, authEmail, "register")}>
                  <Link2 size={16} />
                  {t("domainSsoRegister")} · {registerDomainProvider.display_name}
                </a>
              )}
              {bootstrap.has_users && (
                <Field label={t("invitationCode")} value={registerForm.authorization_code} onChange={(value) => setRegisterForm({ ...registerForm, authorization_code: value })} />
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
              {bootstrap.registration.require_email_verification && bootstrap.has_users && !authorizationCodeRegistration && (
                <InlineCode
                  icon={<Mail size={16} />}
                  label={t("emailCode")}
                  button={t("sendEmailCode")}
                  value={registerForm.email_code}
                  onChange={(value) => setRegisterForm({ ...registerForm, email_code: value })}
                  onSend={() => sendVerification("email")}
                />
              )}
              {!authorizationCodeRegistration && (
                <>
                  <Field label={t("phone")} value={registerForm.phone} onChange={(value) => setRegisterForm({ ...registerForm, phone: value })} />
                  {bootstrap.registration.require_phone_verification && bootstrap.has_users && (
                    <InlineCode
                      icon={<Phone size={16} />}
                      label={t("phoneCode")}
                      button={t("sendPhoneCode")}
                      value={registerForm.phone_code}
                      onChange={(value) => setRegisterForm({ ...registerForm, phone_code: value })}
                      onSend={() => sendVerification("phone")}
                    />
                  )}
                </>
              )}
              <Field label={t("username")} value={registerForm.username} onChange={(value) => setRegisterForm({ ...registerForm, username: value })} />
              <Field label={t("displayName")} value={registerForm.display_name} onChange={(value) => setRegisterForm({ ...registerForm, display_name: value })} />
              {!authorizationCodeRegistration && (
                <Field label={t("password")} type="password" value={registerForm.password} onChange={(value) => setRegisterForm({ ...registerForm, password: value })} />
              )}
              <button className="primary" type="submit" disabled={busy || passwordRegistrationUnavailable}>
                {t("register")}
              </button>
              {bootstrap.has_users && (
                <button className="link-button" type="button" onClick={() => setAuthMode("login")}>
                  {t("openLogin")}
                </button>
              )}
            </form>
          )}
          {visibleExternalProviders.length > 0 && (
            <div className="external-list">
              <span>{t("externalLogin")}</span>
              {visibleExternalProviders.map((provider) => (
                <a
                  key={provider.slug}
                  className="secondary-link"
                  href={oidcStartUrl(
                    provider.start_url,
                    authEmail,
                    authMode === "login" ? "login" : "register"
                  )}
                >
                  <Link2 size={16} />
                  {provider.display_name}
                </a>
              ))}
            </div>
          )}
          {bootstrap.ldap_providers.length > 0 && (
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
          <QuickJump links={bootstrap.login.quick_links} />
        </section>
      </main>
    );
  }

  return (
    <div className="app-shell">
      <aside>
        <div className="brand-row compact">
          <Shield size={24} />
          <div>
            <h1>GPT SSO</h1>
            <p>{user.email}</p>
          </div>
        </div>
        <TopLanguage locale={locale} switchLocale={switchLocale} label={t("language")} compact />
        <nav>
          {tabs.map((item) => {
            const Icon = item.icon;
            return (
              <button type="button" key={item.id} className={tab === item.id ? "active" : ""} onClick={() => setTab(item.id)}>
                <Icon size={18} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
        <button className="ghost" type="button" onClick={handleLogout} title={t("logout")}>
          <LogOut size={18} />
          <span>{t("logout")}</span>
        </button>
      </aside>
      <main className="content">
        <header>
          <div>
            <h2>{tabs.find((item) => item.id === tab)?.label}</h2>
            <p>{tab === "account" ? user.email : overview?.issuer ?? "OIDC provider"}</p>
          </div>
          <button className="icon-button" type="button" onClick={refreshCurrentTab} title={t("refresh")}>
            <RefreshCw size={18} />
          </button>
        </header>
        {error && <div className="error">{error}</div>}
        {!canAdmin && tab !== "account" ? <div className="empty">{t("noUserAdminOnly")}</div> : null}
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
                {!user.archived_at && (
                  <div className="actions">
                    <button type="button" onClick={startTotpSetup}><KeyRound size={14} />{t("startTotpSetup")}</button>
                    {mfaStatus?.enabled && <button type="button" onClick={rotateRecoveryCodes}>{t("rotateRecoveryCodes")}</button>}
                    {mfaStatus?.enabled && <button type="button" onClick={disableMfa}>{t("disableMfa")}</button>}
                  </div>
                )}
                {totpSetup && !user.archived_at && (
                  <div className="mfa-setup">
                    <label>{t("totpSecret")}</label>
                    <textarea readOnly value={totpSetup.secret} />
                    <label>{t("otpauthUri")}</label>
                    <textarea readOnly value={totpSetup.otpauth_uri} />
                    <Field label={t("mfaCode")} value={totpSetupCode} onChange={setTotpSetupCode} />
                    <div className="actions">
                      <button type="button" onClick={confirmTotpSetup}><Save size={14} />{t("confirmTotp")}</button>
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
                {!user.archived_at && (
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
                          {!user.archived_at && (
                            <button type="button" onClick={() => deletePasskey(passkey.id)} disabled={busy}>
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
                          {!user.archived_at && !session.current && (
                            <button type="button" onClick={() => revokeMySession(session.id)} disabled={busy}>
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
                          {!user.archived_at && (
                            <button type="button" onClick={() => revokeMyConsent(consent.client_id)} disabled={busy}>
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
        {canAdmin && tab === "overview" && (
          <section className="metrics-grid">
            <Metric label={t("usersMetric")} value={overview?.users ?? 0} detail={`${overview?.active_users ?? 0} ${t("active")}`} />
            <Metric label={t("clientsMetric")} value={overview?.clients ?? 0} detail={`${overview?.active_clients ?? 0} ${t("active")}`} />
            <Metric label={t("database")} value={overview?.database_kind ?? "-"} detail={t("settings")} />
            <Metric label={t("issuerLabel")} value={overview?.issuer ?? "-"} detail="OIDC" />
          </section>
        )}
        {canReadUsers && tab === "users" && (
          <section className="users-layout">
            {canManageUsers && (
              <form className="panel" onSubmit={saveUser}>
                <h3>{userForm.id ? t("updateUser") : t("createUser")}</h3>
                <Field label={t("email")} value={userForm.email} onChange={(value) => setUserForm({ ...userForm, email: value })} />
                <Field label={t("username")} value={userForm.username} onChange={(value) => setUserForm({ ...userForm, username: value })} />
                <Field label={t("displayName")} value={userForm.display_name} onChange={(value) => setUserForm({ ...userForm, display_name: value })} />
                <Field label={t("phone")} value={userForm.phone} onChange={(value) => setUserForm({ ...userForm, phone: value })} />
                <Field label={t("password")} type="password" value={userForm.password} onChange={(value) => setUserForm({ ...userForm, password: value })} />
                <Check label={t("admin")} checked={userForm.is_admin} onChange={(value) => setUserForm({ ...userForm, is_admin: value })} />
                {!userForm.id && <Check label={t("active")} checked={userForm.is_active} onChange={(value) => setUserForm({ ...userForm, is_active: value })} />}
                <button className="primary" type="submit" disabled={busy}>
                  <Save size={16} />
                  {t("save")}
                </button>
              </form>
            )}
            <div className="table-panel">
              <div className="table-toolbar">
                <label className="filter-control">
                  <span>{t("userFilter")}</span>
                  <select value={userFilter} onChange={(event) => setUserFilter(event.target.value as UserFilter)}>
                    <option value="live">{t("liveUsers")}</option>
                    <option value="active">{t("activeUsers")}</option>
                    <option value="disabled">{t("disabledUsers")}</option>
                    <option value="archived">{t("archivedUsers")}</option>
                    <option value="all">{t("allUsers")}</option>
                  </select>
                </label>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>{t("email")}</th>
                    <th>{t("role")}</th>
                    <th>{t("registeredAt")}</th>
                    <th>{t("lastLogin")}</th>
                    <th>{t("status")}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((item) => (
                    <tr key={item.id}>
                      <td>{item.email}<br /><small>{item.username}</small></td>
                      <td>{item.is_admin ? t("admin") : t("normalUser")}</td>
                      <td>{formatTime(item.created_at, locale)}</td>
                      <td>{formatTime(item.last_login_at, locale)}</td>
                      <td>
                        {item.archived_at ? t("archived") : item.is_active ? t("active") : t("disabled")}
                        {item.archived_at && <><br /><small>{formatTime(item.archived_at, locale)}</small></>}
                      </td>
                      <td className="actions">
                        {canManageUsers && !item.archived_at && (
                          <button type="button" onClick={() => {
                            setUserForm({
                              id: item.id,
                              email: item.email,
                              username: item.username,
                              display_name: item.display_name ?? "",
                              phone: item.phone ?? "",
                              password: "",
                              is_admin: item.is_admin,
                              is_active: item.is_active
                            });
                          }}>{t("edit")}</button>
                        )}
                        <button type="button" onClick={() => showUserDetails(item.id)}>{t("details")}</button>
                        {canManageUsers && !item.archived_at && (
                          <button type="button" onClick={() => resetUserMfa(item.id)}>
                            <KeyRound size={14} />
                            {t("resetMfa")}
                          </button>
                        )}
                        {canManageUsers && !item.archived_at && item.is_active && (
                          <button type="button" onClick={() => advanceUserLifecycle(item.id)}>
                            <Ban size={14} />
                            {t("disable")}
                          </button>
                        )}
                        {canManageUsers && !item.archived_at && !item.is_active && (
                          <>
                            <button type="button" onClick={() => enableUser(item.id)}>
                              <RotateCcw size={14} />
                              {t("enable")}
                            </button>
                            <button type="button" onClick={() => advanceUserLifecycle(item.id)}>
                              <Archive size={14} />
                              {t("archive")}
                            </button>
                          </>
                        )}
                        {canManageUsers && item.archived_at && (
                          <>
                            <button type="button" onClick={() => enableUser(item.id)}>
                              <RotateCcw size={14} />
                              {t("enable")}
                            </button>
                            <button type="button" onClick={() => advanceUserLifecycle(item.id)}>
                              <Trash2 size={14} />
                              {t("delete")}
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {selectedUser && (
                <UserDetailPanel detail={selectedUser} locale={locale} t={t} onClose={() => setSelectedUser(null)} />
              )}
            </div>
          </section>
        )}
        {canReadOrganizations && tab === "organizations" && (
          <section className="split wide">
            {canManageOrganizations && (
              <form className="panel" onSubmit={saveOrganization}>
                <h3>{organizationForm.id ? t("updateOrganization") : t("createOrganization")}</h3>
                <Field label={t("organizationSlug")} value={organizationForm.slug} onChange={(value) => setOrganizationForm({ ...organizationForm, slug: value })} />
                <Field label={t("organizationName")} value={organizationForm.name} onChange={(value) => setOrganizationForm({ ...organizationForm, name: value })} />
                <Field label={t("description")} value={organizationForm.description} onChange={(value) => setOrganizationForm({ ...organizationForm, description: value })} textarea />
                <Field label={t("allowedEmailDomains")} value={organizationForm.allowed_email_domains} onChange={(value) => setOrganizationForm({ ...organizationForm, allowed_email_domains: value })} textarea />
                <Check label={t("active")} checked={organizationForm.is_active} onChange={(value) => setOrganizationForm({ ...organizationForm, is_active: value })} />
                <label>{t("organizationMembers")}</label>
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
                          <select value={role} onChange={(event) => setOrganizationMemberRole(item.id, event.target.value)}>
                            <option value="member">member</option>
                            <option value="admin">admin</option>
                            <option value="owner">owner</option>
                          </select>
                        )}
                      </div>
                    );
                  })}
                </div>
                <div className="actions">
                  <button type="submit" disabled={busy}><Save size={14} />{organizationForm.id ? t("save") : t("create")}</button>
                  {organizationForm.id && (
                    <button type="button" onClick={() => {
                      setOrganizationForm(emptyOrganizationForm);
                      setOrganizationMemberRoles({});
                    }}>{t("clear")}</button>
                  )}
                </div>
              </form>
            )}
            <div className="table-panel">
              <h3>{t("organizations")}</h3>
              <table>
                <thead>
                  <tr>
                    <th>{t("organizationName")}</th>
                    <th>{t("organizationMembers")}</th>
                    <th>{t("status")}</th>
                    <th>{t("updatedAt")}</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {organizations.map((organization) => (
                    <tr key={organization.id}>
                      <td>
                        {organization.name}<br />
                        <small>{organization.slug}</small>
                        {organization.allowed_email_domains.length > 0 && (
                          <div className="tag-row">
                            {organization.allowed_email_domains.map((domain) => <span key={domain}>@{domain}</span>)}
                          </div>
                        )}
                      </td>
                      <td>
                        <div className="token-list">
                          {organization.members.map((member) => (
                            <span key={member.user_id}>{member.email} · {member.role}</span>
                          ))}
                        </div>
                      </td>
                      <td>{organization.is_active ? t("active") : t("disabled")}</td>
                      <td>{formatTime(organization.updated_at, locale)}</td>
                      <td className="actions">
                        {canManageOrganizations && <button type="button" onClick={() => editOrganization(organization)}>{t("edit")}</button>}
                        {canManageOrganizations && <button type="button" onClick={() => deleteOrganization(organization.id)}>{t("delete")}</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {organizations.length === 0 && <div className="empty">{t("noData")}</div>}
            </div>
          </section>
        )}
        {canReadClients && tab === "clients" && (
          <section className="split wide">
            {canManageClients && (
              <form className="panel" onSubmit={saveClient}>
                <h3>{clientForm.id ? t("save") : t("createClient")}</h3>
                <Field label={t("clientId")} value={clientForm.client_id} onChange={(value) => setClientForm({ ...clientForm, client_id: value })} />
                <Field label={t("clientName")} value={clientForm.client_name} onChange={(value) => setClientForm({ ...clientForm, client_name: value })} />
                <label>{t("clientOrganization")}</label>
                <select value={clientForm.organization_id} onChange={(event) => setClientForm({ ...clientForm, organization_id: event.target.value })}>
                  <option value="">{t("noOrganization")}</option>
                  {organizations.map((organization) => (
                    <option key={organization.id} value={organization.id}>
                      {organization.name} · {organization.slug}{organization.is_active ? "" : ` · ${t("disabled")}`}
                    </option>
                  ))}
                </select>
                <Field label={t("clientSecret")} type="password" value={clientForm.client_secret} onChange={(value) => setClientForm({ ...clientForm, client_secret: value })} />
                <Field label={t("redirectUris")} textarea value={clientForm.redirect_uris} onChange={(value) => setClientForm({ ...clientForm, redirect_uris: value })} />
                <Field label={t("postLogoutUris")} textarea value={clientForm.post_logout_redirect_uris} onChange={(value) => setClientForm({ ...clientForm, post_logout_redirect_uris: value })} />
                <Field label={t("backchannelLogoutUri")} value={clientForm.backchannel_logout_uri} onChange={(value) => setClientForm({ ...clientForm, backchannel_logout_uri: value })} />
                <Field label={t("frontchannelLogoutUri")} value={clientForm.frontchannel_logout_uri} onChange={(value) => setClientForm({ ...clientForm, frontchannel_logout_uri: value })} />
                <Field label={t("scopes")} value={clientForm.scopes} onChange={(value) => setClientForm({ ...clientForm, scopes: value })} />
                <Field label={t("grantTypes")} value={clientForm.grant_types} onChange={(value) => setClientForm({ ...clientForm, grant_types: value })} />
                <Field label={t("responseTypes")} value={clientForm.response_types} onChange={(value) => setClientForm({ ...clientForm, response_types: value })} />
                <label>{t("tokenAuthMethod")}</label>
                <select value={clientForm.token_endpoint_auth_method} onChange={(event) => setClientForm({ ...clientForm, token_endpoint_auth_method: event.target.value })}>
                  <option value="client_secret_basic">client_secret_basic</option>
                  <option value="client_secret_post">client_secret_post</option>
                  <option value="client_secret_jwt">client_secret_jwt</option>
                  <option value="private_key_jwt">private_key_jwt</option>
                  <option value="none">none</option>
                </select>
                <label>{t("subjectType")}</label>
                <select value={clientForm.subject_type} onChange={(event) => setClientForm({ ...clientForm, subject_type: event.target.value })}>
                  <option value="public">public</option>
                  <option value="pairwise">pairwise</option>
                </select>
                <Field label={t("sectorIdentifierUri")} value={clientForm.sector_identifier_uri} onChange={(value) => setClientForm({ ...clientForm, sector_identifier_uri: value })} />
                <Field label={t("jwksUri")} value={clientForm.jwks_uri} onChange={(value) => setClientForm({ ...clientForm, jwks_uri: value })} />
                <Field label={t("jwks")} value={clientForm.jwks} onChange={(value) => setClientForm({ ...clientForm, jwks: value })} textarea />
                <Check label={t("backchannelLogoutSessionRequired")} checked={clientForm.backchannel_logout_session_required} onChange={(value) => setClientForm({ ...clientForm, backchannel_logout_session_required: value })} />
                <Check label={t("frontchannelLogoutSessionRequired")} checked={clientForm.frontchannel_logout_session_required} onChange={(value) => setClientForm({ ...clientForm, frontchannel_logout_session_required: value })} />
                <Check label={t("requirePkce")} checked={clientForm.require_pkce} onChange={(value) => setClientForm({ ...clientForm, require_pkce: value })} />
                <Check label={t("requireClientMfa")} checked={clientForm.require_mfa} onChange={(value) => setClientForm({ ...clientForm, require_mfa: value })} />
                <Check label={t("requirePar")} checked={clientForm.require_pushed_authorization_requests} onChange={(value) => setClientForm({ ...clientForm, require_pushed_authorization_requests: value })} />
                <Check label={t("requireS256Pkce")} checked={clientForm.require_s256_pkce} onChange={(value) => setClientForm({ ...clientForm, require_s256_pkce: value, require_pkce: value ? true : clientForm.require_pkce })} />
                <Check label={t("requireConfidentialClient")} checked={clientForm.require_confidential_client} onChange={(value) => setClientForm({ ...clientForm, require_confidential_client: value })} />
                <Check label={t("requireDpop")} checked={clientForm.require_dpop} onChange={(value) => setClientForm({ ...clientForm, require_dpop: value })} />
                <Check label={t("requireAccountSelection")} checked={clientForm.require_account_selection} onChange={(value) => setClientForm({ ...clientForm, require_account_selection: value })} />
                <Check label={t("trustEmailVerified")} checked={clientForm.trust_email_verified} onChange={(value) => setClientForm({ ...clientForm, trust_email_verified: value })} />
                <Field label={t("authorizationDetailsTypes")} textarea value={clientForm.authorization_details_types} onChange={(value) => setClientForm({ ...clientForm, authorization_details_types: value })} />
                <Check label={t("serviceAccount")} checked={clientForm.service_account_enabled} onChange={(value) => setClientForm({ ...clientForm, service_account_enabled: value })} />
                <Field label={t("serviceAccountPermissions")} textarea value={clientForm.service_account_permissions} onChange={(value) => setClientForm({ ...clientForm, service_account_permissions: value })} />
                <Check label={t("active")} checked={clientForm.is_active} onChange={(value) => setClientForm({ ...clientForm, is_active: value })} />
                <div className="mapper-list">
                  <div className="mapper-heading">
                    <h4>{t("claimMappers")}</h4>
                    <button type="button" onClick={addClientClaimMapper}>
                      <Plus size={14} />
                      {t("addClaimMapper")}
                    </button>
                  </div>
                  {clientForm.claim_mappers.map((mapper, index) => (
                    <div className="mapper-card" key={index}>
                      <div className="mapper-grid">
                        <Field label={t("claimName")} value={mapper.claim_name} onChange={(value) => updateClientClaimMapper(index, { claim_name: value })} />
                        <div>
                          <label>{t("claimSource")}</label>
                          <select value={mapper.source} onChange={(event) => updateClientClaimMapper(index, { source: event.target.value })}>
                            <option value="user_field">{t("userField")}</option>
                            <option value="static">{t("staticValue")}</option>
                            <option value="scope">{t("scopeFlag")}</option>
                            <option value="client">{t("clientField")}</option>
                          </select>
                        </div>
                        <Field label={t("sourceValue")} value={mapper.source_value} onChange={(value) => updateClientClaimMapper(index, { source_value: value })} />
                        <div>
                          <label>{t("valueType")}</label>
                          <select value={mapper.value_type} onChange={(event) => updateClientClaimMapper(index, { value_type: event.target.value })}>
                            <option value="string">string</option>
                            <option value="bool">bool</option>
                            <option value="number">number</option>
                            <option value="json">json</option>
                          </select>
                        </div>
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
                <button className="primary" type="submit" disabled={busy}><Save size={16} />{t("save")}</button>
              </form>
            )}
            <div className="client-list">
              {clients.map((client) => (
                <article className="client-card" key={client.id}>
                  <div>
                    <h3>{client.client_name}</h3>
                    <p>{client.client_id} · {client.subject_type} · {client.organization_name ?? t("noOrganization")}</p>
                  </div>
                  <div className="tag-row">{client.scopes.map((scope) => <span key={scope}>{scope}</span>)}</div>
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
                  {canManageClients && <button type="button" onClick={() => setClientForm({
                    id: client.id,
                    client_id: client.client_id,
                    client_name: client.client_name,
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
                  })}>{t("edit")}</button>}
                </article>
              ))}
            </div>
          </section>
        )}
        {canReadIap && tab === "iap" && (
          <section className="split wide">
            {canManageIap && (
              <form className="panel" onSubmit={saveIapApplication}>
                <h3>{iapApplicationForm.id ? t("updateIapApplication") : t("createIapApplication")}</h3>
                <Field label={t("slug")} value={iapApplicationForm.slug} onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, slug: value })} />
                <Field label={t("iapApplication")} value={iapApplicationForm.name} onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, name: value })} />
                <Field label={t("description")} value={iapApplicationForm.description} onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, description: value })} textarea />
                <Field label={t("externalHost")} value={iapApplicationForm.external_host} onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, external_host: value })} />
                <Field label={t("pathPrefix")} value={iapApplicationForm.path_prefix} onChange={(value) => setIapApplicationForm({ ...iapApplicationForm, path_prefix: value })} />
                <label>{t("requiredOrganization")}</label>
                <select value={iapApplicationForm.required_organization_id} onChange={(event) => setIapApplicationForm({ ...iapApplicationForm, required_organization_id: event.target.value })}>
                  <option value="">{t("noOrganization")}</option>
                  {organizations.map((organization) => (
                    <option key={organization.id} value={organization.id}>
                      {organization.name} · {organization.slug}{organization.is_active ? "" : ` · ${t("disabled")}`}
                    </option>
                  ))}
                </select>
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
                <div className="actions">
                  <button type="submit" disabled={busy}><Save size={14} />{iapApplicationForm.id ? t("save") : t("create")}</button>
                  {iapApplicationForm.id && (
                    <button type="button" onClick={() => setIapApplicationForm(emptyIapApplicationForm)}>{t("clear")}</button>
                  )}
                </div>
              </form>
            )}
            <div className="client-list">
              {iapApplications.map((application) => {
                const organization = organizations.find((item) => item.id === application.required_organization_id);
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
                        <button type="button" onClick={() => editIapApplication(application)}>{t("edit")}</button>
                        <button type="button" onClick={() => deleteIapApplication(application.id)}>{t("delete")}</button>
                      </div>
                    )}
                  </article>
                );
              })}
              {iapApplications.length === 0 && <div className="empty">{t("noData")}</div>}
            </div>
          </section>
        )}
        {canManageAuthorizationCodes && tab === "invitations" && (
          <section className="split">
            <form className="panel" onSubmit={saveInvitation}>
              <h3>{invitationForm.id ? t("updateInvitation") : t("createInvitation")}</h3>
              <Field label={t("description")} value={invitationForm.description} onChange={(value) => setInvitationForm({ ...invitationForm, description: value })} />
              <Field label={t("authorizedEmail")} value={invitationForm.authorized_email} onChange={(value) => setInvitationForm({ ...invitationForm, authorized_email: value })} />
              <Field label={t("authorizedUsername")} value={invitationForm.authorized_username} onChange={(value) => setInvitationForm({ ...invitationForm, authorized_username: value })} />
              <Field label={t("authorizedDisplayName")} value={invitationForm.authorized_display_name} onChange={(value) => setInvitationForm({ ...invitationForm, authorized_display_name: value })} />
              <Field label={t("expiresAt")} type="datetime-local" value={invitationForm.expires_at} onChange={(value) => setInvitationForm({ ...invitationForm, expires_at: value })} />
              <Field label={t("maxUses")} type="number" value={invitationForm.max_uses} onChange={(value) => setInvitationForm({ ...invitationForm, max_uses: value })} />
              <Check label={t("active")} checked={invitationForm.is_active} onChange={(value) => setInvitationForm({ ...invitationForm, is_active: value })} />
              <button className="primary" type="submit" disabled={busy}><Ticket size={16} />{t("save")}</button>
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
            <div className="table-panel">
              <table>
                <thead><tr><th>{t("authorizationCodePrefix")}</th><th>{t("description")}</th><th>{t("authorizedEmail")}</th><th>{t("expiresAt")}</th><th>{t("used")}</th><th>{t("status")}</th><th></th></tr></thead>
                <tbody>
                  {invitations.map((item) => (
                    <tr key={item.id}>
                      <td>{item.code_prefix}...</td>
                      <td>{item.description ?? "-"}</td>
                      <td>{item.authorized_email ?? "-"}</td>
                      <td>{item.expires_at ? formatTime(item.expires_at, locale) : t("permanent")}</td>
                      <td>
                        {item.uses_count}/{item.max_uses ?? t("unlimited")}
                        {item.redemptions.length > 0 && (
                          <small>
                            <br />{t("redemptions")}: {item.redemptions.slice(0, 3).map((redemption) => (
                              <span key={redemption.id}>
                                <br />{redemption.user_email ?? redemption.user_username ?? redemption.user_id} · {formatTime(redemption.redeemed_at, locale)}
                              </span>
                            ))}
                          </small>
                        )}
                      </td>
                      <td>{item.is_active ? t("active") : t("disabled")}</td>
                      <td className="actions">
                        <button type="button" onClick={() => setInvitationForm({
                          id: item.id,
                          description: item.description ?? "",
                          authorized_email: item.authorized_email ?? "",
                          authorized_username: item.authorized_username ?? "",
                          authorized_display_name: item.authorized_display_name ?? "",
                          expires_at: toDatetimeLocalValue(item.expires_at),
                          max_uses: item.max_uses ? String(item.max_uses) : "",
                          is_active: item.is_active
                        })}>{t("edit")}</button>
                        <button type="button" onClick={() => deleteInvitation(item.id)}>{t("delete")}</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
        {canManageSettings && tab === "registration" && registrationSettings && (
          <form className="panel narrow" onSubmit={saveRegistrationSettings}>
            <h3>{t("registrationSettings")}</h3>
            <Check label={t("passwordRegistration")} checked={registrationSettings.allow_password_registration} onChange={(value) => setRegistrationSettings({ ...registrationSettings, allow_password_registration: value })} />
            <Check label={t("requireEmailVerification")} checked={registrationSettings.require_email_verification} onChange={(value) => setRegistrationSettings({ ...registrationSettings, require_email_verification: value })} />
            <Check label={t("requirePhoneVerification")} checked={registrationSettings.require_phone_verification} onChange={(value) => setRegistrationSettings({ ...registrationSettings, require_phone_verification: value })} />
            <Check label={t("allowExternalOidc")} checked={registrationSettings.allow_external_oidc_registration} onChange={(value) => setRegistrationSettings({ ...registrationSettings, allow_external_oidc_registration: value })} />
            <Check label={t("requireInvitation")} checked={registrationSettings.require_invitation} onChange={(value) => setRegistrationSettings({ ...registrationSettings, require_invitation: value })} />
            <Check label={t("defaultUserActive")} checked={registrationSettings.default_user_active} onChange={(value) => setRegistrationSettings({ ...registrationSettings, default_user_active: value })} />
            <button className="primary" type="submit" disabled={busy}><Save size={16} />{t("save")}</button>
          </form>
        )}
        {canManageProviders && tab === "providers" && (
          <section className="split wide">
            <form className="panel" onSubmit={saveProvider}>
              <h3>{providerForm.id ? t("updateProvider") : t("createProvider")}</h3>
              {providerTemplates.length > 0 && (
                <>
                  <label>{t("providerTemplate")}</label>
                  <select value={providerTemplateId} onChange={(event) => setProviderTemplateId(event.target.value)}>
                    <option value="">-</option>
                    {providerTemplates.map((template) => (
                      <option key={template.id} value={template.id}>{template.display_name}</option>
                    ))}
                  </select>
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
              <label>{t("clientOrganization")}</label>
              <select value={providerForm.organization_id} onChange={(event) => setProviderForm({ ...providerForm, organization_id: event.target.value })}>
                <option value="">{t("noOrganization")}</option>
                {organizations.map((organization) => (
                  <option key={organization.id} value={organization.id}>
                    {organization.name} · {organization.slug}{organization.is_active ? "" : ` · ${t("disabled")}`}
                  </option>
                ))}
              </select>
              <Field label={t("issuer")} value={providerForm.issuer} onChange={(value) => setProviderForm({ ...providerForm, issuer: value })} />
              <div className="actions">
                <button type="button" onClick={() => void discoverProviderEndpoints()} disabled={busy || !providerForm.issuer.trim()}>
                  <RefreshCw size={14} />
                  {t("discoverProvider")}
                </button>
              </div>
              <Field label={t("clientId")} value={providerForm.client_id} onChange={(value) => setProviderForm({ ...providerForm, client_id: value })} />
              <Field label={t("clientSecret")} type="password" value={providerForm.client_secret} onChange={(value) => setProviderForm({ ...providerForm, client_secret: value })} />
              <Field label={t("authorizationEndpoint")} value={providerForm.authorization_endpoint} onChange={(value) => setProviderForm({ ...providerForm, authorization_endpoint: value })} />
              <Field label={t("tokenEndpoint")} value={providerForm.token_endpoint} onChange={(value) => setProviderForm({ ...providerForm, token_endpoint: value })} />
              <Field label={t("userinfoEndpoint")} value={providerForm.userinfo_endpoint} onChange={(value) => setProviderForm({ ...providerForm, userinfo_endpoint: value })} />
              <Field label={t("redirectPath")} value={providerForm.redirect_path} onChange={(value) => setProviderForm({ ...providerForm, redirect_path: value })} />
              <Field label={t("scopes")} value={providerForm.scopes} onChange={(value) => setProviderForm({ ...providerForm, scopes: value })} />
              <Field label={t("providerEmailDomains")} value={providerForm.email_domains} onChange={(value) => setProviderForm({ ...providerForm, email_domains: value })} textarea />
              <Check label={t("active")} checked={providerForm.is_active} onChange={(value) => setProviderForm({ ...providerForm, is_active: value })} />
              <Check label={t("allowLogin")} checked={providerForm.allow_login} onChange={(value) => setProviderForm({ ...providerForm, allow_login: value })} />
              <Check label={t("allowRegistration")} checked={providerForm.allow_registration} onChange={(value) => setProviderForm({ ...providerForm, allow_registration: value })} />
              <button className="primary" type="submit" disabled={busy}><Save size={16} />{t("save")}</button>
            </form>
            <div className="client-list">
              {providers.map((provider) => (
                <article className="client-card" key={provider.id}>
                  {(() => {
                    const organization = organizations.find((item) => item.id === provider.organization_id);
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
                    <button type="button" onClick={() => setProviderForm({
                      id: provider.id,
                      slug: provider.slug,
                      display_name: provider.display_name,
                      organization_id: provider.organization_id ?? "",
                      issuer: provider.issuer,
                      client_id: provider.client_id,
                      client_secret: "",
                      authorization_endpoint: provider.authorization_endpoint,
                      token_endpoint: provider.token_endpoint,
                      userinfo_endpoint: provider.userinfo_endpoint,
                      redirect_path: provider.redirect_path,
                      scopes: joinList(provider.scopes),
                      email_domains: joinList(provider.email_domains),
                      is_active: provider.is_active,
                      allow_login: provider.allow_login,
                      allow_registration: provider.allow_registration
                    })}>{t("edit")}</button>
                    <button type="button" onClick={() => deleteProvider(provider.id)}>{t("delete")}</button>
                  </div>
                      </>
                    );
                  })()}
                </article>
              ))}
            </div>
            <form className="panel" onSubmit={saveLdapProvider}>
              <h3>{ldapProviderForm.id ? t("updateLdapProvider") : t("createLdapProvider")}</h3>
              <Field label={t("slug")} value={ldapProviderForm.slug} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, slug: value })} />
              <Field label={t("displayName")} value={ldapProviderForm.display_name} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, display_name: value })} />
              <Field label={t("ldapUrl")} value={ldapProviderForm.url} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, url: value })} />
              <Check label={t("startTls")} checked={ldapProviderForm.starttls} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, starttls: value })} />
              <Field label={t("bindDn")} value={ldapProviderForm.bind_dn} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, bind_dn: value })} />
              <Field label={t("bindPassword")} type="password" value={ldapProviderForm.bind_password} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, bind_password: value })} />
              {ldapProviderForm.id && (
                <Check label={t("clearBindPassword")} checked={ldapProviderForm.clear_bind_password} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, clear_bind_password: value })} />
              )}
              <Field label={t("baseDn")} value={ldapProviderForm.base_dn} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, base_dn: value })} />
              <Field label={t("ldapUserFilter")} value={ldapProviderForm.user_filter} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, user_filter: value })} textarea />
              <Field label={t("userIdAttribute")} value={ldapProviderForm.user_id_attribute} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, user_id_attribute: value })} />
              <Field label={t("emailAttribute")} value={ldapProviderForm.email_attribute} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, email_attribute: value })} />
              <Field label={t("usernameAttribute")} value={ldapProviderForm.username_attribute} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, username_attribute: value })} />
              <Field label={t("displayNameAttribute")} value={ldapProviderForm.display_name_attribute} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, display_name_attribute: value })} />
              <Field label={t("phoneAttribute")} value={ldapProviderForm.phone_attribute} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, phone_attribute: value })} />
              <Check label={t("active")} checked={ldapProviderForm.is_active} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, is_active: value })} />
              <Check label={t("allowLogin")} checked={ldapProviderForm.allow_login} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, allow_login: value })} />
              <Check label={t("allowRegistration")} checked={ldapProviderForm.allow_registration} onChange={(value) => setLdapProviderForm({ ...ldapProviderForm, allow_registration: value })} />
              <div className="actions">
                <button type="submit" className="primary" disabled={busy}><Save size={16} />{t("save")}</button>
                {ldapProviderForm.id && (
                  <button type="button" onClick={() => setLdapProviderForm(emptyLdapProviderForm)}>{t("clear")}</button>
                )}
              </div>
            </form>
            <div className="client-list">
              {ldapProviders.map((provider) => (
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
                    <button type="button" onClick={() => deleteLdapProvider(provider.id)}>{t("delete")}</button>
                  </div>
                </article>
              ))}
              {ldapProviders.length === 0 && <div className="empty">{t("noData")}</div>}
            </div>
          </section>
        )}
        {canManageSettings && tab === "portal" && loginSettings && (
          <section className="split wide">
            <form className="panel" onSubmit={saveLoginSettings}>
              <h3>{t("loginSettings")}</h3>
              <Field
                label={t("companyEmailDomains")}
                textarea
                value={loginSettingsDraft.email_domains}
                onChange={(value) => setLoginSettingsDraft({ ...loginSettingsDraft, email_domains: value })}
              />
              <button className="primary" type="submit" disabled={busy}><Save size={16} />{t("save")}</button>
            </form>
            <form
              className="table-panel"
              onSubmit={(event) => {
                event.preventDefault();
                void saveQuickLinkDraft();
              }}
            >
              <h3>{quickLinkForm.id ? t("updateQuickLink") : t("createQuickLink")}</h3>
              <Field label={t("linkLabel")} value={quickLinkForm.label} onChange={(value) => setQuickLinkForm({ ...quickLinkForm, label: value })} />
              <Field label={t("linkUrl")} value={quickLinkForm.url} onChange={(value) => setQuickLinkForm({ ...quickLinkForm, url: value })} />
              <label>{t("linkIcon")}</label>
              <select value={quickLinkForm.icon} onChange={(event) => setQuickLinkForm({ ...quickLinkForm, icon: event.target.value })}>
                <option value="openai">OpenAI</option>
                <option value="link">Link</option>
                <option value="mail">Mail</option>
                <option value="help">Help</option>
              </select>
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
              <table>
                <thead><tr><th>{t("linkLabel")}</th><th>{t("linkUrl")}</th><th>{t("status")}</th><th></th></tr></thead>
                <tbody>
                  {loginSettingsDraft.quick_links.map((link) => (
                    <tr key={link.id}>
                      <td>{link.label}<br /><small>{link.icon}</small></td>
                      <td>{link.url}</td>
                      <td>{link.is_active ? t("active") : t("disabled")}</td>
                      <td className="actions">
                        <button type="button" onClick={() => editQuickLink(link)} disabled={busy}>{t("edit")}</button>
                        <button type="button" onClick={() => void removeQuickLink(link.id)} disabled={busy}>{t("delete")}</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </form>
          </section>
        )}
        {(canManageSecurity || canReadAudit) && tab === "security" && (
          <section className="security-grid wide">
            {canManageSecurity && (
              <>
            <div className="panel">
              <h3>{t("mfaSettings")}</h3>
              <p className="muted">
                {mfaStatus?.enabled ? t("active") : t("disabled")} · {t("recoveryCodesRemaining")}: {mfaStatus?.recovery_codes_remaining ?? 0}/{mfaStatus?.recovery_codes_total ?? 0}
              </p>
              <div className="actions">
                <button type="button" onClick={startTotpSetup}><KeyRound size={14} />{t("startTotpSetup")}</button>
                {mfaStatus?.enabled && <button type="button" onClick={rotateRecoveryCodes}>{t("rotateRecoveryCodes")}</button>}
                {mfaStatus?.enabled && <button type="button" onClick={disableMfa}>{t("disableMfa")}</button>}
              </div>
              {totpSetup && (
                <div className="mfa-setup">
                  <label>{t("totpSecret")}</label>
                  <textarea readOnly value={totpSetup.secret} />
                  <label>{t("otpauthUri")}</label>
                  <textarea readOnly value={totpSetup.otpauth_uri} />
                  <Field label={t("mfaCode")} value={totpSetupCode} onChange={setTotpSetupCode} />
                  <div className="actions">
                    <button type="button" onClick={confirmTotpSetup}><Save size={14} />{t("confirmTotp")}</button>
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
            <div className="table-panel">
              <h3>{t("signingKeys")}</h3>
              <Field label={t("keyId")} value={signingKeyKid} onChange={setSigningKeyKid} />
              <div className="actions">
                <button type="button" onClick={rotateSigningKey} disabled={busy}><RotateCcw size={14} />{t("rotateSigningKey")}</button>
              </div>
              <table>
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
            </div>
            {securityPolicy && (
              <form className="panel" onSubmit={saveSecurityPolicy}>
                <h3>{t("securityPolicy")}</h3>
                <label>{t("passwordPolicy")}</label>
                <Field
                  label={t("minPasswordLength")}
                  type="number"
                  value={String(securityPolicy.password_min_length)}
                  onChange={(value) => setSecurityPolicy({ ...securityPolicy, password_min_length: Number(value) })}
                />
                <Check label={t("requireUppercase")} checked={Boolean(securityPolicy.password_require_uppercase)} onChange={(value) => setSecurityPolicy({ ...securityPolicy, password_require_uppercase: value ? 1 : 0 })} />
                <Check label={t("requireLowercase")} checked={Boolean(securityPolicy.password_require_lowercase)} onChange={(value) => setSecurityPolicy({ ...securityPolicy, password_require_lowercase: value ? 1 : 0 })} />
                <Check label={t("requireDigit")} checked={Boolean(securityPolicy.password_require_digit)} onChange={(value) => setSecurityPolicy({ ...securityPolicy, password_require_digit: value ? 1 : 0 })} />
                <Check label={t("requireSymbol")} checked={Boolean(securityPolicy.password_require_symbol)} onChange={(value) => setSecurityPolicy({ ...securityPolicy, password_require_symbol: value ? 1 : 0 })} />
                <Check label={t("rejectUserInfo")} checked={Boolean(securityPolicy.password_reject_user_info)} onChange={(value) => setSecurityPolicy({ ...securityPolicy, password_reject_user_info: value ? 1 : 0 })} />
                <label>{t("loginLockout")}</label>
                <Check label={t("active")} checked={Boolean(securityPolicy.login_lockout_enabled)} onChange={(value) => setSecurityPolicy({ ...securityPolicy, login_lockout_enabled: value ? 1 : 0 })} />
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
                <label>{t("captchaPolicy")}</label>
                <Check
                  label={t("active")}
                  checked={securityPolicy.captcha_enabled}
                  onChange={(value) => setSecurityPolicy({ ...securityPolicy, captcha_enabled: value })}
                />
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
                <label>{t("trustedNetworks")}</label>
                <Field
                  label={t("trustedIpCidrs")}
                  textarea
                  value={securityPolicy.trusted_ip_cidrs.join("\n")}
                  onChange={(value) => setSecurityPolicy({ ...securityPolicy, trusted_ip_cidrs: splitList(value) })}
                />
                <Check
                  label={t("requireMfaOutsideTrustedNetworks")}
                  checked={securityPolicy.require_mfa_outside_trusted_networks}
                  onChange={(value) => setSecurityPolicy({ ...securityPolicy, require_mfa_outside_trusted_networks: value })}
                />
                <label>{t("accessRiskRules")}</label>
                <Field
                  label={t("allowedIpCidrs")}
                  textarea
                  value={securityPolicy.allowed_ip_cidrs.join("\n")}
                  onChange={(value) => setSecurityPolicy({ ...securityPolicy, allowed_ip_cidrs: splitList(value) })}
                />
                <Field
                  label={t("blockedIpCidrs")}
                  textarea
                  value={securityPolicy.blocked_ip_cidrs.join("\n")}
                  onChange={(value) => setSecurityPolicy({ ...securityPolicy, blocked_ip_cidrs: splitList(value) })}
                />
                <Field
                  label={t("allowedEmailDomains")}
                  textarea
                  value={securityPolicy.allowed_email_domains.join("\n")}
                  onChange={(value) => setSecurityPolicy({ ...securityPolicy, allowed_email_domains: splitList(value).map(normalizeDomain) })}
                />
                <Field
                  label={t("blockedEmailDomains")}
                  textarea
                  value={securityPolicy.blocked_email_domains.join("\n")}
                  onChange={(value) => setSecurityPolicy({ ...securityPolicy, blocked_email_domains: splitList(value).map(normalizeDomain) })}
                />
                <button className="primary" type="submit" disabled={busy}><Save size={16} />{t("save")}</button>
              </form>
            )}
            <form className="panel" onSubmit={saveRole}>
              <h3>{roleForm.id ? t("updateRole") : t("createRole")}</h3>
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
              <div className="actions">
                <button type="submit" disabled={busy}><Save size={14} />{roleForm.id ? t("save") : t("create")}</button>
                {roleForm.id && (
                  <button type="button" onClick={() => setRoleForm(emptyRoleForm)}>{t("clear")}</button>
                )}
              </div>
            </form>
            <div className="table-panel">
              <h3>{t("roles")}</h3>
              <table>
                <thead><tr><th>{t("role")}</th><th>{t("permissions")}</th><th>{t("status")}</th><th></th></tr></thead>
                <tbody>
                  {roles.map((role) => (
                    <tr key={role.id}>
                      <td>{role.name}<br /><small>{role.description ?? "-"}</small></td>
                      <td><div className="token-list">{role.permissions.map((permission) => <span key={permission}>{permission}</span>)}</div></td>
                      <td>{role.is_system ? t("systemRole") : t("customRole")}</td>
                      <td className="actions">
                        {!role.is_system && <button type="button" onClick={() => editRole(role)}>{t("edit")}</button>}
                        {!role.is_system && <button type="button" onClick={() => deleteRole(role.id)}>{t("delete")}</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <form className="panel" onSubmit={saveGroup}>
              <h3>{groupForm.id ? t("updateGroup") : t("createGroup")}</h3>
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
              <div className="actions">
                <button type="submit" disabled={busy}><Save size={14} />{groupForm.id ? t("save") : t("create")}</button>
                {groupForm.id && (
                  <button type="button" onClick={() => setGroupForm(emptyGroupForm)}>{t("clear")}</button>
                )}
              </div>
            </form>
            <div className="table-panel">
              <h3>{t("groups")}</h3>
              <table>
                <thead><tr><th>{t("groups")}</th><th>{t("groupRoles")}</th><th>{t("groupMembers")}</th><th></th></tr></thead>
                <tbody>
                  {groups.map((group) => (
                    <tr key={group.id}>
                      <td>{group.name}<br /><small>{group.description ?? "-"}</small></td>
                      <td><div className="token-list">{(group.roles ?? []).map((role) => <span key={role.id}>{role.name}</span>)}</div></td>
                      <td><div className="token-list">{(group.members ?? []).map((member) => <span key={member.id}>{member.email}</span>)}</div></td>
                      <td className="actions">
                        <button type="button" onClick={() => editGroup(group)}>{t("edit")}</button>
                        <button type="button" onClick={() => deleteGroup(group.id)}>{t("delete")}</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="panel">
              <h3>{t("userAccess")}</h3>
              <label>{t("selectUser")}</label>
              <select value={selectedAccessUserId} onChange={(event) => loadUserAccess(event.target.value)}>
                <option value="">-</option>
                {users.map((item) => (
                  <option key={item.id} value={item.id}>{item.email}</option>
                ))}
              </select>
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
                    <button type="button" onClick={saveUserRoles}><Save size={14} />{t("save")}</button>
                  </div>
                  <label>{t("groups")}</label>
                  <div className="token-list">{userAccess.groups.map((group) => <span key={group.id}>{group.name}</span>)}</div>
                  <label>{t("effectivePermissions")}</label>
                  <div className="token-list">{userAccess.effective_permissions.map((permission) => <span key={permission}>{permission}</span>)}</div>
                </>
              )}
            </div>
            <form className="panel" onSubmit={saveAuditWebhook}>
              <h3>{auditWebhookForm.id ? t("updateAuditWebhook") : t("createAuditWebhook")}</h3>
              <Field label={t("webhookName")} value={auditWebhookForm.name} onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, name: value })} />
              <Field label={t("webhookUrl")} value={auditWebhookForm.url} onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, url: value })} />
              <Field label={t("webhookSecret")} type="password" value={auditWebhookForm.secret} onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, secret: value })} />
              {auditWebhookForm.id && (
                <Check label={t("clearWebhookSecret")} checked={auditWebhookForm.clear_secret} onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, clear_secret: value })} />
              )}
              <Field label={t("webhookActions")} value={auditWebhookForm.actions} onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, actions: value })} textarea />
              <Field
                label={t("webhookTimeout")}
                type="number"
                value={String(auditWebhookForm.timeout_seconds)}
                onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, timeout_seconds: Number(value) })}
              />
              <Check label={t("active")} checked={auditWebhookForm.is_active} onChange={(value) => setAuditWebhookForm({ ...auditWebhookForm, is_active: value })} />
              <div className="actions">
                <button type="submit" disabled={busy}><Save size={14} />{auditWebhookForm.id ? t("save") : t("create")}</button>
                {auditWebhookForm.id && (
                  <button type="button" onClick={() => setAuditWebhookForm(emptyAuditWebhookForm)}>{t("clear")}</button>
                )}
              </div>
            </form>
              </>
            )}
            {(canReadAudit || canManageSecurity) && (
            <div className="table-panel">
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
                  {auditWebhooks.map((webhook) => (
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
                        {canManageSecurity && <button type="button" onClick={() => deleteAuditWebhook(webhook.id)}>{t("delete")}</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            )}
            {canReadAudit && (
            <div className="table-panel">
              <h3>{t("auditEvents")}</h3>
              <table>
                <thead><tr><th>{t("action")}</th><th>{t("actor")}</th><th>{t("target")}</th><th>{t("outcome")}</th><th>{t("registeredAt")}</th></tr></thead>
                <tbody>
                  {auditEvents.map((event) => (
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
            </div>
            )}
          </section>
        )}
        {canManageSettings && tab === "settings" && settings && runtimeSettings && (
          <section className="split wide">
            <form className="panel" onSubmit={saveRuntimeSettings}>
              <h3>{t("runtimeSettings")}</h3>
              <Field label={t("publicBaseUrl")} value={runtimeSettings.public_base_url} onChange={(value) => setRuntimeSettings({ ...runtimeSettings, public_base_url: value })} />
              <Field label={t("issuer")} value={runtimeSettings.issuer} onChange={(value) => setRuntimeSettings({ ...runtimeSettings, issuer: value })} />
              <Check label={t("trustProxyHeaders")} checked={runtimeSettings.trust_proxy_headers} onChange={(value) => setRuntimeSettings({ ...runtimeSettings, trust_proxy_headers: value })} />
              <div className="info">
                <strong>{t("effectivePublicBaseUrl")}:</strong> {runtimeSettings.effective_public_base_url}<br />
                <strong>{t("effectiveIssuer")}:</strong> {runtimeSettings.effective_issuer}
              </div>
              <button className="primary" type="submit" disabled={busy}><Save size={16} />{t("save")}</button>
            </form>
            <div className="settings-grid">
              {Object.entries(settings).map(([key, value]) => (
                <div className="setting-row" key={key}>
                  <span>{key}</span>
                  <strong>{Array.isArray(value) ? value.join(", ") : String(value)}</strong>
                </div>
              ))}
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

function TopLanguage({
  locale,
  switchLocale,
  label,
  compact = false
}: {
  locale: Locale;
  switchLocale: (locale: Locale) => void;
  label: string;
  compact?: boolean;
}) {
  return (
    <div className={compact ? "language-row compact-language" : "language-row"}>
      <Globe2 size={16} />
      <span>{label}</span>
      <button type="button" className={locale === "zh-CN" ? "active" : ""} onClick={() => switchLocale("zh-CN")}>中文</button>
      <button type="button" className={locale === "en-US" ? "active" : ""} onClick={() => switchLocale("en-US")}>EN</button>
    </div>
  );
}

function Metric({ label, value, detail }: { label: string; value: string | number; detail: string }) {
  return (
    <article className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      <p>{detail}</p>
    </article>
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
  applyLabel
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  domains: string[];
  customDomain: string;
  onCustomDomainChange: (value: string) => void;
  customLabel: string;
  applyLabel: string;
}) {
  const customSuffix = usableEmailDomain(customDomain);
  return (
    <div className="email-field">
      <Field label={label} value={value} onChange={onChange} type="email" />
      {domains.length > 0 && (
        <div className="domain-pills">
          {domains.map((domain) => (
            <button type="button" key={domain} onClick={() => onChange(applyEmailDomain(value, domain))}>
              @{domain}
            </button>
          ))}
        </div>
      )}
      <div className="custom-domain">
        <input value={customDomain} placeholder={customLabel} onChange={(event) => onCustomDomainChange(event.target.value)} />
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
      {links.map((link) => {
        const Icon = quickLinkIcon(link.icon);
        return (
          <a key={link.id} href={link.url} target="_blank" rel="noreferrer" title={link.label} aria-label={link.label}>
            <Icon size={18} />
          </a>
        );
      })}
    </div>
  );
}

function quickLinkIcon(icon: string) {
  switch (icon) {
    case "openai":
      return Bot;
    case "mail":
      return Mail;
    case "help":
      return Shield;
    default:
      return ExternalLink;
  }
}

function Field({
  label,
  value,
  onChange,
  type = "text",
  textarea = false
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  textarea?: boolean;
}) {
  return (
    <>
      <label>{label}</label>
      {textarea ? (
        <textarea value={value} onChange={(event) => onChange(event.target.value)} />
      ) : (
        <input type={type} value={value} onChange={(event) => onChange(event.target.value)} />
      )}
    </>
  );
}

function InlineCode({
  icon,
  label,
  button,
  value,
  onChange,
  onSend
}: {
  icon: React.ReactNode;
  label: string;
  button: string;
  value: string;
  onChange: (value: string) => void;
  onSend: () => void;
}) {
  return (
    <div className="inline-code">
      <Field label={label} value={value} onChange={onChange} />
      <button type="button" onClick={onSend}>{icon}{button}</button>
    </div>
  );
}

function Check({ label, checked, onChange }: { label: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <label className="check">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      {label}
    </label>
  );
}

function UserDetailPanel({
  detail,
  locale,
  t,
  onClose
}: {
  detail: UserDetail;
  locale: Locale;
  t: (key: TranslationKey) => string;
  onClose: () => void;
}) {
  return (
    <section className="detail-panel">
      <div className="detail-header">
        <h3>{t("userDetails")}</h3>
        <button type="button" onClick={onClose}>×</button>
      </div>
      <div className="detail-grid">
        <Info label={t("email")} value={`${detail.user.email} · ${detail.user.email_verified_at ? t("verified") : t("unverified")}`} />
        <Info label={t("phone")} value={`${detail.user.phone ?? "-"} · ${detail.user.phone_verified_at ? t("verified") : t("unverified")}`} />
        <Info label={t("status")} value={detail.user.archived_at ? t("archived") : detail.user.is_active ? t("active") : t("disabled")} />
        <Info label={t("archivedAt")} value={formatTime(detail.user.archived_at, locale)} />
        <Info label={t("registeredAt")} value={formatTime(detail.user.created_at, locale)} />
        <Info label={t("lastLogin")} value={formatTime(detail.user.last_login_at, locale)} />
        <Info label={t("lastIp")} value={detail.user.last_login_ip ?? "-"} />
        <Info label={t("lastClient")} value={detail.user.last_oidc_client_id ?? "-"} />
        <Info label={t("loginMethod")} value={detail.user.last_login_method ?? "-"} />
      </div>
      {detail.user.archived_at && <p className="muted">{t("archivedReadOnly")}</p>}
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
      {detail.login_events.length === 0 ? <p className="muted">{t("noData")}</p> : detail.login_events.map((event) => (
        <div className="event-row" key={event.id}>
          <strong>{formatTime(event.login_at, locale)}</strong>
          <span>{event.method} · {event.ip_address ?? "-"} · {event.oidc_client_id ?? event.external_provider ?? "-"}</span>
        </div>
      ))}
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
