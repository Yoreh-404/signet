import {
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  Circle,
  Code2,
  Copy as CopyIcon,
  Database,
  Eye,
  Globe2,
  KeyRound,
  LockKeyhole,
  Pencil,
  Plus,
  RefreshCw,
  Settings2,
  ShieldCheck,
  SlidersHorizontal,
  Trash2
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../../lib/api";
import type {
  ApplicationModule,
  ApplicationModuleKey,
  ApplicationAuthorizationProfile,
  ApplicationJwtClient,
  ApplicationDirectorySyncRun,
  ApplicationAuthorizationPreview,
  ApplicationAuthorizationSubjects,
  ApplicationPermissionDefinition,
  ApplicationPermissionOverride,
  ApplicationProfileRole,
  ApplicationScimToken,
  Client,
  ExternalProvider,
  LdapProvider,
  Locale,
  TenantApplication
} from "../../types";

type Copy = {
  applications: string;
  websites: string;
  applicationIntro: string;
  createWebsite: string;
  selectWebsite: string;
  noWebsites: string;
  noWebsitesHint: string;
  active: string;
  disabled: string;
  edit: string;
  delete: string;
  overview: string;
  protocols: string;
  identity: string;
  directory: string;
  permissions: string;
  accessBundle: string;
  accessBundleHint: string;
  websiteUrl: string;
  notConfigured: string;
  configured: string;
  enabled: string;
  save: string;
  saving: string;
  saved: string;
  saveFailed: string;
  protocolHint: string;
  protocolRuntimeHint: string;
  oauth: string;
  oauthHint: string;
  saml: string;
  samlHint: string;
  cas: string;
  casHint: string;
  jwt: string;
  jwtHint: string;
  connections: string;
  noConnections: string;
  client: string;
  clientId: string;
  redirect: string;
  entityId: string;
  acsUrl: string;
  sloUrl: string;
  spMetadataXml: string;
  spSigningCertificate: string;
  nameIdClaim: string;
  nameIdFormat: string;
  signedRequests: string;
  signedAssertions: string;
  signedLogout: string;
  signedLogoutResponses: string;
  serviceValidateUrl: string;
  casServiceUrls: string;
  casProxyCallbacks: string;
  casAllowProxy: string;
  casTicketTtl: string;
  casPgtTtl: string;
  audience: string;
  tokenTtl: string;
  jwtClientType: string;
  publicClient: string;
  confidentialClient: string;
  rotateSecret: string;
  secretOnlyOnce: string;
  revokeSecrets: string;
  loginAdapters: string;
  loginAdaptersHint: string;
  noLoginAdapters: string;
  directorySync: string;
  directorySyncHint: string;
  ldapAd: string;
  scim: string;
  scimHint: string;
  scimAudience: string;
  groupSync: string;
  userSyncFilter: string;
  groupBaseDn: string;
  groupFilter: string;
  groupIdAttribute: string;
  groupNameAttribute: string;
  groupMemberAttribute: string;
  reactivateUsers: string;
  maxEntries: string;
  deprovisionAction: string;
  runNow: string;
  syncRunning: string;
  syncCompleted: string;
  syncHistory: string;
  noSyncRuns: string;
  syncSuccess: string;
  syncFailure: string;
  syncSeen: string;
  syncCreated: string;
  syncUpdated: string;
  syncDisabled: string;
  syncCheckpoint: string;
  syncNoCheckpoint: string;
  scimTokens: string;
  scimTokensHint: string;
  createScimToken: string;
  scimTokenScopes: string;
  scimRead: string;
  scimWrite: string;
  scimTokenExpiry: string;
  scimTokenExpiryHint: string;
  noScimTokens: string;
  tokenPrefix: string;
  tokenExpires: string;
  tokenNeverExpires: string;
  tokenLastUsed: string;
  tokenNeverUsed: string;
  tokenCreated: string;
  copyToken: string;
  copied: string;
  revokeToken: string;
  revoked: string;
  tokenOnlyOnce: string;
  authorizationHint: string;
  authorizationProfile: string;
  authorizationProfileHint: string;
  noAuthorizationProfile: string;
  profileManual: string;
  profileSigned: string;
  profileManifestUrl: string;
  profileSigner: string;
  profileMode: string;
  refreshProfile: string;
  profileSynced: string;
  profileManualStatus: string;
  profileNoDefinition: string;
  permissionTree: string;
  roleKey: string;
  inheritEnterprise: string;
  inheritEnterpriseHint: string;
  defaultRole: string;
  customRoles: string;
  customRolesHint: string;
  claims: string;
  claimsHint: string;
  roleName: string;
  roleDescription: string;
  rolePermissions: string;
  rolePermissionsHint: string;
  standardPermissions: string;
  customPermissions: string;
  customPermissionsHint: string;
  activeRole: string;
  editRole: string;
  deleteRole: string;
  noApplicationRoles: string;
  defaultRoleDeleteHint: string;
  addRole: string;
  removeRole: string;
  loginBoundaryNote: string;
  userRoleBindings: string;
  userRoleBindingsHint: string;
  selectUser: string;
  noAuthorizationUsers: string;
  groupRoleBindings: string;
  groupRoleBindingsHint: string;
  selectGroup: string;
  noAuthorizationGroups: string;
  enterpriseRoleMappings: string;
  enterpriseRoleMappingsHint: string;
  permissionOverrides: string;
  permissionOverridesHint: string;
  inheritPermission: string;
  allowPermission: string;
  denyPermission: string;
  customOverrides: string;
  customOverridesHint: string;
  saveBindings: string;
  authorizationPreview: string;
  authorizationPreviewHint: string;
  runPreview: string;
  previewEmpty: string;
  previewAllowed: string;
  previewDenied: string;
  previewRoles: string;
  previewPermissions: string;
  previewGroups: string;
  previewPolicyVersion: string;
  lastUpdated: string;
  noModuleConfig: string;
  back: string;
  identitySources: string;
  sourcesSelected: string;
  syncSources: string;
  protocolCount: string;
  setupNext: string;
  setupNextHint: string;
  configure: string;
  notAvailable: string;
};

const ZH: Copy = {
  applications: "应用",
  websites: "网站接入",
  applicationIntro: "每个应用对应一个网站。把协议、登录适配器、目录同步和权限策略配置在这里，Signet 统一账户即可直接登录。",
  createWebsite: "接入网站",
  selectWebsite: "选择一个网站",
  noWebsites: "还没有网站应用",
  noWebsitesHint: "先接入一个网站，再按需开启协议和身份源。",
  active: "已启用",
  disabled: "已停用",
  edit: "编辑基本信息",
  delete: "删除应用",
  overview: "总览",
  protocols: "协议",
  identity: "登录适配器",
  directory: "目录同步",
  permissions: "权限",
  accessBundle: "网站接入包",
  accessBundleHint: "应用把网站需要的接入能力绑定在一起；模块可以独立配置和启停。",
  websiteUrl: "网站地址",
  notConfigured: "未配置",
  configured: "已配置",
  enabled: "启用此模块",
  save: "保存配置",
  saving: "保存中…",
  saved: "配置已保存",
  saveFailed: "配置保存失败",
  protocolHint: "选择这个网站接受的标准协议。OAuth 2.0 / OIDC 使用下方的客户端连接；其他协议保留独立的端点和签名配置。",
  protocolRuntimeHint: "协议配置属于应用，不再散落在全局客户端列表中。",
  oauth: "OAuth 2.0 / OIDC",
  oauthHint: "使用 Signet 作为身份提供方，为网站提供标准授权码、Token 和 UserInfo。",
  saml: "SAML 2.0",
  samlHint: "为传统企业网站提供 SAML 身份提供方配置。",
  cas: "CAS",
  casHint: "为支持 CAS 的内部系统提供票据校验入口。",
  jwt: "JWT",
  jwtHint: "为 API 或无状态服务配置 Signet 签发的 JWT 受众和有效期。",
  connections: "OIDC 客户端连接",
  noConnections: "尚未绑定 OIDC 客户端",
  client: "客户端",
  clientId: "客户端 ID",
  redirect: "回调地址",
  entityId: "Entity ID",
  acsUrl: "ACS URL",
  sloUrl: "SLO URL",
  spMetadataXml: "SP metadata XML（可选）",
  spSigningCertificate: "SP signing certificate（可选）",
  nameIdClaim: "NameID claim",
  nameIdFormat: "NameID format",
  signedRequests: "要求签名的 AuthnRequest",
  signedAssertions: "要求签名的 Assertion",
  signedLogout: "要求签名的 LogoutRequest",
  signedLogoutResponses: "签名 LogoutResponse",
  serviceValidateUrl: "Service Validate URL",
  casServiceUrls: "CAS service URLs",
  casProxyCallbacks: "CAS proxy callback URLs",
  casAllowProxy: "Allow proxy tickets",
  casTicketTtl: "Ticket lifetime (seconds)",
  casPgtTtl: "PGT lifetime (seconds)",
  audience: "受众（Audience）",
  tokenTtl: "Token 有效期（秒）",
  jwtClientType: "客户端认证方式",
  publicClient: "Public（仅 PKCE）",
  confidentialClient: "Confidential（Secret）",
  rotateSecret: "轮换 Secret",
  secretOnlyOnce: "Secret 只显示这一次，请立即复制并安全保存。",
  revokeSecrets: "撤销所有 Secret",
  loginAdapters: "第三方登录适配器",
  loginAdaptersHint: "选择允许从哪些企业身份源进入这个网站；用户仍会落到同一个 Signet 账户。",
  noLoginAdapters: "暂无可用的第三方 OIDC 适配器",
  directorySync: "企业目录同步",
  directorySyncHint: "把 LDAP/AD 或 SCIM 的用户、组同步能力纳入这个网站的接入包。",
  ldapAd: "LDAP / AD",
  scim: "SCIM 2.0",
  scimHint: "为企业 IdP 或目录平台提供标准用户和组供应接口。",
  scimAudience: "SCIM 受众",
  groupSync: "同步用户组",
  userSyncFilter: "用户同步过滤器",
  groupBaseDn: "用户组 Base DN",
  groupFilter: "用户组过滤器",
  groupIdAttribute: "用户组 ID 属性",
  groupNameAttribute: "用户组名称属性",
  groupMemberAttribute: "用户组成员属性",
  reactivateUsers: "同步时重新启用停用账户",
  maxEntries: "单次最大条目数",
  deprovisionAction: "撤权策略",
  runNow: "立即同步",
  syncRunning: "同步中…",
  syncCompleted: "同步已完成",
  syncHistory: "同步运行记录",
  noSyncRuns: "还没有同步运行记录",
  syncSuccess: "成功",
  syncFailure: "失败",
  syncSeen: "发现用户",
  syncCreated: "新建",
  syncUpdated: "更新",
  syncDisabled: "撤权",
  syncCheckpoint: "最后成功 checkpoint",
  syncNoCheckpoint: "暂无成功 checkpoint",
  scimTokens: "应用 SCIM 令牌",
  scimTokensHint: "为这个网站创建独立的 SCIM Bearer 令牌。令牌只显示一次，不会成为全局 Signet 账户凭据。",
  createScimToken: "创建 SCIM 令牌",
  scimTokenScopes: "令牌权限",
  scimRead: "读取用户和组",
  scimWrite: "写入用户和组",
  scimTokenExpiry: "过期时间（可选）",
  scimTokenExpiryHint: "留空表示不自动过期；生产环境建议设置有限期限。",
  noScimTokens: "还没有应用 SCIM 令牌",
  tokenPrefix: "令牌前缀",
  tokenExpires: "过期",
  tokenNeverExpires: "永不过期",
  tokenLastUsed: "最近使用",
  tokenNeverUsed: "尚未使用",
  tokenCreated: "创建于",
  copyToken: "复制令牌",
  copied: "已复制",
  revokeToken: "撤销令牌",
  revoked: "已撤销",
  tokenOnlyOnce: "完整令牌只显示这一次，请立即复制并安全保存。",
  authorizationHint: "权限采用两层合并：继承企业默认角色，再叠加这个网站的专属角色和 Claim。",
  authorizationProfile: "OIDC 权限 Profile",
  authorizationProfileHint: "每个 OIDC 客户端独立维护一套权限定义、角色和用户映射。网站可以通过签名 manifest 提供定义，也可以在 Signet 手工维护。",
  noAuthorizationProfile: "请先为网站绑定一个 OIDC 客户端",
  profileManual: "手工配置",
  profileSigned: "签名 Manifest",
  profileManifestUrl: "Manifest 地址",
  profileSigner: "Manifest 签名客户端",
  profileMode: "权限来源",
  refreshProfile: "刷新权限定义",
  profileSynced: "已同步",
  profileManualStatus: "手工模式",
  profileNoDefinition: "目标网站没有提供权限定义；请在下方手工创建角色并填写权限字符串。",
  permissionTree: "权限树",
  roleKey: "角色键",
  inheritEnterprise: "继承企业默认权限",
  inheritEnterpriseHint: "企业管理员调整默认角色后，这个网站自动获得变更。",
  defaultRole: "默认应用角色",
  customRoles: "应用专属角色",
  customRolesHint: "仅对这个网站生效，可映射到 OIDC Claim、SAML Attribute 或 JWT Claim。",
  claims: "应用 Claim",
  claimsHint: "每行一个 Claim 名称，值由应用权限映射生成。",
  roleName: "角色名",
  roleDescription: "说明",
  rolePermissions: "角色权限",
  rolePermissionsHint: "角色权限只影响这个网站；可选择标准权限，也可以填写网站专属权限键。",
  standardPermissions: "标准权限",
  customPermissions: "网站专属权限键",
  customPermissionsHint: "每行一个权限键，例如 reports.read 或 billing.export。",
  activeRole: "启用角色",
  editRole: "编辑角色",
  deleteRole: "删除角色",
  noApplicationRoles: "还没有应用专属角色",
  defaultRoleDeleteHint: "默认角色不能直接删除；请先把另一个角色设为默认角色。",
  addRole: "添加角色",
  removeRole: "移除",
  loginBoundaryNote: "活跃且未归档的 Signet 统一账户都可以登录；下面的角色、组和覆盖项只决定登录后在这个网站获得的权限，不是加入应用名单。",
  userRoleBindings: "用户角色绑定",
  userRoleBindingsHint: "为企业用户叠加网站专属角色。没有绑定也不影响活跃账户登录。",
  selectUser: "选择用户",
  noAuthorizationUsers: "当前企业还没有可配置的活跃用户",
  groupRoleBindings: "组角色绑定",
  groupRoleBindingsHint: "组角色会随用户的企业组关系实时合并到网站授权。",
  selectGroup: "选择组",
  noAuthorizationGroups: "还没有可配置的组",
  enterpriseRoleMappings: "企业角色映射",
  enterpriseRoleMappingsHint: "把企业 owner/admin/member 默认角色映射到这个网站的专属角色。",
  permissionOverrides: "用户权限覆盖",
  permissionOverridesHint: "覆盖项只对指定用户生效；deny 优先于继承或 allow。",
  inheritPermission: "继承",
  allowPermission: "允许",
  denyPermission: "拒绝",
  customOverrides: "专属权限覆盖",
  customOverridesHint: "每行一个 effect:permission，例如 allow:reports.read 或 deny:billing.export。",
  saveBindings: "保存绑定",
  authorizationPreview: "授权预览",
  authorizationPreviewHint: "使用同一个运行时授权解析器预览用户最终会收到的角色和权限。",
  runPreview: "预览授权",
  previewEmpty: "尚未生成预览",
  previewAllowed: "允许登录",
  previewDenied: "禁止登录",
  previewRoles: "最终角色",
  previewPermissions: "最终权限",
  previewGroups: "企业组",
  previewPolicyVersion: "策略版本",
  lastUpdated: "最近更新",
  noModuleConfig: "还没有配置",
  back: "返回网站列表",
  identitySources: "身份源",
  sourcesSelected: "个已选择",
  syncSources: "个同步源",
  protocolCount: "个协议",
  setupNext: "接入下一步",
  setupNextHint: "先绑定 OAuth/OIDC 客户端，再按网站实际情况开启 SAML、CAS、JWT、第三方登录或目录同步。",
  configure: "去配置",
  notAvailable: "尚未接入运行时"
};

const EN: Copy = {
  applications: "Applications",
  websites: "Website access",
  applicationIntro: "Each application represents one website. Configure protocols, login adapters, directory sync, and authorization here so every active Signet account can sign in directly.",
  createWebsite: "Connect a website",
  selectWebsite: "Select a website",
  noWebsites: "No website applications yet",
  noWebsitesHint: "Connect a website first, then enable only the capabilities it needs.",
  active: "Enabled",
  disabled: "Disabled",
  edit: "Edit basics",
  delete: "Delete application",
  overview: "Overview",
  protocols: "Protocols",
  identity: "Login adapters",
  directory: "Directory sync",
  permissions: "Permissions",
  accessBundle: "Website access bundle",
  accessBundleHint: "An application binds the capabilities a website needs; each module can be configured and enabled independently.",
  websiteUrl: "Website URL",
  notConfigured: "Not configured",
  configured: "Configured",
  enabled: "Enable this module",
  save: "Save configuration",
  saving: "Saving…",
  saved: "Configuration saved",
  saveFailed: "Failed to save configuration",
  protocolHint: "Choose the standards this website accepts. OAuth 2.0 / OIDC uses the client connections below; other protocols keep independent endpoint and signing settings.",
  protocolRuntimeHint: "Protocol settings belong to the application instead of being scattered across a global client list.",
  oauth: "OAuth 2.0 / OIDC",
  oauthHint: "Use Signet as the identity provider with standard authorization code, token, and UserInfo flows.",
  saml: "SAML 2.0",
  samlHint: "Configure a SAML identity-provider connection for legacy enterprise websites.",
  cas: "CAS",
  casHint: "Provide ticket validation endpoints for internal CAS systems.",
  jwt: "JWT",
  jwtHint: "Configure Signet-issued JWT audiences and lifetimes for APIs or stateless services.",
  connections: "OIDC client connections",
  noConnections: "No OIDC client is attached",
  client: "Client",
  clientId: "Client ID",
  redirect: "Redirect URI",
  entityId: "Entity ID",
  acsUrl: "ACS URL",
  sloUrl: "SLO URL",
  spMetadataXml: "SP metadata XML (optional)",
  spSigningCertificate: "SP signing certificate (optional)",
  nameIdClaim: "NameID claim",
  nameIdFormat: "NameID format",
  signedRequests: "Require signed AuthnRequest",
  signedAssertions: "Require signed assertions",
  signedLogout: "Require signed LogoutRequest",
  signedLogoutResponses: "Sign LogoutResponse",
  serviceValidateUrl: "Service Validate URL",
  casServiceUrls: "CAS service URLs",
  casProxyCallbacks: "CAS proxy callback URLs",
  casAllowProxy: "Allow proxy tickets",
  casTicketTtl: "Ticket lifetime (seconds)",
  casPgtTtl: "PGT lifetime (seconds)",
  audience: "Audience",
  tokenTtl: "Token lifetime (seconds)",
  jwtClientType: "Client authentication",
  publicClient: "Public (PKCE only)",
  confidentialClient: "Confidential (secret)",
  rotateSecret: "Rotate secret",
  secretOnlyOnce: "This secret is shown only once. Copy it now and store it securely.",
  revokeSecrets: "Revoke all secrets",
  loginAdapters: "Third-party login adapters",
  loginAdaptersHint: "Choose which enterprise identity sources may enter this website; users still resolve to one Signet account.",
  noLoginAdapters: "No external OIDC adapters are available",
  directorySync: "Enterprise directory sync",
  directorySyncHint: "Bundle LDAP/AD or SCIM user and group provisioning into this website integration.",
  ldapAd: "LDAP / AD",
  scim: "SCIM 2.0",
  scimHint: "Expose standard user and group provisioning to an enterprise IdP or directory platform.",
  scimAudience: "SCIM audience",
  groupSync: "Sync user groups",
  userSyncFilter: "User sync filter",
  groupBaseDn: "Group base DN",
  groupFilter: "Group filter",
  groupIdAttribute: "Group ID attribute",
  groupNameAttribute: "Group name attribute",
  groupMemberAttribute: "Group member attribute",
  reactivateUsers: "Reactivate disabled accounts during sync",
  maxEntries: "Maximum entries per run",
  deprovisionAction: "Deprovisioning policy",
  runNow: "Run now",
  syncRunning: "Syncing…",
  syncCompleted: "Sync completed",
  syncHistory: "Sync run history",
  noSyncRuns: "No sync runs yet",
  syncSuccess: "Succeeded",
  syncFailure: "Failed",
  syncSeen: "Users seen",
  syncCreated: "Created",
  syncUpdated: "Updated",
  syncDisabled: "Deprovisioned",
  syncCheckpoint: "Last successful checkpoint",
  syncNoCheckpoint: "No successful checkpoint yet",
  scimTokens: "Application SCIM tokens",
  scimTokensHint: "Create an independent SCIM Bearer token for this website. It is shown once and is not a global Signet account credential.",
  createScimToken: "Create SCIM token",
  scimTokenScopes: "Token scopes",
  scimRead: "Read users and groups",
  scimWrite: "Write users and groups",
  scimTokenExpiry: "Expiry (optional)",
  scimTokenExpiryHint: "Leave blank for no automatic expiry; production tokens should have a finite lifetime.",
  noScimTokens: "No application SCIM tokens yet",
  tokenPrefix: "Token prefix",
  tokenExpires: "Expires",
  tokenNeverExpires: "Never",
  tokenLastUsed: "Last used",
  tokenNeverUsed: "Never used",
  tokenCreated: "Created",
  copyToken: "Copy token",
  copied: "Copied",
  revokeToken: "Revoke token",
  revoked: "Revoked",
  tokenOnlyOnce: "The complete token is shown only once. Copy it now and store it securely.",
  authorizationHint: "Authorization is merged in two layers: inherit enterprise defaults, then add website-specific roles and claims.",
  authorizationProfile: "OIDC authorization profile",
  authorizationProfileHint: "Each OIDC client has an independent permission vocabulary, role catalog, and subject mappings. A website can publish a signed manifest or be configured manually in Signet.",
  noAuthorizationProfile: "Attach an OIDC client to this website first",
  profileManual: "Manual configuration",
  profileSigned: "Signed manifest",
  profileManifestUrl: "Manifest URL",
  profileSigner: "Manifest signing client",
  profileMode: "Permission source",
  refreshProfile: "Refresh permission definitions",
  profileSynced: "Synced",
  profileManualStatus: "Manual mode",
  profileNoDefinition: "The website did not publish permission definitions. Create roles below and enter permission strings manually.",
  permissionTree: "Permission tree",
  roleKey: "Role key",
  inheritEnterprise: "Inherit enterprise defaults",
  inheritEnterpriseHint: "Enterprise role changes automatically flow into this website.",
  defaultRole: "Default application role",
  customRoles: "Website-specific roles",
  customRolesHint: "These roles apply only to this website and can map to OIDC, SAML, or JWT claims.",
  claims: "Application claims",
  claimsHint: "One claim name per line; values are produced by the authorization mapping.",
  roleName: "Role name",
  roleDescription: "Description",
  rolePermissions: "Role permissions",
  rolePermissionsHint: "Permissions apply only to this website. Select standard permissions or enter website-specific keys.",
  standardPermissions: "Standard permissions",
  customPermissions: "Website-specific permission keys",
  customPermissionsHint: "One permission key per line, for example reports.read or billing.export.",
  activeRole: "Enable role",
  editRole: "Edit role",
  deleteRole: "Delete role",
  noApplicationRoles: "No website-specific roles yet",
  defaultRoleDeleteHint: "The default role cannot be deleted directly. Set another role as default first.",
  addRole: "Add role",
  removeRole: "Remove",
  loginBoundaryNote: "Every active, non-archived Signet account can sign in. Roles, groups, and overrides below affect post-login website permissions; they are not an application membership list.",
  userRoleBindings: "User role bindings",
  userRoleBindingsHint: "Add website-specific roles for an enterprise user. No binding is required for sign-in.",
  selectUser: "Select user",
  noAuthorizationUsers: "No active configurable users in this enterprise",
  groupRoleBindings: "Group role bindings",
  groupRoleBindingsHint: "Group roles are merged from the user's enterprise group memberships at runtime.",
  selectGroup: "Select group",
  noAuthorizationGroups: "No configurable groups yet",
  enterpriseRoleMappings: "Enterprise role mappings",
  enterpriseRoleMappingsHint: "Map enterprise owner/admin/member defaults to website-specific roles.",
  permissionOverrides: "User permission overrides",
  permissionOverridesHint: "Overrides apply to one user; deny wins over inherited or allowed permissions.",
  inheritPermission: "Inherit",
  allowPermission: "Allow",
  denyPermission: "Deny",
  customOverrides: "Website-specific overrides",
  customOverridesHint: "One effect:permission per line, for example allow:reports.read or deny:billing.export.",
  saveBindings: "Save bindings",
  authorizationPreview: "Authorization preview",
  authorizationPreviewHint: "Preview the final roles and permissions with the same resolver used by runtime protocol responses.",
  runPreview: "Preview authorization",
  previewEmpty: "No preview generated yet",
  previewAllowed: "Login allowed",
  previewDenied: "Login denied",
  previewRoles: "Effective roles",
  previewPermissions: "Effective permissions",
  previewGroups: "Enterprise groups",
  previewPolicyVersion: "Policy version",
  lastUpdated: "Last updated",
  noModuleConfig: "Not configured yet",
  back: "Back to websites",
  identitySources: "Identity sources",
  sourcesSelected: "selected",
  syncSources: "sync sources",
  protocolCount: "protocols",
  setupNext: "Next steps",
  setupNextHint: "Attach an OAuth/OIDC client first, then enable SAML, CAS, JWT, external login, or directory sync as needed.",
  configure: "Configure",
  notAvailable: "Runtime not connected yet"
};

const MODULE_KEYS: ApplicationModuleKey[] = ["protocols", "login_adapters", "directory_sync", "authorization"];

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function booleanValue(value: unknown, fallback = false): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function stringValue(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

type ApplicationRoleDraft = {
  id: string | null;
  role_key: string;
  name: string;
  description: string;
  permissions: string[];
  is_default: boolean;
  is_active: boolean;
  source: string;
};

function applicationRoleDraft(role: ApplicationProfileRole): ApplicationRoleDraft {
  return {
    id: role.id,
    role_key: role.role_key,
    name: role.name,
    description: role.description ?? "",
    permissions: [...role.permissions],
    is_default: role.is_default,
    is_active: role.is_active,
    source: role.source
  };
}

function normalizedPermissionList(values: string[]): string[] {
  return Array.from(new Set(values.map((value) => value.trim()).filter(Boolean)));
}

type PermissionTreeNode = {
  label: string;
  children: Map<string, PermissionTreeNode>;
  definition?: ApplicationPermissionDefinition;
};

function permissionTree(definitions: ApplicationPermissionDefinition[]): PermissionTreeNode[] {
  const root: PermissionTreeNode = { label: "", children: new Map() };
  for (const definition of definitions.filter((item) => item.is_active)) {
    const segments = definition.key.split(":");
    let current = root;
    segments.forEach((segment, index) => {
      let next = current.children.get(segment);
      if (!next) {
        next = { label: segment, children: new Map() };
        current.children.set(segment, next);
      }
      if (index === segments.length - 1) next.definition = definition;
      current = next;
    });
  }
  return Array.from(root.children.values()).sort((left, right) => left.label.localeCompare(right.label));
}

function PermissionTree({
  definitions,
  renderLeaf
}: {
  definitions: ApplicationPermissionDefinition[];
  renderLeaf: (definition: ApplicationPermissionDefinition) => React.ReactNode;
}) {
  function renderNode(node: PermissionTreeNode, depth: number): React.ReactNode {
    const children = Array.from(node.children.values()).sort((left, right) => left.label.localeCompare(right.label));
    return (
      <div className="permission-tree-node" key={`${node.definition?.key ?? node.label}-${depth}`}>
        {node.definition && renderLeaf(node.definition)}
        {!node.definition && <div className="permission-tree-branch"><ChevronRight size={13} /><strong>{node.label}</strong></div>}
        {children.length > 0 && <div className="permission-tree-children">{children.map((child) => renderNode(child, depth + 1))}</div>}
      </div>
    );
  }

  const nodes = permissionTree(definitions);
  return <div className="permission-tree">{nodes.length > 0 ? nodes.map((node) => renderNode(node, 0)) : <p className="muted">{"—"}</p>}</div>;
}

function formatScimTokenTime(value: number | null, locale: Locale): string {
  if (value === null) return "";
  return new Date(value * 1000).toLocaleString(locale === "zh-CN" ? "zh-CN" : "en-US");
}

function defaultModuleConfig(key: ApplicationModuleKey, application: TenantApplication): Record<string, unknown> {
  switch (key) {
    case "protocols":
      return {
        oauth2_oidc: { enabled: application.oidc_clients.length > 0, client_ids: application.oidc_clients.map((client) => client.id) },
        saml2: {
          enabled: false,
          entity_id: "",
          acs_url: "",
          slo_url: "",
          name_id_claim: "email",
          name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
          require_signed_requests: false,
          want_assertions_signed: false,
          require_signed_logout: true,
          want_logout_responses_signed: true,
          sp_metadata_xml: "",
          sp_signing_certificate: ""
        },
        cas: { enabled: false, service_urls: [], proxy_callback_urls: [], allow_proxy: false, ticket_ttl_seconds: 300, pgt_ttl_seconds: 300 },
        jwt: { enabled: false, client_id: application.slug, client_type: "public", redirect_uris: [], audience: "", token_ttl_seconds: 3600 }
      };
    case "login_adapters":
      return { enabled: true, provider_ids: [], allow_signet_password: true };
    case "directory_sync":
      return {
        enabled: false,
        ldap_provider_ids: [],
        user_sync_filter: "",
        group_base_dn: "",
        group_filter: "(objectClass=group)",
        group_id_attribute: "dn",
        group_name_attribute: "cn",
        group_member_attribute: "member",
        reactivate_users: true,
        max_entries: 100000,
        deprovision_action: "remove_membership",
        scim_enabled: false,
        scim_audience: "",
        sync_groups: true
      };
    case "authorization":
      return { inherit_enterprise_roles: true, default_role: "member", custom_roles: [], claims: [] };
  }
}

function moduleConfig(application: TenantApplication, key: ApplicationModuleKey): Record<string, unknown> {
  const module = (application.modules ?? []).find((item) => item.module_key === key);
  return { ...defaultModuleConfig(key, application), ...record(module?.config) };
}

function moduleEnabled(application: TenantApplication, key: ApplicationModuleKey): boolean {
  const module = (application.modules ?? []).find((item) => item.module_key === key);
  return module?.is_enabled ?? (
    key === "authorization"
    || key === "login_adapters"
    || (key === "protocols" && application.oidc_clients.length > 0)
  );
}

function ModuleIcon({ keyName }: { keyName: ApplicationModuleKey }) {
  if (keyName === "protocols") return <Code2 size={18} />;
  if (keyName === "login_adapters") return <KeyRound size={18} />;
  if (keyName === "directory_sync") return <Database size={18} />;
  return <ShieldCheck size={18} />;
}

export function ApplicationWorkspace({
  applications,
  clients,
  providers,
  ldapProviders,
  locale,
  canManage,
  onCreateApplication,
  onEditApplication,
  onDeleteApplication,
  onApplicationModuleChanged
}: {
  applications: TenantApplication[];
  clients: Client[];
  providers: ExternalProvider[];
  ldapProviders: LdapProvider[];
  locale: Locale;
  canManage: boolean;
  onCreateApplication: () => void;
  onEditApplication: (application: TenantApplication) => void;
  onDeleteApplication: (id: string) => void;
  onApplicationModuleChanged: (applicationId: string, module: ApplicationModule, oidcClients?: Client[]) => void;
}) {
  const c = locale === "zh-CN" ? ZH : EN;
  const [selectedId, setSelectedId] = useState<string | null>(applications[0]?.id ?? null);
  const [section, setSection] = useState<"overview" | ApplicationModuleKey>("overview");
  const [drafts, setDrafts] = useState<Partial<Record<ApplicationModuleKey, Record<string, unknown>>>>({});
  const [savingKey, setSavingKey] = useState<ApplicationModuleKey | null>(null);
  const [feedback, setFeedback] = useState("");
  const [jwtClient, setJwtClient] = useState<ApplicationJwtClient | null>(null);
  const [rotatedSecret, setRotatedSecret] = useState("");
  const [secretSaving, setSecretSaving] = useState(false);
  const [scimTokens, setScimTokens] = useState<ApplicationScimToken[]>([]);
  const [scimTokenScopes, setScimTokenScopes] = useState<string[]>(["scim.read", "scim.write"]);
  const [scimTokenExpiry, setScimTokenExpiry] = useState("");
  const [scimTokenSaving, setScimTokenSaving] = useState(false);
  const [createdScimToken, setCreatedScimToken] = useState("");
  const [syncRuns, setSyncRuns] = useState<ApplicationDirectorySyncRun[]>([]);
  const [runningProviderId, setRunningProviderId] = useState<string | null>(null);
  const [authorizationProfiles, setAuthorizationProfiles] = useState<ApplicationAuthorizationProfile[]>([]);
  const [selectedAuthorizationProfileId, setSelectedAuthorizationProfileId] = useState("");
  const [profileManifestUrl, setProfileManifestUrl] = useState("");
  const [profileSignerClientId, setProfileSignerClientId] = useState("");
  const [profileSignedEnabled, setProfileSignedEnabled] = useState(false);
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileRefreshing, setProfileRefreshing] = useState(false);
  const [profileFeedback, setProfileFeedback] = useState("");
  const [applicationRoles, setApplicationRoles] = useState<ApplicationProfileRole[]>([]);
  const [applicationPermissionCatalog, setApplicationPermissionCatalog] = useState<ApplicationPermissionDefinition[]>([]);
  const [roleDraft, setRoleDraft] = useState<ApplicationRoleDraft | null>(null);
  const [roleSaving, setRoleSaving] = useState(false);
  const [roleFeedback, setRoleFeedback] = useState("");
  const [authorizationSubjects, setAuthorizationSubjects] = useState<ApplicationAuthorizationSubjects | null>(null);
  const [selectedAuthorizationUserId, setSelectedAuthorizationUserId] = useState("");
  const [selectedAuthorizationGroupId, setSelectedAuthorizationGroupId] = useState("");
  const [userRoleIds, setUserRoleIds] = useState<string[]>([]);
  const [groupRoleIds, setGroupRoleIds] = useState<string[]>([]);
  const [organizationRoleIds, setOrganizationRoleIds] = useState<Record<string, string[]>>({});
  const [userPermissionOverrides, setUserPermissionOverrides] = useState<ApplicationPermissionOverride[]>([]);
  const [authorizationPreview, setAuthorizationPreview] = useState<ApplicationAuthorizationPreview | null>(null);
  const [authorizationLoading, setAuthorizationLoading] = useState(false);
  const [authorizationSaving, setAuthorizationSaving] = useState(false);
  const [authorizationFeedback, setAuthorizationFeedback] = useState("");
  const selected = applications.find((item) => item.id === selectedId) ?? null;
  const selectedAuthorizationProfile = authorizationProfiles.find((profile) => profile.id === selectedAuthorizationProfileId) ?? null;

  useEffect(() => {
    if (applications.length === 0) {
      setSelectedId(null);
      return;
    }
    if (!selectedId || !applications.some((item) => item.id === selectedId)) {
      setSelectedId(applications[0].id);
    }
  }, [applications, selectedId]);

  useEffect(() => {
    setSection("overview");
    setFeedback("");
    // Drafts are scoped to the selected website. Keeping them across a
    // selection change can silently show (and later save) one website's
    // protocol or authorization settings on another website.
    setDrafts({});
    setJwtClient(null);
    setRotatedSecret("");
    setScimTokens([]);
    setScimTokenScopes(["scim.read", "scim.write"]);
    setScimTokenExpiry("");
    setCreatedScimToken("");
    setSyncRuns([]);
    setRunningProviderId(null);
    setAuthorizationProfiles([]);
    setSelectedAuthorizationProfileId("");
    setProfileManifestUrl("");
    setProfileSignerClientId("");
    setProfileSignedEnabled(false);
    setProfileFeedback("");
    setApplicationRoles([]);
    setApplicationPermissionCatalog([]);
    setRoleDraft(null);
    setRoleFeedback("");
    setAuthorizationSubjects(null);
    setSelectedAuthorizationUserId("");
    setSelectedAuthorizationGroupId("");
    setUserRoleIds([]);
    setGroupRoleIds([]);
    setOrganizationRoleIds({});
    setUserPermissionOverrides([]);
    setAuthorizationPreview(null);
    setAuthorizationFeedback("");
  }, [selectedId]);

  useEffect(() => {
    let cancelled = false;
    if (!selected) return () => { cancelled = true; };
    void api<ApplicationJwtClient | null>(`/api/admin/applications/${selected.id}/jwt-client`)
      .then((client) => {
        if (!cancelled) setJwtClient(client);
      })
      .catch(() => {
        if (!cancelled) setJwtClient(null);
      });
    return () => { cancelled = true; };
  }, [selected]);

  useEffect(() => {
    let cancelled = false;
    if (!selected || !selectedAuthorizationProfileId || !selectedAuthorizationUserId) {
      setUserRoleIds([]);
      setUserPermissionOverrides([]);
      return () => { cancelled = true; };
    }
    setAuthorizationLoading(true);
    void Promise.all([
      api<string[]>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/users/${selectedAuthorizationUserId}/roles`),
      api<ApplicationPermissionOverride[]>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/users/${selectedAuthorizationUserId}/permission-overrides`)
    ])
      .then(([roles, overrides]) => {
        if (cancelled) return;
        setUserRoleIds(roles);
        setUserPermissionOverrides(overrides);
        setAuthorizationPreview(null);
      })
      .catch(() => {
        if (cancelled) return;
        setUserRoleIds([]);
        setUserPermissionOverrides([]);
        setAuthorizationFeedback(c.saveFailed);
      })
      .finally(() => {
        if (!cancelled) setAuthorizationLoading(false);
      });
    return () => { cancelled = true; };
  }, [selected, selectedAuthorizationProfileId, selectedAuthorizationUserId]);

  useEffect(() => {
    let cancelled = false;
    if (!selected || !selectedAuthorizationProfileId || !selectedAuthorizationGroupId) {
      setGroupRoleIds([]);
      return () => { cancelled = true; };
    }
    void api<string[]>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/groups/${selectedAuthorizationGroupId}/roles`)
      .then((roles) => {
        if (!cancelled) setGroupRoleIds(roles);
      })
      .catch(() => {
        if (!cancelled) {
          setGroupRoleIds([]);
          setAuthorizationFeedback(c.saveFailed);
        }
      });
    return () => { cancelled = true; };
  }, [selected, selectedAuthorizationProfileId, selectedAuthorizationGroupId]);

  useEffect(() => {
    let cancelled = false;
    const organizationRoles = authorizationSubjects?.organization_roles ?? [];
    if (!selected || !selectedAuthorizationProfileId || organizationRoles.length === 0) {
      setOrganizationRoleIds({});
      return () => { cancelled = true; };
    }
    void Promise.all(organizationRoles.map(async (organizationRole) => {
      const roleIds = await api<string[]>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/organization-roles/${encodeURIComponent(organizationRole)}/roles`);
      return [organizationRole, roleIds] as const;
    }))
      .then((entries) => {
        if (!cancelled) setOrganizationRoleIds(Object.fromEntries(entries));
      })
      .catch(() => {
        if (!cancelled) {
          setOrganizationRoleIds({});
          setAuthorizationFeedback(c.saveFailed);
        }
      });
    return () => { cancelled = true; };
  }, [selected, selectedAuthorizationProfileId, authorizationSubjects]);

  useEffect(() => {
    let cancelled = false;
    if (!selected) return () => { cancelled = true; };
    void Promise.all([
      api<ApplicationAuthorizationProfile[]>(`/api/admin/applications/${selected.id}/authorization/profiles`),
      api<ApplicationAuthorizationSubjects>(`/api/admin/applications/${selected.id}/authorization/subjects`)
    ])
      .then(([profiles, subjects]) => {
        if (cancelled) return;
        setAuthorizationProfiles(profiles);
        setSelectedAuthorizationProfileId((current) => current && profiles.some((profile) => profile.id === current)
          ? current
          : profiles[0]?.id ?? "");
        setAuthorizationSubjects(subjects);
        setSelectedAuthorizationUserId(subjects.users[0]?.user_id ?? "");
        setSelectedAuthorizationGroupId(subjects.groups[0]?.id ?? "");
      })
      .catch(() => {
        if (cancelled) return;
        setAuthorizationProfiles([]);
        setSelectedAuthorizationProfileId("");
        setApplicationRoles([]);
        setApplicationPermissionCatalog([]);
        setAuthorizationSubjects(null);
      });
    return () => { cancelled = true; };
  }, [selected]);

  useEffect(() => {
    let cancelled = false;
    if (!selected || !selectedAuthorizationProfileId) {
      setApplicationRoles([]);
      setApplicationPermissionCatalog([]);
      return () => { cancelled = true; };
    }
    const profile = authorizationProfiles.find((item) => item.id === selectedAuthorizationProfileId);
    if (profile) {
      setProfileManifestUrl(profile.manifest_url);
      setProfileSignerClientId(profile.signer_client_id ?? "");
      setProfileSignedEnabled(profile.source_mode === "signed_manifest");
    }
    void Promise.all([
      api<ApplicationProfileRole[]>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/roles`),
      api<ApplicationPermissionDefinition[]>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/catalog`)
    ])
      .then(([roles, catalog]) => {
        if (cancelled) return;
        setApplicationRoles(roles);
        setApplicationPermissionCatalog(catalog);
      })
      .catch(() => {
        if (cancelled) return;
        setApplicationRoles([]);
        setApplicationPermissionCatalog([]);
        setAuthorizationFeedback(c.saveFailed);
      });
    return () => { cancelled = true; };
  }, [selected, selectedAuthorizationProfileId, authorizationProfiles]);

  useEffect(() => {
    let cancelled = false;
    if (!selected) return () => { cancelled = true; };
    void api<ApplicationDirectorySyncRun[]>(`/api/admin/applications/${selected.id}/directory-sync/runs`)
      .then((runs) => {
        if (!cancelled) setSyncRuns(runs);
      })
      .catch(() => {
        if (!cancelled) setSyncRuns([]);
      });
    return () => { cancelled = true; };
  }, [selected]);

  useEffect(() => {
    let cancelled = false;
    if (!selected) return () => { cancelled = true; };
    void api<ApplicationScimToken[]>(`/api/admin/applications/${selected.id}/scim-tokens`)
      .then((tokens) => {
        if (!cancelled) setScimTokens(tokens);
      })
      .catch(() => {
        if (!cancelled) setScimTokens([]);
      });
    return () => { cancelled = true; };
  }, [selected]);

  const selectedClients = useMemo(() => {
    if (!selected) return [];
    const ids = new Set(selected.oidc_clients.map((client) => client.id));
    return clients.filter((client) => ids.has(client.id));
  }, [clients, selected]);

  function draftFor(key: ApplicationModuleKey): Record<string, unknown> {
    if (!selected) return {};
    return drafts[key] ?? moduleConfig(selected, key);
  }

  function updateDraft(key: ApplicationModuleKey, next: Record<string, unknown>) {
    setDrafts((current) => ({ ...current, [key]: next }));
  }

  async function saveModule(key: ApplicationModuleKey) {
    if (!selected) return;
    setSavingKey(key);
    setFeedback("");
    try {
      const config = draftFor(key);
      let attachedClients: Client[] | undefined;
      if (key === "protocols") {
        const protocolConfig = record(config);
        const oauthConfig = record(protocolConfig.oauth2_oidc);
        const clientIds = stringList(oauthConfig.client_ids);
        attachedClients = await api<Client[]>(`/api/admin/applications/${selected.id}/oidc-clients`, {
          method: "PUT",
          body: JSON.stringify({ client_ids: clientIds })
        });
      }
      const isEnabled = key === "protocols"
        ? ["oauth2_oidc", "saml2", "cas", "jwt"].some((protocol) => booleanValue(record(config[protocol]).enabled))
        : key === "login_adapters"
          ? booleanValue(config.enabled, true)
          : key === "directory_sync"
            ? booleanValue(config.enabled)
            : true;
      const module = await api<ApplicationModule>(`/api/admin/applications/${selected.id}/modules/${key}`, {
        method: "PUT",
        body: JSON.stringify({ config, is_enabled: isEnabled })
      });
      if (key === "protocols") {
        const jwt = record(record(config).jwt);
        const jwtEnabled = booleanValue(jwt.enabled);
        if (jwtEnabled) {
          const configuredClient = await api<ApplicationJwtClient>(`/api/admin/applications/${selected.id}/jwt-client`, {
            method: "PUT",
            body: JSON.stringify({
              client_id: stringValue(jwt.client_id, selected.slug),
              client_type: stringValue(jwt.client_type, "public"),
              is_active: true
            })
          });
          setJwtClient(configuredClient);
        }
      }
      onApplicationModuleChanged(selected.id, module, attachedClients);
      setDrafts((current) => ({ ...current, [key]: config }));
      setFeedback(c.saved);
    } catch {
      setFeedback(c.saveFailed);
    } finally {
      setSavingKey(null);
    }
  }

  async function saveAuthorizationProfile() {
    if (!selected || !selectedAuthorizationProfileId) return;
    setProfileSaving(true);
    setProfileFeedback("");
    try {
      const profile = await api<ApplicationAuthorizationProfile>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}`, {
        method: "PUT",
        body: JSON.stringify({
          manifest_url: profileManifestUrl.trim() || null,
          signer_client_id: profileSignerClientId.trim() || null,
          signed_manifest_enabled: profileSignedEnabled
        })
      });
      setAuthorizationProfiles((current) => current.map((item) => item.id === profile.id ? profile : item));
      setProfileManifestUrl(profile.manifest_url);
      setProfileSignerClientId(profile.signer_client_id ?? "");
      setProfileSignedEnabled(profile.source_mode === "signed_manifest");
      setProfileFeedback(c.saved);
    } catch {
      setProfileFeedback(c.saveFailed);
    } finally {
      setProfileSaving(false);
    }
  }

  async function refreshAuthorizationProfile() {
    if (!selected || !selectedAuthorizationProfileId || !profileSignedEnabled) return;
    setProfileRefreshing(true);
    setProfileFeedback("");
    try {
      const profile = await api<ApplicationAuthorizationProfile>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/refresh`, { method: "POST" });
      setAuthorizationProfiles((current) => current.map((item) => item.id === profile.id ? profile : item));
      setProfileFeedback(profile.sync_status === "synced" ? c.profileSynced : c.profileManualStatus);
    } catch {
      setProfileFeedback(c.saveFailed);
      try {
        const profile = await api<ApplicationAuthorizationProfile>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}`);
        setAuthorizationProfiles((current) => current.map((item) => item.id === profile.id ? profile : item));
      } catch {
        // Keep the refresh error visible when the status request also fails.
      }
    } finally {
      setProfileRefreshing(false);
    }
  }

  function startApplicationRole(role?: ApplicationProfileRole) {
    setRoleFeedback("");
    if (role) {
      setRoleDraft(applicationRoleDraft(role));
      return;
    }
    setRoleDraft({
      id: null,
      role_key: "",
      name: "",
      description: "",
      permissions: [],
      is_default: !applicationRoles.some((item) => item.is_default && item.is_active),
      is_active: true,
      source: "manual"
    });
  }

  function updateRoleDraft(next: Partial<ApplicationRoleDraft>) {
    setRoleDraft((current) => current ? { ...current, ...next } : current);
  }

  function toggleRolePermission(permission: string) {
    if (!roleDraft) return;
    const permissions = roleDraft.permissions.includes(permission)
      ? roleDraft.permissions.filter((item) => item !== permission)
      : [...roleDraft.permissions, permission];
    updateRoleDraft({ permissions: normalizedPermissionList(permissions) });
  }

  async function saveApplicationRole() {
    if (!selected || !selectedAuthorizationProfileId || !roleDraft) return;
    const name = roleDraft.name.trim();
    const roleKey = roleDraft.role_key.trim();
    if (!name || !roleKey) {
      setRoleFeedback(c.saveFailed);
      return;
    }
    setRoleSaving(true);
    setRoleFeedback("");
    try {
      const payload = JSON.stringify({
        role_key: roleKey,
        name,
        description: roleDraft.description.trim() || null,
        permissions: normalizedPermissionList(roleDraft.permissions),
        is_default: roleDraft.is_default,
        is_active: roleDraft.is_active
      });
      const path = roleDraft.id
        ? `/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/roles/${roleDraft.id}`
        : `/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/roles`;
      await api<ApplicationProfileRole>(path, {
        method: roleDraft.id ? "PUT" : "POST",
        body: payload
      });
      const roles = await api<ApplicationProfileRole[]>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/roles`);
      setApplicationRoles(roles);
      setRoleDraft(null);
      setRoleFeedback(c.saved);
    } catch {
      setRoleFeedback(c.saveFailed);
    } finally {
      setRoleSaving(false);
    }
  }

  async function deleteApplicationRole(role: ApplicationProfileRole) {
    if (!selected || !selectedAuthorizationProfileId || role.is_default) {
      setRoleFeedback(c.defaultRoleDeleteHint);
      return;
    }
    if (!window.confirm(`${c.deleteRole}: ${role.name}?`)) return;
    setRoleSaving(true);
    setRoleFeedback("");
    try {
      await api(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/roles/${role.id}`, { method: "DELETE" });
      setApplicationRoles((current) => current.filter((item) => item.id !== role.id));
      if (roleDraft?.id === role.id) setRoleDraft(null);
      setRoleFeedback(c.saved);
    } catch {
      setRoleFeedback(c.saveFailed);
    } finally {
      setRoleSaving(false);
    }
  }

  function toggleRoleId(roleIds: string[], roleId: string): string[] {
    return roleIds.includes(roleId)
      ? roleIds.filter((item) => item !== roleId)
      : [...roleIds, roleId];
  }

  function updatePermissionOverride(permission: string, effect: "" | "allow" | "deny") {
    setUserPermissionOverrides((current) => {
      const withoutPermission = current.filter((item) => item.permission !== permission);
      if (!effect) return withoutPermission;
      return [...withoutPermission, { permission, effect }];
    });
    setAuthorizationPreview(null);
  }

  function updateCustomPermissionOverrides(value: string) {
    const knownPermissions = new Set(applicationPermissionCatalog.map((permission) => permission.key));
    const standard = userPermissionOverrides.filter((item) => knownPermissions.has(item.permission));
    const custom = value
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const separator = line.indexOf(":");
        const effect = separator > 0 ? line.slice(0, separator).trim() : "allow";
        const permission = (separator > 0 ? line.slice(separator + 1) : line).trim();
        return effect === "deny" && permission ? { permission, effect: "deny" as const } : permission ? { permission, effect: "allow" as const } : null;
      })
      .filter((item): item is ApplicationPermissionOverride => item !== null);
    setUserPermissionOverrides([...standard, ...custom]);
    setAuthorizationPreview(null);
  }

  async function saveAuthorizationBindings() {
    if (!selected || !selectedAuthorizationProfileId) return;
    setAuthorizationSaving(true);
    setAuthorizationFeedback("");
    try {
      const requests: Promise<unknown>[] = [];
      if (selectedAuthorizationUserId) {
        requests.push(api<string[]>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/users/${selectedAuthorizationUserId}/roles`, {
          method: "PUT",
          body: JSON.stringify({ role_ids: userRoleIds })
        }));
        requests.push(api<ApplicationPermissionOverride[]>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/users/${selectedAuthorizationUserId}/permission-overrides`, {
          method: "PUT",
          body: JSON.stringify({ overrides: userPermissionOverrides })
        }));
      }
      if (selectedAuthorizationGroupId) {
        requests.push(api<string[]>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/groups/${selectedAuthorizationGroupId}/roles`, {
          method: "PUT",
          body: JSON.stringify({ role_ids: groupRoleIds })
        }));
      }
      for (const organizationRole of authorizationSubjects?.organization_roles ?? []) {
        requests.push(api<string[]>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/organization-roles/${encodeURIComponent(organizationRole)}/roles`, {
          method: "PUT",
          body: JSON.stringify({ role_ids: organizationRoleIds[organizationRole] ?? [] })
        }));
      }
      await Promise.all(requests);
      setAuthorizationFeedback(c.saved);
      setAuthorizationPreview(null);
    } catch {
      setAuthorizationFeedback(c.saveFailed);
    } finally {
      setAuthorizationSaving(false);
    }
  }

  async function runAuthorizationPreview() {
    if (!selected || !selectedAuthorizationProfileId || !selectedAuthorizationUserId) return;
    setAuthorizationLoading(true);
    setAuthorizationFeedback("");
    try {
      const preview = await api<ApplicationAuthorizationPreview>(`/api/admin/applications/${selected.id}/authorization/profiles/${selectedAuthorizationProfileId}/${selectedAuthorizationUserId}`);
      setAuthorizationPreview(preview);
    } catch {
      setAuthorizationFeedback(c.saveFailed);
      setAuthorizationPreview(null);
    } finally {
      setAuthorizationLoading(false);
    }
  }

  async function rotateJwtSecret() {
    if (!selected || !jwtClient || jwtClient.client_type !== "confidential") return;
    setSecretSaving(true);
    setFeedback("");
    try {
      const response = await api<{ secret: string }>(`/api/admin/applications/${selected.id}/jwt-client/secret`, {
        method: "POST",
        body: JSON.stringify({ grace_seconds: 300 })
      });
      setRotatedSecret(response.secret);
      const refreshed = await api<ApplicationJwtClient | null>(`/api/admin/applications/${selected.id}/jwt-client`);
      setJwtClient(refreshed);
    } catch {
      setFeedback(c.saveFailed);
    } finally {
      setSecretSaving(false);
    }
  }

  async function revokeJwtSecrets() {
    if (!selected || !jwtClient || jwtClient.active_secret_count === 0) return;
    setSecretSaving(true);
    try {
      await api(`/api/admin/applications/${selected.id}/jwt-client/secrets`, { method: "DELETE" });
      setRotatedSecret("");
      const refreshed = await api<ApplicationJwtClient | null>(`/api/admin/applications/${selected.id}/jwt-client`);
      setJwtClient(refreshed);
    } catch {
      setFeedback(c.saveFailed);
    } finally {
      setSecretSaving(false);
    }
  }

  function toggleScimTokenScope(scope: string) {
    setScimTokenScopes((current) => current.includes(scope)
      ? current.filter((item) => item !== scope)
      : [...current, scope]);
  }

  async function createScimToken() {
    if (!selected || scimTokenScopes.length === 0) return;
    let expiresAt: number | null = null;
    if (scimTokenExpiry) {
      const parsed = Date.parse(scimTokenExpiry);
      if (!Number.isFinite(parsed) || parsed <= Date.now()) {
        setFeedback(c.saveFailed);
        return;
      }
      expiresAt = Math.floor(parsed / 1000);
    }
    setScimTokenSaving(true);
    setFeedback("");
    try {
      const response = await api<ApplicationScimToken>(`/api/admin/applications/${selected.id}/scim-tokens`, {
        method: "POST",
        body: JSON.stringify({ scopes: scimTokenScopes, expires_at: expiresAt })
      });
      const { token, ...metadata } = response;
      setScimTokens((current) => [metadata, ...current]);
      setCreatedScimToken(token ?? "");
      setScimTokenExpiry("");
      setFeedback(c.saved);
    } catch {
      setFeedback(c.saveFailed);
    } finally {
      setScimTokenSaving(false);
    }
  }

  async function revokeScimToken(tokenId: string) {
    if (!selected) return;
    setScimTokenSaving(true);
    setFeedback("");
    try {
      await api(`/api/admin/applications/${selected.id}/scim-tokens/${tokenId}`, { method: "DELETE" });
      setScimTokens((current) => current.map((token) => token.id === tokenId
        ? { ...token, revoked_at: Math.floor(Date.now() / 1000) }
        : token));
      if (createdScimToken) setCreatedScimToken("");
    } catch {
      setFeedback(c.saveFailed);
    } finally {
      setScimTokenSaving(false);
    }
  }

  async function runDirectorySync(providerId: string) {
    if (!selected || !canManage) return;
    setRunningProviderId(providerId);
    setFeedback("");
    try {
      const run = await api<ApplicationDirectorySyncRun>(`/api/admin/applications/${selected.id}/directory-sync/${providerId}/run`, {
        method: "POST"
      });
      setSyncRuns((current) => [run, ...current.filter((item) => item.id !== run.id)]);
      setFeedback(c.syncCompleted);
    } catch {
      setFeedback(c.saveFailed);
      try {
        const runs = await api<ApplicationDirectorySyncRun[]>(`/api/admin/applications/${selected.id}/directory-sync/runs`);
        setSyncRuns(runs);
      } catch {
        // Preserve the original action error in the UI when refreshing the
        // history is also unavailable.
      }
    } finally {
      setRunningProviderId(null);
    }
  }

  async function copyCreatedScimToken() {
    if (!createdScimToken) return;
    try {
      await navigator.clipboard.writeText(createdScimToken);
      setFeedback(c.copied);
    } catch {
      setFeedback(c.saveFailed);
    }
  }

  function openSection(next: "overview" | ApplicationModuleKey) {
    setFeedback("");
    setSection(next);
    if (next !== "overview") {
      setDrafts((current) => current[next] ? current : { ...current, [next]: selected ? moduleConfig(selected, next) : {} });
    }
  }

  function updateProtocol(
    protocol: "oauth2_oidc" | "saml2" | "cas" | "jwt",
    field: string,
    value: string | boolean | number | string[]
  ) {
    const current = draftFor("protocols");
    const nextProtocol = { ...record(current[protocol]), [field]: value };
    updateDraft("protocols", { ...current, [protocol]: nextProtocol });
  }

  function toggleId(key: "client_ids" | "provider_ids" | "ldap_provider_ids", id: string) {
    const current = draftFor(key === "client_ids" ? "protocols" : key === "provider_ids" ? "login_adapters" : "directory_sync");
    const values = stringList(current[key]);
    const next = values.includes(id) ? values.filter((item) => item !== id) : [...values, id];
    updateDraft(key === "client_ids" ? "protocols" : key === "provider_ids" ? "login_adapters" : "directory_sync", { ...current, [key]: next });
  }

  function renderProtocolEditor() {
    if (!selected) return null;
    const config = draftFor("protocols");
    const oauth = record(config.oauth2_oidc);
    const saml = record(config.saml2);
    const cas = record(config.cas);
    const jwt = record(config.jwt);
    return (
      <div className="application-module-content">
        <ModuleHeader icon={<Code2 size={19} />} title={c.protocols} description={c.protocolHint} />
        <div className="protocol-grid">
          <ProtocolCard icon={<Globe2 size={19} />} title={c.oauth} description={c.oauthHint} enabled={booleanValue(oauth.enabled, selected.oidc_clients.length > 0)} onToggle={(value) => updateProtocol("oauth2_oidc", "enabled", value)} tone="brand">
            <div className="application-connection-list">
              <div className="subsection-heading"><strong>{c.connections}</strong><span>{selectedClients.length}</span></div>
              {clients.filter((client) => client.organization_id === selected.organization_id).map((client) => (
                <label className="application-choice" key={client.id}>
                  <input type="checkbox" checked={stringList(oauth.client_ids).includes(client.id)} onChange={() => toggleId("client_ids", client.id)} />
                  <span><strong>{client.client_name}</strong><small>{client.client_id}</small></span>
                  <span className="application-choice-status">{client.is_active ? c.active : c.disabled}</span>
                </label>
              ))}
              {clients.filter((client) => client.organization_id === selected.organization_id).length === 0 && <p className="muted">{c.noConnections}</p>}
            </div>
          </ProtocolCard>
          <ProtocolCard icon={<LockKeyhole size={19} />} title={c.saml} description={c.samlHint} enabled={booleanValue(saml.enabled)} onToggle={(value) => updateProtocol("saml2", "enabled", value)}>
            <div className="form-grid-2 compact-form-grid">
              <Input label={c.entityId} value={stringValue(saml.entity_id)} onChange={(value) => updateProtocol("saml2", "entity_id", value)} />
              <Input label={c.acsUrl} value={stringValue(saml.acs_url)} onChange={(value) => updateProtocol("saml2", "acs_url", value)} />
              <Input label={c.sloUrl} hint={locale === "zh-CN" ? "网站的 SingleLogoutService；填写后 Signet metadata 会广告应用级 SLO endpoint。" : "The website SingleLogoutService. When set, Signet metadata advertises the application SLO endpoint."} value={stringValue(saml.slo_url)} onChange={(value) => updateProtocol("saml2", "slo_url", value)} />
              <Input label={c.nameIdClaim} value={stringValue(saml.name_id_claim, "email")} onChange={(value) => updateProtocol("saml2", "name_id_claim", value)} />
              <Input label={c.nameIdFormat} value={stringValue(saml.name_id_format)} onChange={(value) => updateProtocol("saml2", "name_id_format", value)} />
            </div>
            <div className="form-grid-2 compact-form-grid">
              <Input label={c.spSigningCertificate} value={stringValue(saml.sp_signing_certificate)} onChange={(value) => updateProtocol("saml2", "sp_signing_certificate", value)} textarea />
              <Input label={c.spMetadataXml} value={stringValue(saml.sp_metadata_xml)} onChange={(value) => updateProtocol("saml2", "sp_metadata_xml", value)} textarea />
            </div>
            <div className="application-toggle-grid">
              <Toggle label={c.signedRequests} checked={booleanValue(saml.require_signed_requests)} onChange={(value) => updateProtocol("saml2", "require_signed_requests", value)} />
              <Toggle label={c.signedAssertions} checked={booleanValue(saml.want_assertions_signed)} onChange={(value) => updateProtocol("saml2", "want_assertions_signed", value)} />
              <Toggle label={c.signedLogout} checked={booleanValue(saml.require_signed_logout, true)} onChange={(value) => updateProtocol("saml2", "require_signed_logout", value)} />
              <Toggle label={c.signedLogoutResponses} checked={booleanValue(saml.want_logout_responses_signed, true)} onChange={(value) => updateProtocol("saml2", "want_logout_responses_signed", value)} />
            </div>
            <small className="module-note"><Circle size={11} />{c.protocolRuntimeHint}</small>
          </ProtocolCard>
          <ProtocolCard icon={<TicketIcon />} title={c.cas} description={c.casHint} enabled={booleanValue(cas.enabled)} onToggle={(value) => updateProtocol("cas", "enabled", value)}>
            <Input
              label={c.casServiceUrls}
              hint={locale === "zh-CN" ? "每行一个精确 service URL；生产环境必须使用 HTTPS。旧配置中的 Service Validate URL 会作为兼容值读取。" : "One exact service URL per line; production deployments must use HTTPS. The legacy Service Validate URL is read as a compatibility value."}
              value={stringList(cas.service_urls).join("\n") || stringValue(cas.service_validate_url)}
              textarea
              onChange={(value) => updateProtocol("cas", "service_urls", value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))}
            />
            <Input
              label={c.casProxyCallbacks}
              hint={locale === "zh-CN" ? "启用 PGT/代理票据时，每行一个已登记的回调 URL。" : "When PGT/proxy tickets are enabled, enter one registered callback URL per line."}
              value={stringList(cas.proxy_callback_urls).join("\n")}
              textarea
              onChange={(value) => updateProtocol("cas", "proxy_callback_urls", value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))}
            />
            <Toggle label={c.casAllowProxy} checked={booleanValue(cas.allow_proxy)} onChange={(value) => updateProtocol("cas", "allow_proxy", value)} />
            <div className="form-grid-2 compact-form-grid">
              <Input label={c.casTicketTtl} type="number" value={String(typeof cas.ticket_ttl_seconds === "number" ? cas.ticket_ttl_seconds : 300)} onChange={(value) => updateProtocol("cas", "ticket_ttl_seconds", Number(value) || 300)} />
              <Input label={c.casPgtTtl} type="number" value={String(typeof cas.pgt_ttl_seconds === "number" ? cas.pgt_ttl_seconds : 300)} onChange={(value) => updateProtocol("cas", "pgt_ttl_seconds", Number(value) || 300)} />
            </div>
          </ProtocolCard>
          <ProtocolCard icon={<Code2 size={19} />} title={c.jwt} description={c.jwtHint} enabled={booleanValue(jwt.enabled)} onToggle={(value) => updateProtocol("jwt", "enabled", value)}>
            <div className="form-grid-2 compact-form-grid">
              <Input label={c.clientId} value={stringValue(jwt.client_id, selected.slug)} onChange={(value) => updateProtocol("jwt", "client_id", value)} />
              <Input label={c.audience} value={stringValue(jwt.audience)} onChange={(value) => updateProtocol("jwt", "audience", value)} />
              <Input label={c.tokenTtl} type="number" value={String(typeof jwt.token_ttl_seconds === "number" ? jwt.token_ttl_seconds : 3600)} onChange={(value) => updateProtocol("jwt", "token_ttl_seconds", Number(value) || 3600)} />
              <label className="application-input"><span>{c.jwtClientType}</span><select value={stringValue(jwt.client_type, "public")} onChange={(event) => updateProtocol("jwt", "client_type", event.target.value)}><option value="public">{c.publicClient}</option><option value="confidential">{c.confidentialClient}</option></select></label>
            </div>
            <Input label={c.redirect} hint={locale === "zh-CN" ? "每行一个精确回调地址；生产环境必须使用 HTTPS。" : "One exact redirect URI per line; production deployments must use HTTPS."} value={stringList(jwt.redirect_uris).join("\n")} textarea onChange={(value) => updateProtocol("jwt", "redirect_uris", value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))} />
            {jwtClient?.client_type === "confidential" && <div className="module-secret-panel"><div><strong>{c.confidentialClient}</strong><small>{jwtClient.active_secret_count} active secret(s)</small></div><div className="module-secret-actions"><button type="button" className="text-button" onClick={() => void rotateJwtSecret()} disabled={secretSaving}>{secretSaving ? c.saving : c.rotateSecret}</button><button type="button" className="text-danger-button" onClick={() => void revokeJwtSecrets()} disabled={secretSaving || jwtClient.active_secret_count === 0}>{c.revokeSecrets}</button></div>{rotatedSecret && <div className="module-secret-value"><code>{rotatedSecret}</code><small>{c.secretOnlyOnce}</small></div>}</div>}
          </ProtocolCard>
        </div>
        <ModuleSave saving={savingKey === "protocols"} feedback={feedback} copy={c} onSave={() => void saveModule("protocols")} />
      </div>
    );
  }

  function renderIdentityEditor() {
    if (!selected) return null;
    const config = draftFor("login_adapters");
    return (
      <div className="application-module-content">
        <ModuleHeader icon={<KeyRound size={19} />} title={c.loginAdapters} description={c.loginAdaptersHint} />
        <div className="module-setting-card">
          <Toggle label={c.enabled} checked={booleanValue(config.enabled, moduleEnabled(selected, "login_adapters"))} onChange={(value) => updateDraft("login_adapters", { ...config, enabled: value })} />
          <div className="application-choice-list">
            {providers.filter((provider) => !provider.organization_id || provider.organization_id === selected.organization_id).map((provider) => (
              <label className="application-choice" key={provider.id}>
                <input type="checkbox" checked={stringList(config.provider_ids).includes(provider.id)} onChange={() => toggleId("provider_ids", provider.id)} />
                <span><strong>{provider.display_name}</strong><small>{provider.issuer}</small></span>
                <span className="application-choice-status">{provider.allow_login && provider.is_active ? c.active : c.disabled}</span>
              </label>
            ))}
            {providers.length === 0 && <p className="muted">{c.noLoginAdapters}</p>}
          </div>
          <Toggle label={locale === "zh-CN" ? "允许 Signet 密码 / Passkey 登录" : "Allow Signet password / Passkey sign-in"} checked={booleanValue(config.allow_signet_password, true)} onChange={(value) => updateDraft("login_adapters", { ...config, allow_signet_password: value })} />
        </div>
        <ModuleSave saving={savingKey === "login_adapters"} feedback={feedback} copy={c} onSave={() => void saveModule("login_adapters")} />
      </div>
    );
  }

  function renderDirectoryEditor() {
    if (!selected) return null;
    const config = draftFor("directory_sync");
    return (
      <div className="application-module-content">
        <ModuleHeader icon={<Database size={19} />} title={c.directorySync} description={c.directorySyncHint} />
        <div className="module-setting-card">
          <div className="subsection-heading"><strong>{c.ldapAd}</strong><span>{stringList(config.ldap_provider_ids).length} {c.syncSources}</span></div>
          <div className="application-choice-list">
            {ldapProviders.map((provider) => (
              <div className="directory-sync-provider-row" key={provider.id}>
                <label className="application-choice">
                  <input type="checkbox" checked={stringList(config.ldap_provider_ids).includes(provider.id)} onChange={() => toggleId("ldap_provider_ids", provider.id)} />
                  <span><strong>{provider.display_name}</strong><small>{provider.url} · {provider.base_dn}</small></span>
                  <span className="application-choice-status">{provider.is_active ? c.active : c.disabled}</span>
                </label>
                <button type="button" className="text-button directory-sync-run-button" onClick={() => void runDirectorySync(provider.id)} disabled={!canManage || runningProviderId !== null || !stringList(config.ldap_provider_ids).includes(provider.id) || !booleanValue(config.enabled)}>
                  <RefreshCw size={14} className={runningProviderId === provider.id ? "spin" : undefined} />
                  {runningProviderId === provider.id ? c.syncRunning : c.runNow}
                </button>
              </div>
            ))}
            {ldapProviders.length === 0 && <p className="muted">{c.notConfigured}</p>}
          </div>
          <div className="module-divider" />
          <div className="subsection-heading"><strong>{c.ldapAd} {c.directorySync}</strong><span>{c.deprovisionAction}: remove_membership</span></div>
          <div className="form-grid-2 compact-form-grid">
            <Input label={c.userSyncFilter} hint={locale === "zh-CN" ? "留空则使用 LDAP provider 的用户过滤器，并将登录占位符替换为通配符。" : "Leave blank to derive a wildcard filter from the LDAP provider user filter."} value={stringValue(config.user_sync_filter)} onChange={(value) => updateDraft("directory_sync", { ...config, user_sync_filter: value })} />
            <Input label={c.groupBaseDn} value={stringValue(config.group_base_dn)} onChange={(value) => updateDraft("directory_sync", { ...config, group_base_dn: value })} />
            <Input label={c.groupIdAttribute} value={stringValue(config.group_id_attribute, "dn")} onChange={(value) => updateDraft("directory_sync", { ...config, group_id_attribute: value })} />
            <Input label={c.groupNameAttribute} value={stringValue(config.group_name_attribute, "cn")} onChange={(value) => updateDraft("directory_sync", { ...config, group_name_attribute: value })} />
            <Input label={c.groupMemberAttribute} value={stringValue(config.group_member_attribute, "member")} onChange={(value) => updateDraft("directory_sync", { ...config, group_member_attribute: value })} />
            <Input label={c.maxEntries} type="number" value={String(typeof config.max_entries === "number" ? config.max_entries : 100000)} onChange={(value) => updateDraft("directory_sync", { ...config, max_entries: Number(value) || 100000 })} />
          </div>
          <Input label={c.groupFilter} value={stringValue(config.group_filter, "(objectClass=group)")} onChange={(value) => updateDraft("directory_sync", { ...config, group_filter: value })} />
          <Toggle label={c.reactivateUsers} checked={booleanValue(config.reactivate_users, true)} onChange={(value) => updateDraft("directory_sync", { ...config, reactivate_users: value })} />
          <label className="application-input"><span>{c.deprovisionAction}</span><select value={stringValue(config.deprovision_action, "remove_membership")} onChange={(event) => updateDraft("directory_sync", { ...config, deprovision_action: event.target.value })}><option value="remove_membership">remove_membership</option></select></label>
          <div className="module-divider" />
          <div className="subsection-heading"><strong>{c.scim}</strong><span>{booleanValue(config.scim_enabled) ? c.configured : c.notConfigured}</span></div>
          <p className="muted">{c.scimHint}</p>
          <Toggle label={c.enabled} checked={booleanValue(config.enabled)} onChange={(value) => updateDraft("directory_sync", { ...config, enabled: value })} />
          <Toggle label={c.enabled} checked={booleanValue(config.scim_enabled)} onChange={(value) => updateDraft("directory_sync", { ...config, scim_enabled: value })} />
          <div className="form-grid-2 compact-form-grid">
            <Input label={c.scimAudience} value={stringValue(config.scim_audience)} onChange={(value) => updateDraft("directory_sync", { ...config, scim_audience: value })} />
          </div>
          <Toggle label={c.groupSync} checked={booleanValue(config.sync_groups, true)} onChange={(value) => updateDraft("directory_sync", { ...config, sync_groups: value })} />
        </div>
        <div className="module-setting-card directory-sync-history">
          <div className="subsection-heading"><div><strong>{c.syncHistory}</strong><p className="muted">{c.syncCheckpoint}: {(() => {
            const checkpoint = syncRuns.find((run) => run.status === "succeeded" && run.cursor);
            return checkpoint?.cursor ? formatScimTokenTime(Number(checkpoint.cursor), locale) : c.syncNoCheckpoint;
          })()}</p></div><span>{syncRuns.length}</span></div>
          <div className="directory-sync-run-list">
            {syncRuns.map((run) => {
              const provider = ldapProviders.find((item) => item.id === run.provider_id);
              const status = run.status === "succeeded" ? c.syncSuccess : run.status === "failed" ? c.syncFailure : c.syncRunning;
              return <div className={`directory-sync-run${run.status === "succeeded" ? " succeeded" : run.status === "failed" ? " failed" : " running"}`} key={run.id}>
                <div className="directory-sync-run-heading"><strong>{provider?.display_name ?? run.provider_id}</strong><span>{status}</span></div>
                <div className="directory-sync-run-meta"><span>{formatScimTokenTime(run.started_at, locale)}</span><span>{c.syncSeen}: {run.total_seen}</span><span>{c.syncCreated}: {run.created_count}</span><span>{c.syncUpdated}: {run.updated_count}</span><span>{c.syncDisabled}: {run.disabled_count}</span></div>
                {run.error && <small className="directory-sync-run-error">{run.error}</small>}
              </div>;
            })}
            {syncRuns.length === 0 && <p className="muted">{c.noSyncRuns}</p>}
          </div>
        </div>
        <div className="module-setting-card scim-token-card">
          <div className="subsection-heading"><div><strong>{c.scimTokens}</strong><p className="muted">{c.scimTokensHint}</p></div><span>{scimTokens.filter((token) => !token.revoked_at).length}</span></div>
          <div className="scim-token-create">
            <strong>{c.createScimToken}</strong>
            <div className="scim-token-scope-list">
              <label className="application-choice"><input type="checkbox" checked={scimTokenScopes.includes("scim.read")} onChange={() => toggleScimTokenScope("scim.read")} /><span><strong>{c.scimRead}</strong><small>scim.read</small></span></label>
              <label className="application-choice"><input type="checkbox" checked={scimTokenScopes.includes("scim.write")} onChange={() => toggleScimTokenScope("scim.write")} /><span><strong>{c.scimWrite}</strong><small>scim.write</small></span></label>
            </div>
            <Input label={c.scimTokenExpiry} hint={c.scimTokenExpiryHint} type="datetime-local" value={scimTokenExpiry} onChange={setScimTokenExpiry} />
            <button type="button" className="secondary-button" onClick={() => void createScimToken()} disabled={scimTokenSaving || scimTokenScopes.length === 0 || !booleanValue(config.scim_enabled)}><Plus size={14} />{scimTokenSaving ? c.saving : c.createScimToken}</button>
          </div>
          {createdScimToken && <div className="module-secret-value scim-token-reveal"><div><code>{createdScimToken}</code><small>{c.tokenOnlyOnce}</small></div><button type="button" className="text-button" onClick={() => void copyCreatedScimToken()}><CopyIcon size={14} />{c.copyToken}</button></div>}
          <div className="scim-token-list">
            {scimTokens.map((token) => (
              <div className={`scim-token-row${token.revoked_at ? " revoked" : ""}`} key={token.id}>
                <div className="scim-token-main"><strong>{token.token_prefix}…</strong><small>{token.scopes.join(" · ")}</small></div>
                <div className="scim-token-meta"><span>{token.revoked_at ? c.revoked : `${c.tokenExpires}: ${token.expires_at ? formatScimTokenTime(token.expires_at, locale) : c.tokenNeverExpires}`}</span><span>{c.tokenLastUsed}: {token.last_used_at ? formatScimTokenTime(token.last_used_at, locale) : c.tokenNeverUsed}</span><small>{c.tokenCreated}: {formatScimTokenTime(token.created_at, locale)}</small></div>
                {!token.revoked_at && <button type="button" className="text-danger-button" onClick={() => void revokeScimToken(token.id)} disabled={scimTokenSaving}>{c.revokeToken}</button>}
              </div>
            ))}
            {scimTokens.length === 0 && <p className="muted">{c.noScimTokens}</p>}
          </div>
        </div>
        <ModuleSave saving={savingKey === "directory_sync"} feedback={feedback} copy={c} onSave={() => void saveModule("directory_sync")} />
      </div>
    );
  }

  function renderAuthorizationEditor() {
    if (!selected) return null;
    const config = draftFor("authorization");
    const claims = stringList(config.claims);
    const knownPermissions = new Set(applicationPermissionCatalog.map((permission) => permission.key));
    const customRolePermissions = roleDraft
      ? roleDraft.permissions.filter((permission) => !knownPermissions.has(permission))
      : [];
    const authorizationUsers = authorizationSubjects?.users ?? [];
    const authorizationGroups = authorizationSubjects?.groups ?? [];
    const customOverrideLines = userPermissionOverrides
      .filter((override) => !knownPermissions.has(override.permission))
      .map((override) => `${override.effect}:${override.permission}`)
      .join("\n");
    return (
      <div className="application-module-content">
        <ModuleHeader icon={<ShieldCheck size={19} />} title={c.permissions} description={c.authorizationHint} />
        {authorizationProfiles.length === 0 ? (
          <div className="module-setting-card authorization-empty-profile">
            <strong>{c.noAuthorizationProfile}</strong>
            <p className="muted">{c.setupNextHint}</p>
          </div>
        ) : <div className="module-setting-card">
          <div className="authorization-profile-panel">
            <div className="subsection-heading">
              <div><strong>{c.authorizationProfile}</strong><p className="muted">{c.authorizationProfileHint}</p></div>
              <span>{authorizationProfiles.length}</span>
            </div>
            <label className="application-input">
              <span>{c.authorizationProfile}</span>
              <select value={selectedAuthorizationProfileId} onChange={(event) => setSelectedAuthorizationProfileId(event.target.value)}>
                {authorizationProfiles.map((profile) => <option value={profile.id} key={profile.id}>{profile.profile_key}</option>)}
              </select>
            </label>
            {selectedAuthorizationProfile && <>
              <div className="form-grid-2 compact-form-grid">
                <Input label={c.profileManifestUrl} value={profileManifestUrl} onChange={setProfileManifestUrl} />
                <label className="application-input"><span>{c.profileSigner}</span><select value={profileSignerClientId} onChange={(event) => setProfileSignerClientId(event.target.value)}>
                  <option value="">{c.notConfigured}</option>
                  {selected.oidc_clients.map((client) => <option value={client.client_id} key={client.id}>{client.client_name} · {client.client_id}</option>)}
                </select></label>
              </div>
              <div className="authorization-profile-mode-row">
                <Toggle label={c.profileMode} hint={profileSignedEnabled ? c.profileSigned : c.profileManual} checked={profileSignedEnabled} onChange={setProfileSignedEnabled} />
                <span className={`application-role-badge ${selectedAuthorizationProfile.sync_status === "synced" ? "default" : ""}`}>
                  {selectedAuthorizationProfile.sync_status === "synced" ? c.profileSynced : selectedAuthorizationProfile.source_mode === "manual" ? c.profileManualStatus : selectedAuthorizationProfile.sync_status}
                </span>
              </div>
              <div className="application-role-editor-actions">
                <span className={profileFeedback === c.saveFailed ? "module-save-error" : "module-save-feedback"} role="status">{profileFeedback}</span>
                {canManage && <>
                  <button type="button" className="secondary-button" onClick={() => void refreshAuthorizationProfile()} disabled={profileRefreshing || profileSaving || !profileSignedEnabled}><RefreshCw size={14} />{profileRefreshing ? c.saving : c.refreshProfile}</button>
                  <button type="button" className="primary-action" onClick={() => void saveAuthorizationProfile()} disabled={profileSaving || profileRefreshing}>{profileSaving ? c.saving : c.save}<ArrowRight size={15} /></button>
                </>}
              </div>
              {selectedAuthorizationProfile.last_error && <p className="module-save-error" role="alert">{selectedAuthorizationProfile.last_error}</p>}
              {selectedAuthorizationProfile.source_mode === "manual" && <p className="module-note"><Circle size={11} />{c.profileNoDefinition}</p>}
            </>}
          </div>
          <div className="module-divider" />
          <p className="module-note"><Circle size={11} />{c.loginBoundaryNote}</p>
          <div className="module-divider" />
          <div className="subsection-heading">
            <div><strong>{c.customRoles}</strong><p className="muted">{c.customRolesHint}</p></div>
            {canManage && <button type="button" className="secondary-button" onClick={() => startApplicationRole()} disabled={roleSaving}><Plus size={14} />{c.addRole}</button>}
          </div>
          <div className="application-role-list">
            {applicationRoles.map((role) => (
              <article className={`application-role-record${role.is_active ? "" : " inactive"}`} key={role.id}>
                <div className="application-role-record-main">
                  <strong>{role.name}</strong>
                  <small><code>{role.role_key}</code> · {role.description || c.noModuleConfig}</small>
                  <div className="application-role-permission-summary">
                    {role.permissions.length > 0
                      ? role.permissions.map((permission) => <span key={permission}>{permission}</span>)
                      : <span>{c.notConfigured}</span>}
                  </div>
                </div>
                <div className="application-role-record-meta">
                  {role.is_default && <span className="application-role-badge default">{c.defaultRole}</span>}
                  <span className="application-role-badge">{role.is_active ? c.active : c.disabled}</span>
                </div>
                {canManage && <div className="application-role-record-actions">
                  <button type="button" className="secondary-button" onClick={() => startApplicationRole(role)} disabled={roleSaving}><Pencil size={13} />{c.editRole}</button>
                  <button type="button" className="text-danger-button" onClick={() => void deleteApplicationRole(role)} disabled={roleSaving || role.is_default} title={role.is_default ? c.defaultRoleDeleteHint : c.deleteRole}><Trash2 size={13} />{c.deleteRole}</button>
                </div>}
              </article>
            ))}
            {applicationRoles.length === 0 && <p className="muted">{c.noApplicationRoles}</p>}
          </div>
          {roleDraft && (
            <div className="application-role-editor">
              <div className="subsection-heading"><strong>{roleDraft.id ? c.editRole : c.addRole}</strong><span>{roleDraft.id ?? c.notConfigured}</span></div>
              <div className="form-grid-2 compact-form-grid">
                <Input label={c.roleKey} value={roleDraft.role_key} disabled={roleDraft.source === "manifest"} onChange={(value) => updateRoleDraft({ role_key: value })} />
                <Input label={c.roleName} value={roleDraft.name} onChange={(value) => updateRoleDraft({ name: value })} />
                <Input label={c.roleDescription} value={roleDraft.description} onChange={(value) => updateRoleDraft({ description: value })} />
              </div>
              <Toggle label={c.activeRole} checked={roleDraft.is_active} onChange={(value) => updateRoleDraft({ is_active: value, is_default: value ? roleDraft.is_default : false })} />
              <Toggle label={c.defaultRole} hint={c.inheritEnterpriseHint} checked={roleDraft.is_default} disabled={!roleDraft.is_active} onChange={(value) => updateRoleDraft({ is_default: value })} />
              <div className="module-divider" />
              <div><strong>{c.rolePermissions}</strong><p className="muted">{c.rolePermissionsHint}</p></div>
              {applicationPermissionCatalog.length > 0 && <>
                <span className="application-permission-label">{c.permissionTree}</span>
                <PermissionTree
                  definitions={applicationPermissionCatalog}
                  renderLeaf={(permission) => <label className="application-choice permission-tree-choice" key={permission.key}>
                    <input type="checkbox" checked={roleDraft.permissions.includes(permission.key)} onChange={() => toggleRolePermission(permission.key)} />
                    <span><strong>{permission.label}</strong><small><code>{permission.key}</code>{permission.description ? ` · ${permission.description}` : ""}</small></span>
                  </label>}
                />
              </>}
              <Input
                label={c.customPermissions}
                hint={c.customPermissionsHint}
                value={customRolePermissions.join("\n")}
                textarea
                onChange={(value) => updateRoleDraft({ permissions: normalizedPermissionList([
                  ...roleDraft.permissions.filter((permission) => knownPermissions.has(permission)),
                  ...value.split(/\r?\n/)
                ]) })}
              />
              <div className="application-role-editor-actions">
                <button type="button" className="secondary-button" onClick={() => setRoleDraft(null)} disabled={roleSaving}>{c.removeRole}</button>
                <button type="button" className="primary-action" onClick={() => void saveApplicationRole()} disabled={roleSaving || !roleDraft.name.trim() || !roleDraft.role_key.trim()}>{roleSaving ? c.saving : c.save}<ArrowRight size={15} /></button>
              </div>
            </div>
          )}
          {roleFeedback && <p className={roleFeedback === c.saveFailed || roleFeedback === c.defaultRoleDeleteHint ? "module-save-error" : "module-save-feedback"} role="status">{roleFeedback}</p>}
          <div className="module-divider" />
          <div className="authorization-subsection">
            <div className="subsection-heading"><div><strong>{c.userRoleBindings}</strong><p className="muted">{c.userRoleBindingsHint}</p></div><span>{authorizationUsers.length}</span></div>
            {authorizationUsers.length > 0 ? <>
              <label className="application-input"><span>{c.selectUser}</span><select value={selectedAuthorizationUserId} disabled={authorizationLoading} onChange={(event) => setSelectedAuthorizationUserId(event.target.value)}>
                {authorizationUsers.map((user) => <option value={user.user_id} key={user.user_id}>{user.email} · {user.display_name || user.username}</option>)}
              </select></label>
              <div className="application-permission-grid">
                {applicationRoles.filter((role) => role.is_active || userRoleIds.includes(role.id)).map((role) => (
                  <label className="application-choice" key={role.id}>
                    <input type="checkbox" checked={userRoleIds.includes(role.id)} onChange={() => setUserRoleIds((current) => toggleRoleId(current, role.id))} disabled={authorizationSaving} />
                    <span><strong>{role.name}</strong><small>{role.description || c.noModuleConfig}</small></span>
                  </label>
                ))}
                {applicationRoles.length === 0 && <p className="muted">{c.noApplicationRoles}</p>}
              </div>
            </> : <p className="muted">{c.noAuthorizationUsers}</p>}
          </div>
          <div className="authorization-subsection">
            <div className="subsection-heading"><div><strong>{c.groupRoleBindings}</strong><p className="muted">{c.groupRoleBindingsHint}</p></div><span>{authorizationGroups.length}</span></div>
            {authorizationGroups.length > 0 ? <>
              <label className="application-input"><span>{c.selectGroup}</span><select value={selectedAuthorizationGroupId} disabled={authorizationLoading} onChange={(event) => setSelectedAuthorizationGroupId(event.target.value)}>
                {authorizationGroups.map((group) => <option value={group.id} key={group.id}>{group.name}</option>)}
              </select></label>
              <div className="application-permission-grid">
                {applicationRoles.filter((role) => role.is_active || groupRoleIds.includes(role.id)).map((role) => (
                  <label className="application-choice" key={role.id}>
                    <input type="checkbox" checked={groupRoleIds.includes(role.id)} onChange={() => setGroupRoleIds((current) => toggleRoleId(current, role.id))} disabled={authorizationSaving} />
                    <span><strong>{role.name}</strong><small>{role.description || c.noModuleConfig}</small></span>
                  </label>
                ))}
                {applicationRoles.length === 0 && <p className="muted">{c.noApplicationRoles}</p>}
              </div>
            </> : <p className="muted">{c.noAuthorizationGroups}</p>}
          </div>
          <div className="authorization-subsection">
            <div className="subsection-heading"><div><strong>{c.enterpriseRoleMappings}</strong><p className="muted">{c.enterpriseRoleMappingsHint}</p></div><span>{authorizationSubjects?.organization_roles.length ?? 0}</span></div>
            <div className="authorization-mapping-list">
              {(authorizationSubjects?.organization_roles ?? []).map((organizationRole) => (
                <div className="authorization-mapping-row" key={organizationRole}>
                  <strong>{organizationRole}</strong>
                  <div className="application-role-chip-list">
                    {applicationRoles.filter((role) => role.is_active || (organizationRoleIds[organizationRole] ?? []).includes(role.id)).map((role) => (
                      <label className="application-choice" key={role.id}>
                        <input type="checkbox" checked={(organizationRoleIds[organizationRole] ?? []).includes(role.id)} onChange={() => setOrganizationRoleIds((current) => ({ ...current, [organizationRole]: toggleRoleId(current[organizationRole] ?? [], role.id) }))} disabled={authorizationSaving} />
                        <span><strong>{role.name}</strong><small>{role.description || c.noModuleConfig}</small></span>
                      </label>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="authorization-subsection">
            <div className="subsection-heading"><div><strong>{c.permissionOverrides}</strong><p className="muted">{c.permissionOverridesHint}</p></div><span>{selectedAuthorizationUserId ? userPermissionOverrides.length : 0}</span></div>
            {selectedAuthorizationUserId ? <>
              <PermissionTree
                definitions={applicationPermissionCatalog}
                renderLeaf={(permission) => {
                  const effect = userPermissionOverrides.find((override) => override.permission === permission.key)?.effect ?? "";
                  return <label className="application-input permission-tree-override" key={permission.key}><span>{permission.label}<small><code>{permission.key}</code></small></span><select value={effect} disabled={authorizationSaving} onChange={(event) => updatePermissionOverride(permission.key, event.target.value as "" | "allow" | "deny")}><option value="">{c.inheritPermission}</option><option value="allow">{c.allowPermission}</option><option value="deny">{c.denyPermission}</option></select></label>;
                }}
              />
              <Input label={c.customOverrides} hint={c.customOverridesHint} value={customOverrideLines} textarea onChange={updateCustomPermissionOverrides} />
            </> : <p className="muted">{c.noAuthorizationUsers}</p>}
          </div>
          <div className="application-role-editor-actions">
            <span className="module-save-feedback" role="status">{authorizationFeedback}</span>
            {canManage && <button type="button" className="primary-action" onClick={() => void saveAuthorizationBindings()} disabled={authorizationSaving || authorizationLoading}>{authorizationSaving ? c.saving : c.saveBindings}<ArrowRight size={15} /></button>}
          </div>
          <div className="module-divider" />
          <div className="authorization-subsection">
            <div className="subsection-heading"><div><strong>{c.authorizationPreview}</strong><p className="muted">{c.authorizationPreviewHint}</p></div><button type="button" className="secondary-button" onClick={() => void runAuthorizationPreview()} disabled={!selectedAuthorizationUserId || authorizationLoading}><Eye size={14} />{authorizationLoading ? c.saving : c.runPreview}</button></div>
            {authorizationPreview ? <div className="authorization-preview" role="status">
              <strong className={authorizationPreview.decision.allowed ? "preview-allowed" : "preview-denied"}>{authorizationPreview.decision.allowed ? c.previewAllowed : c.previewDenied}</strong>
              <div className="authorization-preview-grid"><div><span>{c.previewRoles}</span><strong>{authorizationPreview.entitlements?.roles.join(" · ") || "-"}</strong></div><div><span>{c.previewPermissions}</span><strong>{authorizationPreview.entitlements?.permissions.join(" · ") || "-"}</strong></div><div><span>{c.previewGroups}</span><strong>{authorizationPreview.entitlements?.groups.join(" · ") || "-"}</strong></div><div><span>{c.previewPolicyVersion}</span><code>{authorizationPreview.decision.policy_version}</code></div></div>
            </div> : <p className="muted">{c.previewEmpty}</p>}
          </div>
          <div className="module-divider" />
          <p className="module-note">{c.loginBoundaryNote}</p>
          <Input label={c.claims} hint={c.claimsHint} value={claims.join("\n")} textarea onChange={(value) => updateDraft("authorization", { ...config, claims: value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean) })} />
        </div>}
        <ModuleSave saving={savingKey === "authorization"} feedback={feedback} copy={c} onSave={() => void saveModule("authorization")} />
      </div>
    );
  }

  if (applications.length === 0) {
    return (
      <section className="application-workspace empty-application-workspace">
        <div className="application-empty-illustration"><Globe2 size={30} /></div>
        <h3>{c.noWebsites}</h3>
        <p>{c.noWebsitesHint}</p>
        {canManage && <button type="button" onClick={onCreateApplication}><Plus size={15} />{c.createWebsite}</button>}
      </section>
    );
  }

  const protocolConfig = selected ? record(draftFor("protocols")) : {};
  const websiteUrl = stringValue(protocolConfig.website_url);
  const enabledProtocolCount = selected
    ? ["oauth2_oidc", "saml2", "cas", "jwt"].filter((key) => booleanValue(record(protocolConfig[key]).enabled)).length
    : 0;
  const enabledIdentityCount = selected ? stringList(record(draftFor("login_adapters")).provider_ids).length : 0;
  const enabledSyncCount = selected ? stringList(record(draftFor("directory_sync")).ldap_provider_ids).length + (booleanValue(record(draftFor("directory_sync")).scim_enabled) ? 1 : 0) : 0;
  return (
    <section className="application-workspace">
      <div className="application-workspace-heading">
        <div>
          <span className="eyebrow"><Globe2 size={14} />{c.websites}</span>
          <h3>{c.applications}</h3>
          <p>{c.applicationIntro}</p>
        </div>
        {canManage && <button type="button" className="primary-action" onClick={onCreateApplication}><Plus size={15} />{c.createWebsite}</button>}
      </div>
      <div className="application-stat-strip">
        <div><span>{c.websites}</span><strong>{applications.length}</strong></div>
        <div><span>{c.protocols}</span><strong>{applications.reduce((total, item) => total + (item.oidc_clients.length > 0 ? 1 : 0) + (item.modules ?? []).filter((module) => module.module_key === "protocols" && module.is_enabled).length, 0)}</strong></div>
        <div><span>{c.identitySources}</span><strong>{providers.filter((provider) => provider.is_active).length + ldapProviders.filter((provider) => provider.is_active).length}</strong></div>
      </div>
      <div className="application-workspace-layout">
        <aside className="application-picker" aria-label={c.selectWebsite}>
          <div className="application-picker-heading"><span>{c.selectWebsite}</span><strong>{applications.length}</strong></div>
          <div className="application-picker-list">
            {applications.map((application) => (
              <button type="button" key={application.id} className={application.id === selected?.id ? "selected" : ""} onClick={() => setSelectedId(application.id)}>
                <span className="application-avatar">{Array.from(application.name)[0]?.toUpperCase() ?? "W"}</span>
                <span className="application-picker-copy"><strong>{application.name}</strong><small>{application.slug}</small><em><span className="status-dot" />{application.is_active ? c.active : c.disabled}</em></span>
                <ChevronRight size={16} />
              </button>
            ))}
          </div>
        </aside>
        {selected && (
          <div className="application-detail">
            <div className="application-detail-hero">
              <div className="application-hero-identity"><span className="application-hero-avatar"><Globe2 size={25} /></span><div><div className="application-breadcrumb"><span>{c.websites}</span><ChevronRight size={13} /><span>{selected.slug}</span></div><h4>{selected.name}</h4><p>{selected.description || c.accessBundleHint}</p>{websiteUrl && <a className="application-website-link" href={websiteUrl} target="_blank" rel="noreferrer"><Globe2 size={12} />{websiteUrl}</a>}</div></div>
              <div className="application-hero-actions">{canManage && <button type="button" className="icon-button" onClick={() => onEditApplication(selected)} title={c.edit} aria-label={c.edit}><Pencil size={16} /></button>}</div>
            </div>
            <nav className="application-detail-tabs" aria-label={c.accessBundle}>
              {(["overview", ...MODULE_KEYS] as const).map((item) => {
                const label = item === "overview" ? c.overview : item === "protocols" ? c.protocols : item === "login_adapters" ? c.identity : item === "directory_sync" ? c.directory : c.permissions;
                return <button type="button" className={section === item ? "active" : ""} key={item} onClick={() => openSection(item)}><ModuleTabIcon item={item} /><span>{label}</span>{item !== "overview" && <span className={`tab-status ${moduleEnabled(selected, item) ? "on" : ""}`} />}</button>;
              })}
            </nav>
            {section === "overview" && (
              <div className="application-overview-panel">
                <div className="application-module-grid">
                  <ModuleSummary keyName="protocols" title={c.protocols} icon={<Code2 size={18} />} enabled={moduleEnabled(selected, "protocols")} summary={`${enabledProtocolCount} ${c.protocolCount}`} onClick={() => openSection("protocols")} />
                  <ModuleSummary keyName="login_adapters" title={c.identity} icon={<KeyRound size={18} />} enabled={moduleEnabled(selected, "login_adapters")} summary={`${enabledIdentityCount} ${c.sourcesSelected}`} onClick={() => openSection("login_adapters")} />
                  <ModuleSummary keyName="directory_sync" title={c.directory} icon={<Database size={18} />} enabled={moduleEnabled(selected, "directory_sync")} summary={`${enabledSyncCount} ${c.syncSources}`} onClick={() => openSection("directory_sync")} />
                  <ModuleSummary keyName="authorization" title={c.permissions} icon={<ShieldCheck size={18} />} enabled={moduleEnabled(selected, "authorization")} summary={booleanValue(record(draftFor("authorization")).inherit_enterprise_roles, true) ? c.inheritEnterprise : c.notConfigured} onClick={() => openSection("authorization")} />
                </div>
                <div className="application-next-step"><div className="next-step-icon"><SlidersHorizontal size={18} /></div><div><strong>{c.setupNext}</strong><p>{c.setupNextHint}</p></div><button type="button" onClick={() => openSection("protocols")}><span>{c.configure}</span><ArrowRight size={15} /></button></div>
              </div>
            )}
            {section === "protocols" && renderProtocolEditor()}
            {section === "login_adapters" && renderIdentityEditor()}
            {section === "directory_sync" && renderDirectoryEditor()}
            {section === "authorization" && renderAuthorizationEditor()}
            {canManage && <div className="application-danger-zone"><button type="button" className="text-danger-button" onClick={() => onDeleteApplication(selected.id)}><Trash2 size={14} />{c.delete}</button></div>}
          </div>
        )}
      </div>
    </section>
  );
}

function ModuleHeader({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return <div className="application-module-header"><span className="module-heading-icon">{icon}</span><div><h5>{title}</h5><p>{description}</p></div></div>;
}

function ModuleTabIcon({ item }: { item: "overview" | ApplicationModuleKey }) {
  if (item === "overview") return <Settings2 size={16} />;
  return <ModuleIcon keyName={item} />;
}

function ModuleSummary({ keyName, title, icon, enabled, summary, onClick }: { keyName: ApplicationModuleKey; title: string; icon: React.ReactNode; enabled: boolean; summary: string; onClick: () => void }) {
  return <button type="button" className="application-module-summary" onClick={onClick}><span className={`module-summary-icon module-${keyName}`}>{icon}</span><span className="module-summary-copy"><strong>{title}</strong><small>{summary}</small></span><span className={`module-summary-state ${enabled ? "on" : ""}`}>{enabled ? <CheckCircle2 size={15} /> : <Circle size={15} />}</span><ChevronRight size={15} /></button>;
}

function ProtocolCard({ icon, title, description, enabled, onToggle, tone, children }: { icon: React.ReactNode; title: string; description: string; enabled: boolean; onToggle: (value: boolean) => void; tone?: string; children: React.ReactNode }) {
  return <article className={`protocol-card${tone ? ` protocol-${tone}` : ""}${enabled ? " enabled" : ""}`}><div className="protocol-card-heading"><span className="protocol-icon">{icon}</span><div><h6>{title}</h6><p>{description}</p></div><Toggle compact checked={enabled} onChange={onToggle} /></div><div className="protocol-card-body">{children}</div></article>;
}

function ModuleSave({ saving, feedback, copy, onSave }: { saving: boolean; feedback: string; copy: Copy; onSave: () => void }) {
  return <div className="application-module-actions"><span className={feedback === copy.saveFailed ? "module-save-error" : "module-save-feedback"}>{feedback}</span><button type="button" className="primary-action" onClick={onSave} disabled={saving}>{saving ? copy.saving : copy.save}<ArrowRight size={15} /></button></div>;
}

function Toggle({ label, hint, checked, onChange, compact = false, disabled = false }: { label?: string; hint?: string; checked: boolean; onChange: (value: boolean) => void; compact?: boolean; disabled?: boolean }) {
  return <label className={`application-toggle${compact ? " compact" : ""}`}><span className="toggle-copy">{label && <strong>{label}</strong>}{hint && <small>{hint}</small>}</span><input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} /><span className="toggle-track" aria-hidden="true"><span /></span></label>;
}

function Input({ label, hint, value, onChange, type = "text", textarea = false, disabled = false }: { label: string; hint?: string; value: string; onChange: (value: string) => void; type?: string; textarea?: boolean; disabled?: boolean }) {
  return <label className="application-input"><span>{label}</span>{textarea ? <textarea value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} /> : <input type={type} value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} />}{hint && <small>{hint}</small>}</label>;
}

function TicketIcon() {
  return <span className="ticket-icon" aria-hidden="true">✦</span>;
}
