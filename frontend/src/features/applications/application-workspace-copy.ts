export type ApplicationWorkspaceCopy = {
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
  description: string;
  slug: string;
  overview: string;
  protocols: string;
  identity: string;
  directory: string;
  permissions: string;
  billing: string;
  billingHint: string;
  acceptSignetBalance: string;
  acceptSignetBalanceHint: string;
  walletMode: string;
  sharedWallet: string;
  isolatedWallet: string;
  walletModeLocked: string;
  billingCurrency: string;
  billingCurrencies: string;
  billingCurrenciesHint: string;
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
  loadFailed: string;
  retry: string;
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
  oidcClients: string;
  oidcClientHint: string;
  createOidcClient: string;
  editOidcClient: string;
  clientName: string;
  clientSecret: string;
  clientSecretHint: string;
  redirectUris: string;
  postLogoutUris: string;
  scopes: string;
  grantTypes: string;
  responseTypes: string;
  tokenAuthMethod: string;
  requirePkce: string;
  requireMfa: string;
  newClientSecretHint: string;
  iapRules: string;
  iapRulesHint: string;
  noIapRules: string;
  createIapRule: string;
  externalHost: string;
  pathPrefix: string;
  requiredOrganization: string;
  requiredRoles: string;
  requiredPermissions: string;
  walletOverview: string;
  walletAvailable: string;
  walletReserved: string;
  walletTransfer: string;
  walletTransferHint: string;
  transferAmount: string;
  transferDirection: string;
  transferToApplication: string;
  transferFromApplication: string;
  executeTransfer: string;
  noApplicationWallet: string;
  client: string;
  bindingProtocol: string;
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
  revokeSecretsHint: string;
  loginAdapters: string;
  loginAdaptersHint: string;
  allowSignetPassword: string;
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
  revokeTokenHint: string;
  revoked: string;
  tokenOnlyOnce: string;
  unsavedChanges: string;
  discardChanges: string;
  authorizationHint: string;
  authorizationProfile: string;
  authorizationProfileHint: string;
  noAuthorizationProfile: string;
  profileManual: string;
  profileSigned: string;
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
};

export const ZH: ApplicationWorkspaceCopy = {
  applications: "应用",
  websites: "应用",
  applicationIntro: "每个应用在自己的工作区创建并管理 OIDC 客户端。协议、登录适配器、目录同步、IAP 和余额策略都归属于应用。",
  createWebsite: "创建应用",
  selectWebsite: "选择一个应用",
  noWebsites: "还没有应用",
  noWebsitesHint: "先创建一个应用，再在应用内创建 OIDC 客户端并按需开启能力。",
  active: "已启用",
  disabled: "已停用",
  edit: "编辑基本信息",
  delete: "删除应用",
  description: "说明",
  slug: "Slug",
  overview: "总览",
  protocols: "协议",
  identity: "登录适配器",
  directory: "目录同步",
  permissions: "权限",
  billing: "余额接入",
  billingHint: "决定这个应用是否接受 Signet 余额，以及用户是否需要先把总账户余额划转到应用账户。",
  acceptSignetBalance: "接受 Signet 余额",
  acceptSignetBalanceHint: "关闭后，应用可以继续使用自己的支付系统；Signet 不会为它执行余额扣费。",
  walletMode: "账户模式",
  sharedWallet: "共享总账户",
  isolatedWallet: "独立应用账户",
  walletModeLocked: "首次发生账务交易后账户模式会锁定。",
  billingCurrency: "币种",
  billingCurrencies: "支持币种",
  billingCurrenciesHint: "留空表示使用 Signet 全局启用的币种；多个币种用逗号分隔。",
  accessBundle: "应用能力包",
  accessBundleHint: "应用把多个 OIDC 客户端需要的接入能力集中管理；模块可以独立配置和启停。",
  websiteUrl: "应用地址",
  notConfigured: "未配置",
  configured: "已配置",
  enabled: "启用此模块",
  save: "保存配置",
  saving: "保存中…",
  saved: "配置已保存",
  saveFailed: "配置保存失败",
  loadFailed: "配置加载失败",
  retry: "重试",
  protocolHint: "选择应用支持的标准协议，并在应用内创建属于它的 OIDC 客户端。",
  protocolRuntimeHint: "协议配置属于应用，不再散落在全局客户端列表中。",
  oauth: "OAuth 2.0 / OIDC",
  oauthHint: "使用 Signet 作为身份提供方，为网站提供标准授权码、Token 和 UserInfo。",
  saml: "SAML 2.0",
  samlHint: "为传统企业网站提供 SAML 身份提供方配置。",
  cas: "CAS",
  casHint: "为支持 CAS 的内部系统提供票据校验入口。",
  jwt: "JWT",
  jwtHint: "为 API 或无状态服务配置 Signet 签发的 JWT 受众和有效期。",
  connections: "应用内客户端",
  noConnections: "还没有 OIDC 客户端",
  oidcClients: "OIDC 客户端",
  oidcClientHint: "先创建应用，再在应用内创建属于它的 OIDC 客户端。一个客户端只能属于一个应用。",
  createOidcClient: "创建 OIDC 客户端",
  editOidcClient: "编辑 OIDC 客户端",
  clientName: "客户端名称",
  clientSecret: "客户端 Secret",
  clientSecretHint: "更新时留空表示保留现有 Secret；新建机密客户端必须填写。",
  redirectUris: "回调地址",
  postLogoutUris: "退出回调地址",
  scopes: "Scopes",
  grantTypes: "Grant types",
  responseTypes: "Response types",
  tokenAuthMethod: "Token 端点认证方式",
  requirePkce: "要求 PKCE",
  requireMfa: "要求客户端 MFA",
  newClientSecretHint: "Secret 只在这里由你输入或保存，请立即安全记录。",
  iapRules: "IAP 规则",
  iapRulesHint: "在应用内配置多条 Host/path 规则；每条规则都属于当前应用。",
  noIapRules: "还没有 IAP 规则",
  createIapRule: "添加 IAP 规则",
  externalHost: "外部 Host",
  pathPrefix: "路径前缀",
  requiredOrganization: "要求组织（可选）",
  requiredRoles: "要求组织角色",
  requiredPermissions: "要求权限",
  walletOverview: "应用钱包",
  walletAvailable: "可用余额",
  walletReserved: "冻结余额",
  walletTransfer: "应用账户划转",
  walletTransferHint: "仅独立应用账户模式需要划转；共享模式直接使用总账户余额。",
  transferAmount: "划转金额",
  transferDirection: "划转方向",
  transferToApplication: "总账户 → 应用账户",
  transferFromApplication: "应用账户 → 总账户",
  executeTransfer: "执行划转",
  noApplicationWallet: "当前币种还没有应用钱包",
  client: "客户端",
  bindingProtocol: "绑定协议",
  authorizationProfile: "权限 Profile",
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
  revokeSecretsHint: "这会立即使当前应用的所有 JWT Secret 失效，可能中断网站或 API。",
  loginAdapters: "第三方登录适配器",
  loginAdaptersHint: "选择允许从哪些企业身份源进入这个网站；用户仍会落到同一个 Signet 账户。",
  allowSignetPassword: "允许 Signet 密码 / Passkey 登录",
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
  revokeTokenHint: "撤销后，使用此令牌的目录同步会立即停止，且无法恢复。",
  revoked: "已撤销",
  tokenOnlyOnce: "完整令牌只显示这一次，请立即复制并安全保存。",
  unsavedChanges: "有未保存的更改",
  discardChanges: "放弃更改",
  authorizationHint: "权限采用两层合并：继承企业默认角色，再叠加应用 Profile 的专属角色和 Claim。",
  authorizationProfileHint: "每个客户端 Profile 独立维护权限定义、角色和用户映射。应用可以通过签名 v3 契约提供定义，也可以在 Signet 手工维护。",
  noAuthorizationProfile: "请先在应用内创建一个 OIDC 客户端",
  profileManual: "手工配置",
  profileSigned: "签名 Manifest",
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
  setupNextHint: "先在协议页创建 OIDC 客户端，再按应用实际情况开启 SAML、CAS、JWT、第三方登录、目录同步或 IAP。",
  configure: "去配置"
};

export const EN: ApplicationWorkspaceCopy = {
  applications: "Applications",
  websites: "Applications",
  applicationIntro: "Create and manage OIDC clients inside each application. Protocols, login adapters, directory sync, IAP, and billing policies belong to the application.",
  createWebsite: "Create application",
  selectWebsite: "Select an application",
  noWebsites: "No applications yet",
  noWebsitesHint: "Create an application first, then create its OIDC clients and enable only the capabilities it needs.",
  active: "Enabled",
  disabled: "Disabled",
  edit: "Edit basics",
  delete: "Delete application",
  description: "Description",
  slug: "Slug",
  overview: "Overview",
  protocols: "Protocols",
  identity: "Login adapters",
  directory: "Directory sync",
  permissions: "Permissions",
  billing: "Billing",
  billingHint: "Choose whether this application accepts Signet balance and whether users must transfer funds into an application wallet first.",
  acceptSignetBalance: "Accept Signet balance",
  acceptSignetBalanceHint: "When disabled, the application may use its own payment system and Signet will not authorize wallet charges for it.",
  walletMode: "Wallet mode",
  sharedWallet: "Shared global wallet",
  isolatedWallet: "Isolated application wallet",
  walletModeLocked: "Wallet mode is locked after the first billing transaction.",
  billingCurrency: "Currency",
  billingCurrencies: "Supported currencies",
  billingCurrenciesHint: "Leave empty to accept all currencies enabled globally; separate multiple currencies with commas.",
  accessBundle: "Application capability bundle",
  accessBundleHint: "An application owns the capabilities used by its OIDC clients; each module can be configured and enabled independently.",
  websiteUrl: "Application URL",
  notConfigured: "Not configured",
  configured: "Configured",
  enabled: "Enable this module",
  save: "Save configuration",
  saving: "Saving…",
  saved: "Configuration saved",
  saveFailed: "Failed to save configuration",
  loadFailed: "Failed to load configuration",
  retry: "Retry",
  protocolHint: "Choose the standards this application supports, then create its OIDC clients here.",
  protocolRuntimeHint: "Protocol settings belong to the application instead of being scattered across a global client list.",
  oauth: "OAuth 2.0 / OIDC",
  oauthHint: "Use Signet as the identity provider with standard authorization code, token, and UserInfo flows.",
  saml: "SAML 2.0",
  samlHint: "Configure a SAML identity-provider connection for legacy enterprise websites.",
  cas: "CAS",
  casHint: "Provide ticket validation endpoints for internal CAS systems.",
  jwt: "JWT",
  jwtHint: "Configure Signet-issued JWT audiences and lifetimes for APIs or stateless services.",
  connections: "Application clients",
  noConnections: "No OIDC clients yet",
  oidcClients: "OIDC clients",
  oidcClientHint: "Create the application first, then create its OIDC clients here. A client belongs to one application only.",
  createOidcClient: "Create OIDC client",
  editOidcClient: "Edit OIDC client",
  clientName: "Client name",
  clientSecret: "Client secret",
  clientSecretHint: "Leave this blank when updating to keep the existing secret; new confidential clients require one.",
  redirectUris: "Redirect URIs",
  postLogoutUris: "Post-logout URIs",
  scopes: "Scopes",
  grantTypes: "Grant types",
  responseTypes: "Response types",
  tokenAuthMethod: "Token endpoint authentication",
  requirePkce: "Require PKCE",
  requireMfa: "Require client MFA",
  newClientSecretHint: "Record the secret securely after saving; it is not displayed by Signet.",
  iapRules: "IAP rules",
  iapRulesHint: "Configure multiple Host/path rules inside this application; every rule belongs to this application.",
  noIapRules: "No IAP rules yet",
  createIapRule: "Add IAP rule",
  externalHost: "External host",
  pathPrefix: "Path prefix",
  requiredOrganization: "Required organization (optional)",
  requiredRoles: "Required organization roles",
  requiredPermissions: "Required permissions",
  walletOverview: "Application wallet",
  walletAvailable: "Available",
  walletReserved: "Reserved",
  walletTransfer: "Application wallet transfer",
  walletTransferHint: "Transfers are needed only for isolated application wallets; shared mode uses the global wallet directly.",
  transferAmount: "Transfer amount",
  transferDirection: "Transfer direction",
  transferToApplication: "Global → application",
  transferFromApplication: "Application → global",
  executeTransfer: "Transfer balance",
  noApplicationWallet: "No application wallet exists for this currency yet",
  client: "Client",
  bindingProtocol: "Binding protocol",
  authorizationProfile: "Authorization profile",
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
  revokeSecretsHint: "All JWT secrets for this application become invalid immediately. This may interrupt the website or API.",
  loginAdapters: "Third-party login adapters",
  loginAdaptersHint: "Choose which enterprise identity sources may enter this website; users still resolve to one Signet account.",
  allowSignetPassword: "Allow Signet password / Passkey sign-in",
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
  revokeTokenHint: "The directory sync using this token stops immediately and cannot be restored.",
  revoked: "Revoked",
  tokenOnlyOnce: "The complete token is shown only once. Copy it now and store it securely.",
  unsavedChanges: "Unsaved changes",
  discardChanges: "Discard changes",
  authorizationHint: "Authorization is merged in two layers: inherit enterprise defaults, then add application Profile roles and claims.",
  authorizationProfileHint: "Each client Profile has an independent permission vocabulary, role catalog, and subject mappings. An application can publish a signed v3 contract or be configured manually in Signet.",
  noAuthorizationProfile: "Create an OIDC client inside this application first",
  profileManual: "Manual configuration",
  profileSigned: "Signed manifest",
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
  setupNextHint: "Create an OIDC client first, then enable SAML, CAS, JWT, external login, directory sync, or IAP as needed.",
  configure: "Configure"
};
