use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct ClientInput {
    pub(super) client_id: String,
    pub(super) client_name: String,
    #[serde(default)]
    pub(super) logo_uri: String,
    #[serde(default)]
    pub(super) organization_id: Option<String>,
    pub(super) client_secret: Option<String>,
    pub(super) redirect_uris: Vec<String>,
    pub(super) post_logout_redirect_uris: Vec<String>,
    pub(super) scopes: Vec<String>,
    #[serde(default)]
    pub(super) audience: Option<String>,
    pub(super) grant_types: Vec<String>,
    pub(super) response_types: Vec<String>,
    pub(super) token_endpoint_auth_method: String,
    pub(super) require_pkce: bool,
    #[serde(default)]
    pub(super) require_mfa: bool,
    #[serde(default)]
    pub(super) require_pushed_authorization_requests: bool,
    #[serde(default)]
    pub(super) require_s256_pkce: bool,
    #[serde(default)]
    pub(super) require_confidential_client: bool,
    #[serde(default)]
    pub(super) require_dpop: bool,
    #[serde(default)]
    pub(super) require_account_selection: bool,
    #[serde(default)]
    pub(super) trust_email_verified: bool,
    #[serde(default)]
    pub(super) authorization_details_types: Vec<String>,
    pub(super) subject_type: String,
    pub(super) sector_identifier_uri: String,
    #[serde(default)]
    pub(super) jwks_uri: String,
    #[serde(default)]
    pub(super) jwks: String,
    #[serde(default)]
    pub(super) backchannel_logout_uri: String,
    #[serde(default)]
    pub(super) backchannel_logout_session_required: bool,
    #[serde(default)]
    pub(super) frontchannel_logout_uri: String,
    #[serde(default)]
    pub(super) frontchannel_logout_session_required: bool,
    #[serde(default)]
    pub(super) service_account_enabled: bool,
    #[serde(default)]
    pub(super) service_account_permissions: Vec<String>,
    pub(super) is_active: bool,
    #[serde(default)]
    pub(super) claim_mappers: Vec<ClientClaimMapperInput>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ClientClaimMapperInput {
    pub(super) claim_name: String,
    pub(super) source: String,
    pub(super) source_value: String,
    pub(super) value_type: String,
    pub(super) include_in_id_token: bool,
    pub(super) include_in_access_token: bool,
    pub(super) include_in_userinfo: bool,
    pub(super) is_active: bool,
    #[serde(default)]
    pub(super) sort_order: i32,
}
