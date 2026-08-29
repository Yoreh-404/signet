use crate::{error::AppResult, util};
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ClientRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub client_secret_hash: Option<String>,
    #[diesel(sql_type = Text)]
    pub client_name: String,
    #[diesel(sql_type = Text)]
    pub logo_uri: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub organization_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub redirect_uris: String,
    #[diesel(sql_type = Text)]
    pub post_logout_redirect_uris: String,
    #[diesel(sql_type = Text)]
    pub scopes: String,
    #[diesel(sql_type = Text)]
    pub audience: String,
    #[diesel(sql_type = Text)]
    pub grant_types: String,
    #[diesel(sql_type = Text)]
    pub response_types: String,
    #[diesel(sql_type = Text)]
    pub token_endpoint_auth_method: String,
    #[diesel(sql_type = Integer)]
    pub require_pkce: i32,
    #[diesel(sql_type = Integer)]
    pub require_mfa: i32,
    #[diesel(sql_type = Integer)]
    pub require_pushed_authorization_requests: i32,
    #[diesel(sql_type = Integer)]
    pub require_s256_pkce: i32,
    #[diesel(sql_type = Integer)]
    pub require_confidential_client: i32,
    #[diesel(sql_type = Integer)]
    pub require_dpop: i32,
    #[diesel(sql_type = Integer)]
    pub require_account_selection: i32,
    #[diesel(sql_type = Integer)]
    pub trust_email_verified: i32,
    #[diesel(sql_type = Text)]
    pub authorization_details_types: String,
    #[diesel(sql_type = Text)]
    pub subject_type: String,
    #[diesel(sql_type = Text)]
    pub sector_identifier_uri: String,
    #[diesel(sql_type = Text)]
    pub jwks_uri: String,
    #[diesel(sql_type = Text)]
    pub jwks: String,
    #[diesel(sql_type = Text)]
    pub backchannel_logout_uri: String,
    #[diesel(sql_type = Integer)]
    pub backchannel_logout_session_required: i32,
    #[diesel(sql_type = Text)]
    pub frontchannel_logout_uri: String,
    #[diesel(sql_type = Integer)]
    pub frontchannel_logout_session_required: i32,
    #[diesel(sql_type = Integer)]
    pub service_account_enabled: i32,
    #[diesel(sql_type = Text)]
    pub service_account_permissions: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ClientRegistrationRecord {
    #[diesel(sql_type = Text)]
    pub client_db_id: String,
    #[diesel(sql_type = Text)]
    pub registration_access_token_hash: String,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ClientClaimMapperRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub client_db_id: String,
    #[diesel(sql_type = Text)]
    pub claim_name: String,
    #[diesel(sql_type = Text)]
    pub source: String,
    #[diesel(sql_type = Text)]
    pub source_value: String,
    #[diesel(sql_type = Text)]
    pub value_type: String,
    #[diesel(sql_type = Integer)]
    pub include_in_id_token: i32,
    #[diesel(sql_type = Integer)]
    pub include_in_access_token: i32,
    #[diesel(sql_type = Integer)]
    pub include_in_userinfo: i32,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Integer)]
    pub sort_order: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicClient {
    pub id: String,
    pub client_id: String,
    pub client_name: String,
    pub logo_uri: String,
    pub organization_id: Option<String>,
    pub organization_slug: Option<String>,
    pub organization_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub audience: String,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub require_pkce: bool,
    pub require_mfa: bool,
    pub require_pushed_authorization_requests: bool,
    pub require_s256_pkce: bool,
    pub require_confidential_client: bool,
    pub require_dpop: bool,
    pub require_account_selection: bool,
    pub trust_email_verified: bool,
    pub authorization_details_types: Vec<String>,
    pub subject_type: String,
    pub sector_identifier_uri: String,
    pub jwks_uri: String,
    pub jwks: String,
    pub backchannel_logout_uri: String,
    pub backchannel_logout_session_required: bool,
    pub frontchannel_logout_uri: String,
    pub frontchannel_logout_session_required: bool,
    pub service_account_enabled: bool,
    pub service_account_permissions: Vec<String>,
    pub is_active: bool,
    pub claim_mappers: Vec<PublicClientClaimMapper>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicClientClaimMapper {
    pub id: String,
    pub claim_name: String,
    pub source: String,
    pub source_value: String,
    pub value_type: String,
    pub include_in_id_token: bool,
    pub include_in_access_token: bool,
    pub include_in_userinfo: bool,
    pub is_active: bool,
    pub sort_order: i32,
    pub created_at: i64,
    pub updated_at: i64,
}

impl ClientRecord {
    pub fn public(self) -> AppResult<PublicClient> {
        Ok(PublicClient {
            id: self.id,
            client_id: self.client_id,
            client_name: self.client_name,
            logo_uri: self.logo_uri,
            organization_id: self.organization_id,
            organization_slug: None,
            organization_name: None,
            redirect_uris: util::from_json(&self.redirect_uris)?,
            post_logout_redirect_uris: util::from_json(&self.post_logout_redirect_uris)?,
            scopes: util::from_json(&self.scopes)?,
            audience: self.audience,
            grant_types: util::from_json(&self.grant_types)?,
            response_types: util::from_json(&self.response_types)?,
            token_endpoint_auth_method: self.token_endpoint_auth_method,
            require_pkce: self.require_pkce == 1,
            require_mfa: self.require_mfa == 1,
            require_pushed_authorization_requests: self.require_pushed_authorization_requests == 1,
            require_s256_pkce: self.require_s256_pkce == 1,
            require_confidential_client: self.require_confidential_client == 1,
            require_dpop: self.require_dpop == 1,
            require_account_selection: self.require_account_selection == 1,
            trust_email_verified: self.trust_email_verified == 1,
            authorization_details_types: util::from_json(&self.authorization_details_types)?,
            subject_type: self.subject_type,
            sector_identifier_uri: self.sector_identifier_uri,
            jwks_uri: self.jwks_uri,
            jwks: self.jwks,
            backchannel_logout_uri: self.backchannel_logout_uri,
            backchannel_logout_session_required: self.backchannel_logout_session_required == 1,
            frontchannel_logout_uri: self.frontchannel_logout_uri,
            frontchannel_logout_session_required: self.frontchannel_logout_session_required == 1,
            service_account_enabled: self.service_account_enabled == 1,
            service_account_permissions: util::from_json(&self.service_account_permissions)?,
            is_active: self.is_active == 1,
            claim_mappers: Vec::new(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    pub fn redirect_uris(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.redirect_uris)
    }

    pub fn post_logout_redirect_uris(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.post_logout_redirect_uris)
    }

    pub fn scopes(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.scopes)
    }

    pub fn grant_types(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.grant_types)
    }

    pub fn response_types(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.response_types)
    }

    pub fn authorization_details_types(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.authorization_details_types)
    }
}

impl ClientClaimMapperRecord {
    pub fn public(self) -> PublicClientClaimMapper {
        PublicClientClaimMapper {
            id: self.id,
            claim_name: self.claim_name,
            source: self.source,
            source_value: self.source_value,
            value_type: self.value_type,
            include_in_id_token: self.include_in_id_token == 1,
            include_in_access_token: self.include_in_access_token == 1,
            include_in_userinfo: self.include_in_userinfo == 1,
            is_active: self.is_active == 1,
            sort_order: self.sort_order,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewClient {
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub client_name: String,
    pub logo_uri: String,
    pub organization_id: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    pub audience: String,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub require_pkce: bool,
    pub require_mfa: bool,
    pub require_pushed_authorization_requests: bool,
    pub require_s256_pkce: bool,
    pub require_confidential_client: bool,
    pub require_dpop: bool,
    pub require_account_selection: bool,
    pub trust_email_verified: bool,
    pub authorization_details_types: Vec<String>,
    pub subject_type: String,
    pub sector_identifier_uri: String,
    pub jwks_uri: String,
    pub jwks: String,
    pub backchannel_logout_uri: String,
    pub backchannel_logout_session_required: bool,
    pub frontchannel_logout_uri: String,
    pub frontchannel_logout_session_required: bool,
    pub service_account_enabled: bool,
    pub service_account_permissions: Vec<String>,
    pub is_active: bool,
}

#[derive(Debug, Clone)]
pub struct NewClientClaimMapper {
    pub claim_name: String,
    pub source: String,
    pub source_value: String,
    pub value_type: String,
    pub include_in_id_token: bool,
    pub include_in_access_token: bool,
    pub include_in_userinfo: bool,
    pub is_active: bool,
    pub sort_order: i32,
}
