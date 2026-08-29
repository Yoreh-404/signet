use crate::{error::AppResult, util};
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct ExternalOidcStateRecord {
    #[diesel(sql_type = Text)]
    pub state: String,
    #[diesel(sql_type = Text)]
    pub provider_slug: String,
    #[diesel(sql_type = Text)]
    pub nonce: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub return_to: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub expires_at: i64,
    #[diesel(sql_type = Nullable<BigInt>)]
    pub consumed_at: Option<i64>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
}

pub fn ldap_provider_key(slug: &str) -> String {
    format!("ldap:{slug}")
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct LinkedIdentityRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub user_id: String,
    #[diesel(sql_type = Text)]
    pub provider_slug: String,
    #[diesel(sql_type = Text)]
    pub external_subject: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub external_email: Option<String>,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct ExternalOidcProviderRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub slug: String,
    #[diesel(sql_type = Text)]
    pub display_name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub organization_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub issuer: String,
    #[diesel(sql_type = Text)]
    pub client_id: String,
    #[diesel(sql_type = Text)]
    pub client_secret: String,
    #[diesel(sql_type = Text)]
    pub authorization_endpoint: String,
    #[diesel(sql_type = Text)]
    pub token_endpoint: String,
    #[diesel(sql_type = Text)]
    pub userinfo_endpoint: String,
    #[diesel(sql_type = Text)]
    pub redirect_path: String,
    #[diesel(sql_type = Text)]
    pub scopes: String,
    #[diesel(sql_type = Text)]
    pub email_domains: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Integer)]
    pub allow_login: i32,
    #[diesel(sql_type = Integer)]
    pub allow_registration: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicExternalOidcProvider {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub organization_id: Option<String>,
    pub issuer: String,
    pub client_id: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub redirect_path: String,
    pub scopes: Vec<String>,
    pub email_domains: Vec<String>,
    pub is_active: bool,
    pub allow_login: bool,
    pub allow_registration: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize)]
pub struct LdapProviderRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Text)]
    pub slug: String,
    #[diesel(sql_type = Text)]
    pub display_name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub organization_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub url: String,
    #[diesel(sql_type = Integer)]
    pub starttls: i32,
    #[diesel(sql_type = Text)]
    pub bind_dn: String,
    #[diesel(sql_type = Text)]
    pub bind_password: String,
    #[diesel(sql_type = Text)]
    pub base_dn: String,
    #[diesel(sql_type = Text)]
    pub user_filter: String,
    #[diesel(sql_type = Text)]
    pub user_id_attribute: String,
    #[diesel(sql_type = Text)]
    pub email_attribute: String,
    #[diesel(sql_type = Text)]
    pub username_attribute: String,
    #[diesel(sql_type = Text)]
    pub display_name_attribute: String,
    #[diesel(sql_type = Text)]
    pub phone_attribute: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = Integer)]
    pub allow_login: i32,
    #[diesel(sql_type = Integer)]
    pub allow_registration: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicLdapProvider {
    pub id: String,
    pub slug: String,
    pub display_name: String,
    pub organization_id: Option<String>,
    pub url: String,
    pub starttls: bool,
    pub bind_dn: String,
    pub has_bind_password: bool,
    pub base_dn: String,
    pub user_filter: String,
    pub user_id_attribute: String,
    pub email_attribute: String,
    pub username_attribute: String,
    pub display_name_attribute: String,
    pub phone_attribute: String,
    pub is_active: bool,
    pub allow_login: bool,
    pub allow_registration: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl LdapProviderRecord {
    pub fn provider_key(&self) -> String {
        ldap_provider_key(&self.slug)
    }

    pub fn public(self) -> PublicLdapProvider {
        PublicLdapProvider {
            id: self.id,
            slug: self.slug,
            display_name: self.display_name,
            organization_id: self.organization_id,
            url: self.url,
            starttls: self.starttls == 1,
            bind_dn: self.bind_dn,
            has_bind_password: !self.bind_password.is_empty(),
            base_dn: self.base_dn,
            user_filter: self.user_filter,
            user_id_attribute: self.user_id_attribute,
            email_attribute: self.email_attribute,
            username_attribute: self.username_attribute,
            display_name_attribute: self.display_name_attribute,
            phone_attribute: self.phone_attribute,
            is_active: self.is_active == 1,
            allow_login: self.allow_login == 1,
            allow_registration: self.allow_registration == 1,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl ExternalOidcProviderRecord {
    pub fn public(self) -> AppResult<PublicExternalOidcProvider> {
        Ok(PublicExternalOidcProvider {
            id: self.id,
            slug: self.slug,
            display_name: self.display_name,
            organization_id: self.organization_id,
            issuer: self.issuer,
            client_id: self.client_id,
            authorization_endpoint: self.authorization_endpoint,
            token_endpoint: self.token_endpoint,
            userinfo_endpoint: self.userinfo_endpoint,
            redirect_path: self.redirect_path,
            scopes: util::from_json(&self.scopes)?,
            email_domains: util::from_json(&self.email_domains)?,
            is_active: self.is_active == 1,
            allow_login: self.allow_login == 1,
            allow_registration: self.allow_registration == 1,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NewExternalOidcProvider {
    pub slug: String,
    pub display_name: String,
    pub organization_id: Option<String>,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub redirect_path: String,
    pub scopes: Vec<String>,
    pub email_domains: Vec<String>,
    pub is_active: bool,
    pub allow_login: bool,
    pub allow_registration: bool,
}

#[derive(Debug, Clone)]
pub struct NewLdapProvider {
    pub slug: String,
    pub display_name: String,
    pub organization_id: Option<String>,
    pub url: String,
    pub starttls: bool,
    pub bind_dn: String,
    pub bind_password: Option<String>,
    pub base_dn: String,
    pub user_filter: String,
    pub user_id_attribute: String,
    pub email_attribute: String,
    pub username_attribute: String,
    pub display_name_attribute: String,
    pub phone_attribute: String,
    pub is_active: bool,
    pub allow_login: bool,
    pub allow_registration: bool,
}
