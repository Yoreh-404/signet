use crate::error::AppResult;
use crate::util;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, diesel::QueryableByName, Serialize, Deserialize)]
pub struct RuntimeSettingsRecord {
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub public_base_url: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub issuer: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    pub trust_proxy_headers: i32,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicRuntimeSettings {
    pub public_base_url: String,
    pub issuer: String,
    pub trust_proxy_headers: bool,
    pub updated_at: i64,
}

impl RuntimeSettingsRecord {
    pub fn public(&self) -> PublicRuntimeSettings {
        PublicRuntimeSettings {
            public_base_url: self.public_base_url.clone(),
            issuer: self.issuer.clone(),
            trust_proxy_headers: self.trust_proxy_headers == 1,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewRuntimeSettings {
    pub public_base_url: String,
    pub issuer: String,
    pub trust_proxy_headers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickLink {
    pub id: String,
    pub label: String,
    pub url: String,
    #[serde(default)]
    pub icon: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, diesel::QueryableByName, Serialize, Deserialize)]
pub struct LoginSettingsRecord {
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub id: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub brand_logo_url: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub email_domains: String,
    #[diesel(sql_type = diesel::sql_types::Text)]
    pub quick_links: String,
    #[diesel(sql_type = diesel::sql_types::BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicLoginSettings {
    pub brand_logo_url: String,
    pub email_domains: Vec<String>,
    pub quick_links: Vec<QuickLink>,
    pub updated_at: i64,
}

impl LoginSettingsRecord {
    pub fn public(&self) -> AppResult<PublicLoginSettings> {
        Ok(PublicLoginSettings {
            brand_logo_url: self.brand_logo_url.clone(),
            email_domains: util::from_json(&self.email_domains)?,
            quick_links: util::from_json(&self.quick_links)?,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NewLoginSettings {
    pub brand_logo_url: String,
    pub email_domains: Vec<String>,
    pub quick_links: Vec<QuickLink>,
}
