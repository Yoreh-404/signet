use crate::{error::AppResult, util};
use diesel::sql_types::{BigInt, Integer, Nullable, Text};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, diesel::QueryableByName)]
pub struct IapApplicationRecord {
    #[diesel(sql_type = Text)]
    pub id: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub application_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub slug: String,
    #[diesel(sql_type = Text)]
    pub name: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub description: Option<String>,
    #[diesel(sql_type = Text)]
    pub external_host: String,
    #[diesel(sql_type = Text)]
    pub path_prefix: String,
    #[diesel(sql_type = Nullable<Text>)]
    pub required_organization_id: Option<String>,
    #[diesel(sql_type = Text)]
    pub required_organization_roles: String,
    #[diesel(sql_type = Text)]
    pub required_permissions: String,
    #[diesel(sql_type = Integer)]
    pub is_active: i32,
    #[diesel(sql_type = BigInt)]
    pub created_at: i64,
    #[diesel(sql_type = BigInt)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIapApplication {
    pub id: String,
    pub application_id: Option<String>,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub external_host: String,
    pub path_prefix: String,
    pub required_organization_id: Option<String>,
    pub required_organization_roles: Vec<String>,
    pub required_permissions: Vec<String>,
    pub is_active: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

impl IapApplicationRecord {
    pub fn public(self) -> AppResult<PublicIapApplication> {
        Ok(PublicIapApplication {
            id: self.id,
            application_id: self.application_id,
            slug: self.slug,
            name: self.name,
            description: self.description,
            external_host: self.external_host,
            path_prefix: self.path_prefix,
            required_organization_id: self.required_organization_id,
            required_organization_roles: util::from_json(&self.required_organization_roles)?,
            required_permissions: util::from_json(&self.required_permissions)?,
            is_active: self.is_active == 1,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }

    pub fn required_organization_roles(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.required_organization_roles)
    }

    pub fn required_permissions(&self) -> AppResult<Vec<String>> {
        util::from_json(&self.required_permissions)
    }
}

#[derive(Debug, Clone)]
pub struct NewIapApplication {
    pub application_id: String,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub external_host: String,
    pub path_prefix: String,
    pub required_organization_id: Option<String>,
    pub required_organization_roles: Vec<String>,
    pub required_permissions: Vec<String>,
    pub is_active: bool,
}
