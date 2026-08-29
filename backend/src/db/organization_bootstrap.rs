use super::{Db, ORGANIZATION_KIND_SYSTEM, OrganizationRecord};
use crate::error::{AppError, AppResult};

impl Db {
    pub async fn system_organization(&self) -> AppResult<OrganizationRecord> {
        let organization = self.ensure_signet_organization().await?;
        if organization.kind != ORGANIZATION_KIND_SYSTEM {
            return Err(AppError::Internal(
                "Signet system organization is not marked as system".to_string(),
            ));
        }
        Ok(organization)
    }
}
