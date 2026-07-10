use crate::{
    db::{Db, UserRecord},
    error::{AppError, AppResult},
};
use serde::{Deserialize, Serialize};
use std::future::Future;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    AdminRead,
    SettingsManage,
    UsersRead,
    UsersManage,
    ClientsRead,
    ClientsManage,
    IapRead,
    IapManage,
    OrganizationsRead,
    OrganizationsManage,
    AuthorizationCodesManage,
    ProvidersManage,
    AuditRead,
    SecurityManage,
}

#[derive(Debug, Clone, Serialize)]
pub struct PermissionInfo {
    pub key: &'static str,
    pub category: &'static str,
    pub label: &'static str,
}

impl Permission {
    pub const ALL: &'static [Permission] = &[
        Permission::AdminRead,
        Permission::SettingsManage,
        Permission::UsersRead,
        Permission::UsersManage,
        Permission::ClientsRead,
        Permission::ClientsManage,
        Permission::IapRead,
        Permission::IapManage,
        Permission::OrganizationsRead,
        Permission::OrganizationsManage,
        Permission::AuthorizationCodesManage,
        Permission::ProvidersManage,
        Permission::AuditRead,
        Permission::SecurityManage,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Permission::AdminRead => "admin.read",
            Permission::SettingsManage => "settings.manage",
            Permission::UsersRead => "users.read",
            Permission::UsersManage => "users.manage",
            Permission::ClientsRead => "clients.read",
            Permission::ClientsManage => "clients.manage",
            Permission::IapRead => "iap.read",
            Permission::IapManage => "iap.manage",
            Permission::OrganizationsRead => "organizations.read",
            Permission::OrganizationsManage => "organizations.manage",
            Permission::AuthorizationCodesManage => "authorization_codes.manage",
            Permission::ProvidersManage => "providers.manage",
            Permission::AuditRead => "audit.read",
            Permission::SecurityManage => "security.manage",
        }
    }

    pub fn category(self) -> &'static str {
        match self {
            Permission::AdminRead => "admin",
            Permission::SettingsManage => "settings",
            Permission::UsersRead | Permission::UsersManage => "users",
            Permission::ClientsRead | Permission::ClientsManage => "clients",
            Permission::IapRead | Permission::IapManage => "iap",
            Permission::OrganizationsRead | Permission::OrganizationsManage => "organizations",
            Permission::AuthorizationCodesManage => "authorization_codes",
            Permission::ProvidersManage => "providers",
            Permission::AuditRead => "audit",
            Permission::SecurityManage => "security",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Permission::AdminRead => "Read admin console",
            Permission::SettingsManage => "Manage runtime settings",
            Permission::UsersRead => "Read users",
            Permission::UsersManage => "Manage users",
            Permission::ClientsRead => "Read OIDC clients",
            Permission::ClientsManage => "Manage OIDC clients",
            Permission::IapRead => "Read IAP applications",
            Permission::IapManage => "Manage IAP applications",
            Permission::OrganizationsRead => "Read organizations",
            Permission::OrganizationsManage => "Manage organizations",
            Permission::AuthorizationCodesManage => "Manage authorization codes",
            Permission::ProvidersManage => "Manage external OIDC providers",
            Permission::AuditRead => "Read audit events",
            Permission::SecurityManage => "Manage roles and groups",
        }
    }

    pub fn info(self) -> PermissionInfo {
        PermissionInfo {
            key: self.as_str(),
            category: self.category(),
            label: self.label(),
        }
    }
}

pub fn permission_catalog() -> Vec<PermissionInfo> {
    Permission::ALL
        .iter()
        .copied()
        .map(Permission::info)
        .collect()
}

pub fn user_can_hold_permissions(user: &UserRecord) -> bool {
    user.is_active == 1 && user.archived_at.is_none()
}

impl TryFrom<&str> for Permission {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "admin.read" => Ok(Permission::AdminRead),
            "settings.manage" => Ok(Permission::SettingsManage),
            "users.read" => Ok(Permission::UsersRead),
            "users.manage" => Ok(Permission::UsersManage),
            "clients.read" => Ok(Permission::ClientsRead),
            "clients.manage" => Ok(Permission::ClientsManage),
            "iap.read" => Ok(Permission::IapRead),
            "iap.manage" => Ok(Permission::IapManage),
            "organizations.read" => Ok(Permission::OrganizationsRead),
            "organizations.manage" => Ok(Permission::OrganizationsManage),
            "authorization_codes.manage" => Ok(Permission::AuthorizationCodesManage),
            "providers.manage" => Ok(Permission::ProvidersManage),
            "audit.read" => Ok(Permission::AuditRead),
            "security.manage" => Ok(Permission::SecurityManage),
            other => Err(AppError::BadRequest(format!("unknown permission: {other}"))),
        }
    }
}

pub trait Authorizer {
    fn has_permission(
        &self,
        user: &UserRecord,
        permission: Permission,
    ) -> impl Future<Output = AppResult<bool>> + Send;

    fn require_permission(
        &self,
        user: &UserRecord,
        permission: Permission,
    ) -> impl Future<Output = AppResult<()>> + Send
    where
        Self: Sync,
    {
        async move {
            if self.has_permission(user, permission).await? {
                Ok(())
            } else {
                Err(AppError::Forbidden)
            }
        }
    }

    fn has_any_permission(
        &self,
        user: &UserRecord,
        permissions: &[Permission],
    ) -> impl Future<Output = AppResult<bool>> + Send
    where
        Self: Sync,
    {
        async move {
            for permission in permissions {
                if self.has_permission(user, *permission).await? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }

    fn require_any_permission(
        &self,
        user: &UserRecord,
        permissions: &[Permission],
    ) -> impl Future<Output = AppResult<()>> + Send
    where
        Self: Sync,
    {
        async move {
            if self.has_any_permission(user, permissions).await? {
                Ok(())
            } else {
                Err(AppError::Forbidden)
            }
        }
    }
}

impl Authorizer for Db {
    fn has_permission(
        &self,
        user: &UserRecord,
        permission: Permission,
    ) -> impl Future<Output = AppResult<bool>> + Send {
        async move {
            if !user_can_hold_permissions(user) {
                return Ok(false);
            }
            if user.is_admin == 1 {
                return Ok(true);
            }
            let permissions = self.list_effective_permissions(&user.id).await?;
            Ok(permissions.iter().any(|item| item == permission.as_str()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(is_active: i32, archived_at: Option<i64>) -> UserRecord {
        UserRecord {
            id: "user-id".to_string(),
            email: "user@example.com".to_string(),
            username: "user".to_string(),
            display_name: None,
            phone: None,
            password_hash: "hash".to_string(),
            email_verified_at: None,
            phone_verified_at: None,
            is_admin: 1,
            is_active,
            archived_at,
            last_login_at: None,
            last_login_ip: None,
            last_oidc_client_id: None,
            last_login_method: None,
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn archived_or_disabled_users_cannot_hold_permissions() {
        assert!(user_can_hold_permissions(&user(1, None)));
        assert!(!user_can_hold_permissions(&user(0, None)));
        assert!(!user_can_hold_permissions(&user(1, Some(100))));
    }
}
