use crate::{
    Settings,
    db::{Db, RuntimeSettingsRecord},
    error::AppResult,
    jwt::JwtManager,
    util,
};
use axum::http::HeaderMap;
use std::net::SocketAddr;

#[derive(Clone)]
pub struct AppState {
    pub settings: Settings,
    pub db: Db,
    pub jwt: JwtManager,
}

impl AppState {
    pub async fn runtime_settings(&self) -> AppResult<RuntimeSettingsRecord> {
        self.db.runtime_settings().await
    }

    pub async fn effective_public_base_url(&self, headers: &HeaderMap) -> AppResult<String> {
        let runtime = self.runtime_settings().await?;
        Ok(util::external_base_url_for(
            runtime.trust_proxy_headers == 1,
            headers,
            &runtime.public_base_url,
        ))
    }

    pub async fn effective_issuer(&self, headers: &HeaderMap) -> AppResult<String> {
        let runtime = self.runtime_settings().await?;
        Ok(util::external_base_url_for(
            runtime.trust_proxy_headers == 1,
            headers,
            &runtime.issuer,
        ))
    }

    pub async fn accepted_issuers(&self, headers: &HeaderMap) -> AppResult<Vec<String>> {
        let runtime = self.runtime_settings().await?;
        let effective =
            util::external_base_url_for(runtime.trust_proxy_headers == 1, headers, &runtime.issuer);
        let mut issuers = vec![effective, runtime.issuer, self.settings.oidc.issuer.clone()];
        issuers.iter_mut().for_each(|value| {
            *value = value.trim_end_matches('/').to_string();
        });
        issuers.sort();
        issuers.dedup();
        Ok(issuers)
    }

    pub async fn request_ip(
        &self,
        headers: &HeaderMap,
        remote_addr: Option<SocketAddr>,
    ) -> AppResult<Option<String>> {
        let runtime = self.runtime_settings().await?;
        Ok(util::request_ip_for(
            runtime.trust_proxy_headers == 1,
            headers,
            remote_addr,
        ))
    }
}
