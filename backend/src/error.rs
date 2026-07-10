use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("database error: {0}")]
    Database(String),
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("oidc error: {0}")]
    Oidc(String),
    #[error("{error}: {description}")]
    OAuth {
        error: String,
        description: String,
        status: StatusCode,
    },
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

impl AppError {
    pub fn oauth(error: &str, description: &str, status: StatusCode) -> Self {
        Self::OAuth {
            error: error.to_string(),
            description: description.to_string(),
            status,
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) | AppError::Oidc(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden => StatusCode::FORBIDDEN,
            AppError::NotFound => StatusCode::NOT_FOUND,
            AppError::OAuth { status, .. } => *status,
            AppError::Database(_) | AppError::Configuration(_) | AppError::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    pub fn oauth_error(&self) -> String {
        match self {
            AppError::Unauthorized => "invalid_client".to_string(),
            AppError::Forbidden => "access_denied".to_string(),
            AppError::BadRequest(_) | AppError::Oidc(_) => "invalid_request".to_string(),
            AppError::NotFound => "invalid_request".to_string(),
            AppError::OAuth { error, .. } => error.clone(),
            AppError::Database(_) | AppError::Configuration(_) | AppError::Internal(_) => {
                "server_error".to_string()
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let error_description = match &self {
            AppError::OAuth { description, .. } => Some(description.clone()),
            _ => None,
        };
        let message = match &self {
            AppError::OAuth { description, .. } => description.clone(),
            _ => self.to_string(),
        };
        let body = ErrorBody {
            error: self.oauth_error(),
            message,
            error_description,
        };
        (status, Json(body)).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        AppError::Internal(value.to_string())
    }
}

impl From<diesel::result::Error> for AppError {
    fn from(value: diesel::result::Error) -> Self {
        match value {
            diesel::result::Error::NotFound => AppError::NotFound,
            other => AppError::Database(other.to_string()),
        }
    }
}

impl From<diesel::r2d2::PoolError> for AppError {
    fn from(value: diesel::r2d2::PoolError) -> Self {
        AppError::Database(value.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;
