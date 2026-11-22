use crate::{
    db::{ClientClaimMapperRecord, ClientRecord, UserRecord},
    error::{AppError, AppResult},
};
use serde_json::{Map, Number, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimOutputTarget {
    IdToken,
    AccessToken,
    UserInfo,
}

pub struct ClaimContext<'a> {
    pub user: &'a UserRecord,
    pub client: &'a ClientRecord,
    pub scope: &'a str,
}

pub trait ClaimMapper {
    fn claim_name(&self) -> &str;
    fn is_active(&self) -> bool;
    fn includes_target(&self, target: ClaimOutputTarget) -> bool;
    fn map_claim(&self, context: &ClaimContext<'_>) -> AppResult<Option<Value>>;
}

impl ClaimMapper for ClientClaimMapperRecord {
    fn claim_name(&self) -> &str {
        &self.claim_name
    }

    fn is_active(&self) -> bool {
        self.is_active == 1
    }

    fn includes_target(&self, target: ClaimOutputTarget) -> bool {
        match target {
            ClaimOutputTarget::IdToken => self.include_in_id_token == 1,
            ClaimOutputTarget::AccessToken => self.include_in_access_token == 1,
            ClaimOutputTarget::UserInfo => self.include_in_userinfo == 1,
        }
    }

    fn map_claim(&self, context: &ClaimContext<'_>) -> AppResult<Option<Value>> {
        match self.source.as_str() {
            "user_field" => user_field_claim(context.user, &self.source_value),
            "static" => static_claim(&self.source_value, &self.value_type).map(Some),
            "scope" => scope_claim(context.scope, &self.source_value),
            "client" => client_claim(context.client, &self.source_value),
            _ => Err(AppError::BadRequest(format!(
                "unsupported claim mapper source: {}",
                self.source
            ))),
        }
    }
}

pub fn mapped_claims(
    records: &[ClientClaimMapperRecord],
    context: &ClaimContext<'_>,
    target: ClaimOutputTarget,
) -> AppResult<Map<String, Value>> {
    let mut claims = Map::new();
    for record in records {
        validate_mapper_record(record)?;
        if !record.is_active() || !record.includes_target(target) {
            continue;
        }
        if let Some(value) = record.map_claim(context)? {
            claims.insert(record.claim_name().to_string(), value);
        }
    }
    Ok(claims)
}

pub fn validate_mapper_record(record: &ClientClaimMapperRecord) -> AppResult<()> {
    validate_claim_name(&record.claim_name)?;
    validate_source(&record.source, &record.source_value, &record.value_type)?;
    if record.include_in_id_token != 1
        && record.include_in_access_token != 1
        && record.include_in_userinfo != 1
    {
        return Err(AppError::BadRequest(
            "claim mapper must target at least one output".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_claim_name(name: &str) -> AppResult<()> {
    let value = name.trim();
    if value.is_empty() || value.len() > 128 {
        return Err(AppError::BadRequest(
            "claim name must be 1-128 characters".to_string(),
        ));
    }
    if value
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '\'' | '\\' | '{' | '}' | '[' | ']'))
    {
        return Err(AppError::BadRequest(
            "claim name contains unsupported characters".to_string(),
        ));
    }
    if STRUCTURAL_RESERVED_CLAIMS
        .iter()
        .any(|reserved| reserved == &value)
    {
        return Err(AppError::BadRequest(format!(
            "claim name is reserved: {value}"
        )));
    }
    Ok(())
}

pub fn validate_source(source: &str, source_value: &str, value_type: &str) -> AppResult<()> {
    match source {
        "user_field" => {
            if user_field_names()
                .iter()
                .any(|field| field == &source_value)
            {
                Ok(())
            } else {
                Err(AppError::BadRequest(format!(
                    "unsupported user field claim source: {source_value}"
                )))
            }
        }
        "static" => {
            static_claim(source_value, value_type)?;
            Ok(())
        }
        "scope" => {
            if source_value.split_whitespace().count() == 1 && !source_value.trim().is_empty() {
                Ok(())
            } else {
                Err(AppError::BadRequest(
                    "scope mapper source_value must be one scope".to_string(),
                ))
            }
        }
        "client" => {
            if client_field_names()
                .iter()
                .any(|field| field == &source_value)
            {
                Ok(())
            } else {
                Err(AppError::BadRequest(format!(
                    "unsupported client field claim source: {source_value}"
                )))
            }
        }
        _ => Err(AppError::BadRequest(format!(
            "unsupported claim mapper source: {source}"
        ))),
    }
}

fn user_field_claim(user: &UserRecord, field: &str) -> AppResult<Option<Value>> {
    let value = match field {
        "id" => Some(Value::String(user.id.clone())),
        "email" => Some(Value::String(user.email.clone())),
        "username" => Some(Value::String(user.username.clone())),
        "display_name" => user.display_name.clone().map(Value::String),
        "phone" => user.phone.clone().map(Value::String),
        "email_verified" => Some(Value::Bool(user.email_verified_at.is_some())),
        "phone_verified" => Some(Value::Bool(user.phone_verified_at.is_some())),
        "is_admin" => Some(Value::Bool(user.is_admin == 1)),
        "is_active" => Some(Value::Bool(user.is_active == 1)),
        "created_at" => Some(Value::Number(Number::from(user.created_at))),
        "updated_at" => Some(Value::Number(Number::from(user.updated_at))),
        "last_login_at" => user.last_login_at.map(Number::from).map(Value::Number),
        "last_login_ip" => user.last_login_ip.clone().map(Value::String),
        "last_oidc_client_id" => user.last_oidc_client_id.clone().map(Value::String),
        "last_login_method" => user.last_login_method.clone().map(Value::String),
        _ => {
            return Err(AppError::BadRequest(format!(
                "unsupported user field claim source: {field}"
            )));
        }
    };
    Ok(value)
}

fn client_claim(client: &ClientRecord, field: &str) -> AppResult<Option<Value>> {
    let value = match field {
        "client_id" => Value::String(client.client_id.clone()),
        "client_name" => Value::String(client.client_name.clone()),
        _ => {
            return Err(AppError::BadRequest(format!(
                "unsupported client field claim source: {field}"
            )));
        }
    };
    Ok(Some(value))
}

fn static_claim(source_value: &str, value_type: &str) -> AppResult<Value> {
    match value_type {
        "string" => Ok(Value::String(source_value.to_string())),
        "bool" => bool_value(source_value).map(Value::Bool),
        "number" => number_value(source_value).map(Value::Number),
        "json" => serde_json::from_str(source_value).map_err(|err| {
            AppError::BadRequest(format!("static JSON claim value is invalid: {err}"))
        }),
        _ => Err(AppError::BadRequest(format!(
            "unsupported claim mapper value_type: {value_type}"
        ))),
    }
}

fn scope_claim(scope: &str, required_scope: &str) -> AppResult<Option<Value>> {
    validate_source("scope", required_scope, "bool")?;
    Ok(Some(Value::Bool(
        scope
            .split_whitespace()
            .any(|value| value == required_scope.trim()),
    )))
}

fn bool_value(value: &str) -> AppResult<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(AppError::BadRequest(
            "boolean claim value must be true or false".to_string(),
        )),
    }
}

fn number_value(value: &str) -> AppResult<Number> {
    let trimmed = value.trim();
    if let Ok(integer) = trimmed.parse::<i64>() {
        return Ok(Number::from(integer));
    }
    let float = trimmed.parse::<f64>().map_err(|_| {
        AppError::BadRequest("number claim value must be a valid number".to_string())
    })?;
    Number::from_f64(float)
        .ok_or_else(|| AppError::BadRequest("number claim value must be finite".to_string()))
}

pub fn user_field_names() -> &'static [&'static str] {
    &[
        "id",
        "email",
        "username",
        "display_name",
        "phone",
        "email_verified",
        "phone_verified",
        "is_admin",
        "is_active",
        "created_at",
        "updated_at",
        "last_login_at",
        "last_login_ip",
        "last_oidc_client_id",
        "last_login_method",
    ]
}

pub fn client_field_names() -> &'static [&'static str] {
    &["client_id", "client_name"]
}

const STRUCTURAL_RESERVED_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "token_use",
    "client_id",
    "scope",
    "email",
    "name",
    "preferred_username",
    "nonce",
    "auth_time",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_claims_are_rejected() {
        assert!(validate_claim_name("sub").is_err());
        assert!(validate_claim_name("email_verified").is_ok());
        assert!(validate_claim_name("x-company-role").is_ok());
    }

    #[test]
    fn static_claims_parse_types() {
        assert_eq!(static_claim("true", "bool").unwrap(), Value::Bool(true));
        assert_eq!(
            static_claim("{\"team\":\"ops\"}", "json").unwrap()["team"],
            "ops"
        );
        assert!(static_claim("nan", "number").is_err());
    }
}
