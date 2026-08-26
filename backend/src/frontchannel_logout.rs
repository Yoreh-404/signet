use crate::{
    AppState,
    db::{ClientRecord, UserRecord},
    error::{AppError, AppResult},
    html::escape as html_escape,
};
use axum::response::Html;
use serde::Serialize;
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct FrontchannelLogoutFrame {
    pub client_id: String,
    pub uri: String,
}

pub fn validate_frontchannel_logout_config(
    uri: &str,
    session_required: bool,
    redirect_uris: &[String],
) -> AppResult<String> {
    let uri = validate_frontchannel_logout_uri(uri, redirect_uris)?;
    if session_required && uri.is_empty() {
        return Err(AppError::BadRequest(
            "frontchannel_logout_uri is required when frontchannel_logout_session_required is true"
                .to_string(),
        ));
    }
    Ok(uri)
}

pub fn validate_frontchannel_logout_uri(uri: &str, redirect_uris: &[String]) -> AppResult<String> {
    let uri = uri.trim();
    if uri.is_empty() {
        return Ok(String::new());
    }
    let parsed = parse_http_url(uri, "frontchannel_logout_uri")?;
    if parsed.fragment().is_some() {
        return Err(AppError::BadRequest(
            "frontchannel_logout_uri cannot contain a fragment".to_string(),
        ));
    }
    let redirect_origins = redirect_uris
        .iter()
        .filter_map(|redirect_uri| parse_http_url(redirect_uri, "redirect_uri").ok())
        .collect::<Vec<_>>();
    if redirect_origins.is_empty()
        || !redirect_origins
            .iter()
            .any(|redirect| same_origin(&parsed, redirect))
    {
        return Err(AppError::BadRequest(
            "frontchannel_logout_uri must share scheme, host, and port with a registered redirect_uri"
                .to_string(),
        ));
    }
    Ok(uri.to_string())
}

pub async fn frames_for_user(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    user: &UserRecord,
    sid: &str,
) -> AppResult<Vec<FrontchannelLogoutFrame>> {
    let clients = state
        .db
        .list_frontchannel_logout_clients_for_user(&user.id)
        .await?;
    if clients.is_empty() {
        return Ok(Vec::new());
    }
    let issuer = state.effective_issuer(headers).await?;
    clients
        .into_iter()
        .filter_map(|client| frame_for_client(&issuer, sid, &client).transpose())
        .collect()
}

pub fn frame_for_client(
    issuer: &str,
    sid: &str,
    client: &ClientRecord,
) -> AppResult<Option<FrontchannelLogoutFrame>> {
    if client.frontchannel_logout_uri.trim().is_empty() {
        return Ok(None);
    }
    let mut uri = parse_http_url(&client.frontchannel_logout_uri, "frontchannel_logout_uri")?;
    if client.frontchannel_logout_session_required == 1 {
        uri.query_pairs_mut()
            .append_pair("iss", issuer.trim_end_matches('/'))
            .append_pair("sid", sid);
    }
    Ok(Some(FrontchannelLogoutFrame {
        client_id: client.client_id.clone(),
        uri: uri.to_string(),
    }))
}

pub fn logout_page(frames: &[FrontchannelLogoutFrame], redirect_to: &str) -> Html<String> {
    let iframe_html = frames
        .iter()
        .map(|frame| {
            format!(
                r#"<iframe src="{}" title="{}" style="display:none;width:0;height:0;border:0"></iframe>"#,
                html_escape(&frame.uri),
                html_escape(&frame.client_id),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let redirect_json = serde_json::to_string(redirect_to).unwrap_or_else(|_| "\"/\"".to_string());
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta http-equiv="refresh" content="1;url={redirect_attr}" />
  <title>Signing out</title>
</head>
<body>
  {iframe_html}
  <script>
    window.setTimeout(function () {{
      window.location.replace({redirect_json});
    }}, 800);
  </script>
</body>
</html>"#,
        redirect_attr = html_escape(redirect_to)
    ))
}

fn parse_http_url(value: &str, field: &str) -> AppResult<Url> {
    let parsed =
        Url::parse(value).map_err(|_| AppError::BadRequest(format!("{field} must be absolute")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(AppError::BadRequest(format!(
            "{field} must use http or https"
        )));
    }
    Ok(parsed)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str().map(str::to_ascii_lowercase)
            == right.host_str().map(str::to_ascii_lowercase)
        && left.port_or_known_default() == right.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redirects() -> Vec<String> {
        vec!["https://app.example/callback".to_string()]
    }

    #[test]
    fn accepts_same_origin_logout_uri() {
        assert_eq!(
            validate_frontchannel_logout_uri("https://app.example/logout", &redirects()).unwrap(),
            "https://app.example/logout"
        );
    }

    #[test]
    fn rejects_cross_origin_or_fragmented_uri() {
        assert!(
            validate_frontchannel_logout_uri("https://other.example/logout", &redirects()).is_err()
        );
        assert!(
            validate_frontchannel_logout_uri("https://app.example/logout#frag", &redirects())
                .is_err()
        );
        assert!(validate_frontchannel_logout_uri("/logout", &redirects()).is_err());
    }

    #[test]
    fn session_required_needs_uri() {
        assert!(validate_frontchannel_logout_config("", false, &redirects()).is_ok());
        assert!(validate_frontchannel_logout_config("", true, &redirects()).is_err());
    }
}
