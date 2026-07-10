use axum::{
    body::Body,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};

include!(concat!(env!("OUT_DIR"), "/frontend_assets.rs"));

pub async fn serve(uri: Uri) -> Response {
    let path = requested_path(uri.path());
    if path == "__invalid__" || path.starts_with("api/") || path.starts_with("oauth2/") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }

    let asset = find_asset(&path).or_else(|| {
        if path.contains('.') {
            None
        } else {
            find_asset("index.html")
        }
    });

    let Some(asset) = asset else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };

    let cache_control = if asset.path == "index.html" {
        "no-cache"
    } else {
        "public, max-age=31536000, immutable"
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, asset.mime)
        .header(header::CACHE_CONTROL, cache_control)
        .body(Body::from(asset.bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn requested_path(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        "index.html".to_string()
    } else if trimmed
        .split('/')
        .any(|segment| segment == ".." || segment == ".")
    {
        "__invalid__".to_string()
    } else {
        trimmed.to_string()
    }
}

fn find_asset(path: &str) -> Option<&'static EmbeddedAsset> {
    ASSETS.iter().find(|asset| asset.path == path)
}
