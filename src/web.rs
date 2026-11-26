use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/"]
pub struct Assets;

fn versioned_index(html: &str, version: &str) -> String {
    html.replace("src=\"app.js\"", &format!("src=\"app.js?v={version}\""))
}

pub async fn index() -> Response {
    match Assets::get("index.html") {
        Some(f) => (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
            ],
            versioned_index(&String::from_utf8_lossy(&f.data), env!("CARGO_PKG_VERSION")),
        )
            .into_response(),
        None => (StatusCode::INTERNAL_SERVER_ERROR, "index.html missing").into_response(),
    }
}

pub async fn login_page() -> Response {
    match Assets::get("login.html") {
        Some(f) => (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
            ],
            String::from_utf8_lossy(&f.data).to_string(),
        )
            .into_response(),
        None => (StatusCode::INTERNAL_SERVER_ERROR, "login.html missing").into_response(),
    }
}

pub async fn asset(Path(path): Path<String>) -> Response {
    let path = path.trim_start_matches('/');
    if path.contains("..") {
        return (StatusCode::NOT_FOUND, "not found");
    }
    match Assets::get(path) {
        Some(f) => {
            let mime = if path.ends_with(".js") {
                "text/javascript; charset=utf-8"
            } else if path.ends_with(".css") {
                "text/css; charset=utf-8"
            } else if path.ends_with(".html") {
                "text/html; charset=utf-8"
            } else if path.ends_with(".svg") {
                "image/svg+xml"
            } else {
                "application/octet-stream"
            };
            (
                [
                    (header::CONTENT_TYPE, mime),
                    (header::CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
                ],
                f.data.into_owned(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_uses_versioned_script_url() {
        let html = versioned_index("<script src=\"app.js\"></script>", "0.0.6");
        assert!(html.contains("app.js?v=0.0.6"));
        assert!(!html.contains("src=\"app.js\""));
    }
}
