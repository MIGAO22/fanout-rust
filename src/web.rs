use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "web/"]
pub struct Assets;

pub async fn index() -> Response {
    match Assets::get("index.html") {
        Some(f) => (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            f.data.into_owned(),
        )
            .into_response(),
        None => (StatusCode::INTERNAL_SERVER_ERROR, "index.html missing").into_response(),
    }
}

pub async fn login_page() -> Html<String> {
    match Assets::get("login.html") {
        Some(f) => Html(String::from_utf8_lossy(&f.data).to_string()),
        None => Html("<h1>fanout-rust</h1><p>login.html missing</p>".into()),
    }
}

pub async fn asset(Path(path): Path<String>) -> Response {
    let path = path.trim_start_matches('/');
    if path.contains("..") {
        return (StatusCode::NOT_FOUND, "not found").into_response();
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
            ([(header::CONTENT_TYPE, mime)], f.data.into_owned()).into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}
