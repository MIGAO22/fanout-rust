use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

pub async fn exits() -> impl IntoResponse {
    Json(json!({
        "exits": [],
        "public_ip": "",
        "backend": "native",
        "panel_info": "fanout-rust 自建 Xray",
        "warp": {
            "enabled": false, "ready": false, "reason": "Rust 版正在移植",
            "need_tools": false, "pkg_cmd": "", "version": "", "count": 0,
            "live": 0, "stale": 0
        }
    }))
}

pub async fn nodes() -> impl IntoResponse {
    Json(json!({
        "available": false,
        "fetched": false,
        "nodes": [],
        "residential_only": true,
        "total": 0
    }))
}

pub async fn regions() -> impl IntoResponse {
    Json(json!([]))
}

pub async fn pools() -> impl IntoResponse {
    Json(json!({"pools": [], "modes": [], "rr_step": 5, "max_hosts": 32}))
}

pub async fn jobs() -> impl IntoResponse {
    Json(json!([]))
}

pub async fn warp() -> impl IntoResponse {
    Json(json!({
        "enabled": false, "ready": false, "reason": "Rust 版正在移植",
        "need_tools": false, "pkg_cmd": "", "version": "", "count": 0,
        "live": 0, "stale": 0
    }))
}

pub async fn stats() -> impl IntoResponse {
    Json(json!({}))
}

pub async fn client_status() -> impl IntoResponse {
    Json(json!({
        "xray": {"installed": false, "version": "", "managed": false, "reason": ""},
        "openvpn": {"installed": false, "version": "", "managed": true, "reason": ""},
        "warp": {"version": "", "count": 0}
    }))
}

pub async fn xui_status() -> impl IntoResponse {
    Json(json!({"available": false, "kind": "native", "reason": "Rust 版正在移植"}))
}

pub async fn not_implemented() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"error": "Rust 版正在移植"})),
    )
}

pub async fn ok() -> impl IntoResponse {
    Json(json!({"ok": true}))
}

pub async fn health() -> impl IntoResponse {
    Json(json!({"ok": true, "version": env!("CARGO_PKG_VERSION"), "name": "fanout-rust"}))
}
