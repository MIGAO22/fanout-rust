use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};

use crate::{
    appstate::AppState,
    config::ConnSettings,
    manager::{Manager, ProvisionRequest},
    models::{ExitsView, WarpOverview},
};

pub fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({"error": msg.into()}))).into_response()
}

fn internal(e: impl std::fmt::Display) -> Response {
    error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

pub async fn health() -> impl IntoResponse {
    Json(json!({"ok": true, "version": env!("CARGO_PKG_VERSION"), "name": "fanout-rust"}))
}

pub async fn exits(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let m = &state.manager;
    Json(ExitsView {
        exits: m.exits().await,
        direct: Vec::new(),
        pools: Vec::new(),
        panel: Vec::new(),
        backend: "native".into(),
        panel_info: "fanout-rust 自建 Xray".into(),
        public_ip: crate::publicip::host_public_ip(),
        warp: WarpOverview::default(),
    })
}

pub async fn tunnels(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let m = &state.manager;
    Json(m.states().await)
}

#[derive(Deserialize)]
pub struct NodesQuery {
    pub all: Option<String>,
}

pub async fn nodes(
    State(state): State<Arc<AppState>>,
    Query(q): Query<NodesQuery>,
) -> impl IntoResponse {
    let m = &state.manager;
    let all = q.all.as_deref() == Some("1");
    let (nodes, fetched) = m.node_list(all).await;
    let total = nodes.len();
    Json(json!({
        "available": fetched,
        "fetched": fetched,
        "nodes": nodes,
        "residential_only": m.settings().await.residential_only(),
        "total": total
    }))
}

pub async fn regions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let m = &state.manager;
    Json(m.regions().await)
}

#[derive(Deserialize)]
pub struct HostQuery {
    pub host: String,
}

pub async fn start(State(state): State<Arc<AppState>>, Query(q): Query<HostQuery>) -> Response {
    let m = &state.manager;
    let nodes = m.node_list(true).await.0;
    let Some(node) = nodes.into_iter().find(|n| n.hostname == q.host) else {
        return error(StatusCode::NOT_FOUND, "节点不存在");
    };
    match m.start(node).await {
        Ok(t) => Json(t.state().await).into_response(),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub struct SlotQuery {
    pub slot: usize,
}

pub async fn stop(State(state): State<Arc<AppState>>, Query(q): Query<SlotQuery>) -> Response {
    let m = &state.manager;
    match m.stop(q.slot).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => error(StatusCode::NOT_FOUND, e.to_string()),
    }
}

pub async fn swap(State(state): State<Arc<AppState>>, Query(q): Query<SlotQuery>) -> Response {
    let m = &state.manager;
    match m.swap(q.slot).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => error(StatusCode::CONFLICT, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct CredQuery {
    pub slot: usize,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub pass: String,
}

pub async fn cred(State(state): State<Arc<AppState>>, Query(q): Query<CredQuery>) -> Response {
    let m = &state.manager;
    match m.set_cred(q.slot, q.user, q.pass).await {
        Ok(c) => Json(json!({"user": c.user, "pass": c.pass})).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

pub async fn refresh(State(state): State<Arc<AppState>>) -> Response {
    let m = &state.manager;
    match m.refresh_nodes().await {
        Ok(n) => Json(json!({"count": n})).into_response(),
        Err(e) => error(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct ProvisionQuery {
    pub count: usize,
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub template: usize,
    #[serde(default)]
    pub every: String,
}

pub async fn provision(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ProvisionQuery>,
) -> Response {
    let m = &state.manager;
    let req = ProvisionRequest {
        region: q.region,
        count: q.count,
        template_id: q.template,
        every_region: q.every == "1",
    };
    match m.provision(req).await {
        Ok(job) => Json(json!({"job": job.id()})).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

pub async fn jobs(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let m = &state.manager;
    Json(m.jobs.views().await)
}

#[derive(Deserialize)]
pub struct JobQuery {
    pub id: String,
}

pub async fn job_dismiss(
    State(state): State<Arc<AppState>>,
    Query(q): Query<JobQuery>,
) -> impl IntoResponse {
    let m = &state.manager;
    m.jobs.dismiss(&q.id).await;
    Json(json!({"ok": true}))
}

pub async fn pools() -> impl IntoResponse {
    Json(json!({"pools": [], "modes": [], "rr_step": 5, "max_hosts": 32}))
}

pub async fn warp() -> impl IntoResponse {
    Json(WarpOverview::default())
}

pub async fn stats(State(state): State<Arc<AppState>>) -> Response {
    match crate::hoststats::read_host_stats(&state.dir) {
        Ok(s) => Json(s).into_response(),
        Err(e) => internal(e),
    }
}

pub async fn client_status() -> impl IntoResponse {
    Json(json!({
        "backend": "native", "path": "", "current": "", "openvpn": "", "latest": "",
        "has_update": false, "updatable": false, "openvpn_updatable": false,
        "openvpn_has_update": false, "warp_enabled": false, "warp_ready": false,
        "warp_need_tools": false, "warp_has_update": false, "warp_count": 0,
        "warp_stale": 0, "warp_can_apply": false
    }))
}

pub async fn xui_status() -> impl IntoResponse {
    Json(json!({"available": false, "kind": "native", "reason": "Rust 版正在移植"}))
}

pub async fn not_implemented() -> impl IntoResponse {
    error(StatusCode::NOT_IMPLEMENTED, "Rust 版正在移植")
}

pub async fn ok() -> impl IntoResponse {
    Json(json!({"ok": true}))
}

pub async fn sub() -> impl IntoResponse {
    error(StatusCode::NOT_IMPLEMENTED, "Rust 版正在移植")
}

#[derive(Deserialize)]
pub struct SettingsReq {
    pub password: Option<String>,
    pub base_path: Option<String>,
    pub port: Option<u16>,
    pub listen_addr: Option<String>,
    pub residential_only: Option<bool>,
    pub conn: Option<ConnSettings>,
}

pub async fn settings(
    State(state): State<Arc<AppState>>,
    body: Option<Json<SettingsReq>>,
) -> Response {
    if let Some(Json(req)) = body {
        let mut next = state.manager.settings().await;
        if let Some(p) = req.password.filter(|p| !p.is_empty()) {
            if let Err(e) = state.auth.set_password(&p).await {
                return error(StatusCode::BAD_REQUEST, e.to_string());
            }
        }
        if let Some(p) = req.port {
            next.port = p;
        }
        if let Some(a) = req.listen_addr {
            match crate::config::normalize_listen_addr(&a) {
                Ok(a) => next.listen_addr = a,
                Err(e) => return error(StatusCode::BAD_REQUEST, e.to_string()),
            }
        }
        if let Some(v) = req.residential_only {
            next.residential_only = Some(v);
        }
        if let Some(c) = req.conn {
            next.conn = c;
        }
        if let Err(e) = state.manager.update_settings(next).await {
            return internal(e);
        }
        if req.base_path.is_some() {
            return error(StatusCode::CONFLICT, "访问路径改动需要重启服务后生效");
        }
    }
    let s = state.manager.settings().await;
    Json(json!({
        "base_path": state.basepath,
        "port": s.port,
        "listen_addr": s.listen_addr,
        "has_password": true,
        "residential_only": s.residential_only(),
        "conn": s.conn,
        "version": env!("CARGO_PKG_VERSION")
    }))
    .into_response()
}

fn req_host(headers: &HeaderMap) -> String {
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:8899")
        .to_string()
}

pub async fn sub_info(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match crate::sub::sub_token(&state.dir) {
        Ok(token) => {
            let path = crate::sub::sub_path(&token);
            Json(json!({"token": token, "path": path, "url": format!("http://{}{}", req_host(&headers), path)})).into_response()
        }
        Err(e) => internal(e),
    }
}

pub async fn sub_reset(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match crate::sub::reset_sub_token(&state.dir) {
        Ok(token) => {
            let path = crate::sub::sub_path(&token);
            Json(json!({"token": token, "path": path, "url": format!("http://{}{}", req_host(&headers), path)})).into_response()
        }
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub struct SubQuery {
    pub token: String,
    pub target: Option<String>,
    pub host: Option<String>,
    pub bound: Option<String>,
}

pub async fn subscription(
    State(state): State<Arc<AppState>>,
    Query(q): Query<SubQuery>,
) -> Response {
    let expected = match crate::sub::sub_token(&state.dir) {
        Ok(t) => t,
        Err(e) => return internal(e),
    };
    if q.token != expected {
        return error(StatusCode::NOT_FOUND, "not found");
    }
    let links: Vec<String> = Vec::new();
    match crate::sub::encode_sub(&links, q.target.as_deref().unwrap_or("base64")) {
        Ok(body) => {
            let mut h = HeaderMap::new();
            h.insert(
                header::CONTENT_TYPE,
                "text/plain; charset=utf-8".parse().unwrap(),
            );
            h.insert(
                axum::http::HeaderName::from_static("profile-update-interval"),
                "12".parse().unwrap(),
            );
            (h, body).into_response()
        }
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

pub async fn update_check() -> impl IntoResponse {
    Json(json!({
        "current": env!("CARGO_PKG_VERSION"),
        "latest": env!("CARGO_PKG_VERSION"),
        "has_update": false,
        "notes": "",
        "url": "https://github.com/MIGAO22/fanout-rust/releases/latest"
    }))
}

pub type SharedManager = Arc<Manager>;
pub type EmptyQuery = HashMap<String, String>;
