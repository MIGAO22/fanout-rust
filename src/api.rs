use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
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
    let panel = state.panel.status().await;
    Json(ExitsView {
        exits: m.exits().await,
        direct: Vec::new(),
        pools: state.pools.views().await,
        panel: Vec::new(),
        backend: panel.kind.unwrap_or_else(|| "native".into()),
        panel_info: panel.describe.unwrap_or_default(),
        public_ip: crate::publicip::host_public_ip(),
        warp: warp_overview(&state).await,
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

pub async fn pools(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let modes: Vec<_> = crate::models::POOL_MODES
        .iter()
        .map(|mode| {
            json!({
                "mode": mode,
                "label": crate::models::pool_mode_label(mode),
                "desc": crate::models::pool_mode_desc(mode)
            })
        })
        .collect();
    Json(json!({
        "pools": state.pools.views().await,
        "modes": modes,
        "rr_step": crate::models::POOL_DEFAULT_RR_STEP,
        "max_hosts": crate::models::POOL_MAX_HOSTS
    }))
}

#[derive(Deserialize)]
pub struct PoolSaveReq {
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub mode: String,
    #[serde(default)]
    pub rr_step: usize,
    pub hosts: Vec<String>,
    #[serde(default)]
    pub auto_fill: bool,
    #[serde(default)]
    pub size: usize,
}

pub async fn pool_save(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PoolSaveReq>,
) -> Response {
    let pool = crate::models::Pool {
        id: req.id,
        name: req.name,
        mode: req.mode,
        hosts: req.hosts,
        rr_step: req.rr_step,
        port: 0,
        cred: crate::models::SocksCred::default(),
        auto_fill: req.auto_fill,
        size: req.size,
    };
    match state.pools.set_pool(pool).await {
        Ok(p) => Json(json!({"id": p.id, "name": p.name})).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct PoolDeleteReq {
    pub id: String,
}

pub async fn pool_delete(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PoolDeleteReq>,
) -> Response {
    match state.pools.delete_pool(&req.id).await {
        Ok(()) => Json(json!({"ok": true, "unbound": []})).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct PoolCredReq {
    pub id: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub pass: String,
}

pub async fn pool_cred(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PoolCredReq>,
) -> Response {
    match state
        .pools
        .set_cred(
            &req.id,
            crate::models::SocksCred {
                user: req.user,
                pass: req.pass,
            },
        )
        .await
    {
        Ok(c) => Json(json!({"user": c.user, "pass": c.pass})).into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

async fn warp_overview(state: &AppState) -> WarpOverview {
    let mut overview = state.warp.overview().await;
    for t in state.manager.tunnels().await {
        if t.status().await == "up" && t.runtime.transit_status().await.1 {
            overview.live += 1;
        }
    }
    overview
}

pub async fn warp_get(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(warp_overview(&state).await)
}

#[derive(Deserialize)]
pub struct WarpQuery {
    pub on: String,
}

pub async fn warp_set(State(state): State<Arc<AppState>>, Query(q): Query<WarpQuery>) -> Response {
    let on = matches!(q.on.as_str(), "1" | "true");
    if !matches!(q.on.as_str(), "1" | "true" | "0" | "false") {
        return error(StatusCode::BAD_REQUEST, "on 只能是 1 或 0");
    }
    let mut settings = state.manager.settings().await;
    settings.warp = Some(crate::config::WarpSettings {
        enabled: on,
        ..settings.warp.unwrap_or_default()
    });
    if let Err(e) = state.manager.update_settings(settings).await {
        return internal(e);
    }
    if !on {
        if let Err(e) = state.warp.drop_all().await {
            tracing::warn!("撤销 WARP 注册失败: {e}");
        }
    }
    for t in state.manager.tunnels().await {
        let old = t.host().await;
        state.manager.reconnect(t, old).await;
    }
    Json(json!({
        "ok": true,
        "enabled": on,
        "message": if on { "中转已开启，正在把出口逐条接进 Cloudflare" } else { "中转已关闭，正在把出口逐条接回直连" }
    })).into_response()
}

pub async fn stats(State(state): State<Arc<AppState>>) -> Response {
    match crate::hoststats::read_host_stats(&state.dir) {
        Ok(s) => Json(s).into_response(),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub struct ClientStatusQuery {
    pub check: Option<String>,
}

pub async fn client_status(Query(q): Query<ClientStatusQuery>) -> Response {
    let runtime = crate::clients::ClientRuntime::detect();
    match crate::clients::client_bin_status_json(&runtime, q.check.as_deref() == Some("1")).await {
        Ok(v) => Json(v).into_response(),
        Err(e) => internal(e),
    }
}

pub async fn client_xray_apply() -> Response {
    match crate::clients::apply_xray_update().await {
        Ok(msg) => Json(json!({"ok": true, "message": msg})).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn client_openvpn_apply() -> Response {
    match crate::clients::apply_openvpn_update().await {
        Ok(msg) => Json(json!({"ok": true, "message": msg})).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct OffQuery {
    pub off: Option<String>,
}

pub async fn client_openvpn_repo(Query(q): Query<OffQuery>) -> Response {
    if q.off.as_deref() != Some("1") {
        return error(StatusCode::BAD_REQUEST, "这个接口只负责撤销官方源");
    }
    if !crate::clients::openvpn_apt_repo_ours() {
        return Json(json!({"ok": true, "message": "fanout 名下没有官方源文件"})).into_response();
    }
    match crate::clients::remove_openvpn_apt_repo() {
        Ok(()) => Json(json!({"ok": true, "message": "已删掉 fanout 写的官方源和签名钥匙"}))
            .into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn client_openvpn_build() -> Response {
    match crate::clients::start_openvpn_source_build().await {
        Ok(job) => Json(json!({"ok": true, "job": job.view().await.id,
            "message": "已在后台开始编译，进度在这张卡和出口页的作业卡片里"}))
        .into_response(),
        Err(e) => error(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

pub async fn client_openvpn_source(Query(q): Query<OffQuery>) -> Response {
    if q.off.as_deref() != Some("1") {
        return error(StatusCode::BAD_REQUEST, "这个接口只负责撤销源码版");
    }
    match crate::clients::remove_openvpn_source_build() {
        Ok(msg) => Json(json!({"ok": true, "message": msg})).into_response(),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

pub async fn xui_status() -> impl IntoResponse {
    Json(json!({"available": false, "kind": "native", "reason": "Rust 版正在移植"}))
}

pub async fn not_implemented() -> impl IntoResponse {
    error(StatusCode::NOT_IMPLEMENTED, "Rust 版正在移植")
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

pub async fn update_check() -> Response {
    match crate::clients::check_update().await {
        Ok(v) => Json(v).into_response(),
        Err(e) => error(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}

pub async fn update_apply() -> Response {
    match crate::clients::check_update().await {
        Ok(st) if !st.has_update => {
            Json(json!({"ok": true, "restarting": false, "message": "已经是最新版"}))
                .into_response()
        }
        Ok(st) => match crate::clients::apply_update().await {
            Ok(()) => {
                Json(json!({"ok": true, "restarting": true, "latest": st.latest})).into_response()
            }
            Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        },
        Err(e) => error(StatusCode::BAD_GATEWAY, e.to_string()),
    }
}
