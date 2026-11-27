//! Axum HTTP wiring for the panel runtime.
//!
//! The routes intentionally use their own state rather than `AppState`, so the
//! panel runtime can be integrated without changing unrelated application
//! modules. Query parameters and JSON envelopes follow the Go handlers in
//! `main.go`.

use crate::{
    manager::Manager,
    panel::{InboundPatch, Panel},
    panel_runtime::{CurrentPanel, PanelManager, PanelMode},
    pool_service::PoolService,
};
use anyhow::Result;
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::{collections::HashMap, sync::Arc};

pub type PanelQuery = HashMap<String, String>;

/// Cloneable handler state. Construct it with the same manager and pool service
/// used to construct [`PanelManager`].
#[derive(Clone)]
pub struct PanelApi {
    panel: PanelManager,
    manager: Arc<Manager>,
    pools: Arc<PoolService>,
}

impl PanelApi {
    pub fn new(panel: PanelManager, manager: Arc<Manager>, pools: Arc<PoolService>) -> Self {
        Self {
            panel,
            manager,
            pools,
        }
    }

    /// Build all Go-compatible panel routes. Merge this router into the existing
    /// authenticated application router.
    pub fn router(&self) -> Router {
        Router::new()
            .route("/api/xui", get(xui_status))
            .route("/api/xui/inbounds", get(xui_inbounds))
            .route("/api/xui/detail", get(xui_detail))
            .route("/api/xui/links", get(xui_links))
            .route("/api/xui/bind", post(xui_bind))
            .route("/api/xui/clone", post(xui_clone))
            .route("/api/xui/delete", post(xui_delete))
            .route("/api/panel/inbound/new", post(inbound_create))
            .route("/api/panel/inbound/update", post(inbound_update))
            .route("/api/panel/client/add", post(client_add))
            .route("/api/panel/client/del", post(client_delete))
            .route("/api/panel/client/reset", post(client_reset))
            .route("/api/panel/mode", get(panel_mode).post(panel_mode))
            .with_state(self.clone())
    }

    async fn panel(&self) -> Result<CurrentPanel> {
        self.panel
            .lock_current_panel_from(&self.manager, &self.pools)
            .await
    }
}

/// Convenience router factory for callers that do not need to retain
/// [`PanelApi`].
pub fn panel_routes(panel: PanelManager, manager: Arc<Manager>, pools: Arc<PoolService>) -> Router {
    PanelApi::new(panel, manager, pools).router()
}

fn error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

fn bad_request(message: impl Into<String>) -> Response {
    error(StatusCode::BAD_REQUEST, message)
}

fn bad_gateway(err: impl std::fmt::Display) -> Response {
    error(StatusCode::BAD_GATEWAY, err.to_string())
}

fn normalize_inbound_id(value: &mut Value) {
    let Some(id) = value.get("id").and_then(Value::as_str).map(str::to_string) else {
        return;
    };
    if let Ok(id) = id.parse::<u64>() {
        value["id"] = json!(id);
    }
}

/// The shared Rust models use string IDs for Native/XUI/XCL, whereas Go's HTTP
/// API emits numeric inbound IDs. Normalize only this response boundary.
fn panel_json_response<T: Serialize>(value: T) -> Response {
    match serde_json::to_value(value) {
        Ok(mut value) => {
            match &mut value {
                Value::Array(inbounds) => {
                    for inbound in inbounds {
                        normalize_inbound_id(inbound);
                    }
                }
                _ => normalize_inbound_id(&mut value),
            }
            Json(value).into_response()
        }
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

fn query_map(query: Option<Query<PanelQuery>>) -> PanelQuery {
    query.map(|Query(query)| query).unwrap_or_default()
}

fn parse_id(query: &PanelQuery) -> std::result::Result<String, Response> {
    query
        .get("id")
        .and_then(|id| id.parse::<i64>().ok())
        .map(|id| id.to_string())
        .ok_or_else(|| bad_request("id 参数无效"))
}

fn parse_ids(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter_map(|part| part.trim().parse::<i64>().ok())
        .map(|id| id.to_string())
        .collect()
}

fn request_public_host(headers: &HeaderMap) -> String {
    let public_ip = crate::publicip::host_public_ip();
    if !public_ip.is_empty() {
        return public_ip;
    }
    let authority = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let host = authority
        .rfind(':')
        .filter(|index| *index > 0)
        .map_or(authority, |index| &authority[..index]);
    if host.is_empty() || host == "127.0.0.1" || host == "localhost" {
        "<服务器IP>".to_string()
    } else {
        host.to_string()
    }
}

fn link_host(query: &PanelQuery, headers: &HeaderMap) -> String {
    query
        .get("host")
        .filter(|host| !host.is_empty())
        .cloned()
        .unwrap_or_else(|| request_public_host(headers))
}

pub async fn xui_status(State(api): State<PanelApi>) -> Response {
    Json(api.panel.status().await).into_response()
}

pub async fn xui_inbounds(State(api): State<PanelApi>) -> Response {
    match api.panel().await {
        Ok(panel) => match panel.inbounds().await {
            Ok(inbounds) => panel_json_response(inbounds),
            Err(err) => bad_gateway(err),
        },
        Err(err) => bad_gateway(err),
    }
}

pub async fn xui_bind(State(api): State<PanelApi>, query: Option<Query<PanelQuery>>) -> Response {
    let query = query_map(query);
    let Some(tag) = query.get("tag").filter(|tag| !tag.is_empty()) else {
        return bad_request("缺少 tag 参数");
    };
    let host = query.get("host").map(String::as_str).unwrap_or_default();
    let panel = match api.panel().await {
        Ok(panel) => panel,
        Err(err) => return bad_gateway(err),
    };
    match panel.bind(tag, host).await {
        Ok(()) => Json(json!({ "ok": "已更新" })).into_response(),
        Err(err) => bad_gateway(err),
    }
}

pub async fn xui_clone(State(api): State<PanelApi>, query: Option<Query<PanelQuery>>) -> Response {
    let query = query_map(query);
    let id = match parse_id(&query) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let tunnels = api.manager.states().await;
    let hosts = if let Some(raw) = query.get("hosts").filter(|raw| !raw.is_empty()) {
        raw.split(',')
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    } else {
        tunnels
            .iter()
            .filter(|tunnel| tunnel.status == "up")
            .map(|tunnel| tunnel.node.hostname.clone())
            .collect()
    };
    if hosts.is_empty() {
        return bad_request("没有可用的隧道");
    }
    let panel = match api.panel().await {
        Ok(panel) => panel,
        Err(err) => return bad_gateway(err),
    };
    match panel.clone_to_tunnels(&id, &hosts).await {
        Ok(created) => Json(json!({ "created": created })).into_response(),
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": err.to_string(),
                "created": Vec::<u16>::new(),
            })),
        )
            .into_response(),
    }
}

pub async fn xui_detail(
    State(api): State<PanelApi>,
    query: Option<Query<PanelQuery>>,
    headers: HeaderMap,
) -> Response {
    let query = query_map(query);
    let id = match parse_id(&query) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let panel = match api.panel().await {
        Ok(panel) => panel,
        Err(err) => return bad_gateway(err),
    };
    let host = link_host(&query, &headers);
    match panel.inbound_detail(&id, &host).await {
        Ok(detail) => panel_json_response(detail),
        Err(err) => bad_gateway(err),
    }
}

pub async fn xui_links(
    State(api): State<PanelApi>,
    query: Option<Query<PanelQuery>>,
    headers: HeaderMap,
) -> Response {
    let query = query_map(query);
    let panel = match api.panel().await {
        Ok(panel) => panel,
        Err(err) => return bad_gateway(err),
    };
    let ids = if let Some(raw) = query.get("ids").filter(|raw| !raw.is_empty()) {
        parse_ids(raw)
    } else {
        match panel.inbounds().await {
            Ok(inbounds) => inbounds.into_iter().map(|inbound| inbound.id).collect(),
            Err(err) => return bad_gateway(err),
        }
    };
    if ids.is_empty() {
        return bad_request("没有可导出的入站");
    }
    let host = link_host(&query, &headers);
    match panel.inbound_links(&ids, &host).await {
        Ok(links) => Json(json!({ "links": links })).into_response(),
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": err.to_string(),
                "links": Vec::<String>::new(),
            })),
        )
            .into_response(),
    }
}

pub async fn xui_delete(State(api): State<PanelApi>, query: Option<Query<PanelQuery>>) -> Response {
    let query = query_map(query);
    let ids = parse_ids(query.get("ids").map(String::as_str).unwrap_or_default());
    if ids.is_empty() {
        return bad_request("没有指定要删除的入站");
    }
    let panel = match api.panel().await {
        Ok(panel) => panel,
        Err(err) => return bad_gateway(err),
    };
    match panel.delete_inbounds(&ids).await {
        Ok(_) => Json(json!({ "deleted": ids.len() })).into_response(),
        Err(err) => bad_gateway(err),
    }
}

pub async fn inbound_create(
    State(api): State<PanelApi>,
    query: Option<Query<PanelQuery>>,
) -> Response {
    let panel = match api.panel().await {
        Ok(panel) => panel,
        Err(err) => return bad_gateway(err),
    };
    let query = query_map(query);
    let mut spec = Map::new();
    for (key, value) in &query {
        spec.insert(key.clone(), Value::String(value.clone()));
    }
    // Go's create handler ignores strconv errors and lets the backend choose a
    // random port for zero. Preserve that behavior while still rejecting an
    // explicitly negative/out-of-range value in the shared spec parser.
    let port = match query.get("port").filter(|port| !port.is_empty()) {
        Some(raw) => match raw.parse::<u16>() {
            Ok(port) => port,
            Err(_) => return bad_request("端口无效"),
        },
        None => 0,
    };
    if let Some(raw) = query.get("enable").filter(|enable| !enable.is_empty()) {
        if !matches!(raw.as_str(), "0" | "1") {
            return bad_request("enable 只能是 0 或 1");
        }
    }
    spec.insert("port".into(), json!(port));
    match panel.create_inbound(&Value::Object(spec)).await {
        Ok(created) => panel_json_response(created),
        Err(err) => bad_request(err.to_string()),
    }
}

pub async fn inbound_update(
    State(api): State<PanelApi>,
    query: Option<Query<PanelQuery>>,
) -> Response {
    let panel = match api.panel().await {
        Ok(panel) => panel,
        Err(err) => return bad_gateway(err),
    };
    let query = query_map(query);
    let id = match parse_id(&query) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let mut patch = InboundPatch::default();
    if let Some(raw) = query.get("port").filter(|port| !port.is_empty()) {
        let Ok(port) = raw.parse::<u16>() else {
            return bad_request("端口无效");
        };
        if port == 0 {
            return bad_request("端口不能为 0");
        }
        patch.port = Some(port);
    }
    if let Some(remark) = query.get("remark") {
        patch.remark = Some(remark.clone());
    }
    if let Some(raw) = query.get("enable").filter(|enable| !enable.is_empty()) {
        if !matches!(raw.as_str(), "0" | "1") {
            return bad_request("enable 只能是 0 或 1");
        }
        patch.enable = Some(raw == "1");
    }
    match panel.update_inbound(&id, &patch).await {
        Ok(()) => Json(json!({ "ok": "已保存" })).into_response(),
        Err(err) => bad_request(err.to_string()),
    }
}

#[derive(Clone, Copy)]
enum ClientAction {
    Add,
    Delete,
    Reset,
}

async fn client_action(api: &PanelApi, query: &PanelQuery, action: ClientAction) -> Response {
    let panel = match api.panel().await {
        Ok(panel) => panel,
        Err(err) => return bad_gateway(err),
    };
    let id = match parse_id(query) {
        Ok(id) => id,
        Err(response) => return response,
    };
    let email = query.get("email").map(String::as_str).unwrap_or_default();
    let result = match action {
        ClientAction::Add => panel.add_client(&id, email).await,
        ClientAction::Delete => panel.delete_client(&id, email).await,
        ClientAction::Reset => panel.reset_client(&id, email).await.map(|_| ()),
    };
    let message = match action {
        ClientAction::Add => "已添加",
        ClientAction::Delete => "已删除",
        ClientAction::Reset => "已重置",
    };
    match result {
        Ok(()) => Json(json!({ "ok": message })).into_response(),
        Err(err) => bad_request(err.to_string()),
    }
}

pub async fn client_add(State(api): State<PanelApi>, query: Option<Query<PanelQuery>>) -> Response {
    client_action(&api, &query_map(query), ClientAction::Add).await
}

pub async fn client_delete(
    State(api): State<PanelApi>,
    query: Option<Query<PanelQuery>>,
) -> Response {
    client_action(&api, &query_map(query), ClientAction::Delete).await
}

pub async fn client_reset(
    State(api): State<PanelApi>,
    query: Option<Query<PanelQuery>>,
) -> Response {
    client_action(&api, &query_map(query), ClientAction::Reset).await
}

async fn panel_mode_get(api: &PanelApi) -> Response {
    let mode = api.panel.current_mode();
    let modes: Vec<PanelMode> = api.panel.available_modes().await;
    let status = api.panel.status().await;
    let mut response = json!({ "mode": mode, "modes": modes });
    if status.available {
        response["kind"] = json!(status.kind);
        response["describe"] = json!(status.describe);
    }
    Json(response).into_response()
}

pub async fn panel_mode(State(api): State<PanelApi>, method: Method, body: Bytes) -> Response {
    match method {
        Method::GET => panel_mode_get(&api).await,
        Method::POST => {
            let value: Value = match serde_json::from_slice(&body) {
                Ok(value) => value,
                Err(_) => return bad_request("请求格式错误"),
            };
            let mode = if value.is_null() {
                ""
            } else {
                let Some(object) = value.as_object() else {
                    return bad_request("请求格式错误");
                };
                match object.get("mode") {
                    None => "",
                    Some(Value::String(mode)) => mode,
                    Some(_) => return bad_request("请求格式错误"),
                }
            };
            let panel = match api.panel.switch_mode(mode).await {
                Ok(panel) => panel,
                Err(err) => return bad_request(err.to_string()),
            };
            Json(json!({
                "mode": api.panel.current_mode(),
                "kind": panel.kind(),
                "describe": panel.describe(),
            }))
            .into_response()
        }
        _ => error(StatusCode::METHOD_NOT_ALLOWED, "用 GET 或 POST"),
    }
}
