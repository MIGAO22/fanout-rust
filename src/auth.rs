use anyhow::Result;
use axum::{
    extract::{Form, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::{
    collections::HashMap,
    net::IpAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

use crate::util::{atomic_write, random_token, read_trim};

pub const SESSION_COOKIE: &str = "fanout_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Default)]
struct Failures {
    count: u32,
    at: Instant,
}

impl Default for Failures {
    fn default() -> Self {
        Self {
            count: 0,
            at: Instant::now(),
        }
    }
}

pub struct Auth {
    dir: std::path::PathBuf,
    password: Arc<Mutex<String>>,
    sessions: Arc<Mutex<HashMap<String, Instant>>>,
    failures: Arc<Mutex<HashMap<String, Failures>>>,
}

impl Auth {
    pub fn load(dir: &Path) -> Result<(Arc<Self>, bool)> {
        let path = dir.join("password");
        let (password, created) = match read_trim(&path) {
            Some(p) if !p.is_empty() => (p, false),
            _ => {
                let p = random_token(18);
                atomic_write(&path, p.as_bytes(), 0o600)?;
                (p, true)
            }
        };
        Ok((
            Arc::new(Self {
                dir: dir.to_path_buf(),
                password: Arc::new(Mutex::new(password)),
                sessions: Arc::new(Mutex::new(HashMap::new())),
                failures: Arc::new(Mutex::new(HashMap::new())),
            }),
            created,
        ))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    async fn check(&self, pw: &str) -> bool {
        *self.password.lock().await == pw
    }

    async fn blocked(&self, ip: &str) -> bool {
        let mut f = self.failures.lock().await;
        if let Some(v) = f.get_mut(ip) {
            if v.at.elapsed() > Duration::from_secs(300) {
                f.remove(ip);
                return false;
            }
            v.count >= 5
        } else {
            false
        }
    }

    async fn record_fail(&self, ip: &str) {
        let mut f = self.failures.lock().await;
        let v = f.entry(ip.to_string()).or_default();
        v.count += 1;
        v.at = Instant::now();
    }

    async fn clear_fails(&self, ip: &str) {
        self.failures.lock().await.remove(ip);
    }

    async fn issue(&self) -> String {
        let token = random_token(32);
        self.sessions
            .lock()
            .await
            .insert(token.clone(), Instant::now() + SESSION_TTL);
        token
    }

    async fn valid(&self, token: &str) -> bool {
        let mut s = self.sessions.lock().await;
        if let Some(exp) = s.get(token) {
            if *exp > Instant::now() {
                return true;
            }
            s.remove(token);
        }
        false
    }

    async fn revoke(&self, token: &str) {
        self.sessions.lock().await.remove(token);
    }

    pub async fn set_password(&self, pw: &str) -> Result<()> {
        atomic_write(self.dir.join("password"), pw.as_bytes(), 0o600)?;
        *self.password.lock().await = pw.to_string();
        self.sessions.lock().await.clear();
        Ok(())
    }
}

fn client_ip(req: &Request) -> String {
    if let Some(v) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        return v.split(',').next().unwrap_or(v).trim().to_string();
    }
    req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|v| v.ip().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let mut kv = part.trim().splitn(2, '=');
        if kv.next()? == SESSION_COOKIE {
            return kv.next().map(str::to_string);
        }
    }
    None
}

pub async fn login(
    State(auth): State<Arc<Auth>>,
    req: Request,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let ip = client_ip(&req);
    if auth.blocked(&ip).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"尝试太频繁，请稍后再试"})),
        )
            .into_response();
    }
    let pw = form.get("password").map(String::as_str).unwrap_or("");
    if !auth.check(pw).await {
        auth.record_fail(&ip).await;
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"口令不对"}))).into_response();
    }
    auth.clear_fails(&ip).await;
    let token = auth.issue().await;
    let mut h = HeaderMap::new();
    h.insert(
        header::SET_COOKIE,
        format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200")
            .parse()
            .unwrap(),
    );
    (h, Json(json!({"ok": true}))).into_response()
}

pub async fn logout(State(auth): State<Arc<Auth>>, req: Request) -> Response {
    if let Some(t) = cookie_token(req.headers()) {
        auth.revoke(&t).await;
    }
    let mut h = HeaderMap::new();
    h.insert(
        header::SET_COOKIE,
        format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
            .parse()
            .unwrap(),
    );
    (h, Json(json!({"ok": true}))).into_response()
}

pub async fn require_auth(State(auth): State<Arc<Auth>>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if path == "/login" || path == "/logout" || path == "/sub" {
        return next.run(req).await;
    }
    if let Some(t) = cookie_token(req.headers()) {
        if auth.valid(&t).await {
            return next.run(req).await;
        }
    }
    if path.starts_with("/api/") {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error":"未登录"}))).into_response();
    }
    crate::web::login_page().await.into_response()
}

pub fn load_basepath(dir: &Path) -> Result<(String, bool)> {
    let path = dir.join("basepath");
    match read_trim(&path) {
        Some(p) if !p.is_empty() => Ok((p.trim_matches('/').to_string(), false)),
        _ => {
            let p = random_token(12);
            atomic_write(&path, p.as_bytes(), 0o600)?;
            Ok((p, true))
        }
    }
}

pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse().ok()
}
