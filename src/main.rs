mod api;
mod auth;
mod config;
mod jobs;
mod models;
mod nodecache;
mod nodes;
mod panel;
mod panel_xcl;
mod pools_logic;
mod socks5;
mod state;
mod sub;
mod util;
mod warp_logic;
mod web;

use anyhow::Result;
use axum::{routing::get, Router};
use std::{net::SocketAddr, path::PathBuf};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Default)]
struct Args {
    dir: Option<PathBuf>,
    web: Option<u16>,
    max: Option<usize>,
    panel: Option<String>,
    ip: Option<String>,
    version: bool,
    help: bool,
}

fn parse_args() -> Result<Args> {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let (key, inline) = k
            .split_once('=')
            .map(|(k, v)| (k.to_string(), Some(v.to_string())))
            .unwrap_or((k.clone(), None));
        let mut value = || -> Result<String> {
            if let Some(v) = inline.clone() {
                return Ok(v);
            }
            it.next().ok_or_else(|| anyhow::anyhow!("参数 {key} 缺值"))
        };
        match key.trim_start_matches('-') {
            "dir" => a.dir = Some(PathBuf::from(value()?)),
            "web" => a.web = Some(value()?.parse()?),
            "max" => a.max = Some(value()?.parse()?),
            "panel" => a.panel = Some(value()?),
            "ip" => a.ip = Some(value()?),
            "version" => a.version = true,
            "h" | "help" => a.help = true,
            _ => anyhow::bail!("未知参数 {k}"),
        }
    }
    Ok(a)
}

fn print_help() {
    println!("fanout-rust v{VERSION}\n\n用法: fanout-rust [选项]\n\n  -dir <目录>      工作目录（默认 /var/lib/fanout）\n  -web <端口>      管理界面端口（默认 8899）\n  -max <数量>      最多同时运行的隧道数（默认 20）\n  -panel <模式>    3x-ui / native / xray-cf-lite\n  -ip <地址>       母机公网 IPv4\n  -version         显示版本\n  -h               显示帮助");
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();

    let args = parse_args()?;
    if args.version {
        println!("fanout-rust v{VERSION}");
        return Ok(());
    }
    if args.help {
        print_help();
        return Ok(());
    }

    let dir = args.dir.unwrap_or_else(|| PathBuf::from("/var/lib/fanout"));
    std::fs::create_dir_all(&dir)?;
    let _lock = util::workdir_lock(&dir)?;
    let port_explicit = args.web.is_some();
    let settings = config::load_settings(
        &dir,
        args.web.unwrap_or(config::DEFAULT_PORT),
        port_explicit,
    )?;
    let auth = auth::Auth::load(&dir)?.0;
    let (basepath, base_created) = auth::load_basepath(&dir)?;
    if base_created {
        tracing::info!("已生成访问路径，见 {}", dir.join("basepath").display());
    }

    let tag = if dir == PathBuf::from("/var/lib/fanout") {
        String::new()
    } else {
        util::short_hash(&dir.to_string_lossy())
    };
    if !tag.is_empty() {
        tracing::info!("非默认工作目录，本实例用 netns fo{tag}*");
    }
    tracing::info!(
        "管理界面: http://{}:{}/{}",
        settings.listen_addr,
        settings.port,
        basepath
    );
    tracing::info!("Rust 重构版 v{VERSION}，Go 版功能正在逐模块移植");

    let mut app = Router::new()
        .route("/", get(web::index))
        .route("/login", get(web::login_page).post(auth::login))
        .route("/logout", get(auth::logout).post(auth::logout))
        .route("/:file", get(web::asset))
        .route("/api/health", get(api::health))
        .route("/api/exits", get(api::exits))
        .route("/api/nodes", get(api::nodes))
        .route("/api/regions", get(api::regions))
        .route("/api/pools", get(api::pools))
        .route("/api/jobs", get(api::jobs))
        .route("/api/warp", get(api::warp).post(api::not_implemented))
        .route("/api/stats", get(api::stats))
        .route("/api/client/status", get(api::client_status))
        .route("/api/xui", get(api::xui_status))
        .route("/sub", get(api::not_implemented));

    for path in [
        "/api/tunnels",
        "/api/start",
        "/api/stop",
        "/api/swap",
        "/api/cred",
        "/api/refresh",
        "/api/provision",
        "/api/jobs/dismiss",
        "/api/client/warp/apply",
        "/api/xui/inbounds",
        "/api/xui/bind",
        "/api/xui/clone",
        "/api/xui/detail",
        "/api/xui/links",
        "/api/xui/delete",
        "/api/pool/save",
        "/api/pool/delete",
        "/api/pool/cred",
        "/api/panel/inbound/new",
        "/api/panel/inbound/update",
        "/api/panel/client/add",
        "/api/panel/client/del",
        "/api/panel/client/reset",
        "/api/panel/mode",
        "/api/sub",
        "/api/sub/reset",
        "/api/settings",
        "/api/update/check",
        "/api/update/apply",
        "/api/client/xray/apply",
        "/api/client/openvpn/apply",
        "/api/client/openvpn/repo",
        "/api/client/openvpn/build",
        "/api/client/openvpn/source",
    ] {
        app = app.route(path, get(api::not_implemented).post(api::not_implemented));
    }
    let app = app.layer(axum::middleware::from_fn_with_state(
        auth,
        auth::require_auth,
    ));
    let app = Router::new().nest(&format!("/{basepath}"), app);

    let addr: SocketAddr = settings.listen().parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("管理界面监听已切换到 {addr}");

    #[cfg(unix)]
    let shutdown = {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = term.recv() => {},
            }
        }
    };
    #[cfg(not(unix))]
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}
