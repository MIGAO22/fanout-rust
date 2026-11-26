mod api;
mod appstate;
mod auth;
mod clients;
mod config;
mod factory;
mod hoststats;
mod instance;
mod jobs;
mod manager;
mod models;
mod netns;
mod nodecache;
mod nodes;
mod panel;
mod panel_api;
mod panel_native;
mod panel_runtime;
mod panel_xcl;
mod panel_xui;
mod pool_service;
mod pools_logic;
mod process;
mod publicip;
mod runtime;
mod socks5;
mod state;
mod sub;
mod tunnel_runtime;
mod util;
mod warp_logic;
mod warp_runtime;
mod web;

use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;

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

    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("需要 root 运行");
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
    let instance = instance::Instance::init(&dir)?;
    let tag = if dir == PathBuf::from("/var/lib/fanout") {
        String::new()
    } else {
        util::short_hash(&dir.to_string_lossy())
    };
    process::init_main_netns()?;
    if let Some(ip) = args.ip.as_ref() {
        publicip::set_public_ip_override(ip);
    }
    let auth = auth::Auth::load(&dir)?.0;
    let (basepath, base_created) = auth::load_basepath(&dir)?;
    if base_created {
        tracing::info!("已生成访问路径，见 {}", dir.join("basepath").display());
    }

    let settings = Arc::new(RwLock::new(settings));
    let warp = warp_runtime::WarpService::load(&dir, instance.clone(), settings.clone())?;
    let listen_addr = settings.read().await.listen_addr.clone();
    let web_port = settings.read().await.port;
    let jobs = jobs::JobStore::new();
    let manager = manager::Manager::new(
        dir.clone(),
        args.max.unwrap_or(20),
        settings.clone(),
        jobs,
        Arc::new(tunnel_runtime::LinuxTunnelFactory {
            instance,
            settings: settings.clone(),
            warp: Some(warp.clone()),
        }),
    );
    let pools = Arc::new(pool_service::PoolService::new(dir.clone(), manager.clone()).await?);
    let panels = Arc::new(
        panel_runtime::PanelManager::with_mode(
            dir.clone(),
            manager.clone(),
            pools.clone(),
            args.panel.as_deref().unwrap_or(""),
        )
        .await,
    );
    manager.set_panel(panels.clone() as Arc<dyn panel::Panel>);
    let state = Arc::new(appstate::AppState {
        auth,
        manager: manager.clone(),
        dir: dir.clone(),
        basepath: basepath.clone(),
        warp,
        panel: panels.clone(),
        pools,
    });
    if let Err(e) = manager.restore().await {
        tracing::warn!("恢复隧道状态失败: {e}");
    }
    state.pools.start_fill_task();
    let health_manager = manager.clone();
    tokio::spawn(async move {
        health_manager.health_loop().await;
    });
    if !tag.is_empty() {
        tracing::info!("非默认工作目录，本实例用 netns fo{tag}*");
    }
    tracing::info!("管理界面: http://{}:{}/{}", listen_addr, web_port, basepath);
    tracing::info!("Rust 重构版 v{VERSION}，Go 版功能正在逐模块移植");

    let mut app = Router::new()
        .route("/", get(web::index))
        .route("/login", get(web::login_page).post(auth::login))
        .route("/logout", get(auth::logout).post(auth::logout))
        .route("/:file", get(web::asset))
        .route("/api/health", get(api::health))
        .route("/api/exits", get(api::exits))
        .route("/api/tunnels", get(api::tunnels))
        .route("/api/nodes", get(api::nodes))
        .route("/api/regions", get(api::regions))
        .route("/api/start", get(api::start))
        .route("/api/stop", get(api::stop))
        .route("/api/swap", get(api::swap))
        .route("/api/cred", get(api::cred))
        .route("/api/refresh", get(api::refresh))
        .route("/api/provision", get(api::provision))
        .route("/api/jobs", get(api::jobs))
        .route("/api/jobs/dismiss", get(api::job_dismiss))
        .route("/api/pools", get(api::pools))
        .route("/api/pool/save", post(api::pool_save))
        .route("/api/pool/delete", post(api::pool_delete))
        .route("/api/pool/cred", post(api::pool_cred))
        .route("/api/warp", get(api::warp_get).post(api::warp_set))
        .route("/api/stats", get(api::stats))
        .route("/api/client/status", get(api::client_status))
        .route("/api/client/xray/apply", post(api::client_xray_apply))
        .route("/api/client/warp/apply", post(api::client_warp_apply))
        .route("/api/client/openvpn/apply", post(api::client_openvpn_apply))
        .route("/api/client/openvpn/repo", post(api::client_openvpn_repo))
        .route("/api/client/openvpn/build", post(api::client_openvpn_build))
        .route(
            "/api/client/openvpn/source",
            post(api::client_openvpn_source),
        )
        .route("/sub", get(api::subscription))
        .route("/api/settings", get(api::settings).post(api::settings))
        .route("/api/sub", get(api::sub_info))
        .route("/api/sub/reset", post(api::sub_reset))
        .route("/api/update/check", get(api::update_check))
        .route("/api/update/apply", post(api::update_apply));

    let app = app.with_state(state.clone());
    let app = app.merge(panel_api::panel_routes(
        panels.as_ref().clone(),
        state.manager.clone(),
        state.pools.clone(),
    ));
    let app = app.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth::require_auth,
    ));
    let app = if basepath.is_empty() {
        app
    } else {
        let canonical = format!("/{basepath}");
        let trailing = format!("{canonical}/");
        Router::new().nest(&canonical, app).route(
            &trailing,
            get(move || {
                let target = canonical.clone();
                async move { axum::response::Redirect::permanent(&target) }
            }),
        )
    };

    let addr: SocketAddr = settings.read().await.listen().parse()?;
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

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await?;
    manager.shutdown().await;
    state.pools.close().await;
    Ok(())
}
