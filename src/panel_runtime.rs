//! Runtime ownership and selection for the native, 3x-ui, and xray-cf-lite
//! panel backends.
//!
//! `PanelManager` is the stable object registered with `Manager`. Backends can
//! therefore be replaced at runtime without replacing the manager's panel
//! callback. Every backend operation first refreshes the tunnel/pool snapshot,
//! giving the argument-free [`Panel`] trait the same live inputs as the Go API.

use crate::{
    manager::Manager,
    models::{PoolView, TunnelState},
    panel::Panel,
    panel_native::{Native, RuntimeSnapshot},
    panel_xcl::{XCLRuntime, XCL},
    panel_xui::XUI,
    pool_service::PoolService,
    util,
};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

pub const PANEL_MODE_XUI: &str = "3x-ui";
pub const PANEL_MODE_NATIVE: &str = "native";
pub const PANEL_MODE_XCL: &str = "xray-cf-lite";

/// The file read at startup and updated after a successful explicit switch.
pub fn panel_mode_file(work_dir: impl AsRef<Path>) -> PathBuf {
    work_dir.as_ref().join("panel_mode")
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

/// A cloneable, synchronous snapshot provider for xray-cf-lite.
///
/// XCL's Panel methods are async but its configuration and runtime provider are
/// deliberately synchronous. The provider is updated before every operation and
/// shared by every detected XCL instance.
#[derive(Clone, Default)]
pub struct SharedPanelRuntime {
    snapshot: Arc<Mutex<RuntimeSnapshot>>,
}

impl SharedPanelRuntime {
    pub fn new(snapshot: RuntimeSnapshot) -> Self {
        Self {
            snapshot: Arc::new(Mutex::new(snapshot)),
        }
    }

    pub fn replace(&self, snapshot: RuntimeSnapshot) {
        *lock_unpoisoned(&self.snapshot) = snapshot;
    }

    pub fn snapshot(&self) -> RuntimeSnapshot {
        lock_unpoisoned(&self.snapshot).clone()
    }
}

impl XCLRuntime for SharedPanelRuntime {
    fn tunnels(&self) -> Vec<TunnelState> {
        self.snapshot().tunnels
    }

    fn pools(&self) -> Vec<PoolView> {
        self.snapshot().pools
    }

    fn snapshot(&self) -> (Vec<TunnelState>, Vec<PoolView>) {
        let snapshot = self.snapshot();
        (snapshot.tunnels, snapshot.pools)
    }
}

#[derive(Clone)]
enum Backend {
    Native(Arc<Native>),
    Xui(Arc<XUI>),
    Xcl(Arc<XCL>),
}

impl Backend {
    fn panel(&self) -> Arc<dyn Panel> {
        match self {
            Self::Native(panel) => panel.clone(),
            Self::Xui(panel) => panel.clone(),
            Self::Xcl(panel) => panel.clone(),
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Native(_) => PANEL_MODE_NATIVE,
            Self::Xui(_) => PANEL_MODE_XUI,
            Self::Xcl(_) => PANEL_MODE_XCL,
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Native(panel) => panel.describe(),
            Self::Xui(panel) => panel.describe(),
            Self::Xcl(panel) => panel.describe(),
        }
    }

    async fn set_runtime(&self, snapshot: RuntimeSnapshot) {
        match self {
            Self::Native(panel) => {
                panel.set_runtime(snapshot.tunnels, snapshot.pools).await;
            }
            Self::Xui(panel) => {
                panel.set_runtime(snapshot.tunnels, snapshot.pools).await;
            }
            Self::Xcl(_) => {
                // XCL reads the shared provider installed by PanelManager.
            }
        }
    }

    async fn close(&self) -> Result<()> {
        match self {
            Self::Native(panel) => panel.close().await,
            Self::Xui(panel) => panel.close().await,
            Self::Xcl(panel) => panel.close().await,
        }
    }
}

struct PanelState {
    current: Option<Backend>,
    /// Empty means automatic detection. Otherwise this is the selected mode.
    forced: String,
    closed: bool,
}

struct PanelManagerInner {
    work_dir: PathBuf,
    manager: Arc<Manager>,
    pools: Arc<PoolService>,
    xcl_runtime: SharedPanelRuntime,
    state: Mutex<PanelState>,
    /// Serializes backend operations with detection, switching, and shutdown.
    operation: Arc<AsyncMutex<()>>,
}

/// Owns the selected panel backend and keeps its runtime snapshot current.
///
/// Clones share the selected backend. This type also implements [`Panel`], so a
/// single clone can be registered with `Manager::set_panel` and reused by HTTP
/// handlers after any number of mode switches.
#[derive(Clone)]
pub struct PanelManager {
    inner: Arc<PanelManagerInner>,
}

/// A refreshed backend handle that keeps mode switching and shutdown blocked
/// until the caller finishes its panel operation.
pub struct CurrentPanel {
    panel: Arc<dyn Panel>,
    _operation: OwnedMutexGuard<()>,
}

impl CurrentPanel {
    pub fn panel(&self) -> Arc<dyn Panel> {
        self.panel.clone()
    }
}

impl std::ops::Deref for CurrentPanel {
    type Target = Arc<dyn Panel>;

    fn deref(&self) -> &Self::Target {
        &self.panel
    }
}

/// JSON shape returned by `GET /api/xui`.
#[derive(Clone, Debug, Serialize)]
pub struct PanelStatus {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub describe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_create: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One entry in the Go-compatible `modes` array.
#[derive(Clone, Debug, Serialize)]
pub struct PanelMode {
    pub mode: String,
    pub label: String,
    pub available: bool,
    pub reason: String,
}

impl PanelManager {
    fn build(
        work_dir: impl Into<PathBuf>,
        manager: Arc<Manager>,
        pools: Arc<PoolService>,
        mode: impl Into<String>,
    ) -> Self {
        let work_dir = work_dir.into();
        let mode = mode.into();
        let forced = if mode.trim().is_empty() {
            util::read_trim(panel_mode_file(&work_dir)).unwrap_or_default()
        } else {
            mode.trim().to_string()
        };
        Self {
            inner: Arc::new(PanelManagerInner {
                work_dir,
                manager,
                pools,
                xcl_runtime: SharedPanelRuntime::default(),
                state: Mutex::new(PanelState {
                    current: None,
                    forced,
                    closed: false,
                }),
                operation: Arc::new(AsyncMutex::new(())),
            }),
        }
    }

    /// Read the persisted mode (or auto-detect) and open the backend on a
    /// best-effort basis. Detection failures remain visible through
    /// [`Self::status`] instead of preventing the web server from starting.
    pub async fn new(
        work_dir: impl Into<PathBuf>,
        manager: Arc<Manager>,
        pools: Arc<PoolService>,
    ) -> Self {
        Self::with_mode(work_dir, manager, pools, "").await
    }

    /// Like [`Self::new`], but a non-empty command-line mode overrides the file.
    pub async fn with_mode(
        work_dir: impl Into<PathBuf>,
        manager: Arc<Manager>,
        pools: Arc<PoolService>,
        mode: impl Into<String>,
    ) -> Self {
        let panel = Self::build(work_dir, manager, pools, mode);
        if let Err(err) = panel.refresh_snapshot().await {
            tracing::warn!("节点链接后端暂不可用: {err}");
        }
        panel
    }

    /// Fallible startup variant for embedders that want detection errors before
    /// serving requests.
    pub async fn open(
        work_dir: impl Into<PathBuf>,
        manager: Arc<Manager>,
        pools: Arc<PoolService>,
        mode: impl Into<String>,
    ) -> Result<Self> {
        let panel = Self::build(work_dir, manager, pools, mode);
        panel.refresh_snapshot().await?;
        Ok(panel)
    }

    pub fn work_dir(&self) -> &Path {
        &self.inner.work_dir
    }

    pub fn xcl_runtime(&self) -> SharedPanelRuntime {
        self.inner.xcl_runtime.clone()
    }

    /// The explicit mode when set; otherwise the detected backend kind.
    pub fn current_mode(&self) -> String {
        let state = lock_unpoisoned(&self.inner.state);
        if !state.forced.is_empty() {
            return state.forced.clone();
        }
        state
            .current
            .as_ref()
            .map(Backend::kind)
            .unwrap_or_default()
            .to_string()
    }

    async fn open_backend(&self, requested: &str) -> Result<Backend> {
        match requested {
            PANEL_MODE_XUI => XUI::detect(&self.inner.work_dir)
                .await
                .map(|panel| Backend::Xui(Arc::new(panel)))
                .context("指定了 3x-ui 模式但探测失败"),
            PANEL_MODE_NATIVE => {
                let panel = Native::open(&self.inner.work_dir).context("打开自建 Xray 失败")?;
                panel.start().await?;
                Ok(Backend::Native(Arc::new(panel)))
            }
            PANEL_MODE_XCL => XCL::detect(self.inner.xcl_runtime.clone())
                .map(|panel| Backend::Xcl(Arc::new(panel)))
                .context("指定了 xray-cf-lite 模式但探测失败"),
            "" => {
                let mut reasons = Vec::new();
                match XUI::detect(&self.inner.work_dir).await {
                    Ok(panel) => return Ok(Backend::Xui(Arc::new(panel))),
                    Err(err) => reasons.push(format!("3x-ui: {err}")),
                }
                match XCL::detect(self.inner.xcl_runtime.clone()) {
                    Ok(panel) => return Ok(Backend::Xcl(Arc::new(panel))),
                    Err(err) => reasons.push(format!("xray-cf-lite: {err}")),
                }
                let native = Native::open(&self.inner.work_dir).map_err(|err| {
                    anyhow::anyhow!(
                        "没有可用的节点链接后端（{}；native: {err}）",
                        reasons.join("；")
                    )
                })?;
                native.start().await?;
                Ok(Backend::Native(Arc::new(native)))
            }
            _ => bail!("未知后端模式 {requested:?}"),
        }
    }

    /// Caller must hold `inner.operation`.
    async fn open_current_locked(&self) -> Result<Backend> {
        let (current, forced, closed) = {
            let state = lock_unpoisoned(&self.inner.state);
            (state.current.clone(), state.forced.clone(), state.closed)
        };
        if closed {
            bail!("节点链接后端已关闭");
        }
        if let Some(current) = current {
            return Ok(current);
        }
        let backend = self.open_backend(&forced).await?;
        lock_unpoisoned(&self.inner.state).current = Some(backend.clone());
        Ok(backend)
    }

    /// Caller must hold `inner.operation`.
    async fn refresh_backend_locked(
        &self,
        manager: &Manager,
        pools: &PoolService,
    ) -> Result<Backend> {
        let backend = self.open_current_locked().await?;
        let snapshot = collect_runtime_snapshot(manager, pools).await;
        // Install this even for Native/XUI so a later XCL detection starts with
        // a complete snapshot and every XCL clone observes the same state.
        self.inner.xcl_runtime.replace(snapshot.clone());
        backend.set_runtime(snapshot).await;
        Ok(backend)
    }

    /// Refresh a backend using explicitly supplied services and return a handle
    /// that prevents a concurrent mode switch from closing it mid-operation.
    pub async fn lock_current_panel_from(
        &self,
        manager: &Arc<Manager>,
        pools: &Arc<PoolService>,
    ) -> Result<CurrentPanel> {
        let operation = Arc::clone(&self.inner.operation).lock_owned().await;
        let backend = self.refresh_backend_locked(manager, pools).await?;
        Ok(CurrentPanel {
            panel: backend.panel(),
            _operation: operation,
        })
    }

    pub async fn lock_current_panel(&self) -> Result<CurrentPanel> {
        self.lock_current_panel_from(&self.inner.manager, &self.inner.pools)
            .await
    }

    /// Refresh a backend using explicitly supplied services and return the
    /// concrete backend erased as `dyn Panel`. HTTP wiring can use this without
    /// adding a panel field to `AppState`. Use [`Self::lock_current_panel_from`]
    /// when the returned panel will perform an operation.
    pub async fn refresh_snapshot_from(
        &self,
        manager: &Arc<Manager>,
        pools: &Arc<PoolService>,
    ) -> Result<Arc<dyn Panel>> {
        Ok(self.lock_current_panel_from(manager, pools).await?.panel())
    }

    pub async fn refresh_snapshot(&self) -> Result<()> {
        self.refresh_snapshot_from(&self.inner.manager, &self.inner.pools)
            .await
            .map(|_| ())
    }

    /// Open (if needed), refresh, and return the current backend.
    pub async fn current_panel(&self) -> Result<Arc<dyn Panel>> {
        self.refresh_snapshot_from(&self.inner.manager, &self.inner.pools)
            .await
    }

    /// Runtime mode switch. An empty mode restores automatic detection. The
    /// previous backend stays live until the replacement has been opened and
    /// supplied with a fresh snapshot.
    pub async fn switch_mode(&self, mode: &str) -> Result<Arc<dyn Panel>> {
        let mode = mode.trim();
        if !matches!(
            mode,
            "" | PANEL_MODE_XUI | PANEL_MODE_NATIVE | PANEL_MODE_XCL
        ) {
            bail!("未知后端模式 {mode:?}");
        }

        let _operation = self.inner.operation.lock().await;
        let (old, same) = {
            let state = lock_unpoisoned(&self.inner.state);
            if state.closed {
                bail!("节点链接后端已关闭");
            }
            (
                state.current.clone(),
                state.current.is_some() && state.forced.as_str() == mode,
            )
        };

        let backend = if same {
            old.expect("same mode implies a current backend")
        } else {
            self.open_backend(mode).await?
        };
        let snapshot = collect_runtime_snapshot(&self.inner.manager, &self.inner.pools).await;
        self.inner.xcl_runtime.replace(snapshot.clone());
        backend.set_runtime(snapshot).await;

        let old = {
            let mut state = lock_unpoisoned(&self.inner.state);
            state.forced = mode.to_string();
            state.current.replace(backend.clone())
        };
        if let Some(old) = old {
            if let Err(err) = old.close().await {
                tracing::warn!("关闭旧节点链接后端失败: {err}");
            }
        }
        if let Err(err) = save_panel_mode(&self.inner.work_dir, mode) {
            tracing::warn!("记录后端模式失败（本次切换仍然生效）: {err}");
        }
        Ok(backend.panel())
    }

    /// Probe all selectable backends using the same labels and JSON fields as
    /// the Go `availablePanelModes` response.
    pub async fn available_modes(&self) -> Vec<PanelMode> {
        let _operation = self.inner.operation.lock().await;
        let xcl = match XCL::detect(self.inner.xcl_runtime.clone()) {
            Ok(_) => (true, String::new()),
            Err(err) => (false, err.to_string()),
        };
        let xui = match XUI::detect(&self.inner.work_dir).await {
            Ok(_) => (true, String::new()),
            Err(err) => (false, err.to_string()),
        };
        vec![
            PanelMode {
                mode: PANEL_MODE_XCL.into(),
                label: "xray-cf-lite".into(),
                available: xcl.0,
                reason: xcl.1,
            },
            PanelMode {
                mode: PANEL_MODE_XUI.into(),
                label: "3x-ui 面板".into(),
                available: xui.0,
                reason: xui.1,
            },
            PanelMode {
                mode: PANEL_MODE_NATIVE.into(),
                label: "自建 Xray".into(),
                available: true,
                reason: String::new(),
            },
        ]
    }

    /// Build `GET /api/xui` without turning backend unavailability into an HTTP
    /// error, matching the Go handler.
    pub async fn status(&self) -> PanelStatus {
        let _operation = self.inner.operation.lock().await;
        let backend = match self
            .refresh_backend_locked(&self.inner.manager, &self.inner.pools)
            .await
        {
            Ok(backend) => backend,
            Err(err) => {
                return PanelStatus {
                    available: false,
                    kind: None,
                    describe: None,
                    can_create: None,
                    port: None,
                    base_path: None,
                    scheme: None,
                    host: None,
                    reason: Some(err.to_string()),
                };
            }
        };

        let mut status = PanelStatus {
            available: true,
            kind: Some(backend.kind().into()),
            describe: Some(backend.describe()),
            can_create: Some(!matches!(backend, Backend::Xcl(_))),
            port: None,
            base_path: None,
            scheme: None,
            host: None,
            reason: None,
        };
        if let Backend::Xui(panel) = backend {
            status.port = Some(panel.port);
            status.base_path = Some(panel.base_path.clone());
            status.scheme = Some(panel.scheme.clone());
            status.host = Some(panel.host.clone());
        }
        status
    }

    /// Idempotently close the active backend. `Manager::shutdown` already calls
    /// this through its registered `Panel`; callers may still call it directly.
    pub async fn close(&self) -> Result<()> {
        let _operation = self.inner.operation.lock().await;
        let old = {
            let mut state = lock_unpoisoned(&self.inner.state);
            state.closed = true;
            state.current.take()
        };
        if let Some(old) = old {
            old.close().await?;
        }
        Ok(())
    }
}

async fn collect_runtime_snapshot(manager: &Manager, pools: &PoolService) -> RuntimeSnapshot {
    let tunnels = manager.states().await;
    // Native emits every supplied pool as a SOCKS outbound, so pass only pools
    // with a live listener. `up == 0` is still valid: the listener remains in
    // place and must not silently turn into a direct connection.
    let pools = pools
        .views()
        .await
        .into_iter()
        .filter(|pool| pool.running)
        .collect();
    RuntimeSnapshot { tunnels, pools }
}

fn save_panel_mode(work_dir: &Path, mode: &str) -> Result<()> {
    if work_dir.as_os_str().is_empty() {
        return Ok(());
    }
    let path = panel_mode_file(work_dir);
    if mode.is_empty() {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    } else {
        util::atomic_write(path, mode.as_bytes(), 0o600)
    }
}

#[async_trait]
impl Panel for PanelManager {
    fn kind(&self) -> String {
        let state = lock_unpoisoned(&self.inner.state);
        if !state.forced.is_empty() {
            state.forced.clone()
        } else {
            state
                .current
                .as_ref()
                .map(Backend::kind)
                .unwrap_or_default()
                .to_string()
        }
    }

    fn describe(&self) -> String {
        let state = lock_unpoisoned(&self.inner.state);
        state.current.as_ref().map_or_else(
            || {
                if state.forced.is_empty() {
                    "节点链接后端尚未打开".to_string()
                } else {
                    format!("{}（尚未打开）", state.forced)
                }
            },
            Backend::describe,
        )
    }

    async fn inbounds(&self) -> Result<Vec<crate::models::Inbound>> {
        self.lock_current_panel().await?.inbounds().await
    }

    async fn inbound_detail(&self, id: &str, host: &str) -> Result<crate::models::InboundDetail> {
        self.lock_current_panel()
            .await?
            .inbound_detail(id, host)
            .await
    }

    async fn inbound_links(&self, ids: &[String], host: &str) -> Result<Vec<String>> {
        self.lock_current_panel()
            .await?
            .inbound_links(ids, host)
            .await
    }

    async fn bind(&self, tag: &str, host: &str) -> Result<()> {
        self.lock_current_panel().await?.bind(tag, host).await
    }

    async fn rebind(&self, old_host: &str, new_host: &str) -> Result<()> {
        self.lock_current_panel()
            .await?
            .rebind(old_host, new_host)
            .await
    }

    async fn resync_outbound(&self, host: &str) -> Result<()> {
        self.lock_current_panel().await?.resync_outbound(host).await
    }

    async fn clone_to_tunnels(&self, id: &str, hosts: &[String]) -> Result<Vec<u16>> {
        self.lock_current_panel()
            .await?
            .clone_to_tunnels(id, hosts)
            .await
    }

    async fn delete_inbounds(&self, ids: &[String]) -> Result<usize> {
        self.lock_current_panel().await?.delete_inbounds(ids).await
    }

    async fn create_inbound(
        &self,
        spec: &serde_json::Value,
    ) -> Result<crate::panel::CreatedInbound> {
        self.lock_current_panel().await?.create_inbound(spec).await
    }

    async fn update_inbound(&self, id: &str, patch: &crate::panel::InboundPatch) -> Result<()> {
        self.lock_current_panel()
            .await?
            .update_inbound(id, patch)
            .await
    }

    async fn add_client(&self, id: &str, email: &str) -> Result<()> {
        self.lock_current_panel().await?.add_client(id, email).await
    }

    async fn delete_client(&self, id: &str, email: &str) -> Result<()> {
        self.lock_current_panel()
            .await?
            .delete_client(id, email)
            .await
    }

    async fn reset_client(&self, id: &str, email: &str) -> Result<crate::models::ClientInfo> {
        self.lock_current_panel()
            .await?
            .reset_client(id, email)
            .await
    }

    async fn on_tunnels_changed(&self) -> Result<()> {
        self.lock_current_panel().await?.on_tunnels_changed().await
    }

    async fn close(&self) -> Result<()> {
        PanelManager::close(self).await
    }
}
