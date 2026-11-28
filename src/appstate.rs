use std::{path::PathBuf, sync::Arc};

use crate::{
    auth::Auth, manager::Manager, observability::ObservabilityStore, panel_runtime::PanelManager,
    pool_service::PoolService, warp_runtime::WarpService,
};

pub struct AppState {
    pub auth: Arc<Auth>,
    pub manager: Arc<Manager>,
    pub dir: PathBuf,
    pub basepath: String,
    pub warp: Arc<WarpService>,
    pub pools: Arc<PoolService>,
    pub panel: Arc<PanelManager>,
    pub observability: Arc<ObservabilityStore>,
}
