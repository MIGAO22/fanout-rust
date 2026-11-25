use std::{path::PathBuf, sync::Arc};

use axum::extract::FromRef;

use crate::{auth::Auth, manager::Manager};

pub struct AppState {
    pub auth: Arc<Auth>,
    pub manager: Arc<Manager>,
    pub dir: PathBuf,
    pub basepath: String,
}

impl FromRef<Arc<AppState>> for Arc<Manager> {
    fn from_ref(input: &Arc<AppState>) -> Self {
        input.manager.clone()
    }
}
