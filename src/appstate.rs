use std::{path::PathBuf, sync::Arc};

use crate::{auth::Auth, manager::Manager};

pub struct AppState {
    pub auth: Arc<Auth>,
    pub manager: Arc<Manager>,
    pub dir: PathBuf,
    pub basepath: String,
}
