use crate::{models::PersistedTunnel, util::atomic_write};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StateFile {
    pub tunnels: Vec<PersistedTunnel>,
}

pub fn load_state(dir: &Path) -> Result<StateFile> {
    match std::fs::read(dir.join("state.json")) {
        Ok(b) => Ok(serde_json::from_slice(&b)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StateFile::default()),
        Err(e) => Err(e.into()),
    }
}

pub fn save_state(dir: &Path, state: &StateFile) -> Result<()> {
    atomic_write(
        dir.join("state.json"),
        &serde_json::to_vec_pretty(state)?,
        0o600,
    )
}
