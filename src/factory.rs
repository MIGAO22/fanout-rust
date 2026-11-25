use anyhow::{bail, Result};
use async_trait::async_trait;
use std::{path::Path, sync::Arc};
use tokio::sync::RwLock;

use crate::{
    models::{Node, SocksCred},
    runtime::{TunnelFactory, TunnelRuntime},
};

pub struct UnavailableRuntime {
    cred: RwLock<SocksCred>,
}

#[async_trait]
impl TunnelRuntime for UnavailableRuntime {
    async fn start(&self, _node: &Node) -> Result<String> {
        bail!("Linux netns/OpenVPN 运行时尚未接入")
    }
    async fn stop(&self) -> Result<()> {
        Ok(())
    }
    async fn set_cred(&self, cred: SocksCred) -> Result<()> {
        *self.cred.write().await = cred;
        Ok(())
    }
    async fn probe_exit_ip(&self) -> Result<String> {
        bail!("Linux netns/OpenVPN 运行时尚未接入")
    }
    fn dead_reason(&self) -> Option<String> {
        None
    }
    async fn healthy(&self) -> bool {
        false
    }
}

pub struct UnavailableFactory;

impl TunnelFactory for UnavailableFactory {
    fn create(
        &self,
        _slot: usize,
        _port: u16,
        cred: SocksCred,
        _dir: &Path,
    ) -> Arc<dyn TunnelRuntime> {
        Arc::new(UnavailableRuntime {
            cred: RwLock::new(cred),
        })
    }
}
