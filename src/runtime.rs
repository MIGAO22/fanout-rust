use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

use crate::models::{Node, SocksCred};
use crate::socks5::SocksDialer;

#[async_trait]
pub trait TunnelRuntime: Send + Sync {
    async fn start(&self, node: &Node) -> Result<String>;
    async fn stop(&self) -> Result<()>;
    async fn set_cred(&self, cred: SocksCred) -> Result<()>;
    async fn probe_exit_ip(&self) -> Result<String>;
    fn dead_reason(&self) -> Option<String>;
    async fn healthy(&self) -> bool;
    fn socks_dialer(&self) -> Arc<dyn SocksDialer>;
    async fn guard_transit(&self) -> Result<()> {
        Ok(())
    }
    async fn transit_status(&self) -> (String, bool) {
        (String::new(), false)
    }
}

pub trait TunnelFactory: Send + Sync {
    fn create(
        &self,
        slot: usize,
        port: u16,
        cred: SocksCred,
        dir: &std::path::Path,
    ) -> Arc<dyn TunnelRuntime>;
}
