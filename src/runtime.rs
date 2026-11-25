use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;

use crate::models::{Node, SocksCred};

#[async_trait]
pub trait TunnelRuntime: Send + Sync {
    async fn start(&self, node: &Node) -> Result<String>;
    async fn stop(&self) -> Result<()>;
    async fn set_cred(&self, cred: SocksCred) -> Result<()>;
    async fn probe_exit_ip(&self) -> Result<String>;
    fn dead_reason(&self) -> Option<String>;
    async fn healthy(&self) -> bool;
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
