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
    async fn local_ready(&self) -> Result<()> {
        if self.healthy().await {
            Ok(())
        } else {
            anyhow::bail!("隧道本地健康检查失败")
        }
    }
    async fn verify_ready(&self, expected_ip: &str) -> Result<()> {
        self.local_ready().await?;
        let observed = self.probe_exit_ip().await?;
        if observed != expected_ip {
            anyhow::bail!("出口 IP 从 {expected_ip} 变成 {observed}");
        }
        Ok(())
    }
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
