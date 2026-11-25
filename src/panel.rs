use crate::models::{ClientInfo, Inbound, InboundDetail};
use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InboundPatch {
    pub port: Option<u16>,
    pub remark: Option<String>,
    pub enable: Option<bool>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CreatedInbound {
    pub id: String,
    pub port: u16,
    pub protocol: String,
    pub remark: String,
    pub network: String,
    pub security: String,
}

#[async_trait]
pub trait Panel: Send + Sync {
    fn kind(&self) -> String;
    fn describe(&self) -> String;
    async fn inbounds(&self) -> Result<Vec<Inbound>>;
    async fn inbound_detail(&self, id: &str, host: &str) -> Result<InboundDetail>;
    async fn inbound_links(&self, ids: &[String], host: &str) -> Result<Vec<String>>;
    async fn bind(&self, tag: &str, host: &str) -> Result<()>;
    async fn rebind(&self, old_host: &str, new_host: &str) -> Result<()>;
    async fn resync_outbound(&self, host: &str) -> Result<()>;
    async fn clone_to_tunnels(&self, id: &str, hosts: &[String]) -> Result<Vec<u16>>;
    async fn delete_inbounds(&self, ids: &[String]) -> Result<usize>;
    async fn create_inbound(&self, spec: &serde_json::Value) -> Result<CreatedInbound>;
    async fn update_inbound(&self, id: &str, patch: &InboundPatch) -> Result<()>;
    async fn add_client(&self, id: &str, email: &str) -> Result<()>;
    async fn delete_client(&self, id: &str, email: &str) -> Result<()>;
    async fn reset_client(&self, id: &str, email: &str) -> Result<ClientInfo>;
    async fn on_tunnels_changed(&self) -> Result<()>;
    async fn close(&self) -> Result<()>;
}
