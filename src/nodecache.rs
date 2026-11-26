use crate::{
    models::Node,
    nodes::{fetch_nodes_scored, selectable_nodes},
};
use anyhow::Result;
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, Semaphore};

struct State {
    nodes: Vec<Node>,
    fetched_at: Option<std::time::Instant>,
}

#[derive(Clone)]
pub struct NodeCache {
    inner: Arc<Mutex<State>>,
    fetch_lock: Arc<Semaphore>,
}

impl Default for NodeCache {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                nodes: Vec::new(),
                fetched_at: None,
            })),
            fetch_lock: Arc::new(Semaphore::new(1)),
        }
    }
}

impl NodeCache {
    pub async fn nodes(&self, residential_only: bool) -> Vec<Node> {
        let s = self.inner.lock().await;
        selectable_nodes(&s.nodes, residential_only)
    }

    pub async fn all_nodes(&self) -> Vec<Node> {
        self.inner.lock().await.nodes.clone()
    }

    pub async fn fetched(&self) -> bool {
        self.inner.lock().await.fetched_at.is_some()
    }

    pub async fn ensure(
        &self,
        ttl: u64,
        score_mode: &str,
        residential_only: bool,
    ) -> Result<usize> {
        let _permit = self
            .fetch_lock
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("节点缓存已关闭"))?;
        {
            let s = self.inner.lock().await;
            if let Some(at) = s.fetched_at {
                if at.elapsed() < Duration::from_secs(ttl) {
                    return Ok(selectable_nodes(&s.nodes, residential_only).len());
                }
            }
        }
        let nodes = fetch_nodes_scored(Duration::from_secs(25), score_mode).await?;
        let mut s = self.inner.lock().await;
        s.nodes = nodes;
        s.fetched_at = Some(std::time::Instant::now());
        Ok(selectable_nodes(&s.nodes, residential_only).len())
    }

    pub async fn replace(&self, nodes: Vec<Node>) {
        let mut state = self.inner.lock().await;
        state.nodes = nodes;
        state.fetched_at = Some(std::time::Instant::now());
    }

    pub async fn refresh(&self, score_mode: &str, residential_only: bool) -> Result<usize> {
        {
            let mut s = self.inner.lock().await;
            s.fetched_at = None;
        }
        self.ensure(0, score_mode, residential_only).await
    }
}
