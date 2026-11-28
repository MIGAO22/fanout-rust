use anyhow::{bail, Result};
use futures::StreamExt;
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    process::Stdio,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex as StdMutex,
    },
    task::JoinHandle,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    sync::{Mutex, RwLock, Semaphore},
};

use crate::{
    config::WebSettings,
    instance::Instance,
    jobs::JobHandle,
    manager::Manager,
    models::{Node, WarpOverview},
    netns::Netns,
    process::{output_command, start_tokio_command},
    util::atomic_write,
    warp_logic::{
        new_warp_reg_request, parse_warp_reg, parse_warp_store_full, parse_wg_dump,
        render_warp_store_with_audit, warp_account_of, warp_argv, warp_gate_ips, warp_gate_names,
        warp_guard_cmds, warp_key_for, warp_live_endpoint, warp_path_mtu, warp_setup_cmds,
        warp_split_cmds, WarpAccount, WarpAccountState, WarpAuditEvent, WarpSetupInput,
    },
};

const WARP_API_VER: &str = "v0a2317";
const WARP_CLIENT_VERSION: &str = "2026.8.2115.0";
const WARP_REGISTER_CONCURRENCY: usize = 2;
const WARP_REGISTER_ATTEMPTS: usize = 5;
const WARP_QUEUE_CAPACITY: usize = 32;
const WARP_AUDIT_LIMIT: usize = 256;
pub const WARP_HANDSHAKE_BUDGET: Duration = Duration::from_secs(15);

pub struct WarpService {
    dir: std::path::PathBuf,
    instance: Instance,
    settings: Arc<RwLock<WebSettings>>,
    accounts: Arc<Mutex<Vec<WarpAccount>>>,
    audit: Arc<Mutex<Vec<WarpAuditEvent>>>,
    slot_locks: Arc<Mutex<HashMap<usize, Arc<Mutex<()>>>>>,
    lock: Arc<Semaphore>,
    queue: Arc<Semaphore>,
    epoch: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
    next_lease_generation: Arc<AtomicU64>,
    prewarm_lock: Arc<Mutex<()>>,
    prewarm_task: StdMutex<Option<JoinHandle<()>>>,
    client: reqwest::Client,
}

impl WarpService {
    pub fn load(
        dir: &Path,
        instance: Instance,
        settings: Arc<RwLock<WebSettings>>,
    ) -> Result<Arc<Self>> {
        let blob = match std::fs::read(dir.join("warp.json")) {
            Ok(blob) => blob,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        let (accounts, mut audit) = if blob.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            parse_warp_store_full(&blob)?
        };
        if audit.is_empty() {
            audit = std::fs::read(dir.join("warp-audit.json"))
                .ok()
                .and_then(|blob| serde_json::from_slice::<Vec<WarpAuditEvent>>(&blob).ok())
                .unwrap_or_default();
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(25))
            .build()?;
        Ok(Arc::new(Self {
            dir: dir.to_path_buf(),
            instance,
            settings,
            accounts: Arc::new(Mutex::new(accounts)),
            audit: Arc::new(Mutex::new(audit)),
            slot_locks: Arc::new(Mutex::new(HashMap::new())),
            lock: Arc::new(Semaphore::new(WARP_REGISTER_CONCURRENCY)),
            queue: Arc::new(Semaphore::new(WARP_QUEUE_CAPACITY)),
            epoch: Arc::new(AtomicU64::new(0)),
            closed: Arc::new(AtomicBool::new(false)),
            next_lease_generation: Arc::new(AtomicU64::new(1)),
            prewarm_lock: Arc::new(Mutex::new(())),
            prewarm_task: StdMutex::new(None),
            client,
        }))
    }

    pub async fn all(&self) -> Vec<WarpAccount> {
        self.accounts.lock().await.clone()
    }

    pub async fn audit_events(&self) -> Vec<WarpAuditEvent> {
        self.audit.lock().await.clone()
    }

    pub async fn get(&self, slot: usize) -> Option<WarpAccount> {
        self.accounts
            .lock()
            .await
            .iter()
            .find(|account| account.slot == slot && account.state != WarpAccountState::Ready)
            .cloned()
    }

    async fn save(&self, accounts: &[WarpAccount]) -> Result<()> {
        let audit = self.audit.lock().await;
        atomic_write(
            self.dir.join("warp.json"),
            &render_warp_store_with_audit(accounts, &audit)?,
            0o600,
        )
    }

    async fn record_audit(&self, account: &WarpAccount, action: &str, result: &str, message: &str) {
        let mut audit = self.audit.lock().await;
        audit.push(WarpAuditEvent {
            at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            account_id: account.pool_id.clone(),
            cloud_id: account.id.clone(),
            slot: account.slot,
            lease_generation: account.lease_generation,
            action: action.to_string(),
            result: result.to_string(),
            message: message.to_string(),
        });
        let excess = audit.len().saturating_sub(WARP_AUDIT_LIMIT);
        if excess > 0 {
            audit.drain(..excess);
        }
        if let Ok(blob) = serde_json::to_vec_pretty(&*audit) {
            let _ = atomic_write(self.dir.join("warp-audit.json"), &blob, 0o600);
        }
    }

    async fn pool_settings(&self) -> crate::config::WarpPoolSettings {
        self.settings.read().await.warp().pool
    }

    async fn pool_enabled(&self) -> bool {
        self.pool_settings().await.enabled
    }

    fn lease_generation(&self) -> u64 {
        self.next_lease_generation.fetch_add(1, Ordering::AcqRel)
    }

    fn touch(account: &mut WarpAccount) {
        account.updated_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    }

    async fn register(&self, slot: usize, version: &str) -> Result<WarpAccount> {
        let (priv_key, pub_key) = crate::warp_logic::new_warp_keys()?;
        let req = new_warp_reg_request(&pub_key, version)?;
        for attempt in 0..WARP_REGISTER_ATTEMPTS {
            let resp = self
                .client
                .post(format!(
                    "https://api.cloudflareclient.com/{WARP_API_VER}/reg"
                ))
                .json(&req)
                .send()
                .await?;
            if resp.status() == 429 {
                let retry_after = resp
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or_else(|| (2_u64 << attempt).min(30))
                    .clamp(1, 60);
                if attempt + 1 == WARP_REGISTER_ATTEMPTS {
                    anyhow::bail!("Cloudflare 注册限流，重试 {} 次仍失败", attempt + 1);
                }
                tokio::time::sleep(Duration::from_secs(retry_after.max(1))).await;
                continue;
            }
            let resp = resp.error_for_status()?;
            let body = resp.bytes().await?;
            let parsed = parse_warp_reg(&body)?;
            return warp_account_of(
                slot,
                &parsed,
                &priv_key,
                &pub_key,
                version,
                chrono::Utc::now(),
            );
        }
        unreachable!("registration attempts are non-zero")
    }

    async fn slot_lock(&self, slot: usize) -> Arc<Mutex<()>> {
        let mut locks = self.slot_locks.lock().await;
        locks
            .entry(slot)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub async fn ensure(&self, slot: usize, version: &str) -> Result<WarpAccount> {
        let slot_lock = self.slot_lock(slot).await;
        let _slot_guard = slot_lock.lock().await;
        if !self.pool_enabled().await {
            let _permit = self
                .lock
                .acquire()
                .await
                .map_err(|_| anyhow::anyhow!("WARP 服务已关闭"))?;
            let existing = {
                let accounts = self.accounts.lock().await;
                accounts
                    .iter()
                    .find(|account| account.slot == slot)
                    .cloned()
            };
            if let Some(account) = existing.as_ref() {
                if account.version == version {
                    return Ok(account.clone());
                }
            }
            let account = self.register(slot, version).await?;
            let mut accounts = self.accounts.lock().await;
            let previous = accounts.clone();
            accounts.retain(|account| account.slot != slot);
            accounts.push(account.clone());
            if let Err(error) = self.save(&accounts).await {
                *accounts = previous;
                drop(accounts);
                if let Err(unregister_error) = unregister(&self.client, &account).await {
                    tracing::warn!("WARP 账号保存失败，云端清理也失败: {unregister_error}");
                }
                return Err(error);
            }
            drop(accounts);
            if let Some(old) = existing {
                if let Err(error) = unregister(&self.client, &old).await {
                    tracing::warn!("新 WARP 账号已保存，但注销旧账号失败: {error}");
                }
            }
            return Ok(account);
        }

        let _queue = self
            .queue
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("WARP 注册队列已满，请稍后重试"))?;
        let epoch = self.epoch.load(Ordering::Acquire);
        let _permit = self
            .lock
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("WARP 服务已关闭"))?;
        let existing = {
            let accounts = self.accounts.lock().await;
            accounts
                .iter()
                .find(|account| account.slot == slot && account.state == WarpAccountState::Leased)
                .cloned()
        };
        if let Some(account) = existing.as_ref() {
            if account.version == version {
                return Ok(account.clone());
            }
        }

        let pool = self.pool_settings().await;
        let ready = {
            let accounts = self.accounts.lock().await;
            accounts.iter().position(|account| {
                account.slot == 0
                    && account.state == WarpAccountState::Ready
                    && account.version == version
                    && !account_expired(account, pool.prewarm_ttl_secs)
            })
        };
        if let Some(index) = ready {
            let mut accounts = self.accounts.lock().await;
            let previous = accounts.clone();
            let account = &mut accounts[index];
            account.slot = slot;
            account.state = WarpAccountState::Leased;
            account.lease_generation = self.lease_generation();
            Self::touch(account);
            let assigned = account.clone();
            if let Err(error) = self.save(&accounts).await {
                *accounts = previous;
                return Err(error);
            }
            drop(accounts);
            self.record_audit(&assigned, "lease", "ok", "assigned ready account")
                .await;
            if let Some(old) = existing {
                self.retire_account(&old).await;
            }
            return Ok(assigned);
        }

        let mut account = self.register(0, version).await?;
        if epoch != self.epoch.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            let _ = unregister(&self.client, &account).await;
            anyhow::bail!("WARP 已关闭，放弃本次注册");
        }
        account.pool_id = format!("pool-{}", account.id);
        account.slot = slot;
        account.state = WarpAccountState::Leased;
        account.lease_generation = self.lease_generation();
        Self::touch(&mut account);
        let mut accounts = self.accounts.lock().await;
        let previous = accounts.clone();
        if let Some(old) = existing.as_ref() {
            if let Some(account) = accounts
                .iter_mut()
                .find(|account| account.pool_id == old.pool_id && account.id == old.id)
            {
                account.slot = 0;
                account.state = WarpAccountState::Retiring;
                Self::touch(account);
            }
        }
        accounts.push(account.clone());
        if let Err(error) = self.save(&accounts).await {
            *accounts = previous;
            drop(accounts);
            if let Err(unregister_error) = unregister(&self.client, &account).await {
                tracing::warn!("WARP 账号保存失败，云端清理也失败: {unregister_error}");
            }
            return Err(error);
        }
        drop(accounts);
        self.record_audit(&account, "register", "ok", "registered and leased")
            .await;
        if let Some(old) = existing {
            self.retire_account(&old).await;
        }
        Ok(account)
    }

    async fn retire_account(&self, account: &WarpAccount) -> Result<()> {
        {
            let mut accounts = self.accounts.lock().await;
            let previous = accounts.clone();
            if let Some(current) = accounts
                .iter_mut()
                .find(|current| current.pool_id == account.pool_id && current.id == account.id)
            {
                current.slot = 0;
                current.state = WarpAccountState::Retiring;
                Self::touch(current);
            }
            if let Err(error) = self.save(&accounts).await {
                *accounts = previous;
                return Err(error);
            }
        }
        match unregister(&self.client, account).await {
            Ok(()) => {
                let mut accounts = self.accounts.lock().await;
                let previous = accounts.clone();
                accounts.retain(|current| {
                    !(current.pool_id == account.pool_id && current.id == account.id)
                });
                if let Err(error) = self.save(&accounts).await {
                    *accounts = previous;
                    return Err(error);
                }
                drop(accounts);
                self.record_audit(account, "retire", "ok", "cloud account removed")
                    .await;
                Ok(())
            }
            Err(error) => {
                let mut accounts = self.accounts.lock().await;
                if let Some(current) = accounts
                    .iter_mut()
                    .find(|current| current.pool_id == account.pool_id && current.id == account.id)
                {
                    current.state = WarpAccountState::Failed;
                    current.last_error = Some(error.to_string());
                    Self::touch(current);
                }
                let _ = self.save(&accounts).await;
                self.record_audit(account, "retire", "failed", &error.to_string())
                    .await;
                Err(error)
            }
        }
    }

    pub async fn release(&self, slot: usize, account_id: &str) -> Result<()> {
        if !self.pool_enabled().await {
            return Ok(());
        }
        let slot_lock = self.slot_lock(slot).await;
        let _slot_guard = slot_lock.lock().await;
        let pool = self.pool_settings().await;
        let mut accounts = self.accounts.lock().await;
        let previous = accounts.clone();
        let Some(index) = accounts
            .iter()
            .position(|account| account.slot == slot && account.id == account_id)
        else {
            return Ok(());
        };
        let ready = accounts
            .iter()
            .filter(|account| account.slot == 0 && account.state == WarpAccountState::Ready)
            .count();
        let mut account = accounts[index].clone();
        account.slot = 0;
        account.lease_generation = 0;
        account.state = if ready < pool.size {
            WarpAccountState::Ready
        } else {
            WarpAccountState::Retiring
        };
        Self::touch(&mut account);
        accounts[index] = account.clone();
        if let Err(error) = self.save(&accounts).await {
            *accounts = previous;
            return Err(error);
        }
        drop(accounts);
        self.record_audit(&account, "release", "ok", "lease released")
            .await;
        if account.state == WarpAccountState::Retiring {
            self.retire_account(&account).await?;
        }
        Ok(())
    }

    pub async fn note_handshake_success(&self, slot: usize) {
        if !self.pool_enabled().await {
            return;
        }
        let mut accounts = self.accounts.lock().await;
        if let Some(account) = accounts
            .iter_mut()
            .find(|account| account.slot == slot && account.state == WarpAccountState::Leased)
        {
            if account.failure_count != 0 {
                account.failure_count = 0;
                account.last_error = None;
                Self::touch(account);
                let _ = self.save(&accounts).await;
            }
        }
    }

    pub async fn note_handshake_failure(&self, slot: usize) -> bool {
        if !self.pool_enabled().await {
            return false;
        }
        let threshold = self.pool_settings().await.rotate_after_failures;
        let mut accounts = self.accounts.lock().await;
        let Some(index) = accounts
            .iter()
            .position(|account| account.slot == slot && account.state == WarpAccountState::Leased)
        else {
            return false;
        };
        let previous = accounts.clone();
        let account = &mut accounts[index];
        account.failure_count = account.failure_count.saturating_add(1);
        account.last_error = Some("WARP handshake missing".into());
        Self::touch(account);
        let rotate = account.failure_count >= threshold;
        if rotate {
            account.slot = 0;
            account.state = WarpAccountState::Failed;
        }
        if let Err(error) = self.save(&accounts).await {
            *accounts = previous;
            return false;
        }
        let account = accounts[index].clone();
        drop(accounts);
        self.record_audit(
            &account,
            if rotate {
                "handshake_rotate"
            } else {
                "handshake_failure"
            },
            if rotate { "pending" } else { "recorded" },
            "WARP handshake missing",
        )
        .await;
        rotate
    }

    pub async fn refresh_pool(&self) {
        let settings = self.settings.read().await.warp();
        if settings.enabled && settings.pool.enabled && settings.pool.prewarm {
            self.start_prewarm();
        } else {
            self.stop_prewarm();
        }
    }

    fn start_prewarm(self: &Arc<Self>) {
        if self.closed.load(Ordering::Acquire) || lock_unpoisoned(&self.prewarm_task).is_some() {
            return;
        }
        let weak = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            loop {
                if let Some(service) = weak.upgrade() {
                    service.prewarm_once().await;
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
        *lock_unpoisoned(&self.prewarm_task) = Some(task);
    }

    fn stop_prewarm(&self) {
        if let Some(task) = lock_unpoisoned(&self.prewarm_task).take() {
            task.abort();
        }
    }

    async fn prewarm_once(&self) {
        let settings = self.settings.read().await.warp();
        if !settings.enabled || !settings.pool.enabled || !settings.pool.prewarm {
            return;
        }
        let _guard = self.prewarm_lock.lock().await;
        let ready = {
            let accounts = self.accounts.lock().await;
            accounts
                .iter()
                .filter(|account| {
                    account.slot == 0
                        && account.state == WarpAccountState::Ready
                        && !account_expired(account, settings.pool.prewarm_ttl_secs)
                })
                .count()
        };
        if ready >= settings.pool.size {
            return;
        }
        let Ok(_queue) = self.queue.clone().try_acquire_owned() else {
            return;
        };
        let Ok(_permit) = self.lock.acquire().await else {
            return;
        };
        let epoch = self.epoch.load(Ordering::Acquire);
        let version = settings
            .client_version
            .unwrap_or_else(|| WARP_CLIENT_VERSION.into());
        let mut account = match self.register(0, &version).await {
            Ok(account) => account,
            Err(error) => {
                tracing::warn!("WARP 预热注册失败: {error}");
                return;
            }
        };
        if epoch != self.epoch.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            let _ = unregister(&self.client, &account).await;
            return;
        }
        account.pool_id = format!("pool-{}", account.id);
        account.state = WarpAccountState::Ready;
        Self::touch(&mut account);
        let mut accounts = self.accounts.lock().await;
        let previous = accounts.clone();
        accounts.push(account.clone());
        if let Err(error) = self.save(&accounts).await {
            *accounts = previous;
            drop(accounts);
            let _ = unregister(&self.client, &account).await;
            return;
        }
        drop(accounts);
        self.record_audit(&account, "prewarm", "ok", "ready account created")
            .await;
    }

    pub async fn shutdown(&self) {
        self.closed.store(true, Ordering::Release);
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.stop_prewarm();
    }

    pub async fn rotate(&self, slot: usize, version: &str) -> Result<WarpAccount> {
        let slot_lock = self.slot_lock(slot).await;
        let _slot_guard = slot_lock.lock().await;
        if !self.pool_enabled().await {
            let _permit = self
                .lock
                .acquire()
                .await
                .map_err(|_| anyhow::anyhow!("WARP 服务已关闭"))?;
            let old = {
                let accounts = self.accounts.lock().await;
                accounts
                    .iter()
                    .find(|account| account.slot == slot)
                    .cloned()
            };
            let account = self.register(slot, version).await?;
            let mut accounts = self.accounts.lock().await;
            let previous = accounts.clone();
            accounts.retain(|account| account.slot != slot);
            accounts.push(account.clone());
            if let Err(error) = self.save(&accounts).await {
                *accounts = previous;
                drop(accounts);
                let _ = unregister(&self.client, &account).await;
                return Err(error);
            }
            drop(accounts);
            if let Some(old) = old {
                if let Err(error) = unregister(&self.client, &old).await {
                    tracing::warn!("新 WARP 账号已保存，但注销旧账号失败: {error}");
                }
            }
            return Ok(account);
        }

        let _queue = self
            .queue
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("WARP 注册队列已满，请稍后重试"))?;
        let epoch = self.epoch.load(Ordering::Acquire);
        let _permit = self
            .lock
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("WARP 服务已关闭"))?;
        let old = {
            let accounts = self.accounts.lock().await;
            accounts
                .iter()
                .find(|account| account.slot == slot && account.state == WarpAccountState::Leased)
                .cloned()
        };
        let mut account = self.register(0, version).await?;
        if epoch != self.epoch.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire) {
            let _ = unregister(&self.client, &account).await;
            anyhow::bail!("WARP 已关闭，放弃本次轮换");
        }
        account.pool_id = format!("pool-{}", account.id);
        account.slot = slot;
        account.state = WarpAccountState::Leased;
        account.lease_generation = self.lease_generation();
        Self::touch(&mut account);
        let mut accounts = self.accounts.lock().await;
        let previous = accounts.clone();
        if let Some(old) = old.as_ref() {
            if let Some(current) = accounts
                .iter_mut()
                .find(|current| current.pool_id == old.pool_id && current.id == old.id)
            {
                current.slot = 0;
                current.state = WarpAccountState::Retiring;
                Self::touch(current);
            }
        }
        accounts.push(account.clone());
        if let Err(error) = self.save(&accounts).await {
            *accounts = previous;
            drop(accounts);
            let _ = unregister(&self.client, &account).await;
            return Err(error);
        }
        drop(accounts);
        self.record_audit(&account, "rotate", "ok", "lease rotated")
            .await;
        if let Some(old) = old {
            self.retire_account(&old).await;
        }
        Ok(account)
    }

    pub async fn remove(&self, slot: usize) -> Result<()> {
        let slot_lock = self.slot_lock(slot).await;
        let _slot_guard = slot_lock.lock().await;
        if self.pool_enabled().await {
            let existing = {
                let accounts = self.accounts.lock().await;
                accounts
                    .iter()
                    .find(|account| {
                        account.slot == slot && account.state == WarpAccountState::Leased
                    })
                    .cloned()
            };
            return if let Some(account) = existing {
                self.retire_account(&account).await
            } else {
                Ok(())
            };
        }
        let _permit = self
            .lock
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("WARP 服务已关闭"))?;
        let existing = {
            let accounts = self.accounts.lock().await;
            accounts.iter().find(|a| a.slot == slot).cloned()
        };
        if let Some(account) = existing {
            unregister(&self.client, &account).await?;
        }
        let mut accounts = self.accounts.lock().await;
        let previous = accounts.clone();
        accounts.retain(|a| a.slot != slot);
        if let Err(error) = self.save(&accounts).await {
            *accounts = previous;
            return Err(error);
        }
        Ok(())
    }

    pub async fn prune(&self, active_slots: &std::collections::HashSet<usize>) -> Result<()> {
        let pool_enabled = self.pool_enabled().await;
        let pool = self.pool_settings().await;
        let candidates = {
            let accounts = self.accounts.lock().await;
            accounts
                .iter()
                .filter(|account| {
                    if pool_enabled {
                        (account.slot > 0 && !active_slots.contains(&account.slot))
                            || matches!(
                                account.state,
                                WarpAccountState::Retiring | WarpAccountState::Failed
                            )
                            || (account.slot == 0
                                && account.state == WarpAccountState::Ready
                                && account_expired(account, pool.prewarm_ttl_secs))
                    } else {
                        !active_slots.contains(&account.slot)
                    }
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        if candidates.is_empty() {
            return Ok(());
        }
        let mut slot_guards = Vec::with_capacity(candidates.len());
        for account in &candidates {
            let lock = self.slot_lock(account.slot).await;
            slot_guards.push(lock.lock_owned().await);
        }
        let _permit = self
            .lock
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("WARP 服务已关闭"))?;
        let removed = {
            let accounts = self.accounts.lock().await;
            accounts
                .iter()
                .filter(|account| {
                    candidates.iter().any(|candidate| {
                        candidate.slot == account.slot
                            && candidate.id == account.id
                            && candidate.token == account.token
                    })
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        if removed.is_empty() {
            return Ok(());
        }
        let results = futures::future::join_all(
            removed
                .iter()
                .map(|account| unregister(&self.client, account)),
        )
        .await;
        let mut removed_ids = HashSet::new();
        for (account, result) in removed.iter().zip(results) {
            match result {
                Ok(()) => {
                    removed_ids.insert((account.slot, account.id.clone(), account.token.clone()));
                }
                Err(error) => tracing::warn!("清理 WARP 账号 {} 失败: {error}", account.slot),
            }
        }
        let mut accounts = self.accounts.lock().await;
        let previous = accounts.clone();
        accounts.retain(|account| {
            !removed_ids.contains(&(account.slot, account.id.clone(), account.token.clone()))
        });
        if let Err(error) = self.save(&accounts).await {
            *accounts = previous;
            return Err(error);
        }
        drop(accounts);
        for account in removed.iter().filter(|account| {
            removed_ids.contains(&(account.slot, account.id.clone(), account.token.clone()))
        }) {
            self.record_audit(account, "prune", "ok", "inactive account removed")
                .await;
        }
        Ok(())
    }

    pub async fn drop_all(&self) -> Result<()> {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.stop_prewarm();
        let _permit = self
            .lock
            .acquire()
            .await
            .map_err(|_| anyhow::anyhow!("WARP 服务已关闭"))?;
        let existing = self.all().await;
        let results = futures::future::join_all(
            existing
                .iter()
                .map(|account| unregister(&self.client, account)),
        )
        .await;
        let failed: HashSet<_> = existing
            .iter()
            .zip(results)
            .filter_map(|(account, result)| {
                if let Err(error) = result {
                    tracing::warn!("清理 WARP 账号 {} 失败: {error}", account.slot);
                    Some((account.slot, account.id.clone()))
                } else {
                    None
                }
            })
            .collect();
        let mut accounts = self.accounts.lock().await;
        let previous = accounts.clone();
        accounts.retain(|account| failed.contains(&(account.slot, account.id.clone())));
        if let Err(error) = self.save(&accounts).await {
            *accounts = previous;
            return Err(error);
        }
        drop(accounts);
        for account in existing
            .iter()
            .filter(|account| !failed.contains(&(account.slot, account.id.clone())))
        {
            self.record_audit(account, "drop_all", "ok", "cloud account removed")
                .await;
        }
        Ok(())
    }

    pub async fn setup(&self, ns: &Netns, node: &Node) -> Result<WarpAccount> {
        let settings = self.settings.read().await.clone();
        let version = settings
            .warp()
            .client_version
            .unwrap_or_else(|| WARP_CLIENT_VERSION.into());
        let a = self.ensure(ns.slot, &version).await?;
        let mtu = warp_path_mtu(true, 1500).0;
        let mut direct = vec!["8.8.8.8".to_string()];
        let lookups = futures::future::join_all(warp_gate_names(&node.config).into_iter().map(
            |host| async move {
                let addrs = tokio::net::lookup_host((host.as_str(), 0)).await?;
                Ok::<Vec<std::net::SocketAddr>, std::io::Error>(addrs.collect())
            },
        ))
        .await;
        for result in lookups {
            if let Ok(addrs) = result {
                for addr in addrs
                    .into_iter()
                    .filter(|a| matches!(a, std::net::SocketAddr::V4(_)))
                {
                    let ip = addr.ip().to_string();
                    if !direct.contains(&ip) {
                        direct.push(ip);
                    }
                }
            }
        }
        let cmds = warp_setup_cmds(&WarpSetupInput {
            dev: a.dev_name(&self.instance.tag),
            peer_key: a.peer_key.clone(),
            endpoint: a.endpoint.clone(),
            port: a.port,
            tun_ip: a.tun_ip.clone(),
            mtu,
            veth_gw: ns.gateway(),
            veth: ns.peer(),
            direct_ips: direct,
        });
        let private_key = Arc::new(a.priv_key.clone());
        let mut routes = Vec::new();
        let mut ordered = Vec::new();
        for command in cmds {
            if command.first().map(String::as_str) == Some("ip")
                && command.get(1).map(String::as_str) == Some("route")
                && command.get(3).is_some_and(|target| target.ends_with("/32"))
            {
                routes.push(command);
            } else {
                ordered.push(command);
            }
        }
        for result in futures::future::join_all(routes.into_iter().map(|command| {
            let private_key = private_key.clone();
            async move { run_warp(ns, &command, &private_key).await }
        }))
        .await
        {
            result?;
        }
        for command in ordered {
            run_warp(ns, &command, &private_key).await?;
        }
        let ips = warp_gate_ips(&node.config, &node.ip);
        let pins = crate::warp_logic::warp_gate_pin_cmds(&a.dev_name(&self.instance.tag), &ips);
        for result in futures::future::join_all(
            pins.into_iter()
                .map(|command| async move { run_warp(ns, &command, "").await }),
        )
        .await
        {
            result?;
        }
        Ok(a)
    }

    pub async fn split(&self, ns: &Netns, node: &Node, a: &WarpAccount) -> Result<()> {
        let commands = warp_split_cmds(
            &a.dev_name(&self.instance.tag),
            "tun0",
            &warp_gate_ips(&node.config, &node.ip),
        );
        for result in futures::future::join_all(
            commands
                .into_iter()
                .map(|command| async move { run_warp(ns, &command, "").await }),
        )
        .await
        {
            result?;
        }
        Ok(())
    }

    pub async fn guard(&self, ns: &Netns, node: &Node, a: &WarpAccount) -> Result<bool> {
        let out = output_command(
            "ip",
            &[
                "netns".into(),
                "exec".into(),
                ns.name(),
                "ip".into(),
                "-o".into(),
                "route".into(),
                "show".into(),
            ],
        )?;
        let state = crate::warp_logic::parse_warp_routes(
            &String::from_utf8_lossy(&out.stdout),
            &a.dev_name(&self.instance.tag),
        );
        if !crate::warp_logic::warp_guard_needed(&state) {
            return Ok(false);
        }
        let commands = warp_guard_cmds(
            &a.dev_name(&self.instance.tag),
            "tun0",
            &warp_gate_ips(&node.config, &node.ip),
            state.tun_up,
        );
        for result in futures::future::join_all(
            commands
                .into_iter()
                .map(|command| async move { run_warp(ns, &command, "").await }),
        )
        .await
        {
            result?;
        }
        Ok(true)
    }

    pub async fn status(&self, ns: &Netns, slot: usize) -> (String, bool) {
        let Ok(accounts) = self.accounts.try_lock() else {
            return (String::new(), false);
        };
        let Some(a) = accounts.iter().find(|a| a.slot == slot) else {
            return (String::new(), false);
        };
        let dev = a.dev_name(&self.instance.tag);
        let args = vec![
            "netns".into(),
            "exec".into(),
            ns.name(),
            "wg".into(),
            "show".into(),
            dev,
            "dump".into(),
        ];
        let Ok(out) = output_command("ip", &args) else {
            return (a.endpoint.clone(), false);
        };
        let peers = parse_wg_dump(&String::from_utf8_lossy(&out.stdout));
        let (ep, live) = warp_live_endpoint(&peers, proc_uptime(), chrono::Utc::now().timestamp());
        (
            if ep.is_empty() {
                a.endpoint.clone()
            } else {
                ep
            },
            live,
        )
    }

    pub async fn wait(&self, ns: &Netns, slot: usize, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.status(ns, slot).await.1 {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    pub async fn reregister(&self, manager: &Arc<Manager>, job: JobHandle) -> Result<()> {
        let settings = self.settings.read().await.clone();
        if !settings.warp().enabled {
            bail!("中转还没打开，开了才谈得上重新注册");
        }
        let tunnels = manager.tunnels().await;
        if tunnels.is_empty() {
            bail!("现在没有出口，没有可重新注册的线路");
        }
        let version = settings
            .warp()
            .client_version
            .unwrap_or_else(|| WARP_CLIENT_VERSION.into());
        let offset = if crate::clients::has_cmd("wg") { 0 } else { 1 };
        if !crate::clients::has_cmd("wg") {
            let at = 0;
            job.set(at, "running", "正在安装 wireguard-tools").await;
            let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
            let plan = match crate::clients::wireguard_install_plan(
                &os_release,
                crate::clients::has_cmd,
            ) {
                Ok((steps, _)) => steps,
                Err(err) => {
                    job.set(at, "failed", &err.to_string()).await;
                    job.finish().await;
                    return Err(err);
                }
            };
            for command in plan {
                if let Err(err) =
                    crate::clients::run_repo_query(&command, Duration::from_secs(10 * 60))
                {
                    job.set(at, "failed", &err.to_string()).await;
                    job.finish().await;
                    return Err(err);
                }
            }
            job.set(at, "ok", "wg 已就位").await;
        }
        let mut tasks =
            futures::stream::iter(tunnels.into_iter().enumerate().map(|(index, tunnel)| {
                let at = index + offset;
                let job = job.clone();
                let version = version.clone();
                async move {
                    let host = tunnel.host().await;
                    job.set(at, "running", "正在重新注册").await;
                    let _ = tunnel.runtime.stop().await;
                    let account = match self.rotate(tunnel.slot, &version).await {
                        Ok(account) => account,
                        Err(err) => {
                            manager.reconnect(tunnel.clone(), host).await;
                            job.set(at, "failed", &err.to_string()).await;
                            return;
                        }
                    };
                    manager.reconnect(tunnel.clone(), host).await;
                    let ns = Netns::new(self.instance.clone(), tunnel.slot);
                    if self.wait(&ns, tunnel.slot, Duration::from_secs(120)).await {
                        job.set(at, "ok", &format!("Cloudflare 接入 {}", account.endpoint))
                            .await;
                    } else {
                        job.set(at, "failed", "WARP 握手超时").await;
                    }
                }
            }))
            .buffer_unordered(WARP_REGISTER_CONCURRENCY);
        while futures::StreamExt::next(&mut tasks).await.is_some() {}
        drop(tasks);
        job.finish().await;
        Ok(())
    }

    pub async fn overview(&self) -> WarpOverview {
        let settings = self.settings.read().await.clone();
        let accounts = self.all().await;
        let audit = self.audit_events().await;
        let version = settings
            .warp()
            .client_version
            .unwrap_or_else(|| WARP_CLIENT_VERSION.into());
        let (ready, reason, need_tools, pkg_cmd) = if crate::clients::has_cmd("wg") {
            (true, String::new(), false, String::new())
        } else {
            let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
            match crate::clients::wireguard_install_plan(&os_release, crate::clients::has_cmd) {
                Ok((steps, _)) => (
                    true,
                    String::new(),
                    true,
                    steps
                        .iter()
                        .map(|step| step.join(" "))
                        .collect::<Vec<_>>()
                        .join(" && "),
                ),
                Err(err) => (false, err.to_string(), false, String::new()),
            }
        };
        WarpOverview {
            enabled: settings.warp().enabled,
            ready,
            reason,
            need_tools,
            pkg_cmd,
            last_err: String::new(),
            version: version.clone(),
            count: accounts.len(),
            live: 0,
            stale: accounts
                .iter()
                .filter(|account| account.version != version)
                .count(),
            pool_enabled: settings.warp().pool.enabled,
            pool_size: settings.warp().pool.size,
            pool_ready: accounts
                .iter()
                .filter(|account| account.state == WarpAccountState::Ready)
                .count(),
            pool_leased: accounts
                .iter()
                .filter(|account| account.state == WarpAccountState::Leased)
                .count(),
            pool_retiring: accounts
                .iter()
                .filter(|account| account.state == WarpAccountState::Retiring)
                .count(),
            pool_failed: accounts
                .iter()
                .filter(|account| account.state == WarpAccountState::Failed)
                .count(),
            prewarm: settings.warp().pool.prewarm,
            audit,
        }
    }
}

async fn unregister(client: &reqwest::Client, account: &WarpAccount) -> Result<()> {
    if account.id.is_empty() || account.token.is_empty() {
        return Ok(());
    }
    let response = client
        .delete(format!(
            "https://api.cloudflareclient.com/{WARP_API_VER}/reg/{}",
            account.id
        ))
        .bearer_auth(&account.token)
        .send()
        .await?;
    if matches!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::GONE
    ) {
        return Ok(());
    }
    response.error_for_status()?;
    Ok(())
}

async fn run_warp(ns: &Netns, command: &[String], private_key: &str) -> Result<()> {
    let (program, args) = warp_argv(&ns.name(), command);
    let mut c = tokio::process::Command::new(program);
    c.args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = start_tokio_command(&mut c)?;
    let key = warp_key_for(command, private_key);
    if !key.is_empty() {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(key.as_bytes()).await?;
        }
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        bail!(
            "{} {}: {}",
            command.first().map(String::as_str).unwrap_or(""),
            command.get(1).map(String::as_str).unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn account_expired(account: &WarpAccount, ttl_secs: u64) -> bool {
    chrono::DateTime::parse_from_rfc3339(&account.created_at)
        .map(|created| {
            chrono::Utc::now()
                .signed_duration_since(created)
                .num_seconds()
                .max(0) as u64
                > ttl_secs
        })
        .unwrap_or(true)
}

fn proc_uptime() -> i64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|v| v as i64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "warp_runtime_test.rs"]
mod tests;
