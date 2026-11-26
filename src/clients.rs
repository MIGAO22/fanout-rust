//! Client updates and version planning ported from fanout's clientbin.go,
//! ovpnsrc.go and update.go.
//!
//! The pure functions in this module deliberately accept probes/fetchers where
//! the Go code accepted callbacks.  That keeps the security-sensitive decisions
//! testable without touching the host package manager or the network.

#![allow(clippy::too_many_arguments)]

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    future::Future,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub use crate::models::UpdateStatus;
use crate::models::{ClientBinStatus, JobStep, JobView};
use crate::util::{atomic_write, first_line, one_line, path_string, random_token, write_file};

#[cfg(test)]
#[path = "clients_test.rs"]
mod tests;

pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const XRAY_RELEASE_REPO: &str = "XTLS/Xray-core";
pub const OPENVPN_RELEASE_REPO: &str = "OpenVPN/openvpn";
pub const UPDATE_REPO: &str = "MIGAO22/fanout-rust";
pub const OS_RELEASE_PATH: &str = "/etc/os-release";

pub const OVPN_APT_BASE: &str = "https://build.openvpn.net/debian/openvpn";
pub const OVPN_APT_KEY_URL: &str = "https://swupdate.openvpn.net/repos/repo-public.gpg";
pub const OVPN_APT_KEY_SHA256: &str =
    "1937b44fbdf4cbe0e187d25fda81dff000bfc9a614975cfb8db83e8945ce710d";
pub const OVPN_APT_KEYRING: &str = "/etc/apt/keyrings/fanout-openvpn-repo-public.asc";
pub const OVPN_APT_SOURCES: &str = "/etc/apt/sources.list.d/fanout-openvpn.list";
pub const OVPN_APT_MARKER: &str = "build.openvpn.net/debian/openvpn";
pub const OVPN_APT_CHANNELS: &[&str] = &["release/2.7", "stable"];

pub const OVPN_SRC_PREFIX_BASE: &str = "/usr/local/fanout-openvpn";
pub const OVPN_SRC_STATE_DIR: &str = "/var/lib/fanout/openvpn";
pub const OVPN_SRC_RECORD_FILE: &str = "/var/lib/fanout/openvpn/source.json";
pub const OVPN_SRC_KEY_FILE: &str = "/var/lib/fanout/openvpn/release-signing.pgp";
pub const OVPN_SRC_GNU_DIR: &str = "/var/lib/fanout/openvpn/gnupg";
pub const OVPN_SRC_KEY_URL_BASE: &str = "https://keys.openpgp.org/vks/v1/by-fingerprint/";
pub const OVPN_SRC_SIGNERS: &[&str] = &["F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7"];

pub const WARP_CLIENT_VERSION: &str = "2026.8.2115.0";
pub const WARP_PKG_INDEX: &str =
    "https://pkg.cloudflareclient.com/dists/%s/main/binary-amd64/Packages";
pub const WARP_CODENAMES: &str = "noble,bookworm,jammy,trixie";
pub const WIREGUARD_PKG: &str = "wireguard-tools";

const REPO_REFRESH_TIMEOUT: Duration = Duration::from_secs(45);
const REPO_QUERY_TIMEOUT: Duration = Duration::from_secs(60);
const REFRESH_RETRY_WAIT: Duration = Duration::from_secs(6);
const PACKAGE_COMMAND_TIMEOUT: Duration = Duration::from_secs(10 * 60);

static XRAY_APPLY_LOCK: Mutex<()> = Mutex::const_new(());
static OPENVPN_APPLY_LOCK: Mutex<()> = Mutex::const_new(());
static UPDATE_APPLY_LOCK: Mutex<()> = Mutex::const_new(());
static OVPN_BUILD_ON: AtomicBool = AtomicBool::new(false);

// ───────────────────────── releases and self-update ─────────────────────────

fn deserialize_null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseAsset {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(
        rename = "browser_download_url",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub url: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub digest: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseInfo {
    #[serde(
        rename = "tag_name",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub tag_name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub body: String,
    #[serde(
        rename = "html_url",
        default,
        deserialize_with = "deserialize_null_default"
    )]
    pub html_url: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    pub assets: Vec<ReleaseAsset>,
}

pub fn update_repo_name() -> String {
    env::var("FANOUT_UPDATE_REPO")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| UPDATE_REPO.to_string())
}

pub fn asset_arch() -> String {
    match env::consts::ARCH {
        "x86_64" => "amd64".into(),
        "aarch64" => "arm64".into(),
        other => other.to_string(),
    }
}

fn runtime_go_arch() -> String {
    match env::consts::ARCH {
        "x86" => "386".into(),
        other => asset_arch(),
    }
}

pub async fn fetch_latest_release() -> Result<ReleaseInfo> {
    fetch_release_latest(&update_repo_name()).await
}

pub async fn fetch_release_latest(repo: &str) -> Result<ReleaseInfo> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("fanout-updater")
        .build()?;
    let response = client
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .with_context(|| format!("请求 {url} 失败"))?;
    if response.status() != reqwest::StatusCode::OK {
        bail!("GitHub 返回 HTTP {}", response.status().as_u16());
    }
    response
        .json::<ReleaseInfo>()
        .await
        .with_context(|| format!("解析 {repo} 的 release 失败"))
}

pub fn release_tag(tag: &str) -> (String, bool) {
    let t = tag.trim().strip_prefix('v').unwrap_or_else(|| tag.trim());
    if t.is_empty() {
        return (String::new(), false);
    }
    for segment in t.split('.') {
        if segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_digit()) {
            return (String::new(), false);
        }
    }
    (t.to_string(), true)
}

pub async fn release_latest_tag(repo: &str) -> Result<String> {
    let release = fetch_release_latest(repo).await?;
    let (tag, stable) = release_tag(&release.tag_name);
    if stable {
        Ok(tag)
    } else {
        bail!("{} 的最新版 tag {:?} 不像稳定版号", repo, release.tag_name)
    }
}

pub fn parse_semver(value: &str) -> ([u64; 3], bool) {
    let mut out = [0_u64; 3];
    let mut value = value.trim();
    value = value.strip_prefix('v').unwrap_or(value);
    if let Some(end) = value.find(['-', '+']) {
        value = &value[..end];
    }
    let parts: Vec<_> = value.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return (out, false);
    }
    for (i, part) in parts.iter().enumerate() {
        match part.parse::<u64>() {
            Ok(number) => out[i] = number,
            Err(_) => return (out, false),
        }
    }
    (out, true)
}

/// Go's update version comparison: at most three numeric components, suffix
/// ignorance, and a conservative update for dev/unparseable builds.
pub fn version_less(current: &str, latest: &str) -> bool {
    if latest.is_empty() {
        return false;
    }
    if current.is_empty() || current == "dev" {
        return true;
    }
    let (current_numbers, current_ok) = parse_semver(current);
    let (latest_numbers, latest_ok) = parse_semver(latest);
    if !current_ok || !latest_ok {
        return current != latest;
    }
    current_numbers < latest_numbers
}

pub async fn check_update() -> Result<UpdateStatus> {
    check_update_with(|| async { fetch_latest_release().await }).await
}

pub async fn check_update_with<F, Fut>(fetch: F) -> Result<UpdateStatus>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<ReleaseInfo>>,
{
    let release = fetch().await?;
    let current = CURRENT_VERSION.trim().to_string();
    let latest = release.tag_name.trim().to_string();
    Ok(UpdateStatus {
        has_update: version_less(&current, &latest),
        current,
        latest,
        notes: release.body.trim().to_string(),
        url: release.html_url,
    })
}

pub async fn download_file(url: &str, destination: &Path) -> Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("fanout-updater")
        .build()?;
    let mut response = client.get(url).send().await?;
    if response.status() != reqwest::StatusCode::OK {
        bail!("HTTP {}", response.status().as_u16());
    }
    let mut output = File::create(destination)
        .with_context(|| format!("创建 {} 失败", destination.display()))?;
    while let Some(chunk) = response.chunk().await? {
        output.write_all(&chunk)?;
    }
    output.sync_all()?;
    Ok(())
}

async fn fetch_http_text(
    url: &str,
    user_agent: &str,
    timeout: Duration,
    limit: usize,
) -> Result<String> {
    let client = Client::builder()
        .timeout(timeout)
        .user_agent(user_agent)
        .build()?;
    let mut response = client.get(url).send().await?;
    if response.status() != reqwest::StatusCode::OK {
        bail!("HTTP {}", response.status().as_u16());
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("索引超过 {limit} 字节上限");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > limit {
            bail!("索引超过 {limit} 字节上限");
        }
        body.extend_from_slice(&chunk);
    }
    if body.is_empty() {
        bail!("索引是空的");
    }
    String::from_utf8(body).context("索引不是 UTF-8 文本")
}

pub async fn apply_update() -> Result<()> {
    apply_update_with(|| async { fetch_latest_release().await }).await
}

pub async fn apply_update_with<F, Fut>(fetch: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<ReleaseInfo>>,
{
    let _guard = UPDATE_APPLY_LOCK.lock().await;
    let release = fetch().await?;
    let arch = asset_arch();
    let asset_name = format!("fanout-linux-{arch}.tar.gz");
    let mut asset_url = String::new();
    let mut sums_url = String::new();
    for asset in &release.assets {
        match asset.name.as_str() {
            name if name == asset_name => asset_url = asset.url.clone(),
            "checksums.txt" => sums_url = asset.url.clone(),
            _ => {}
        }
    }
    if asset_url.is_empty() {
        bail!("最新版里找不到适配 {arch} 的包");
    }

    let temporary = tempfile::Builder::new()
        .prefix("fanout-update-")
        .tempdir()?;
    let tar_path = temporary.path().join(&asset_name);
    download_file(&asset_url, &tar_path)
        .await
        .context("下载失败")?;
    if !sums_url.is_empty() {
        verify_checksum(&tar_path, &asset_name, &sums_url).await?;
    }
    let new_binary = temporary.path().join("fanout");
    extract_binary(&tar_path, "fanout", &new_binary).context("解包失败")?;

    let executable = env::current_exe().context("定位当前程序失败")?;
    let executable = fs::canonicalize(&executable).unwrap_or(executable);
    let staged = sibling_path(&executable, ".new");
    copy_file_mode(&new_binary, &staged, 0o755).context("写入新版本失败")?;
    if let Err(error) = fs::rename(&staged, &executable) {
        let _ = fs::remove_file(&staged);
        return Err(error).context("替换二进制失败");
    }

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(800)).await;
        restart_self();
    });
    Ok(())
}

pub async fn verify_checksum(path: &Path, name: &str, sums_url: &str) -> Result<()> {
    let sums = path
        .parent()
        .ok_or_else(|| anyhow!("包路径没有父目录"))?
        .join("checksums.txt");
    download_file(sums_url, &sums)
        .await
        .context("下载校验和失败")?;
    let expected = sha256_from_list(&sums, name)?;
    let actual = sha256_file(path)?;
    if !expected.eq_ignore_ascii_case(&actual) {
        bail!("校验和不匹配，包可能损坏");
    }
    Ok(())
}

pub fn sha256_from_list(list_path: &Path, name: &str) -> Result<String> {
    let blob = fs::read_to_string(list_path)?;
    for line in blob.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() == 2 && fields[1].strip_prefix('*').unwrap_or(fields[1]) == name {
            return Ok(fields[0].to_string());
        }
    }
    bail!("校验和列表里没有 {name}")
}

pub fn sha256_file(path: &Path) -> Result<String> {
    file_sha256(path)
}

pub fn file_sha256(path: &Path) -> Result<String> {
    let mut input = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hex::encode(hash.finalize()))
}

pub fn extract_binary(tar_gz: &Path, member: &str, destination: &Path) -> Result<()> {
    let input = File::open(tar_gz)?;
    let decoder = flate2::read::GzDecoder::new(input);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.file_name().and_then(|name| name.to_str()) != Some(member) {
            continue;
        }
        let mut body = Vec::new();
        entry.read_to_end(&mut body)?;
        write_file(destination, body, 0o755)?;
        return Ok(());
    }
    bail!("包里没有 {member}")
}

pub fn copy_file_mode(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    let mut input = File::open(source)?;
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    options.mode(mode);
    let mut output = options.open(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    set_permissions(destination, mode)?;
    Ok(())
}

pub fn restart_self() {
    if has_cmd("systemctl") && dir_exists(Path::new("/run/systemd/system")) {
        let _ = Command::new("systemctl")
            .args(["restart", "fanout"])
            .spawn();
        return;
    }
    if has_cmd("rc-service") {
        let _ = Command::new("rc-service")
            .args(["fanout", "restart"])
            .spawn();
        return;
    }
    tracing::info!("fanout: 已替换二进制，但未检测到 systemd/openrc，请手动重启服务");
}

// ───────────────────────── versions and Xray updates ─────────────────────────

pub fn plain_version(version: &str) -> String {
    let without_revision = version.split('-').next().unwrap_or(version);
    without_revision
        .split('+')
        .next()
        .unwrap_or(without_revision)
        .to_string()
}

pub fn ovpn_gap_note(family: &str, have: &str, target: &str, upstream: &str) -> String {
    if upstream.is_empty() || !version_less(have, upstream) {
        return String::new();
    }
    if !target.is_empty() && !version_less(target, upstream) {
        return String::new();
    }
    if family == "deb" {
        if target.is_empty() {
            format!(
                "发行版仓库和 OpenVPN 官方 apt 源里都没有比 {have} 更新的包，官方 {upstream} 这台机器装不到"
            )
        } else {
            format!(
                "这台机器上装得到的最高是 {}；官方 {upstream} 的 apt 源里没有适配本机发行版的包",
                plain_version(target)
            )
        }
    } else if target.is_empty() {
        format!(
            "本机源里没有比 {have} 更新的 openvpn；官方 {upstream} 得另接 OpenVPN 的源（RHEL 系在 Copr @OpenVPN/openvpn-release-2.7）"
        )
    } else {
        format!(
            "本机源里最高只有 {}；官方 {upstream} 得另接 OpenVPN 的源（RHEL 系在 Copr @OpenVPN/openvpn-release-2.7）",
            plain_version(target)
        )
    }
}

pub fn xray_asset_for_arch(goarch: &str) -> String {
    match goarch {
        "amd64" => "Xray-linux-64.zip".into(),
        "386" => "Xray-linux-32.zip".into(),
        "arm64" => "Xray-linux-arm64-v8a.zip".into(),
        "arm" => "Xray-linux-arm32-v7a.zip".into(),
        "mips64le" => "Xray-linux-mips64le.zip".into(),
        "ppc64le" => "Xray-linux-ppc64le.zip".into(),
        other => format!("Xray-linux-{other}.zip"),
    }
}

pub fn parse_xray_version(output: &str) -> String {
    for line in output.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        if fields[0].to_ascii_lowercase().starts_with("xray") {
            return fields[1]
                .strip_prefix("core")
                .unwrap_or(fields[1])
                .strip_prefix('v')
                .unwrap_or_else(|| fields[1].strip_prefix("core").unwrap_or(fields[1]))
                .to_string();
        }
    }
    String::new()
}

pub fn parse_openvpn_version(output: &str) -> String {
    let first = first_line(output);
    let fields: Vec<_> = first.split_whitespace().collect();
    if fields.len() >= 2 && fields[0].to_ascii_lowercase().starts_with("openvpn") {
        fields[1].to_string()
    } else {
        String::new()
    }
}

pub fn probe_version(name: &str, args: &[String]) -> String {
    let mut command = Command::new(name);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match capture_output(command, Duration::from_secs(8)) {
        Ok(output) => combined_output(&output),
        Err(_) => String::new(),
    }
}

pub fn xray_update_target(work_dir: &Path, bin: &str, backend: &str) -> (String, String) {
    let owned = work_dir.join("bin").join("xray");
    match backend {
        "" => (
            String::new(),
            "还没定下用哪种节点后端，等探测完成后再看".into(),
        ),
        "native" => {
            if bin.trim().is_empty() {
                (String::new(), "自建模式下没找到 Xray 可执行文件".into())
            } else if clean_path(Path::new(bin)) != clean_path(&owned) {
                (
                    String::new(),
                    format!(
                        "现在跑的是系统里的 Xray（{bin}），由包管理器负责升级；fanout 只替换自己装在 {} 的那一份",
                        owned.display()
                    ),
                )
            } else {
                (path_string(&owned), String::new())
            }
        }
        other => (
            String::new(),
            format!("现在入站由 {other} 接管，那份 Xray 跟着它自己的升级路径走，fanout 不动它"),
        ),
    }
}

pub fn find_xray(work_dir: &Path) -> Result<PathBuf> {
    let arch = xui_arch_suffix();
    let candidates = [
        work_dir.join("bin").join("xray"),
        PathBuf::from("/usr/local/bin/xray"),
        PathBuf::from("/usr/bin/xray"),
        PathBuf::from(format!("/usr/local/x-ui/bin/xray-linux-{arch}")),
    ];
    for candidate in candidates {
        if is_executable_file(&candidate) {
            return Ok(candidate);
        }
    }
    if let Some(found) = find_command("xray") {
        return Ok(found);
    }
    bail!(
        "找不到 xray 可执行文件，装一份到 {} 或 /usr/local/bin/xray",
        work_dir.join("bin").join("xray").display()
    )
}

fn xui_arch_suffix() -> String {
    match env::consts::ARCH {
        "x86_64" => "amd64".into(),
        "aarch64" => "arm64".into(),
        "arm" => "arm32".into(),
        other => other.to_string(),
    }
}

pub fn extract_from_zip(zip_path: &Path, member: &str, destination: &Path) -> Result<()> {
    let file = File::open(zip_path).context("打开压缩包失败")?;
    let mut archive = zip::ZipArchive::new(file).context("打开压缩包失败")?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.is_dir() || entry.name().rsplit('/').next() != Some(member) {
            continue;
        }
        let mut body = Vec::new();
        entry.read_to_end(&mut body)?;
        write_file(destination, body, 0o755)?;
        return Ok(());
    }
    bail!("压缩包里没有 {member}")
}

pub fn verify_xray_config_now(bin: &Path, config_path: &Path) -> Result<()> {
    match fs::metadata(config_path) {
        Ok(_) => verify_xray_config(bin, config_path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn verify_xray_config(bin: &Path, config_path: &Path) -> Result<()> {
    let output = Command::new(bin)
        .args(["run", "-test", "-c"])
        .arg(config_path)
        .output()?;
    if !output.status.success() {
        let combined = combined_output(&output);
        bail!("Xray 配置校验失败: {}", trim_output(&combined, 400));
    }
    Ok(())
}

pub fn or_unknown(version: &str) -> String {
    if version.trim().is_empty() {
        "未知版本".into()
    } else {
        version.to_string()
    }
}

/// Replace a binary through `target.new`/`target.prev`.  If the reload callback
/// rejects the new binary, the previous inode is put back before returning.
pub fn replace_binary_with(
    target: &Path,
    pulled: &Path,
    reload: Option<&dyn Fn() -> Result<()>>,
) -> Result<()> {
    let staged = sibling_path(target, ".new");
    let previous = sibling_path(target, ".prev");
    copy_file_mode(pulled, &staged, 0o755).context("写入新版失败")?;
    if let Err(error) = fs::rename(target, &previous) {
        let _ = fs::remove_file(&staged);
        return Err(error).context("备份旧版失败");
    }
    if let Err(error) = fs::rename(&staged, target) {
        let _ = fs::remove_file(&staged);
        let _ = fs::rename(&previous, target);
        return Err(error).context("替换失败");
    }
    if let Some(reload) = reload {
        if let Err(error) = reload() {
            let _ = fs::remove_file(target);
            if let Err(rollback_error) = fs::rename(&previous, target) {
                bail!(
                    "新版起不来（{error:#}），而且旧版也没放回去（{rollback_error:#}），请检查 {}",
                    target.display()
                );
            }
            let _ = reload();
            bail!("新版起不来，已退回旧版：{error:#}");
        }
    }
    Ok(())
}

pub async fn apply_xray_update() -> Result<String> {
    apply_xray_update_with(&ClientRuntime::detect()).await
}

pub async fn apply_xray_update_with(runtime: &ClientRuntime) -> Result<String> {
    let _guard = XRAY_APPLY_LOCK.lock().await;
    let bin = match &runtime.xray_path {
        Some(path) => path.clone(),
        None => find_xray(&runtime.work_dir)?,
    };
    let (target, why) = xray_update_target(&runtime.work_dir, &path_string(&bin), &runtime.backend);
    if target.is_empty() {
        bail!("{why}");
    }
    let target = PathBuf::from(target);
    let from = parse_xray_version(&probe_version(&path_string(&target), &["version".into()]));

    let release = fetch_release_latest(XRAY_RELEASE_REPO)
        .await
        .with_context(|| format!("查 {XRAY_RELEASE_REPO} 最新版失败"))?;
    let want = release
        .tag_name
        .trim()
        .strip_prefix('v')
        .unwrap_or("")
        .to_string();
    if want.is_empty() {
        bail!("{XRAY_RELEASE_REPO} 最新版返回了一个空版本号");
    }
    let arch = runtime_go_arch();
    let asset = xray_asset_for_arch(&arch);
    let asset_url = release
        .assets
        .iter()
        .find(|candidate| candidate.name == asset)
        .map(|candidate| candidate.url.clone())
        .ok_or_else(|| anyhow!("{XRAY_RELEASE_REPO} {want} 里没有适配 {arch} 的包"))?;

    let temporary = tempfile::Builder::new().prefix("fanout-xray-").tempdir()?;
    let zip_path = temporary.path().join(&asset);
    download_file(&asset_url, &zip_path)
        .await
        .with_context(|| format!("下载 {asset} 失败"))?;
    let pulled = temporary.path().join("xray");
    extract_from_zip(&zip_path, "xray", &pulled).context("解包失败")?;
    let got = parse_xray_version(&probe_version(&path_string(&pulled), &["version".into()]));
    if got != want {
        bail!("新版在本机跑不起来或版本对不上（期望 {want}，实际 {got}），旧版仍在运行");
    }
    verify_xray_config_now(&pulled, &runtime.work_dir.join("xray.json"))
        .with_context(|| format!("Xray {want} 不认现有配置，已放弃更新"))?;

    let replacement = if let Some(reloader) = &runtime.native_reloader {
        replace_binary_with(&target, &pulled, Some(&|| reloader.swap_xray()))
    } else {
        replace_binary_with(&target, &pulled, None)
    };
    replacement?;
    let message = format!("Xray 已从 {} 升到 {want}", or_unknown(&from));
    if runtime.native_reloader.is_none() {
        Ok(format!(
            "{message}。当前没有自建 Xray 在跑，下次重载配置时生效"
        ))
    } else {
        let previous = sibling_path(&target, ".prev");
        Ok(format!(
            "{message}，自建入站已用新版重新拉起（旧版留在 {}）",
            previous.file_name().unwrap_or_default().to_string_lossy()
        ))
    }
}

// ───────────────────────── package-manager planning ─────────────────────────

#[derive(Clone, Debug)]
pub struct OpenVPNPlanError {
    pub family: String,
    pub message: String,
}

impl std::fmt::Display for OpenVPNPlanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for OpenVPNPlanError {}

pub type OpenVPNPlanResult<T> = std::result::Result<T, OpenVPNPlanError>;

pub fn parse_os_release(blob: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in blob.lines() {
        let mut line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        values.insert(
            key.trim().to_string(),
            value.trim().trim_matches(&['"', '\''][..]).to_string(),
        );
    }
    values
}

pub fn distro_family(values: &HashMap<String, String>) -> String {
    for field in ["ID_LIKE", "ID"] {
        for name in values
            .get(field)
            .map(String::as_str)
            .unwrap_or_default()
            .split_whitespace()
        {
            match name.to_ascii_lowercase().as_str() {
                "debian" | "ubuntu" => return "deb".into(),
                "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "amzn" | "ol" => {
                    return "rpm".into()
                }
                "suse" | "opensuse-tumbleweed" | "opensuse-leap" | "sles" => return "suse".into(),
                "alpine" => return "alpine".into(),
                "arch" | "manjaro" | "endeavouros" => return "arch".into(),
                _ => {}
            }
        }
    }
    String::new()
}

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_string()).collect()
}

fn plan_error(family: &str, message: impl Into<String>) -> OpenVPNPlanError {
    OpenVPNPlanError {
        family: family.into(),
        message: message.into(),
    }
}

pub fn openvpn_upgrade_plan<F>(
    os_release: &str,
    have: F,
) -> OpenVPNPlanResult<(Vec<Vec<String>>, String)>
where
    F: Fn(&str) -> bool,
{
    let values = parse_os_release(os_release);
    let family = distro_family(&values);
    let steps = match family.as_str() {
        "deb" => {
            if !have("apt-get") {
                return Err(plan_error(
                    "deb",
                    "认出来是 Debian/Ubuntu 系，但机器上没有 apt-get",
                ));
            }
            vec![
                argv(&["apt-get", "update", "-qq"]),
                argv(&["apt-get", "install", "-y", "--only-upgrade", "openvpn"]),
            ]
        }
        "rpm" => {
            if have("dnf") {
                vec![argv(&["dnf", "-y", "upgrade", "openvpn"])]
            } else if have("yum") {
                vec![argv(&["yum", "-y", "update", "openvpn"])]
            } else {
                return Err(plan_error(
                    "rpm",
                    "认出来是 RHEL/CentOS/Fedora 系，但机器上没有 dnf 或 yum",
                ));
            }
        }
        "alpine" => {
            if !have("apk") {
                return Err(plan_error("alpine", "认出来是 Alpine，但机器上没有 apk"));
            }
            vec![
                argv(&["apk", "update", "--no-cache"]),
                argv(&["apk", "add", "--no-cache", "--upgrade", "openvpn"]),
            ]
        }
        "arch" => {
            if !have("pacman") {
                return Err(plan_error("arch", "认出来是 Arch 系，但机器上没有 pacman"));
            }
            vec![argv(&["pacman", "-Sy", "--noconfirm", "openvpn"])]
        }
        "suse" => {
            if !have("zypper") {
                return Err(plan_error(
                    "suse",
                    "认出来是 openSUSE 系，但机器上没有 zypper",
                ));
            }
            vec![
                argv(&["zypper", "--non-interactive", "refresh"]),
                argv(&["zypper", "--non-interactive", "update", "openvpn"]),
            ]
        }
        _ => {
            return Err(plan_error(
                "",
                format!(
                "认不出这台机器的发行版（{OS_RELEASE_PATH} 里没有已支持的 ID），请手动升级 openvpn"
            ),
            ))
        }
    };
    Ok((steps, family))
}

#[derive(Clone, Debug, Default)]
pub struct RepoLatest {
    pub version: String,
    pub why: String,
    pub stale: bool,
}

pub fn openvpn_repo_query_plan<F>(
    family: &str,
    have: F,
) -> OpenVPNPlanResult<(Option<Vec<String>>, Vec<String>)>
where
    F: Fn(&str) -> bool,
{
    let (refresh, query) = match family {
        "deb" => {
            if !have("apt-cache") {
                return Err(plan_error(
                    "deb",
                    "机器上没有 apt-cache，问不到仓库里的版本",
                ));
            }
            (
                have("apt-get").then(|| argv(&["apt-get", "update", "-qq"])),
                argv(&["apt-cache", "policy", "openvpn"]),
            )
        }
        "rpm" => {
            if have("dnf") {
                (None, argv(&["dnf", "-q", "--refresh", "list", "openvpn"]))
            } else if have("yum") {
                (
                    Some(argv(&["yum", "-q", "clean", "metadata"])),
                    argv(&["yum", "-q", "list", "openvpn"]),
                )
            } else {
                return Err(plan_error(
                    "rpm",
                    "机器上没有 dnf 或 yum，问不到仓库里的版本",
                ));
            }
        }
        "alpine" => {
            if !have("apk") {
                return Err(plan_error("alpine", "机器上没有 apk，问不到仓库里的版本"));
            }
            (
                Some(argv(&["apk", "update"])),
                argv(&["apk", "policy", "openvpn"]),
            )
        }
        "arch" => {
            if !have("pacman") {
                return Err(plan_error("arch", "机器上没有 pacman，问不到仓库里的版本"));
            }
            (
                Some(argv(&["pacman", "-Sy", "--noconfirm"])),
                argv(&["pacman", "-Si", "openvpn"]),
            )
        }
        "suse" => {
            if !have("zypper") {
                return Err(plan_error("suse", "机器上没有 zypper，问不到仓库里的版本"));
            }
            (
                Some(argv(&["zypper", "--non-interactive", "refresh"])),
                argv(&["zypper", "-n", "info", "openvpn"]),
            )
        }
        _ => {
            return Err(plan_error(
                "",
                "认不出这台机器的包管理器，问不到仓库里的版本",
            ))
        }
    };
    Ok((refresh, query))
}

pub fn openvpn_repo_latest(family: &str) -> RepoLatest {
    openvpn_repo_latest_with(family, has_cmd)
}

pub fn openvpn_repo_latest_with<F>(family: &str, have: F) -> RepoLatest
where
    F: Fn(&str) -> bool,
{
    let have = &have;
    let (refresh, query) = match openvpn_repo_query_plan(family, have) {
        Ok(plan) => plan,
        Err(error) => {
            return RepoLatest {
                why: error.message,
                ..RepoLatest::default()
            }
        }
    };
    let mut stale = false;
    let mut why = String::new();
    if let Some(refresh) = refresh {
        if let Err(error) = run_refresh(&refresh) {
            stale = true;
            why = refresh_why(&refresh[0], &error);
        }
    }
    let output = match run_repo_query(&query, REPO_QUERY_TIMEOUT) {
        Ok(output) => output,
        Err(error) => {
            if stale {
                return RepoLatest {
                    why,
                    stale,
                    ..RepoLatest::default()
                };
            }
            if looks_locked(&error) {
                return RepoLatest {
                    why: format!(
                        "{} 正被别的进程占用（自动更新常在跑），仓库版本号问不到",
                        query[0]
                    ),
                    ..RepoLatest::default()
                };
            }
            return RepoLatest {
                why: format!("{} 没答上来：{error:#}", query[0]),
                ..RepoLatest::default()
            };
        }
    };
    let version = match family {
        "deb" => parse_apt_candidate(&output),
        "rpm" => parse_dnf_list_row(&output),
        "alpine" => parse_apk_policy(&output),
        _ => parse_colon_version(&output),
    };
    if version.is_empty() {
        let why = match family {
            "deb" => "apt 的仓库索引里没有 openvpn 这个包".to_string(),
            "rpm" => "dnf/yum 的仓库里查不到 openvpn 这个包".to_string(),
            "alpine" => "apk 的仓库索引里没有 openvpn 这个包".to_string(),
            _ => "包管理器没给出 openvpn 的版本号".to_string(),
        };
        RepoLatest {
            why,
            stale,
            ..RepoLatest::default()
        }
    } else {
        RepoLatest {
            version,
            why,
            stale,
        }
    }
}

pub fn parse_apt_candidate(output: &str) -> String {
    for line in output.lines() {
        let line = line.trim();
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        if key != "Candidate" {
            continue;
        }
        let version = rest.trim().trim_matches(&['(', ')'][..]);
        return if version.is_empty() || version == "none" {
            String::new()
        } else {
            version.to_string()
        };
    }
    String::new()
}

pub fn parse_dnf_list_row(output: &str) -> String {
    let mut version = String::new();
    for line in output.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let head = fields[0].split('.').next().unwrap_or(fields[0]);
        if head != "openvpn" && !fields[0].starts_with("openvpn-") {
            continue;
        }
        let mut candidate = fields[1];
        if let Some((_, after)) = candidate.split_once(':') {
            if !after.is_empty() {
                candidate = after;
            }
        }
        version = candidate.to_string();
    }
    version
}

pub fn parse_apk_policy(output: &str) -> String {
    let mut best = String::new();
    for line in output.lines() {
        let mut line = line.trim();
        if !line.ends_with(':') {
            continue;
        }
        line = line.strip_suffix(':').unwrap_or(line);
        if let Some((head, version)) = line.split_once('-') {
            if head == "openvpn" {
                if best.is_empty() || version_less(&best, version) {
                    best = version.to_string();
                }
                continue;
            }
        }
        if line.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            if best.is_empty() || version_less(&best, line) {
                best = line.to_string();
            }
        }
    }
    best
}

pub fn parse_colon_version(output: &str) -> String {
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim() == "Version" && !value.trim().is_empty() {
            return value.trim().to_string();
        }
    }
    String::new()
}

pub fn describe_steps(steps: &[Vec<String>]) -> String {
    steps
        .iter()
        .map(|step| step.join(" "))
        .collect::<Vec<_>>()
        .join(" && ")
}

pub fn tail_lines(output: &str, count: usize) -> String {
    if count == 0 {
        return String::new();
    }
    let mut lines: Vec<_> = output.trim_end_matches('\n').split('\n').collect();
    if lines.len() > count {
        lines = lines.split_off(lines.len() - count);
    }
    lines.join("\n").trim().to_string()
}

pub fn looks_locked(error: &anyhow::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    [
        "could not get lock",
        "unable to lock",
        "failed to get lock",
        "waiting for process",
    ]
    .iter()
    .any(|marker| message.contains(marker))
}

pub fn refresh_why(command: &str, error: &anyhow::Error) -> String {
    if looks_locked(error) {
        format!("{command} 正被别的进程占用（自动更新常在跑），索引没刷新，仓库版本号可能偏旧")
    } else {
        format!("{command} 没能刷新索引，仓库版本号可能偏旧：{error:#}")
    }
}

pub fn run_refresh(args: &[String]) -> Result<String> {
    let first = run_repo_query(args, REPO_REFRESH_TIMEOUT);
    match first {
        Err(error) if looks_locked(&error) => {
            thread::sleep(REFRESH_RETRY_WAIT);
            run_repo_query(args, REPO_REFRESH_TIMEOUT)
        }
        other => other,
    }
}

pub fn run_repo_query(args: &[String], timeout: Duration) -> Result<String> {
    if args.is_empty() {
        bail!("空命令");
    }
    let mut command = Command::new(&args[0]);
    command
        .args(&args[1..])
        .env("LANG", "C")
        .env("DEBIAN_FRONTEND", "noninteractive");
    let output = capture_output(command, timeout)?;
    let combined = combined_output(&output);
    if !output.status.success() {
        bail!("{}：{}", output.status, tail_lines(&combined, 3));
    }
    Ok(combined)
}

pub fn run_upgrade_steps(steps: &[Vec<String>]) -> Result<()> {
    run_upgrade_steps_within(steps, Duration::ZERO)
}

pub fn run_upgrade_steps_within(steps: &[Vec<String>], budget: Duration) -> Result<()> {
    let deadline = if budget.is_zero() {
        None
    } else {
        Some(Instant::now() + budget)
    };
    for step in steps {
        let left = match deadline {
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    bail!("{} 没跑：装包总时限 {:?} 用完了", step.join(" "), budget);
                }
                left
            }
            None => Duration::ZERO,
        };
        let (output, result) = run_package_cmd_within(step, left);
        if let Err(error) = result {
            bail!(
                "{} 失败: {error:#}\n{}",
                step.join(" "),
                tail_lines(&output, 8)
            );
        }
    }
    Ok(())
}

pub fn run_package_cmd(args: &[String]) -> (String, Result<()>) {
    run_package_cmd_within(args, Duration::ZERO)
}

pub fn run_package_cmd_within(args: &[String], budget: Duration) -> (String, Result<()>) {
    if args.is_empty() {
        return (String::new(), Err(anyhow!("空命令")));
    }
    let timeout = if budget.is_zero() {
        PACKAGE_COMMAND_TIMEOUT
    } else {
        budget
    };
    let mut command = Command::new(&args[0]);
    command
        .args(&args[1..])
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("NEEDRESTART_MODE", "a")
        .env("APT_LISTCHANGES_FRONTEND", "none")
        .env("LANG", "C");
    let output = match capture_output(command, timeout) {
        Ok(output) => output,
        Err(error) => return (String::new(), Err(error)),
    };
    let text = combined_output(&output);
    let result = if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!("{}", output.status))
    };
    (text, result)
}

// ───────────────────────── OpenVPN official apt repository ─────────────────────────

#[derive(Clone, Debug)]
pub struct AptRepoFiles {
    pub keyring: PathBuf,
    pub sources: PathBuf,
    pub legacy_sources: PathBuf,
    pub key_url: String,
    pub key_sha256: String,
}

impl Default for AptRepoFiles {
    fn default() -> Self {
        Self {
            keyring: PathBuf::from(OVPN_APT_KEYRING),
            sources: PathBuf::from(OVPN_APT_SOURCES),
            legacy_sources: PathBuf::from("/etc/apt/sources.list"),
            key_url: OVPN_APT_KEY_URL.into(),
            key_sha256: OVPN_APT_KEY_SHA256.into(),
        }
    }
}

pub fn deb_arch(goarch: &str) -> String {
    match goarch {
        "amd64" | "x86_64" => "amd64".into(),
        "arm64" | "aarch64" => "arm64".into(),
        "386" | "i386" | "i686" => "i386".into(),
        _ => String::new(),
    }
}

pub fn valid_deb_codename(codename: &str) -> bool {
    if codename.is_empty() || codename.len() > 32 {
        return false;
    }
    for (index, byte) in codename.bytes().enumerate() {
        let valid = byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'_' | b'.')
            || (byte == b'-' && index > 0);
        if !valid {
            return false;
        }
    }
    !codename.starts_with('-') && !codename.starts_with('.')
}

pub fn deb_codename(values: &HashMap<String, String>) -> String {
    for key in ["VERSION_CODENAME", "UBUNTU_CODENAME"] {
        let value = values
            .get(key)
            .map(|value| value.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if valid_deb_codename(&value) {
            return value;
        }
    }
    String::new()
}

pub fn deb_stable_version(version: &str) -> (String, bool) {
    let upstream = version
        .rsplit_once('-')
        .map(|(before, _)| before)
        .unwrap_or(version);
    if upstream.is_empty() || upstream.contains(['~', ':']) {
        return (String::new(), false);
    }
    for segment in upstream.split('.') {
        if segment.is_empty() || !segment.bytes().all(|byte| byte.is_ascii_digit()) {
            return (String::new(), false);
        }
    }
    (upstream.to_string(), true)
}

pub fn parse_deb_pkg_version(blob: &str, package: &str) -> String {
    for block in blob.replace("\r\n", "\n").split("\n\n") {
        let mut name = String::new();
        let mut version = String::new();
        for line in block.lines() {
            if let Some(value) = line.strip_prefix("Package:") {
                name = value.trim().to_string();
            } else if let Some(value) = line.strip_prefix("Version:") {
                version = value.trim().to_string();
            }
        }
        if name == package {
            return version;
        }
    }
    String::new()
}

pub async fn fetch_deb_packages(url: &str) -> Result<String> {
    fetch_http_text(url, "fanout-clientbin", Duration::from_secs(20), 24 << 20).await
}

pub fn ovpn_apt_repo_ver<F>(
    codename: &str,
    arch: &str,
    have: &str,
    mut fetch: F,
) -> (String, String, String)
where
    F: FnMut(&str) -> Result<String>,
{
    if !valid_deb_codename(codename) {
        return (
            String::new(),
            String::new(),
            "/etc/os-release 里没有能用的发行版代号，不去接第三方源".into(),
        );
    }
    if arch.is_empty() {
        return (
            String::new(),
            String::new(),
            "OpenVPN 官方源没有本机这个 CPU 架构的构建".into(),
        );
    }
    let mut official = String::new();
    let mut channel = String::new();
    for candidate_channel in OVPN_APT_CHANNELS {
        let url = format!(
            "{OVPN_APT_BASE}/{candidate_channel}/dists/{codename}/main/binary-{arch}/Packages"
        );
        let Ok(blob) = fetch(&url) else {
            continue;
        };
        let (version, stable) = deb_stable_version(&parse_deb_pkg_version(&blob, "openvpn"));
        if !stable || version.is_empty() {
            continue;
        }
        if official.is_empty() || version_less(&official, &version) {
            official = version;
            channel = (*candidate_channel).to_string();
        }
    }
    if official.is_empty() {
        return (
            String::new(),
            String::new(),
            format!("OpenVPN 官方源没有 {codename}/{arch} 的稳定版构建"),
        );
    }
    if !version_less(have, &official) {
        return (
            String::new(),
            official.clone(),
            format!("OpenVPN 官方源在 {codename} 上最高只到 {official}，不比本机新"),
        );
    }
    (channel, official, String::new())
}

pub fn openvpn_pick_target(
    have: &str,
    repo_version: &str,
    official: &str,
    official_channel: &str,
) -> (String, String) {
    let better = |version: &str| !version.is_empty() && version_less(have, version);
    if better(official) && (!better(repo_version) || version_less(repo_version, official)) {
        (official.to_string(), official_channel.to_string())
    } else if better(repo_version) {
        (repo_version.to_string(), String::new())
    } else {
        (String::new(), String::new())
    }
}

pub fn ovpn_apt_repo_line(channel: &str, arch: &str, codename: &str) -> String {
    format!(
        "deb [arch={arch} signed-by={OVPN_APT_KEYRING}] {OVPN_APT_BASE}/{channel} {codename} main\n"
    )
}

fn ovpn_apt_repo_line_with(
    files: &AptRepoFiles,
    channel: &str,
    arch: &str,
    codename: &str,
) -> String {
    format!(
        "deb [arch={arch} signed-by={}] {OVPN_APT_BASE}/{channel} {codename} main\n",
        files.keyring.display()
    )
}

pub fn openvpn_apt_repo_wired() -> bool {
    openvpn_apt_repo_wired_with(&AptRepoFiles::default())
}

pub fn openvpn_apt_repo_wired_with(files: &AptRepoFiles) -> bool {
    let mut candidates = vec![files.sources.clone(), files.legacy_sources.clone()];
    if let Some(parent) = files.sources.parent() {
        if let Ok(entries) = fs::read_dir(parent) {
            for entry in entries.flatten() {
                if entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "list")
                {
                    candidates.push(entry.path());
                }
            }
        }
    }
    candidates.into_iter().any(|path| {
        fs::read_to_string(path)
            .map(|blob| blob.contains(OVPN_APT_MARKER))
            .unwrap_or(false)
    })
}

pub fn openvpn_apt_repo_has_channel(channel: &str, codename: &str) -> bool {
    openvpn_apt_repo_has_channel_with(&AptRepoFiles::default(), channel, codename)
}

pub fn openvpn_apt_repo_has_channel_with(
    files: &AptRepoFiles,
    channel: &str,
    codename: &str,
) -> bool {
    fs::read_to_string(&files.sources)
        .map(|blob| blob.contains(&format!("{OVPN_APT_BASE}/{channel} {codename} main")))
        .unwrap_or(false)
}

pub fn openvpn_apt_repo_ours() -> bool {
    openvpn_apt_repo_ours_with(&AptRepoFiles::default())
}

pub fn openvpn_apt_repo_ours_with(files: &AptRepoFiles) -> bool {
    fs::read_to_string(&files.sources)
        .map(|blob| blob.contains(OVPN_APT_MARKER))
        .unwrap_or(false)
}

fn validate_apt_repo_input(channel: &str, arch: &str, codename: &str) -> Result<()> {
    if !valid_deb_apt_channel(channel) {
        bail!("未知的 OpenVPN 官方源通道 {channel:?}");
    }
    if !valid_deb_codename(codename) {
        bail!("发行版代号 {codename:?} 不像话，拒绝写进 apt 配置");
    }
    if arch.is_empty() {
        bail!("没有对应的 Debian 架构名，拒绝写进 apt 配置");
    }
    Ok(())
}

pub async fn install_openvpn_apt_repo(channel: &str, arch: &str, codename: &str) -> Result<()> {
    install_openvpn_apt_repo_with(
        AptRepoFiles::default(),
        channel,
        arch,
        codename,
        |url, destination| {
            let url = url.to_string();
            let destination = destination.to_path_buf();
            async move { download_file(&url, &destination).await }
        },
    )
    .await
}

pub async fn install_openvpn_apt_repo_with<F, Fut>(
    files: AptRepoFiles,
    channel: &str,
    arch: &str,
    codename: &str,
    mut download: F,
) -> Result<()>
where
    F: FnMut(&str, &Path) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    validate_apt_repo_input(channel, arch, codename)?;
    let directory = files
        .keyring
        .parent()
        .ok_or_else(|| anyhow!("钥匙路径没有父目录"))?;
    fs::create_dir_all(directory).with_context(|| format!("建 {} 失败", directory.display()))?;
    let temporary = directory.join(format!(".fanout-openvpn-key-{}.tmp", uuid::Uuid::new_v4()));
    let temporary_guard = RemoveFileOnDrop(temporary.clone());
    let result = async {
        download(&files.key_url, &temporary)
            .await
            .context("下载 OpenVPN 官方源签名密钥失败")?;
        let digest = file_sha256(&temporary)?;
        if !digest.eq_ignore_ascii_case(&files.key_sha256) {
            bail!(
                "官方源密钥的摘要对不上（期望 {}…，实际 {}…）：官方换过钥匙的话请升级 fanout，也可以按官方 wiki 手动配置",
                short_digest(&files.key_sha256),
                short_digest(&digest)
            );
        }
        set_permissions(&temporary, 0o644)?;
        fs::rename(&temporary, &files.keyring)
            .with_context(|| format!("写入 {} 失败", files.keyring.display()))?;
        write_file(
            &files.sources,
            ovpn_apt_repo_line_with(&files, channel, arch, codename).as_bytes(),
            0o644,
        )?;
        Ok(())
    }
    .await;
    drop(temporary_guard);
    result
}

pub fn remove_openvpn_apt_repo() -> Result<()> {
    remove_openvpn_apt_repo_with(&AptRepoFiles::default())
}

pub fn remove_openvpn_apt_repo_with(files: &AptRepoFiles) -> Result<()> {
    for path in [&files.sources, &files.keyring] {
        if let Err(error) = fs::remove_file(path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error).with_context(|| format!("删 {} 失败", path.display()));
            }
        }
    }
    if has_cmd("apt-get") {
        run_refresh(&argv(&["apt-get", "update", "-qq"]))?;
    }
    Ok(())
}

pub fn valid_deb_apt_channel(channel: &str) -> bool {
    OVPN_APT_CHANNELS.contains(&channel)
}

pub fn short_digest(digest: &str) -> String {
    digest.chars().take(12).collect()
}

#[derive(Clone, Debug, Default)]
pub struct OpenVPNDecision {
    pub family: String,
    pub steps: Vec<Vec<String>>,
    pub repo_version: String,
    pub repo_why: String,
    pub stale: bool,
    pub codename: String,
    pub arch: String,
    pub official: String,
    pub official_why: String,
    pub channel: String,
    pub needs_write: bool,
    pub target: String,
    pub wired: bool,
    pub why: String,
}

pub fn decide_openvpn_upgrade_with<H, R, F, W, C>(
    os_release: &str,
    have: &str,
    arch: &str,
    has_cmd: H,
    mut repo_probe: R,
    mut fetch: F,
    wired: W,
    has_channel: C,
    ask: bool,
) -> OpenVPNDecision
where
    H: Fn(&str) -> bool,
    R: FnMut(&str) -> RepoLatest,
    F: FnMut(&str) -> Result<String>,
    W: Fn() -> bool,
    C: Fn(&str, &str) -> bool,
{
    let plan = openvpn_upgrade_plan(os_release, &has_cmd);
    decide_openvpn_upgrade_from_plan(
        plan,
        have,
        arch,
        os_release,
        &mut repo_probe,
        &mut fetch,
        &wired,
        &has_channel,
        ask,
    )
}

fn decide_openvpn_upgrade_from_plan<R, F, W, C>(
    plan: OpenVPNPlanResult<(Vec<Vec<String>>, String)>,
    have: &str,
    arch: &str,
    os_release: &str,
    repo_probe: &mut R,
    fetch: &mut F,
    wired: &W,
    has_channel: &C,
    ask: bool,
) -> OpenVPNDecision
where
    R: FnMut(&str) -> RepoLatest,
    F: FnMut(&str) -> Result<String>,
    W: Fn() -> bool,
    C: Fn(&str, &str) -> bool,
{
    let (steps, family) = match plan {
        Ok((steps, family)) => (steps, family),
        Err(error) => {
            return OpenVPNDecision {
                family: error.family,
                why: error.message,
                ..OpenVPNDecision::default()
            }
        }
    };
    let mut decision = OpenVPNDecision {
        family,
        steps,
        ..OpenVPNDecision::default()
    };
    if !ask {
        return decision;
    }
    let repo = repo_probe(&decision.family);
    decision.repo_version = repo.version;
    decision.repo_why = repo.why;
    decision.stale = repo.stale;
    if decision.family == "deb" {
        let values = parse_os_release(os_release);
        decision.codename = deb_codename(&values);
        decision.arch = arch.to_string();
        let (channel, official, why) =
            ovpn_apt_repo_ver(&decision.codename, &decision.arch, have, fetch);
        decision.official = official;
        decision.official_why = why;
        decision.channel = channel;
        decision.wired = wired();
    }
    (decision.target, decision.channel) = openvpn_pick_target(
        have,
        &decision.repo_version,
        &decision.official,
        &decision.channel,
    );
    decision.needs_write =
        !decision.channel.is_empty() && !has_channel(&decision.channel, &decision.codename);
    decision
}

pub async fn decide_openvpn_upgrade(os_release: &str, have: &str) -> OpenVPNDecision {
    let arch = deb_arch(&runtime_go_arch());
    let plan = openvpn_upgrade_plan(os_release, has_cmd);
    let ask = true;
    let mut pages: HashMap<String, std::result::Result<String, String>> = HashMap::new();
    if plan.as_ref().is_ok_and(|(_, family)| family == "deb") {
        let values = parse_os_release(os_release);
        let codename = deb_codename(&values);
        if valid_deb_codename(&codename) && !arch.is_empty() {
            for channel in OVPN_APT_CHANNELS {
                let url = format!(
                    "{OVPN_APT_BASE}/{channel}/dists/{codename}/main/binary-{arch}/Packages"
                );
                let result = fetch_deb_packages(&url)
                    .await
                    .map_err(|error| format!("{error:#}"));
                pages.insert(url, result);
            }
        }
    }
    decide_openvpn_upgrade_from_plan(
        plan,
        have,
        &arch,
        os_release,
        &mut |family| openvpn_repo_latest_with(family, has_cmd),
        &mut |url| match pages.remove(url) {
            Some(Ok(blob)) => Ok(blob),
            Some(Err(error)) => Err(anyhow!(error)),
            None => bail!("没有预取 {url}"),
        },
        &openvpn_apt_repo_wired,
        &|channel, codename| openvpn_apt_repo_has_channel(channel, codename),
        ask,
    )
}

pub async fn apply_openvpn_update() -> Result<String> {
    let _guard = OPENVPN_APPLY_LOCK.lock().await;
    let before = parse_openvpn_version(&probe_version("openvpn", &["--version".into()]));
    if before.is_empty() {
        bail!(
            "本机没有可用的 openvpn，先在系统里装一个（apt/apk install openvpn）再回来点这个按钮"
        );
    }
    let mut shadow = String::new();
    if let Some(record) = read_openvpn_src_record() {
        if is_executable_file(Path::new(&record.bin)) && openvpn_binary() == record.bin {
            shadow = format!(
                "（隧道当前用的是 fanout 编的 {}，在 {}；这次只动系统包，换完仍不会用它。要让它回到系统那份，点「撤销源码版」。）",
                record.version, record.bin
            );
        }
    }
    let os_release = fs::read_to_string(OS_RELEASE_PATH)
        .with_context(|| format!("读 {OS_RELEASE_PATH} 失败"))?;
    let decision = decide_openvpn_upgrade(&os_release, &before).await;
    if !decision.why.is_empty() {
        bail!("{}", decision.why);
    }
    let mut wired = String::new();
    if decision.needs_write {
        install_openvpn_apt_repo(&decision.channel, &decision.arch, &decision.codename).await?;
        wired = format!(
            "（已接上 OpenVPN 官方源 {}，最高 {}；不想要就删掉 {OVPN_APT_SOURCES} 和 {OVPN_APT_KEYRING} 再 apt-get update）",
            decision.channel, decision.official
        );
    }
    run_upgrade_steps(&decision.steps)?;
    let after = parse_openvpn_version(&probe_version("openvpn", &["--version".into()]));
    if after.is_empty() {
        bail!("升级后 openvpn 跑不起来了（升级前是 {before}），请检查包管理器的输出");
    }
    if after == before {
        return Ok(format!(
            "系统包里的 openvpn 已是本机装得到的最新版 {before}，没有变化{}。{}",
            wired,
            or_fallback(&shadow, "已在跑的隧道本来就用着它，不用管。")
        ));
    }
    if !decision.target.is_empty() && version_less(&after, &decision.target) {
        bail!(
            "openvpn 只升到 {after}（升级前 {before}，预期 {}），包管理器的输出里有原因{}",
            decision.target,
            shadow
        );
    }
    Ok(format!(
        "openvpn 已从 {before} 升到 {after}{}。{}已在跑的隧道仍挂在旧进程上（进程不会被包管理器动到），新建出口、换节点或重启服务之后自然切到新版。",
        wired, shadow
    ))
}

pub fn or_fallback<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

// ───────────────────────── OpenVPN verified source builds ─────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OpenVPNSourceBuild {
    #[serde(deserialize_with = "deserialize_null_default")]
    pub version: String,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub prefix: String,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub bin: String,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub sha256: String,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub signer: String,
    #[serde(deserialize_with = "deserialize_null_default")]
    pub built_at: String,
}

pub fn ovpn_src_version_ok(version: &str) -> bool {
    if version.is_empty() || version.len() > 15 {
        return false;
    }
    let parts: Vec<_> = version.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty() && part.len() <= 4 && part.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn is_hex_lower(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn ovpn_src_is_sha256(value: &str) -> bool {
    value.len() == 64 && is_hex_lower(value)
}

pub fn ovpn_src_is_fingerprint(value: &str) -> bool {
    value.len() == 40 && is_hex_lower(value)
}

pub fn ovpn_src_tar_name(version: &str) -> String {
    format!("openvpn-{version}.tar.gz")
}

pub fn ovpn_src_prefix(version: &str) -> String {
    format!("{OVPN_SRC_PREFIX_BASE}/{version}")
}

pub fn ovpn_src_bin(version: &str) -> String {
    format!("{}/sbin/openvpn", ovpn_src_prefix(version))
}

pub fn ovpn_src_build_dir(version: &str) -> String {
    format!("{OVPN_SRC_STATE_DIR}/build-{version}")
}

pub fn ovpn_src_assets(
    release: Option<&ReleaseInfo>,
    version: &str,
) -> Result<(String, String, String)> {
    let release = release.ok_or_else(|| anyhow!("没有拿到 release"))?;
    if !ovpn_src_version_ok(version) {
        bail!("版本号 {version:?} 不能用来拼下载路径");
    }
    let tar_name = ovpn_src_tar_name(version);
    let official_prefix = format!("https://github.com/{OPENVPN_RELEASE_REPO}/releases/download/");
    let mut tar_url = String::new();
    let mut asc_url = String::new();
    let mut digest = String::new();
    for asset in &release.assets {
        match asset.name.as_str() {
            name if name == tar_name => {
                if !asset.url.starts_with(&official_prefix) {
                    bail!("源码包地址不像官方 release：{}", asset.url);
                }
                tar_url = asset.url.clone();
                digest = asset
                    .digest
                    .strip_prefix("sha256:")
                    .unwrap_or(&asset.digest)
                    .to_ascii_lowercase();
            }
            name if name == format!("{tar_name}.asc") => {
                if !asset.url.starts_with(&official_prefix) {
                    bail!("签名文件地址不像官方 release：{}", asset.url);
                }
                asc_url = asset.url.clone();
            }
            _ => {}
        }
    }
    if tar_url.is_empty() || asc_url.is_empty() {
        bail!("release {version} 里找不到 {tar_name} 或它的 .asc");
    }
    if !ovpn_src_is_sha256(&digest) {
        bail!("GitHub 给的源码包摘要不是 sha256（{digest:?}）");
    }
    Ok((tar_url, asc_url, digest))
}

pub fn ovpn_src_configure_argv(prefix: &str) -> Vec<String> {
    vec![
        "./configure".into(),
        format!("--prefix={prefix}"),
        "--disable-dco".into(),
        "--disable-plugin-auth-pam".into(),
        "--disable-unit-tests".into(),
    ]
}

pub fn ovpn_src_make_jobs(cpus: usize) -> usize {
    cpus.clamp(1, 4)
}

pub fn available_parallelism() -> usize {
    thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}

pub fn ovpn_src_deps(family: &str) -> Vec<Vec<String>> {
    if family != "deb" {
        return Vec::new();
    }
    vec![
        argv(&["apt-get", "update", "-qq"]),
        argv(&[
            "apt-get",
            "install",
            "-y",
            "--no-install-recommends",
            "build-essential",
            "pkg-config",
            "libssl-dev",
            "libcap-ng-dev",
            "liblzo2-dev",
            "liblz4-dev",
            "gnupg",
        ]),
    ]
}

pub fn gpg_key_fingerprints(colons: &str) -> Vec<String> {
    let mut fingerprints = Vec::new();
    for line in colons.lines() {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() < 11 || fields[0] != "fpr" {
            continue;
        }
        let fingerprint = fields[9].trim().to_ascii_uppercase();
        if ovpn_src_is_fingerprint(&fingerprint.to_ascii_lowercase()) {
            fingerprints.push(fingerprint);
        }
    }
    fingerprints
}

pub fn gpg_signer_fingerprint(status: &str) -> String {
    let mut good = false;
    let mut fingerprint = String::new();
    for line in status.lines() {
        let line = line.trim();
        if line.starts_with("[GNUPG:] GOODSIG") {
            good = true;
        } else if line.starts_with("[GNUPG:] VALIDSIG ") {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() >= 4 {
                fingerprint = fields[2].to_ascii_uppercase();
            }
        }
    }
    if good {
        fingerprint
    } else {
        String::new()
    }
}

pub fn ovpn_src_pinned_signer(fingerprint: &str) -> bool {
    OVPN_SRC_SIGNERS
        .iter()
        .any(|pinned| pinned.eq_ignore_ascii_case(fingerprint))
}

pub fn gpg_sig_primary_fingerprint(status: &str) -> String {
    for line in status.lines() {
        let line = line.trim();
        if !line.starts_with("[GNUPG:] VALIDSIG ") {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4 {
            return String::new();
        }
        let last = fields.last().unwrap_or(&"").to_ascii_uppercase();
        return if ovpn_src_is_fingerprint(&last.to_ascii_lowercase()) {
            last
        } else {
            String::new()
        };
    }
    String::new()
}

pub fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

pub fn read_openvpn_src_record_at(path: &Path) -> Option<OpenVPNSourceBuild> {
    let blob = fs::read(path).ok()?;
    let record = serde_json::from_slice::<OpenVPNSourceBuild>(&blob).ok()?;
    if !ovpn_src_version_ok(&record.version) || record.bin.is_empty() {
        return None;
    }
    Some(record)
}

pub fn read_openvpn_src_record() -> Option<OpenVPNSourceBuild> {
    read_openvpn_src_record_at(Path::new(OVPN_SRC_RECORD_FILE))
}

pub fn write_openvpn_src_record_at(path: &Path, record: &OpenVPNSourceBuild) -> Result<()> {
    if !ovpn_src_version_ok(&record.version) {
        bail!("版本号 {:?} 不能写进记录", record.version);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let blob = serde_json::to_vec_pretty(record)?;
    atomic_write(path, &blob, 0o644)
}

pub fn write_openvpn_src_record(record: &OpenVPNSourceBuild) -> Result<()> {
    write_openvpn_src_record_at(Path::new(OVPN_SRC_RECORD_FILE), record)
}

pub fn openvpn_binary() -> String {
    if let Some(record) = read_openvpn_src_record() {
        if is_executable_file(Path::new(&record.bin)) {
            return record.bin;
        }
    }
    "openvpn".into()
}

pub fn gpg_run(timeout: Duration, args: &[String]) -> (String, Result<()>) {
    if let Err(error) = fs::create_dir_all(OVPN_SRC_GNU_DIR) {
        return (String::new(), Err(error.into()));
    }
    if let Err(error) = set_permissions(Path::new(OVPN_SRC_GNU_DIR), 0o700) {
        return (String::new(), Err(error));
    }
    let mut command = Command::new("gpg");
    command
        .args([
            "--homedir",
            OVPN_SRC_GNU_DIR,
            "--batch",
            "--no-tty",
            "--quiet",
        ])
        .args(args)
        .env("LANG", "C");
    let output = match capture_output(command, timeout) {
        Ok(output) => output,
        Err(error) => return (String::new(), Err(error)),
    };
    let text = combined_output(&output);
    let result = if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!("{}", output.status))
    };
    (text, result)
}

pub async fn verify_openvpn_tarball(tar_path: &Path, asc_path: &Path) -> Result<String> {
    if let Err(error) = fs::remove_dir_all(OVPN_SRC_GNU_DIR) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error.into());
        }
    }
    fs::create_dir_all(OVPN_SRC_GNU_DIR)?;
    set_permissions(Path::new(OVPN_SRC_GNU_DIR), 0o700)?;
    if !has_cmd("gpg") {
        bail!("本机没有 gpg，验不了官方签名");
    }
    let key_url = format!("{OVPN_SRC_KEY_URL_BASE}{}", OVPN_SRC_SIGNERS[0]);
    download_file(&key_url, Path::new(OVPN_SRC_KEY_FILE))
        .await
        .with_context(|| "下载 OpenVPN 签名公钥失败")?;
    let (output, result) = gpg_run(
        Duration::from_secs(60),
        &["--import".into(), OVPN_SRC_KEY_FILE.into()],
    );
    if let Err(error) = result {
        bail!("导入 OpenVPN 签名公钥失败：{error:#}；{output}");
    }
    let (colons, result) = gpg_run(
        Duration::from_secs(60),
        &[
            "--with-colons".into(),
            "--list-keys".into(),
            "--with-subkey-fingerprints".into(),
        ],
    );
    if let Err(error) = result {
        bail!("列出签名公钥失败：{error:#}；{colons}");
    }
    let fingerprints = gpg_key_fingerprints(&colons);
    if !fingerprints
        .iter()
        .any(|fingerprint| ovpn_src_pinned_signer(fingerprint))
    {
        bail!(
            "下载到的钥匙指纹里没有钉住的那把（期望 {}，实际 {fingerprints:?}）——不敢用它验包",
            OVPN_SRC_SIGNERS[0]
        );
    }
    let (status, result) = gpg_run(
        Duration::from_secs(120),
        &[
            "--status-fd".into(),
            "1".into(),
            "--verify".into(),
            path_string(asc_path),
            path_string(tar_path),
        ],
    );
    if let Err(error) = result {
        bail!(
            "openvpn 源码包验签没通过：{}；{error:#}",
            first_line(&status)
        );
    }
    let signer = gpg_signer_fingerprint(&status);
    if signer.is_empty() {
        bail!("验签输出里没有 GOODSIG/VALIDSIG，看不出是谁签的");
    }
    if !fingerprints
        .iter()
        .any(|fingerprint| fingerprint.eq_ignore_ascii_case(&signer))
    {
        bail!("签名用的子钥匙 {signer} 不属于钉住的那把主钥匙，拒绝这份包");
    }
    let primary = gpg_sig_primary_fingerprint(&status);
    if !primary.is_empty() && !ovpn_src_pinned_signer(&primary) {
        bail!(
            "签名挂在主钥匙 {primary} 上，不是钉住的 {}",
            OVPN_SRC_SIGNERS[0]
        );
    }
    Ok(signer)
}

pub const OPENVPN_BUILD_STEPS: &[&str] = &[
    "问本机包管理器能装到哪",
    "装编译依赖",
    "下载源码包与签名",
    "核对 GitHub 给的摘要",
    "用 OpenVPN 官方钥匙验签",
    "解包",
    "configure",
    "make 编译",
    "安装并自检",
];
pub const B_STEP_REPO: usize = 0;
pub const B_STEP_DEPS: usize = 1;
pub const B_STEP_DOWNLOAD: usize = 2;
pub const B_STEP_DIGEST: usize = 3;
pub const B_STEP_SIGN: usize = 4;
pub const B_STEP_UNPACK: usize = 5;
pub const B_STEP_CONFIGURE: usize = 6;
pub const B_STEP_MAKE: usize = 7;
pub const B_STEP_INSTALL: usize = 8;

pub fn ovpn_build_start() -> bool {
    OVPN_BUILD_ON
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

pub fn ovpn_build_finish() {
    OVPN_BUILD_ON.store(false, Ordering::SeqCst);
}

struct SourceBuildLockGuard;

impl Drop for SourceBuildLockGuard {
    fn drop(&mut self) {
        ovpn_build_finish();
    }
}

#[derive(Clone, Debug)]
pub struct SourceBuildJob {
    inner: Arc<Mutex<JobView>>,
}

impl SourceBuildJob {
    pub fn new(version: &str) -> Self {
        let now: DateTime<Utc> = Utc::now();
        let labels: Vec<String> = OPENVPN_BUILD_STEPS
            .iter()
            .map(|label| (*label).to_string())
            .collect();
        let total = labels.len();
        let view = JobView {
            id: random_token(12),
            summary: format!("源码编译 openvpn {version}"),
            status: "running".into(),
            steps: labels
                .into_iter()
                .map(|label| JobStep {
                    label,
                    status: "pending".into(),
                    detail: String::new(),
                })
                .collect(),
            started: now,
            done: now,
            total,
        };
        Self {
            inner: Arc::new(Mutex::new(view)),
        }
    }

    pub async fn set(&self, index: usize, status: &str, detail: &str) {
        let mut view = self.inner.lock().await;
        if let Some(step) = view.steps.get_mut(index) {
            step.status = status.into();
            step.detail = one_line(detail, 500);
        }
    }

    pub async fn finish(&self) {
        let mut view = self.inner.lock().await;
        view.status = if view.steps.iter().any(|step| step.status == "failed") {
            "failed".into()
        } else {
            "done".into()
        };
        view.done = Utc::now();
    }

    pub async fn view(&self) -> JobView {
        self.inner.lock().await.clone()
    }
}

pub async fn start_openvpn_source_build() -> Result<SourceBuildJob> {
    if !ovpn_build_start() {
        bail!("已经有一个编译在跑了，等它结束");
    }
    let build_guard = SourceBuildLockGuard;
    let prepared = async {
        let release = fetch_release_latest(OPENVPN_RELEASE_REPO).await?;
        let (version, stable) = release_tag(&release.tag_name);
        if !stable || !ovpn_src_version_ok(&version) {
            bail!(
                "OpenVPN 官方最新 tag {:?} 不是能编译的三位版本号",
                release.tag_name
            );
        }
        let (tar_url, asc_url, digest) = ovpn_src_assets(Some(&release), &version)?;
        if let Some(record) = read_openvpn_src_record() {
            if record.version == version {
                bail!(
                    "openvpn {version} 已经编好在用了（{}），不用重复编",
                    record.bin
                );
            }
        }
        Ok((version, tar_url, asc_url, digest))
    }
    .await;
    let (version, tar_url, asc_url, digest) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return Err(error),
    };
    let job = SourceBuildJob::new(&version);
    let background = job.clone();
    tokio::spawn(async move {
        let _build_guard = build_guard;
        run_openvpn_source_build(&background, &version, &tar_url, &asc_url, &digest).await;
    });
    Ok(job)
}

pub async fn run_openvpn_source_build(
    job: &SourceBuildJob,
    version: &str,
    tar_url: &str,
    asc_url: &str,
    digest: &str,
) {
    macro_rules! fail_step {
        ($job:expr, $version:expr, $step:expr, $($arg:tt)*) => {{
            $job.set($step, "failed", &format!($($arg)*)).await;
            cleanup_openvpn_source_build($version);
            $job.finish().await;
            return;
        }};
    }

    if !ovpn_src_version_ok(version) || !ovpn_src_is_sha256(digest) {
        fail_step!(
            job,
            version,
            B_STEP_DIGEST,
            "版本号或 GitHub 摘要形状不合法"
        );
    }
    let old = read_openvpn_src_record();
    job.set(B_STEP_REPO, "running", "").await;
    let os_release = match fs::read_to_string(OS_RELEASE_PATH) {
        Ok(blob) => blob,
        Err(error) => fail_step!(
            job,
            version,
            B_STEP_REPO,
            "读 {} 失败：{error:#}",
            OS_RELEASE_PATH
        ),
    };
    let apt_version = parse_openvpn_version(&probe_version("openvpn", &["--version".into()]));
    if apt_version.is_empty() {
        fail_step!(
            job,
            version,
            B_STEP_REPO,
            "本机没有可用的 openvpn，先按系统包装一个再回来"
        );
    }
    let decision = decide_openvpn_upgrade(&os_release, &apt_version).await;
    if !decision.why.is_empty() {
        fail_step!(job, version, B_STEP_REPO, "{}", decision.why);
    }
    if decision.family != "deb" {
        fail_step!(
            job,
            version,
            B_STEP_REPO,
            "{} 家族的编译依赖包名各家不同，这条只给 Debian / Ubuntu 用",
            decision.family
        );
    }
    if !decision.target.is_empty() && !version_less(&decision.target, version) {
        fail_step!(
            job,
            version,
            B_STEP_REPO,
            "包管理器就能装到 {}（不比官方 {} 旧），请用「升级 openvpn」那个按钮",
            decision.target,
            version
        );
    }
    job.set(
        B_STEP_REPO,
        "ok",
        &format!(
            "{} 家族装得到的最高是 {}，官方 {} 够不到",
            decision.family,
            or_nothing(&decision.target),
            version
        ),
    )
    .await;

    job.set(
        B_STEP_DEPS,
        "running",
        "apt-get update && apt-get install 编译依赖",
    )
    .await;
    let dependencies = ovpn_src_deps(&decision.family);
    if dependencies.is_empty() {
        fail_step!(
            job,
            version,
            B_STEP_DEPS,
            "{} 家族没有给定的依赖包名表",
            decision.family
        );
    }
    if let Err(error) = run_upgrade_steps(&dependencies) {
        fail_step!(job, version, B_STEP_DEPS, "{error:#}");
    }
    let packages = dependencies
        .get(1)
        .and_then(|step| step.get(4..))
        .map(|packages| packages.join(" / "))
        .unwrap_or_default();
    job.set(B_STEP_DEPS, "ok", &packages).await;

    job.set(B_STEP_DOWNLOAD, "running", "").await;
    if let Err(error) = fs::create_dir_all(OVPN_SRC_STATE_DIR) {
        fail_step!(job, version, B_STEP_DOWNLOAD, "{error:#}");
    }
    let tar_name = ovpn_src_tar_name(version);
    let tar_path = Path::new(OVPN_SRC_STATE_DIR).join(&tar_name);
    let asc_path = sibling_path(&tar_path, ".asc");
    if let Err(error) = download_file(tar_url, &tar_path).await {
        fail_step!(job, version, B_STEP_DOWNLOAD, "下载源码包失败：{error:#}");
    }
    if let Err(error) = download_file(asc_url, &asc_path).await {
        fail_step!(job, version, B_STEP_DOWNLOAD, "下载签名失败：{error:#}");
    }
    job.set(B_STEP_DOWNLOAD, "ok", &format!("{tar_name} + .asc"))
        .await;

    job.set(B_STEP_DIGEST, "running", "").await;
    let got = match sha256_file(&tar_path) {
        Ok(digest) => digest,
        Err(error) => fail_step!(job, version, B_STEP_DIGEST, "{error:#}"),
    };
    if !got.eq_ignore_ascii_case(digest) {
        fail_step!(
            job,
            version,
            B_STEP_DIGEST,
            "源码包摘要对不上 GitHub 给的（期望 {}，实际 {}）",
            short_digest(digest),
            short_digest(&got)
        );
    }
    job.set(B_STEP_DIGEST, "ok", &short_digest(&got)).await;

    job.set(B_STEP_SIGN, "running", "下载官方签名公钥").await;
    let signer = match verify_openvpn_tarball(&tar_path, &asc_path).await {
        Ok(signer) => signer,
        Err(error) => fail_step!(job, version, B_STEP_SIGN, "{error:#}"),
    };
    job.set(
        B_STEP_SIGN,
        "ok",
        &format!(
            "主钥匙 {} 的子钥匙 {}",
            short_fingerprint(OVPN_SRC_SIGNERS[0]),
            short_fingerprint(&signer)
        ),
    )
    .await;

    job.set(B_STEP_UNPACK, "running", "").await;
    let build_dir = PathBuf::from(ovpn_src_build_dir(version));
    if let Err(error) = fs::remove_dir_all(&build_dir) {
        if error.kind() != std::io::ErrorKind::NotFound {
            fail_step!(job, version, B_STEP_UNPACK, "{error:#}");
        }
    }
    if let Err(error) = fs::create_dir_all(&build_dir) {
        fail_step!(job, version, B_STEP_UNPACK, "{error:#}");
    }
    let unpack_args = vec![
        "tar".to_string(),
        "-xzf".into(),
        path_string(&tar_path),
        "-C".into(),
        path_string(&build_dir),
        "--no-same-owner".into(),
    ];
    let (output, result) = run_build_cmd(Duration::from_secs(5 * 60), &build_dir, &unpack_args);
    if let Err(error) = result {
        fail_step!(
            job,
            version,
            B_STEP_UNPACK,
            "解包失败：{error:#}\n{}",
            tail_lines(&output, 6)
        );
    }
    let source_dir = build_dir.join(format!("openvpn-{version}"));
    if !source_dir.is_dir() {
        fail_step!(
            job,
            version,
            B_STEP_UNPACK,
            "包里没有 openvpn-{version}/ 这一层"
        );
    }
    job.set(B_STEP_UNPACK, "ok", &path_string(&source_dir))
        .await;

    let configure = ovpn_src_configure_argv(&ovpn_src_prefix(version));
    job.set(B_STEP_CONFIGURE, "running", &configure.join(" "))
        .await;
    let (output, result) = run_build_cmd(Duration::from_secs(10 * 60), &source_dir, &configure);
    if let Err(error) = result {
        fail_step!(
            job,
            version,
            B_STEP_CONFIGURE,
            "configure 失败：{error:#}\n{}",
            tail_lines(&output, 12)
        );
    }
    job.set(B_STEP_CONFIGURE, "ok", &configure[1..].join(" "))
        .await;

    let jobs = ovpn_src_make_jobs(available_parallelism());
    job.set(
        B_STEP_MAKE,
        "running",
        &format!("make -j{jobs}（几分钟到几十分钟）"),
    )
    .await;
    let make_args = vec!["make".to_string(), format!("-j{jobs}")];
    let (output, result) = run_build_cmd(Duration::from_secs(45 * 60), &source_dir, &make_args);
    if let Err(error) = result {
        fail_step!(
            job,
            version,
            B_STEP_MAKE,
            "编译失败：{error:#}\n{}",
            tail_lines(&output, 12)
        );
    }
    job.set(B_STEP_MAKE, "ok", &format!("-j{jobs}")).await;

    job.set(B_STEP_INSTALL, "running", "").await;
    let install_args = vec!["make".to_string(), "install".to_string()];
    let (output, result) = run_build_cmd(Duration::from_secs(10 * 60), &source_dir, &install_args);
    if let Err(error) = result {
        fail_step!(
            job,
            version,
            B_STEP_INSTALL,
            "安装失败：{error:#}\n{}",
            tail_lines(&output, 12)
        );
    }
    let bin = ovpn_src_bin(version);
    if !is_executable_file(Path::new(&bin)) {
        fail_step!(
            job,
            version,
            B_STEP_INSTALL,
            "装完了但 {bin} 不在，记录不写"
        );
    }
    let built_version = parse_openvpn_version(&probe_version(&bin, &["--version".into()]));
    if built_version != version {
        fail_step!(
            job,
            version,
            B_STEP_INSTALL,
            "编出来跑的是 {built_version:?}，不是预期的 {version}，记录不写"
        );
    }
    let record = OpenVPNSourceBuild {
        version: version.into(),
        prefix: ovpn_src_prefix(version),
        bin: bin.clone(),
        sha256: digest.into(),
        signer: OVPN_SRC_SIGNERS[0].into(),
        built_at: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };
    if let Err(error) = write_openvpn_src_record(&record) {
        fail_step!(job, version, B_STEP_INSTALL, "记录没写进去：{error:#}");
    }
    let _ = fs::remove_dir_all(&build_dir);
    if let Some(old) = old {
        if old.version != version
            && ovpn_src_deletable(&old.prefix, &old.version)
            && old.prefix != record.prefix
        {
            let _ = fs::remove_dir_all(old.prefix);
        }
    }
    job.set(
        B_STEP_INSTALL,
        "ok",
        &format!("{version} → {bin}（apt 那份 {apt_version} 原地没动）"),
    )
    .await;
    job.finish().await;
}

pub fn openvpn_can_build_source(
    family: &str,
    have: &str,
    apt_target: &str,
    upstream: &str,
    built: &str,
) -> bool {
    if family != "deb" || upstream.is_empty() || have.is_empty() {
        return false;
    }
    if !version_less(have, upstream) {
        return false;
    }
    if !apt_target.is_empty() && !version_less(apt_target, upstream) {
        return false;
    }
    built != upstream
}

pub fn openvpn_src_plan(version: &str, family: &str) -> String {
    if !ovpn_src_version_ok(version) {
        return String::new();
    }
    let mut lines: Vec<String> = ovpn_src_deps(family)
        .iter()
        .map(|step| step.join(" "))
        .collect();
    lines.push(format!(
        "下载 https://github.com/{OPENVPN_RELEASE_REPO}/releases/download/v{version}/{} 和签名 {}.asc",
        ovpn_src_tar_name(version),
        ovpn_src_tar_name(version)
    ));
    lines.push(format!(
        "核对 GitHub 给的 sha256，再用 OpenVPN 官方主钥匙 {} 验签名",
        short_fingerprint(OVPN_SRC_SIGNERS[0])
    ));
    lines.push(ovpn_src_configure_argv(&ovpn_src_prefix(version)).join(" "));
    lines.push(format!(
        "make -j{} && make install",
        ovpn_src_make_jobs(available_parallelism())
    ));
    lines.push(format!(
        "装进 {}，**不覆盖**系统那份；自检跑到 {} 才登记启用",
        ovpn_src_prefix(version),
        ovpn_src_bin(version)
    ));
    lines.push("任何一步失败都不登记、删掉这棵树，隧道继续用系统那份".into());
    lines.push(format!(
        "撤销 = 删 {} 和这条记录，系统那份原地还在",
        ovpn_src_prefix(version)
    ));
    lines.join("\n")
}

pub fn cleanup_openvpn_source_build(version: &str) {
    if !ovpn_src_version_ok(version) {
        return;
    }
    let _ = fs::remove_dir_all(ovpn_src_prefix(version));
    let _ = fs::remove_dir_all(ovpn_src_build_dir(version));
}

pub fn run_build_cmd(timeout: Duration, directory: &Path, args: &[String]) -> (String, Result<()>) {
    if args.is_empty() {
        return (String::new(), Err(anyhow!("空命令")));
    }
    let mut command = Command::new(&args[0]);
    command
        .args(&args[1..])
        .current_dir(directory)
        .env("LANG", "C")
        .env("DEBIAN_FRONTEND", "noninteractive");
    let output = match capture_output(command, timeout) {
        Ok(output) => output,
        Err(error) => return (String::new(), Err(error)),
    };
    let text = combined_output(&output);
    let result = if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!("{}", output.status))
    };
    (text, result)
}

pub fn ovpn_src_deletable(prefix: &str, version: &str) -> bool {
    ovpn_src_version_ok(version) && prefix == ovpn_src_prefix(version)
}

pub fn remove_openvpn_source_build() -> Result<String> {
    let Some(record) = read_openvpn_src_record() else {
        return Ok("本机没有 fanout 编过的 openvpn，系统那份照旧在用".into());
    };
    if !ovpn_src_deletable(&record.prefix, &record.version) {
        bail!(
            "记录里的安装前缀 {:?} 不在 {OVPN_SRC_PREFIX_BASE} 下面，不敢删",
            record.prefix
        );
    }
    if let Err(error) = fs::remove_dir_all(&record.prefix) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error).with_context(|| format!("删 {} 失败", record.prefix));
        }
    }
    let _ = fs::remove_dir_all(ovpn_src_build_dir(&record.version));
    if let Err(error) = fs::remove_file(OVPN_SRC_RECORD_FILE) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error).context("记录删不掉");
        }
    }
    let apt = parse_openvpn_version(&probe_version("openvpn", &["--version".into()]));
    Ok(format!(
        "已删掉源码编译的 openvpn {}（{}），接下来用系统那份 {}。已在跑的隧道挂在旧进程上，新建出口或重启服务之后才换。",
        record.version,
        record.prefix,
        or_nothing(&apt)
    ))
}

pub fn or_nothing(value: &str) -> String {
    if value.is_empty() {
        "没有".into()
    } else {
        value.to_string()
    }
}

pub fn short_fingerprint(fingerprint: &str) -> String {
    let characters: Vec<char> = fingerprint.chars().collect();
    if characters.len() <= 12 {
        return fingerprint.to_string();
    }
    let first: String = characters.iter().take(8).collect();
    let last: String = characters.iter().skip(characters.len() - 4).collect();
    format!("{first}…{last}")
}

// ───────────────────────── WARP version baseline ─────────────────────────

pub fn warp_version_less(current: &str, latest: &str) -> bool {
    match (warp_version_parts(current), warp_version_parts(latest)) {
        (Some(current), Some(latest)) => {
            for index in 0..current.len().max(latest.len()) {
                let left = current.get(index).copied().unwrap_or(0);
                let right = latest.get(index).copied().unwrap_or(0);
                if left != right {
                    return left < right;
                }
            }
            false
        }
        _ => current.trim() != latest.trim(),
    }
}

pub fn warp_version_parts(version: &str) -> Option<Vec<u64>> {
    let version = plain_version(version.trim())
        .trim_start_matches('v')
        .to_string();
    if version.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for part in version.split('.') {
        if part.is_empty() {
            return None;
        }
        parts.push(part.parse::<u64>().ok()?);
    }
    Some(parts)
}

pub fn parse_warp_pkg_version(body: &str) -> String {
    let mut in_warp = false;
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(package) = line.strip_prefix("Package:") {
            in_warp = package.trim() == "cloudflare-warp";
        } else if in_warp {
            if let Some(version) = line.strip_prefix("Version:") {
                return version.trim().to_string();
            }
        }
    }
    String::new()
}

pub fn parse_warp_codenames(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|codename| !codename.is_empty())
        .map(str::to_string)
        .collect()
}

pub async fn warp_latest_version() -> Result<String> {
    warp_latest_version_with(|url| async move {
        fetch_http_text(&url, "fanout-warp-check", Duration::from_secs(8), 24 << 20).await
    })
    .await
}

pub async fn warp_latest_version_with<F, Fut>(mut fetch: F) -> Result<String>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<String>>,
{
    let started = Instant::now();
    let mut last_error = None;
    for codename in parse_warp_codenames(WARP_CODENAMES) {
        let elapsed = started.elapsed();
        if elapsed >= Duration::from_secs(20) {
            break;
        }
        let url = WARP_PKG_INDEX.replace("%s", &codename);
        let remaining = Duration::from_secs(20)
            .saturating_sub(elapsed)
            .min(Duration::from_secs(8));
        match tokio::time::timeout(remaining, fetch(url)).await {
            Ok(Ok(blob)) => {
                let version = parse_warp_pkg_version(&blob);
                if !version.is_empty() {
                    return Ok(version);
                }
                last_error = Some(anyhow!(
                    "{} 的索引里没有 cloudflare-warp 的版本号",
                    codename
                ));
            }
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => last_error = Some(anyhow!("{codename} 的官方索引查询超时")),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("官方 apt 源没有返回版本号")))
}

// ───────────────────────── client status and WARP prerequisites ─────────────────────────

pub trait XrayReloader: Send + Sync {
    fn swap_xray(&self) -> Result<()>;
}

#[derive(Clone, Debug)]
pub struct WarpRuntime {
    pub enabled: bool,
    pub report_version: String,
    pub account_versions: Vec<String>,
    pub store_ready: bool,
}

impl Default for WarpRuntime {
    fn default() -> Self {
        Self {
            enabled: false,
            report_version: WARP_CLIENT_VERSION.into(),
            account_versions: Vec::new(),
            store_ready: false,
        }
    }
}

#[derive(Clone)]
pub struct ClientRuntime {
    pub work_dir: PathBuf,
    pub backend: String,
    pub xray_path: Option<PathBuf>,
    pub xray_error: String,
    pub native_reloader: Option<Arc<dyn XrayReloader>>,
    pub warp: WarpRuntime,
}

impl Default for ClientRuntime {
    fn default() -> Self {
        Self {
            work_dir: env::var_os("FANOUT_WORK_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/fanout")),
            backend: env::var("FANOUT_PANEL_MODE").unwrap_or_default(),
            xray_path: None,
            xray_error: String::new(),
            native_reloader: None,
            warp: WarpRuntime::default(),
        }
    }
}

impl std::fmt::Debug for ClientRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientRuntime")
            .field("work_dir", &self.work_dir)
            .field("backend", &self.backend)
            .field("xray_path", &self.xray_path)
            .field("xray_error", &self.xray_error)
            .field("native_reloader", &self.native_reloader.is_some())
            .field("warp", &self.warp)
            .finish()
    }
}

impl ClientRuntime {
    pub fn detect() -> Self {
        let mut runtime = Self::default();
        match find_xray(&runtime.work_dir) {
            Ok(path) => runtime.xray_path = Some(path),
            Err(error) => runtime.xray_error = format!("{error:#}"),
        }
        let settings_path = runtime.work_dir.join("settings.json");
        if let Ok(blob) = fs::read_to_string(settings_path) {
            if let Ok(settings) = serde_json::from_str::<serde_json::Value>(&blob) {
                runtime.warp.enabled = settings
                    .pointer("/warp/enabled")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                if let Some(version) = settings
                    .pointer("/warp/client_version")
                    .and_then(serde_json::Value::as_str)
                {
                    if !version.is_empty() {
                        runtime.warp.report_version = version.to_string();
                    }
                }
            }
        }
        runtime.warp.store_ready = runtime.work_dir.is_dir();
        if let Ok(blob) = fs::read_to_string(runtime.work_dir.join("warp.json")) {
            if let Ok(store) = serde_json::from_str::<serde_json::Value>(&blob) {
                runtime.warp.account_versions = store
                    .pointer("/accounts")
                    .and_then(serde_json::Value::as_array)
                    .map(|accounts| {
                        accounts
                            .iter()
                            .filter_map(|account| {
                                account.get("version").and_then(serde_json::Value::as_str)
                            })
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
            }
        }
        runtime
    }
}

#[derive(Clone, Debug, Default)]
pub struct WarpDeps {
    pub ready: bool,
    pub reason: String,
    pub steps: Option<Vec<Vec<String>>>,
    pub cmd: String,
}

pub fn wireguard_install_plan<F>(os_release: &str, have: F) -> Result<(Vec<Vec<String>>, String)>
where
    F: Fn(&str) -> bool,
{
    let family = distro_family(&parse_os_release(os_release));
    let have = &have;
    let steps = match family.as_str() {
        "deb" => {
            if !have("apt-get") {
                bail!("Debian/Ubuntu 系没有 apt-get，无法安装 {WIREGUARD_PKG}");
            }
            vec![
                argv(&["apt-get", "update", "-qq"]),
                argv(&["apt-get", "install", "-y", WIREGUARD_PKG]),
            ]
        }
        "rpm" => {
            if have("dnf") {
                vec![argv(&["dnf", "-y", "install", WIREGUARD_PKG])]
            } else if have("yum") {
                vec![argv(&["yum", "-y", "install", WIREGUARD_PKG])]
            } else {
                bail!("RHEL/CentOS/Fedora 系没有 dnf 或 yum，无法安装 {WIREGUARD_PKG}");
            }
        }
        "alpine" => {
            if !have("apk") {
                bail!("Alpine 没有 apk，无法安装 {WIREGUARD_PKG}");
            }
            vec![argv(&["apk", "add", "--no-cache", WIREGUARD_PKG])]
        }
        "arch" => {
            if !have("pacman") {
                bail!("Arch 系没有 pacman，无法安装 {WIREGUARD_PKG}");
            }
            vec![argv(&[
                "pacman",
                "-Sy",
                "--noconfirm",
                "--needed",
                WIREGUARD_PKG,
            ])]
        }
        "suse" => {
            if !have("zypper") {
                bail!("openSUSE 系没有 zypper，无法安装 {WIREGUARD_PKG}");
            }
            vec![argv(&[
                "zypper",
                "--non-interactive",
                "install",
                "-y",
                WIREGUARD_PKG,
            ])]
        }
        _ => bail!("认不出这台机器的发行版，请手动安装 {WIREGUARD_PKG}"),
    };
    Ok((steps, family))
}

pub fn warp_probe_deps(runtime: &ClientRuntime) -> WarpDeps {
    if !runtime.warp.store_ready {
        return WarpDeps {
            reason: "WARP 注册记录还没就绪（工作目录不可写？）".into(),
            ..WarpDeps::default()
        };
    }
    if has_cmd("wg") {
        return WarpDeps {
            ready: true,
            ..WarpDeps::default()
        };
    }
    let os_release = fs::read_to_string(OS_RELEASE_PATH).unwrap_or_default();
    match wireguard_install_plan(&os_release, has_cmd) {
        Ok((steps, _)) => WarpDeps {
            ready: true,
            cmd: describe_steps(&steps),
            steps: Some(steps),
            ..WarpDeps::default()
        },
        Err(error) => WarpDeps {
            reason: format!("{WIREGUARD_PKG}：本机没有 wg 命令，{error:#}"),
            ..WarpDeps::default()
        },
    }
}

#[derive(Clone, Debug, Default)]
pub struct ClientBinAssessment {
    pub status: ClientBinStatus,
    /// The Rust model predates this port: two Go string fields are bools and one
    /// Go bool is a string. Keep the original values here so the JSON adapter
    /// can still emit the Go contract.
    pub openvpn_official: String,
    pub openvpn_apt: String,
    pub openvpn_from_official: bool,
}

pub async fn client_bin_status(ask_latest: bool) -> ClientBinStatus {
    client_bin_status_with(&ClientRuntime::detect(), ask_latest).await
}

pub async fn client_bin_status_with(runtime: &ClientRuntime, ask_latest: bool) -> ClientBinStatus {
    client_bin_status_assessment(runtime, ask_latest)
        .await
        .status
}

pub async fn client_bin_status_assessment(
    runtime: &ClientRuntime,
    ask_latest: bool,
) -> ClientBinAssessment {
    let mut status = ClientBinStatus {
        backend: runtime.backend.clone(),
        ..ClientBinStatus::default()
    };
    match &runtime.xray_path {
        Some(path) => {
            status.path = path_string(path);
            status.current = parse_xray_version(&probe_version(&status.path, &["version".into()]));
        }
        None if !runtime.xray_error.is_empty() => status.reason = runtime.xray_error.clone(),
        None => match find_xray(&runtime.work_dir) {
            Ok(path) => {
                status.path = path_string(&path);
                status.current =
                    parse_xray_version(&probe_version(&status.path, &["version".into()]));
            }
            Err(error) => status.reason = format!("{error:#}"),
        },
    }

    let active_openvpn = openvpn_binary();
    status.openvpn = parse_openvpn_version(&probe_version(&active_openvpn, &["--version".into()]));
    let mut apt_version = String::new();
    if let Some(record) = read_openvpn_src_record() {
        if is_executable_file(Path::new(&record.bin)) {
            status.openvpn_source_ver = record.version;
            status.openvpn_source_bin = record.bin.clone();
            status.openvpn_source_active = active_openvpn == record.bin;
            if status.openvpn_source_active {
                apt_version =
                    parse_openvpn_version(&probe_version("openvpn", &["--version".into()]));
                status.openvpn_apt = !apt_version.is_empty();
            }
        }
    }

    let mut os_release = String::new();
    if status.openvpn.is_empty() {
        status.openvpn_reason =
            "本机没有 openvpn，出口隧道起不来；先装一个（apt/apk install openvpn）".into();
    } else {
        match fs::read_to_string(OS_RELEASE_PATH) {
            Ok(blob) => {
                os_release = blob;
                match openvpn_upgrade_plan(&os_release, has_cmd) {
                    Ok((steps, family)) => {
                        status.openvpn_family = family;
                        status.openvpn_updatable = true;
                        status.openvpn_cmd = describe_steps(&steps);
                    }
                    Err(error) => status.openvpn_reason = error.message,
                }
            }
            Err(error) => {
                status.openvpn_reason =
                    format!("读 {OS_RELEASE_PATH} 失败，不知道该怎么升：{error:#}")
            }
        }
    }

    let (target, why) = xray_update_target(&runtime.work_dir, &status.path, &status.backend);
    status.updatable = !target.is_empty();
    if !status.updatable {
        status.reason = why;
    }

    status.warp_enabled = runtime.warp.enabled;
    status.warp_version = runtime.warp.report_version.clone();
    let dependencies = warp_probe_deps(runtime);
    status.warp_ready = dependencies.ready;
    status.warp_reason = dependencies.reason;
    status.warp_need_tools = dependencies.steps.is_some();
    status.warp_pkg_cmd = dependencies.cmd;
    status.warp_count = runtime.warp.account_versions.len();
    status.warp_stale = runtime
        .warp
        .account_versions
        .iter()
        .filter(|version| *version != &status.warp_version)
        .count();
    status.warp_can_apply = status.warp_ready && status.warp_enabled && status.warp_count > 0;

    let mut assessment = ClientBinAssessment {
        status,
        openvpn_apt: apt_version,
        ..ClientBinAssessment::default()
    };
    if !ask_latest {
        return assessment;
    }

    match warp_latest_version().await {
        Ok(latest) => {
            assessment.status.warp_latest = latest.clone();
            assessment.status.warp_has_update =
                warp_version_less(&assessment.status.warp_version, &latest)
                    || assessment.status.warp_stale > 0;
        }
        Err(error) => assessment.status.warp_check_error = format!("{error:#}"),
    }

    let mut official_version = String::new();
    if assessment.status.openvpn_updatable && !assessment.status.openvpn.is_empty() {
        let decision = decide_openvpn_upgrade(&os_release, &assessment.status.openvpn).await;
        assessment.status.openvpn_latest = decision.repo_version;
        assessment.status.openvpn_stale = decision.stale;
        if !decision.repo_why.is_empty() {
            assessment.status.openvpn_reason = decision.repo_why;
        }
        official_version = plain_version(&decision.official);
        assessment.status.openvpn_official = !official_version.is_empty();
        assessment.status.openvpn_repo_wired = decision.wired;
        assessment.status.openvpn_target = plain_version(&decision.target);
        assessment.openvpn_from_official = !decision.channel.is_empty();
        assessment.status.openvpn_has_update = !decision.target.is_empty();
        if decision.needs_write {
            assessment.status.openvpn_repo_line =
                ovpn_apt_repo_line(&decision.channel, &decision.arch, &decision.codename);
            assessment.status.openvpn_cmd = format!(
                "写入 {OVPN_APT_KEYRING}（OpenVPN 官方签名密钥）\n写入 {OVPN_APT_SOURCES}：\n  {}\n{}",
                assessment.status.openvpn_repo_line,
                describe_steps(&decision.steps)
            );
        }
    }
    assessment.openvpn_official = official_version;

    let (xray_result, openvpn_result) = tokio::join!(
        release_latest_tag(XRAY_RELEASE_REPO),
        release_latest_tag(OPENVPN_RELEASE_REPO)
    );
    match xray_result {
        Ok(latest) => {
            assessment.status.latest = latest.clone();
            assessment.status.has_update =
                assessment.status.updatable && version_less(&assessment.status.current, &latest);
        }
        Err(error) => assessment.status.check_error = format!("{error:#}"),
    }
    match openvpn_result {
        Ok(upstream) => {
            if !assessment.status.openvpn.is_empty() {
                assessment.status.openvpn_upstream = upstream.clone();
                assessment.status.openvpn_behind_upstream =
                    version_less(&assessment.status.openvpn, &upstream);
                assessment.status.openvpn_note = ovpn_gap_note(
                    &assessment.status.openvpn_family,
                    &assessment.status.openvpn,
                    &assessment.status.openvpn_target,
                    &upstream,
                );
                let built = if assessment.status.openvpn_source_active {
                    assessment.status.openvpn_source_ver.as_str()
                } else {
                    ""
                };
                if openvpn_can_build_source(
                    &assessment.status.openvpn_family,
                    &assessment.status.openvpn,
                    &assessment.status.openvpn_target,
                    &upstream,
                    built,
                ) {
                    assessment.status.openvpn_build_ver = upstream.clone();
                    let plan = openvpn_src_plan(&upstream, &assessment.status.openvpn_family);
                    if !plan.is_empty() {
                        assessment.status.openvpn_can_build = true;
                        assessment.status.openvpn_build_cmd = plan;
                        assessment.status.openvpn_build_path = ovpn_src_prefix(&upstream);
                        if !assessment.status.openvpn_note.is_empty() {
                            assessment
                                .status
                                .openvpn_note
                                .push_str("；可以从官方源码包编一份（装进独立目录，不动系统那份）");
                        }
                    }
                }
            }
        }
        Err(error) => {
            if assessment.status.check_error.is_empty() {
                assessment.status.check_error = format!("{error:#}");
            }
        }
    }
    assessment
}

pub async fn client_bin_status_json(
    runtime: &ClientRuntime,
    ask_latest: bool,
) -> Result<serde_json::Value> {
    client_bin_status_json_from(&client_bin_status_assessment(runtime, ask_latest).await)
}

/// Emit the Go JSON contract despite the three incorrectly typed fields in the
/// pre-existing Rust model. Empty Go `omitempty` booleans are removed too.
pub fn client_bin_status_json_from(assessment: &ClientBinAssessment) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(&assessment.status)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("ClientBinStatus 不是 JSON 对象"))?;
    if assessment.openvpn_official.is_empty() {
        object.remove("openvpn_official");
    } else {
        object.insert(
            "openvpn_official".into(),
            serde_json::Value::String(assessment.openvpn_official.clone()),
        );
    }
    if assessment.openvpn_apt.is_empty() {
        object.remove("openvpn_apt");
    } else {
        object.insert(
            "openvpn_apt".into(),
            serde_json::Value::String(assessment.openvpn_apt.clone()),
        );
    }
    object.insert(
        "openvpn_from_official".into(),
        serde_json::Value::Bool(assessment.openvpn_from_official),
    );
    for key in [
        "openvpn_stale",
        "openvpn_repo_wired",
        "openvpn_can_build",
        "openvpn_source_active",
        "warp_can_apply",
    ] {
        if object.get(key).and_then(serde_json::Value::as_bool) == Some(false) {
            object.remove(key);
        }
    }
    Ok(value)
}

// ───────────────────────── small host helpers ─────────────────────────

pub fn has_cmd(name: &str) -> bool {
    find_command(name).is_some()
}

pub fn find_command(name: &str) -> Option<PathBuf> {
    let direct = Path::new(name);
    if direct.components().count() > 1 {
        return is_executable_file(direct).then(|| direct.to_path_buf());
    }
    let path = env::var_os("PATH")?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            if let Some(extensions) = env::var_os("PATHEXT") {
                for extension in env::split_paths(&extensions) {
                    let mut candidate = candidate.clone().into_os_string();
                    candidate.push(extension);
                    let candidate = PathBuf::from(candidate);
                    if is_executable_file(&candidate) {
                        return Some(candidate);
                    }
                }
            }
        }
    }
    None
}

pub fn dir_exists(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
}

fn capture_output(mut command: Command, timeout: Duration) -> Result<Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("命令 stdout 不可读"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("命令 stderr 不可读"))?;
    let started = Instant::now();
    let (status, stdout, stderr) = thread::scope(|scope| {
        let stdout_reader = scope.spawn(|| {
            let mut body = Vec::new();
            stdout.read_to_end(&mut body).map(|_| body)
        });
        let stderr_reader = scope.spawn(|| {
            let mut body = Vec::new();
            stderr.read_to_end(&mut body).map(|_| body)
        });
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                bail!("命令执行超时（{}）", timeout.as_secs());
            }
            thread::sleep(Duration::from_millis(20));
        };
        let stdout = stdout_reader
            .join()
            .map_err(|_| anyhow!("读取命令 stdout 失败"))??;
        let stderr = stderr_reader
            .join()
            .map_err(|_| anyhow!("读取命令 stderr 失败"))??;
        Ok((status, stdout, stderr))
    })?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn combined_output(output: &Output) -> String {
    let mut stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stdout.is_empty() && !stderr.is_empty() && !stdout.ends_with('\n') {
        stdout.push('\n');
    }
    stdout.push_str(&stderr);
    stdout
}

fn trim_output(output: &str, maximum: usize) -> String {
    if output.len() <= maximum {
        return output.to_string();
    }
    let mut end = maximum;
    while !output.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &output[..end])
}

fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

struct RemoveFileOnDrop(PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn clean_path(path: &Path) -> PathBuf {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                clean.pop();
            }
            other => clean.push(other.as_os_str()),
        }
    }
    clean
}

fn set_permissions(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}
