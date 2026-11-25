use anyhow::{anyhow, bail, Context, Result};
use rand::{distributions::Alphanumeric, Rng};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
};

pub fn random_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub fn one_line(s: &str, max: usize) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.len() <= max {
        flat
    } else {
        let mut end = max.min(flat.len());
        while !flat.is_char_boundary(end) {
            end -= 1;
        }
        flat[..end].to_string()
    }
}

pub fn open_file(path: &Path, mode: u32, read: bool) -> Result<fs::File> {
    let mut o = fs::OpenOptions::new();
    o.create(true).write(true).truncate(!read);
    if read {
        o.read(true);
    }
    #[cfg(unix)]
    o.mode(mode);
    Ok(o.open(path)?)
}

pub fn atomic_write(path: impl AsRef<Path>, data: &[u8], mode: u32) -> Result<()> {
    let path = path.as_ref();
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("路径没有父目录: {}", path.display()))?;
    fs::create_dir_all(parent)?;
    let tmp = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let mut f = open_file(&tmp, mode, false)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

pub fn read_trim(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

pub fn run(name: &str, args: &[String]) -> Result<()> {
    let out = Command::new(name).args(args).output()?;
    if !out.status.success() {
        bail!(
            "{} {}: {}: {}",
            name,
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

pub fn run_quiet(name: &str, args: &[String]) {
    let _ = Command::new(name).args(args).output();
}

pub fn cmd_output(name: &str, args: &[String]) -> Result<Output> {
    let out = Command::new(name).args(args).output()?;
    if !out.status.success() {
        bail!(
            "{} {}: {}: {}",
            name,
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out)
}

pub fn fnv1a32(s: &str) -> u32 {
    let mut h: u32 = 2_166_136_261;
    for b in s.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(16_777_619);
    }
    h
}

pub fn short_hash(s: &str) -> String {
    format!("{:04x}", fnv1a32(s) & 0xffff)
}

pub fn workdir_lock(dir: &Path) -> Result<fs::File> {
    fs::create_dir_all(dir)?;
    let f = open_file(&dir.join("lock"), 0o600, true)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = f.as_raw_fd();
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            bail!("另一个 fanout-rust 正在用工作目录 {}", dir.display());
        }
    }
    Ok(f)
}

pub fn version_less(a: &str, b: &str) -> bool {
    version_cmp(a, b) == std::cmp::Ordering::Less
}

pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let aa = a.trim_start_matches('v');
    let bb = b.trim_start_matches('v');
    if aa == bb {
        return Ordering::Equal;
    }
    let parse = |s: &str| -> Vec<(u64, i32)> {
        let mut out = Vec::new();
        for p in s.split(|c: char| !c.is_ascii_digit()) {
            if p.is_empty() {
                continue;
            }
            out.push((p.parse().unwrap_or(0), 0));
        }
        out
    };
    let mut ap = parse(aa);
    let mut bp = parse(bb);
    let tilde_a = aa.contains('~');
    let tilde_b = bb.contains('~');
    let n = ap.len().max(bp.len());
    ap.resize(n, (0, 0));
    bp.resize(n, (0, 0));
    for i in 0..n {
        if ap[i] != bp[i] {
            return ap[i].cmp(&bp[i]);
        }
    }
    if tilde_a != tilde_b {
        return if tilde_a {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    aa.cmp(bb)
}

pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).with_context(|| format!("创建目录失败: {}", p.display()))?;
    }
    Ok(())
}

pub fn write_file(path: impl AsRef<Path>, data: impl AsRef<[u8]>, mode: u32) -> Result<()> {
    let path = path.as_ref();
    ensure_parent(path)?;
    let mut f = open_file(path, mode, false)?;
    f.write_all(data.as_ref())?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

pub fn path_string(p: impl AsRef<Path>) -> String {
    p.as_ref().to_string_lossy().to_string()
}

pub fn is_ipv4(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}

pub fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or("").trim().to_string()
}

pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn temp_dir(prefix: &str) -> Result<PathBuf> {
    Ok(tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(Into::into)?
        .keep())
}
