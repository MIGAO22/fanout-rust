use anyhow::{bail, Context, Result};
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::os::fd::AsRawFd;

use crate::{
    process::output_command,
    util::{fnv1a32, open_file, path_string, short_hash},
};

pub const DEFAULT_WORK_DIR: &str = "/var/lib/fanout";
pub const DEFAULT_NET_BASE: u8 = 99;
pub const NET_BASE_MIN: u8 = 100;
pub const NET_BASE_MAX: u8 = 255;

/// The persistent kernel-network identity of one fanout work directory.
///
/// The default directory deliberately keeps the historical empty tag and 99.x
/// subnet. Other directories get a stable four-character tag and a persisted
/// second octet, so two instances cannot delete each other's namespaces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Instance {
    pub tag: String,
    pub net_base: u8,
}

impl Default for Instance {
    fn default() -> Self {
        Self {
            tag: String::new(),
            net_base: DEFAULT_NET_BASE,
        }
    }
}

impl Instance {
    pub fn legacy() -> Self {
        Self::default()
    }

    /// Select this work directory's identity and persist a newly selected base.
    pub fn init(work_dir: impl AsRef<Path>) -> Result<Self> {
        let work_dir = work_dir.as_ref();
        let abs = absolute_clean(work_dir);
        if abs == Path::new(DEFAULT_WORK_DIR) {
            return Ok(Self::legacy());
        }

        let tag = short_hash(&path_string(&abs));
        let net_base = load_or_pick_net_base(work_dir, &abs)?;
        Ok(Self { tag, net_base })
    }

    pub fn ns_name(&self, slot: usize) -> String {
        format!("fo{}{slot}", self.tag)
    }

    /// The subnet prefix, without a host part or prefix length.
    pub fn subnet(&self, slot: usize) -> String {
        format!("10.{}.{slot}", self.net_base)
    }

    pub fn subnet_cidr(&self, slot: usize) -> String {
        format!("{}.0/30", self.subnet(slot))
    }

    /// Return the host-side and namespace-side veth names, in that order.
    pub fn veth_names(&self, slot: usize) -> (String, String) {
        (
            format!("fov{}{slot}", self.tag),
            format!("fop{}{slot}", self.tag),
        )
    }
}

/// An advisory, process-lifetime work-directory lock.
///
/// Dropping this value releases the lock. The file itself is intentionally not
/// removed: unlinking a locked file would let a second process lock a new inode.
pub struct WorkDirLock {
    _file: fs::File,
}

impl WorkDirLock {
    fn new(file: fs::File) -> Self {
        Self { _file: file }
    }
}

impl Drop for WorkDirLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::flock(self._file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub fn lock_work_dir(dir: impl AsRef<Path>) -> Result<WorkDirLock> {
    let dir = dir.as_ref();
    let path = dir.join("lock");
    let file = open_file(&path, 0o600, true).context("打开锁文件失败")?;

    #[cfg(unix)]
    {
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            bail!(
                "另一个 fanout 正在用工作目录 {}；要同时跑第二个实例，给它一个不同的 -dir",
                dir.display()
            );
        }
    }

    Ok(WorkDirLock::new(file))
}

/// Read a valid persisted base, or select and atomically persist a free one.
pub fn load_or_pick_net_base(work_dir: &Path, abs: &Path) -> Result<u8> {
    load_or_pick_net_base_with_used(work_dir, abs, host_used_net_bases())
}

/// Testable form of [`load_or_pick_net_base`] with an explicit host snapshot.
pub fn load_or_pick_net_base_with_used(
    work_dir: &Path,
    abs: &Path,
    used: BTreeSet<u8>,
) -> Result<u8> {
    let path = work_dir.join("netbase");
    if let Ok(blob) = fs::read(&path) {
        if let Ok(text) = std::str::from_utf8(&blob) {
            if let Ok(base) = text.trim().parse::<u8>() {
                if (NET_BASE_MIN..=NET_BASE_MAX).contains(&base) {
                    return Ok(base);
                }
            }
        }
    }

    let base = pick_net_base_with_used(abs, &used)?;
    crate::util::atomic_write(&path, format!("{base}\n").as_bytes(), 0o600)
        .context("记录网段失败")?;
    Ok(base)
}

/// Pick a free 10.100.x through 10.255.x subnet, starting at the directory hash.
pub fn pick_net_base(abs: &Path) -> Result<u8> {
    pick_net_base_with_used(abs, &host_used_net_bases())
}

pub fn pick_net_base_with_used(abs: &Path, used: &BTreeSet<u8>) -> Result<u8> {
    let span = u32::from(NET_BASE_MAX - NET_BASE_MIN) + 1;
    let start = fnv1a32(&path_string(abs)) % span;
    for offset in 0..span {
        let base = NET_BASE_MIN + ((start + offset) % span) as u8;
        if !used.contains(&base) {
            return Ok(base);
        }
    }
    bail!("10.100.x 到 10.255.x 都被占用了，腾一个出来再启动");
}

/// Collect the second octets of IPv4 addresses already configured on the host.
/// The historical 99.x range is always reserved, even if `ip` is unavailable.
pub fn host_used_net_bases() -> BTreeSet<u8> {
    let mut used = BTreeSet::from([DEFAULT_NET_BASE]);
    let args = vec!["-4".into(), "-o".into(), "addr".into(), "show".into()];
    let Ok(out) = output_command("ip", &args) else {
        return used;
    };
    used.extend(parse_host_used_net_bases(
        &String::from_utf8_lossy(&out.stdout),
    ));
    used
}

/// Parse `ip -4 -o addr show` output without invoking the command.
pub fn parse_host_used_net_bases(output: &str) -> BTreeSet<u8> {
    let mut used = BTreeSet::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        for (index, field) in fields.iter().enumerate() {
            if *field != "inet" {
                continue;
            }
            let Some(address) = fields.get(index + 1) else {
                continue;
            };
            let address = address.split('/').next().unwrap_or(address);
            let Ok(ip) = address.parse::<std::net::Ipv4Addr>() else {
                continue;
            };
            let octets = ip.octets();
            if octets[0] == 10 {
                used.insert(octets[1]);
            }
        }
    }
    used
}

/// Go's filepath.Abs + filepath.Clean behavior for the identity input: make the
/// path absolute and remove `.`/`..`, but do not resolve symlinks.
fn absolute_clean(path: &Path) -> PathBuf {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut clean = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !clean.pop() && !clean.has_root() {
                    clean.push("..");
                }
            }
            other => clean.push(other.as_os_str()),
        }
    }
    clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn absolute_clean_handles_legacy_spellings() {
        assert_eq!(absolute_clean(Path::new(DEFAULT_WORK_DIR)), Path::new(DEFAULT_WORK_DIR));
        assert_eq!(
            absolute_clean(Path::new("/var/lib/fanout/")),
            Path::new(DEFAULT_WORK_DIR)
        );
        assert_eq!(
            absolute_clean(Path::new("/var/lib/other/../fanout")),
            Path::new(DEFAULT_WORK_DIR)
        );
    }

    #[test]
    fn base_picker_advances_past_occupied_ranges() {
        let abs = Path::new("/opt/fanout-demo");
        let start = (fnv1a32(&path_string(abs)) % 156) as u8;
        let used = BTreeSet::from([DEFAULT_NET_BASE, start]);
        let picked = pick_net_base_with_used(abs, &used).unwrap();
        assert!(picked >= NET_BASE_MIN && picked != start);
    }

    #[test]
    fn base_picker_reports_exhaustion() {
        let used: BTreeSet<u8> = (NET_BASE_MIN..=NET_BASE_MAX).collect();
        let err = pick_net_base_with_used(Path::new("/opt/fanout"), &used).unwrap_err();
        assert!(err.to_string().contains("都被占用了"));
    }

    #[test]
    fn host_address_parser_only_keeps_10_x_second_octets() {
        let output = "2: eth0    inet 10.8.0.2/24 brd 10.8.0.255 scope global eth0\n\
                      3: docker0 inet 10.255.1.1/16 scope global docker0\n\
                      4: eth1    inet 192.168.1.2/24 scope global eth1\n";
        let used = parse_host_used_net_bases(output);
        assert_eq!(used, BTreeSet::from([8, 255]));
    }
}
