use crate::models::HostStats;
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
#[path = "hoststats_test.rs"]
mod tests;

const CPU_FIRST_WINDOW: Duration = Duration::from_millis(200);
const CPU_MIN_WINDOW: Duration = Duration::from_millis(500);
const NET_MIN_WINDOW: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug, Default)]
struct CpuTimes {
    idle: u64,
    total: u64,
}

struct CpuSample {
    prev: CpuTimes,
    at: Option<Instant>,
    has: bool,
}

static CPU_SAMPLE: Mutex<CpuSample> = Mutex::new(CpuSample {
    prev: CpuTimes { idle: 0, total: 0 },
    at: None,
    has: false,
});

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|err| err.into_inner())
}

fn parse_cpu_times(blob: &[u8]) -> Result<CpuTimes> {
    let text = String::from_utf8_lossy(blob);
    for line in text.split('\n') {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 5 || fields[0] != "cpu" {
            continue;
        }
        let mut out = CpuTimes::default();
        for (i, field) in fields.iter().enumerate().skip(1) {
            let value: u64 = field
                .parse()
                .with_context(|| format!("第 {} 列 {:?} 不是数字", i, field))?;
            // guest and guest_nice are already included in user and nice.
            if i < 8 {
                out.total = out.total.wrapping_add(value);
            }
            // iowait is idle time for the purpose of this display.
            if i == 4 || i == 5 {
                out.idle = out.idle.wrapping_add(value);
            }
        }
        return Ok(out);
    }
    bail!("没找到汇总的 cpu 行")
}

fn read_cpu_times() -> Result<CpuTimes> {
    let blob = fs::read("/proc/stat").context("读 /proc/stat 失败")?;
    parse_cpu_times(&blob)
}

fn cpu_pct(prev: CpuTimes, cur: CpuTimes) -> f64 {
    let dt = (cur.total as i64).wrapping_sub(prev.total as i64);
    if dt <= 0 {
        return 0.0;
    }
    let di = (cur.idle as i64).wrapping_sub(prev.idle as i64);
    clamp_pct(100.0 * (dt.wrapping_sub(di)) as f64 / dt as f64)
}

fn read_cpu_pct() -> Result<f64> {
    let mut sample = lock_unpoisoned(&CPU_SAMPLE);
    if !sample.has {
        let prev = read_cpu_times()?;
        sample.prev = prev;
        sample.at = Some(Instant::now());
        sample.has = true;
        thread::sleep(CPU_FIRST_WINDOW);
    } else if let Some(at) = sample.at {
        let wait = CPU_MIN_WINDOW.saturating_sub(at.elapsed());
        if !wait.is_zero() {
            thread::sleep(wait);
        }
    }

    let cur = read_cpu_times()?;
    let pct = cpu_pct(sample.prev, cur);
    sample.prev = cur;
    sample.at = Some(Instant::now());
    Ok(pct)
}

fn parse_meminfo(blob: &[u8]) -> (i64, i64, i64, i64) {
    let text = String::from_utf8_lossy(blob);
    let mut mem_total = 0;
    let mut mem_free = 0;
    let mut mem_avail = 0;
    let mut swap_total = 0;
    let mut swap_free = 0;
    let mut seen_available = false;

    for line in text.split('\n') {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let Some(value) = rest.split_whitespace().next() else {
            continue;
        };
        let Ok(value) = value.parse::<i64>() else {
            continue;
        };
        match key {
            "MemTotal" => mem_total = value,
            "MemFree" => mem_free = value,
            "MemAvailable" => {
                mem_avail = value;
                seen_available = true;
            }
            "SwapTotal" => swap_total = value,
            "SwapFree" => swap_free = value,
            _ => {}
        }
    }
    if !seen_available {
        mem_avail = mem_free;
    }
    (mem_total, mem_avail, swap_total, swap_free)
}

fn parse_loadavg(blob: &[u8]) -> Result<(f64, f64, f64)> {
    let text = String::from_utf8_lossy(blob);
    let fields: Vec<_> = text.split_whitespace().collect();
    if fields.len() < 3 {
        bail!("负载行字段太少: {:?}", text.trim());
    }
    let load1 = fields[0].parse::<f64>().context("解析 load1 失败")?;
    let load5 = fields[1].parse::<f64>().context("解析 load5 失败")?;
    let load15 = fields[2].parse::<f64>().context("解析 load15 失败")?;
    Ok((load1, load5, load15))
}

fn parse_sockstat(blob: &[u8]) -> (u64, u64) {
    fn after(fields: &[&str], keys: &[&str]) -> i64 {
        if keys.is_empty() {
            return 0;
        }
        for i in 0..fields.len().saturating_sub(keys.len() - 1) {
            if fields[i] != keys[0] || !fields[i..].starts_with(keys) {
                continue;
            }
            for field in &fields[i + keys.len()..] {
                if let Ok(value) = field.parse::<isize>() {
                    return value as i64;
                }
            }
        }
        0
    }

    let text = String::from_utf8_lossy(blob);
    let mut tcp = 0i64;
    let mut udp = 0i64;
    for line in text.split('\n') {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        let in_use = || {
            for keys in [&["inuse"][..], &["in", "use"][..]] {
                let value = after(&fields, keys);
                if value != 0 {
                    return value;
                }
            }
            0
        };
        match fields[0] {
            "TCP:" | "TCP6:" => tcp = in_use().wrapping_add(after(&fields, &["tw"])),
            "UDP:" | "UDP6:" => udp = in_use(),
            _ => {}
        }
    }
    (tcp.max(0) as u64, udp.max(0) as u64)
}

fn parse_port_range(blob: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(blob);
    let fields: Vec<_> = text.split_whitespace().collect();
    if fields.len() < 2 {
        return 0;
    }
    let (Ok(lo), Ok(hi)) = (fields[0].parse::<i64>(), fields[1].parse::<i64>()) else {
        return 0;
    };
    if hi < lo {
        return 0;
    }
    hi.wrapping_sub(lo).wrapping_add(1).max(0) as u64
}

type NetDevMap = BTreeMap<String, [u64; 2]>;

fn parse_net_dev(blob: &[u8]) -> NetDevMap {
    let text = String::from_utf8_lossy(blob);
    let mut out = NetDevMap::new();
    for line in text.split('\n') {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let fields: Vec<_> = rest.split_whitespace().collect();
        if fields.len() < 9 {
            continue;
        }
        let (Ok(rx), Ok(tx)) = (fields[0].parse::<u64>(), fields[8].parse::<u64>()) else {
            continue;
        };
        out.insert(name.trim().to_string(), [rx, tx]);
    }
    out
}

fn parse_default_ifaces(blob: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(blob);
    let mut seen = BTreeSet::new();
    for line in text.split('\n') {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() >= 2 && fields[1] == "00000000" {
            seen.insert(fields[0].to_string());
        }
    }
    seen.into_iter().collect()
}

fn fallback_ifaces(devs: &NetDevMap) -> Vec<String> {
    devs.keys()
        .filter(|name| {
            name.as_str() != "lo"
                && !name.starts_with("veth")
                && !name.starts_with("docker")
                && !name.starts_with("br-")
                && !name.starts_with("virbr")
        })
        .cloned()
        .collect()
}

fn parse_link_speed(blob: &[u8]) -> i64 {
    String::from_utf8_lossy(blob)
        .trim()
        .parse::<i64>()
        .unwrap_or(0)
}

fn link_mbps_from<F>(ifaces: &[String], mut read_speed: F) -> f64
where
    F: FnMut(&str) -> Option<Vec<u8>>,
{
    let mut total = 0i64;
    for name in ifaces {
        let Some(blob) = read_speed(name) else {
            continue;
        };
        let speed = parse_link_speed(&blob);
        if speed > 0 {
            total = total.wrapping_add(speed);
        }
    }
    total as f64
}

fn link_mbps(ifaces: &[String]) -> f64 {
    link_mbps_from(ifaces, |name| {
        fs::read(format!("/sys/class/net/{name}/speed")).ok()
    })
}

fn clamp_pct(value: f64) -> f64 {
    if value < 0.0 {
        0.0
    } else if value > 100.0 {
        100.0
    } else {
        value
    }
}

fn pct_of(used: i64, total: i64) -> f64 {
    if total <= 0 {
        0.0
    } else {
        clamp_pct(100.0 * used as f64 / total as f64)
    }
}

fn pct_of_counts(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        clamp_pct(100.0 * used as f64 / total as f64)
    }
}

fn rate_pct(bps: f64, mbps: f64) -> f64 {
    if mbps <= 0.0 {
        0.0
    } else {
        clamp_pct(bps * 8.0 / (mbps * 1e6) * 100.0)
    }
}

fn kb_to_bytes(value: i64) -> u64 {
    if value <= 0 {
        0
    } else {
        (value as u64).saturating_mul(1024)
    }
}

// df's Use% excludes root-reserved blocks from its denominator, while "used"
// still includes them. Keep that distinction rather than reporting used/total.
fn disk_stat(blocks: i64, bfree: i64, bavail: i64, frsize: i64) -> (u64, u64, f64) {
    if blocks <= 0 || frsize <= 0 {
        return (0, 0, 0.0);
    }
    let bfree = bfree.min(blocks);
    let bavail = bavail.min(blocks);
    let used = blocks.wrapping_sub(bfree).wrapping_mul(frsize);
    let total = blocks.wrapping_mul(frsize);
    let room = used.wrapping_add(bavail.wrapping_mul(frsize));
    let pct = if room > 0 {
        clamp_pct(100.0 * used as f64 / room as f64)
    } else {
        0.0
    };
    (used.max(0) as u64, total.max(0) as u64, pct)
}

#[cfg(unix)]
fn statfs_blocks(path: &Path) -> Result<(i64, i64, i64, i64)> {
    let stat = nix::sys::statfs::statfs(path)
        .with_context(|| format!("statfs {} 失败", path.display()))?;
    Ok((
        stat.blocks() as i64,
        stat.blocks_free() as i64,
        stat.blocks_available() as i64,
        stat.block_size() as i64,
    ))
}

#[cfg(not(unix))]
fn statfs_blocks(_path: &Path) -> Result<(i64, i64, i64, i64)> {
    bail!("当前平台不支持 statfs")
}

fn read_disk_usage<P: AsRef<Path>>(paths: &[P]) -> Result<(u64, u64, f64, String)> {
    let mut last_err = None;
    for path in paths {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            continue;
        }
        let (blocks, bfree, bavail, frsize) = match statfs_blocks(path) {
            Ok(values) => values,
            Err(err) => {
                last_err = Some(err);
                continue;
            }
        };
        let (used, total, pct) = disk_stat(blocks, bfree, bavail, frsize);
        if total == 0 {
            continue;
        }
        return Ok((used, total, pct, path.to_string_lossy().into_owned()));
    }
    match last_err {
        Some(err) => Err(err),
        None => bail!("没有可统计的挂载点"),
    }
}

#[derive(Default)]
struct NetCounters {
    at: Option<Instant>,
    devs: NetDevMap,
    has: bool,
    up: f64,
    down: f64,
    ready: bool,
}

static NET_SAMPLE: Mutex<NetCounters> = Mutex::new(NetCounters {
    at: None,
    devs: BTreeMap::new(),
    has: false,
    up: 0.0,
    down: 0.0,
    ready: false,
});

fn net_rates_at(
    cur: NetDevMap,
    ifaces: &[String],
    now: Instant,
    sample: &mut NetCounters,
) -> (f64, f64, bool) {
    let had_prev = sample.has;
    let dt = sample
        .at
        .map(|at| now.saturating_duration_since(at).as_secs_f64())
        .unwrap_or(0.0);
    if !had_prev {
        sample.devs = cur;
        sample.at = Some(now);
        sample.has = true;
        return (sample.up, sample.down, sample.ready);
    }
    if dt < NET_MIN_WINDOW.as_secs_f64() {
        return (sample.up, sample.down, sample.ready);
    }
    let prev = std::mem::replace(&mut sample.devs, cur);
    sample.at = Some(now);

    let mut rx = 0u64;
    let mut tx = 0u64;
    for name in ifaces {
        let (Some(cur), Some(prev)) = (sample.devs.get(name), prev.get(name)) else {
            continue;
        };
        if cur[0] < prev[0] || cur[1] < prev[1] {
            continue;
        }
        rx = rx.wrapping_add(cur[0] - prev[0]);
        tx = tx.wrapping_add(cur[1] - prev[1]);
    }
    sample.up = tx as f64 / dt;
    sample.down = rx as f64 / dt;
    sample.ready = true;
    (sample.up, sample.down, true)
}

fn net_rates(cur: NetDevMap, ifaces: &[String]) -> (f64, f64, bool) {
    let mut sample = lock_unpoisoned(&NET_SAMPLE);
    net_rates_at(cur, ifaces, Instant::now(), &mut sample)
}

fn read_network_stats() -> Result<HostStats> {
    let mut st = HostStats::default();
    let blob = fs::read("/proc/net/sockstat").context("读 /proc/net/sockstat 失败")?;
    (st.tcp, st.udp) = parse_sockstat(&blob);
    if let Ok(v6) = fs::read("/proc/net/sockstat6") {
        (st.tcp6, st.udp6) = parse_sockstat(&v6);
        st.tcp = st.tcp.wrapping_add(st.tcp6);
        st.udp = st.udp.wrapping_add(st.udp6);
    }
    if let Ok(range) = fs::read("/proc/sys/net/ipv4/ip_local_port_range") {
        st.sock_cap = parse_port_range(&range);
    }
    st.tcp_pct = pct_of_counts(st.tcp, st.sock_cap);
    st.udp_pct = pct_of_counts(st.udp, st.sock_cap);

    if let Ok(blob) = fs::read("/proc/net/dev") {
        let devs = parse_net_dev(&blob);
        let mut names = fs::read("/proc/net/route")
            .map(|blob| parse_default_ifaces(&blob))
            .unwrap_or_default();
        if names.is_empty() {
            names = fallback_ifaces(&devs);
        }
        st.net_if = names.join(" ");
        let (up, down, ready) = net_rates(devs, &names);
        st.up_bps = up.max(0.0) as u64;
        st.down_bps = down.max(0.0) as u64;
        st.net_ready = ready;
        st.link_mbps = link_mbps(&names);
        st.up_pct = rate_pct(up, st.link_mbps);
        st.down_pct = rate_pct(down, st.link_mbps);
    }
    Ok(st)
}

/// Collect one host snapshot. The data directory is tried before `/` for disk
/// usage so the displayed filesystem is the one fanout actually writes to.
pub fn read_host_stats(data_dir: &Path) -> Result<HostStats> {
    let mut st = HostStats::default();
    let mut errs = Vec::new();

    match read_cpu_pct() {
        Ok(pct) => st.cpu = pct,
        Err(err) => errs.push(format!("{err:#}")),
    }

    match fs::read("/proc/meminfo") {
        Ok(blob) => {
            let (total, avail, swap_total, swap_free) = parse_meminfo(&blob);
            let mem_used = total.saturating_sub(avail);
            let swap_used = swap_total.saturating_sub(swap_free);
            st.mem_total = kb_to_bytes(total);
            st.mem_used = kb_to_bytes(mem_used);
            st.mem_pct = pct_of(mem_used, total);
            st.swap_total = kb_to_bytes(swap_total);
            st.swap_used = kb_to_bytes(swap_used);
            st.swap_pct = pct_of(swap_used, swap_total);
        }
        Err(err) => errs.push(format!("{err:#}")),
    }

    match read_disk_usage(&[data_dir, Path::new("/")]) {
        Ok((used, total, pct, mount)) => {
            st.disk_used = used;
            st.disk_total = total;
            st.disk_pct = pct;
            st.disk_mount = mount;
        }
        Err(err) => errs.push(format!("{err:#}")),
    }

    st.cores = thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    match fs::read("/proc/loadavg") {
        Ok(blob) => match parse_loadavg(&blob) {
            Ok((load1, load5, load15)) => {
                st.load1 = load1;
                st.load5 = load5;
                st.load15 = load15;
                st.load_pct = clamp_pct(100.0 * load1 / st.cores.max(1) as f64);
            }
            Err(err) => errs.push(format!("{err:#}")),
        },
        Err(err) => errs.push(format!("{err:#}")),
    }

    // /proc/net and sysfs are namespace-scoped, so use the shared startup guard.
    match crate::process::in_main_netns(read_network_stats) {
        Ok(net) => {
            st.tcp = net.tcp;
            st.udp = net.udp;
            st.tcp6 = net.tcp6;
            st.udp6 = net.udp6;
            st.sock_cap = net.sock_cap;
            st.tcp_pct = net.tcp_pct;
            st.udp_pct = net.udp_pct;
            st.up_bps = net.up_bps;
            st.down_bps = net.down_bps;
            st.up_pct = net.up_pct;
            st.down_pct = net.down_pct;
            st.net_ready = net.net_ready;
            st.net_if = net.net_if;
            st.link_mbps = net.link_mbps;
        }
        Err(err) => errs.push(format!("{err:#}")),
    }

    if st.cpu == 0.0 && st.mem_total == 0 && st.load1 == 0.0 && st.tcp == 0 {
        bail!("读不到本机负载：{}", errs.join("；"));
    }
    Ok(st)
}
