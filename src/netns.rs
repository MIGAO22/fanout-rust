use anyhow::{anyhow, bail, Context, Result};
use std::{
    collections::BTreeSet,
    fs, io,
    net::{
        IpAddr, Ipv4Addr, SocketAddr, TcpStream as StdTcpStream, ToSocketAddrs,
        UdpSocket as StdUdpSocket,
    },
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::{fs::File, path::Path};

use tokio::{
    net::{TcpStream, UdpSocket},
    sync::oneshot,
    time::{timeout, MissedTickBehavior},
};

use crate::{
    instance::Instance,
    process::{combined_output_command, output_command, run_formatted, run_quiet, OvpnProc},
    util::write_file,
};

#[cfg(target_os = "linux")]
use crate::process::enter_netns;

pub const SOCKS_DIAL_TIMEOUT: Duration = Duration::from_secs(15);
const NETNS_ROOT: &str = "/var/run/netns";
const NETNS_RESOLV_CONF: &str = "nameserver 8.8.8.8\n";

/// Addresses that the namespace may reach directly before the VPN is up.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetnsDirect {
    /// Host-side veth address, such as 10.99.12.1.
    pub gw: String,
    /// Namespace-side veth device, such as fop12.
    pub dev: String,
    /// VPN endpoints and DNS servers. Only IPv4 literals are accepted.
    pub ips: Vec<String>,
}

/// Generate the fail-closed direct route table.
///
/// There is intentionally no default route. Each valid IPv4 literal gets one
/// idempotent `/32` route through the host-side veth. Sorting and deduplication
/// keep command logs stable across reconnects.
pub fn netns_direct_cmds(input: NetnsDirect) -> Vec<Vec<String>> {
    if input.gw.is_empty() || input.dev.is_empty() {
        return Vec::new();
    }

    let mut addresses = BTreeSet::new();
    for value in input.ips {
        let address = match value.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) => Some(address),
            // Match Go's net.ParseIP(...).To4(): IPv4-mapped literals are
            // normalized to their IPv4 route rather than emitted as invalid v6.
            Ok(IpAddr::V6(address)) => address.to_ipv4_mapped(),
            Err(_) => None,
        };
        if let Some(address) = address {
            addresses.insert(address.to_string());
        }
    }

    addresses
        .into_iter()
        .map(|address| {
            vec![
                "ip".into(),
                "route".into(),
                "replace".into(),
                format!("{address}/32"),
                "via".into(),
                input.gw.clone(),
                "dev".into(),
                input.dev.clone(),
            ]
        })
        .collect()
}

/// Recognize a real `default` route line, not merely the word "default".
pub fn route_has_default(output: &str) -> bool {
    output.lines().any(|line| {
        let mut fields = line.split_whitespace();
        fields.next() == Some("default") && fields.next().is_some()
    })
}

/// Converge generic TCP/UDP network names onto IPv4. Already versioned names
/// are preserved, matching Go's `forceIPv4Network`.
pub fn force_ipv4_network(network: &str) -> &str {
    match network {
        "tcp" => "tcp4",
        "udp" => "udp4",
        other => other,
    }
}

/// The namespace and veth identity belonging to one tunnel slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Netns {
    pub instance: Instance,
    pub slot: usize,
}

impl Netns {
    pub fn new(instance: Instance, slot: usize) -> Self {
        Self { instance, slot }
    }

    pub fn name(&self) -> String {
        self.instance.ns_name(self.slot)
    }

    pub fn subnet(&self) -> String {
        self.instance.subnet(self.slot)
    }

    pub fn subnet_cidr(&self) -> String {
        self.instance.subnet_cidr(self.slot)
    }

    pub fn gateway(&self) -> String {
        format!("{}.1", self.subnet())
    }

    pub fn veth(&self) -> String {
        self.instance.veth_names(self.slot).0
    }

    pub fn peer(&self) -> String {
        self.instance.veth_names(self.slot).1
    }

    /// Recreate the namespace, veth, DNS pins, NAT, and forwarding rules.
    /// `direct_ips` should contain the node's resolved egress IPs; the netns DNS
    /// server is added here automatically.
    pub fn setup(&self, direct_ips: &[String]) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, direct_ips);
            bail!("Linux network namespaces are not available on this platform");
        }

        #[cfg(target_os = "linux")]
        self.setup_linux(direct_ips)
    }

    #[cfg(target_os = "linux")]
    fn setup_linux(&self, direct_ips: &[String]) -> Result<()> {
        let name = self.name();
        let subnet = self.subnet();
        let veth = self.veth();
        let peer = self.peer();

        self.teardown();

        run_formatted("ip", &strings(["netns", "add", &name]))?;
        run_formatted(
            "ip",
            &strings(["netns", "exec", &name, "ip", "link", "set", "lo", "up"]),
        )?;
        run_formatted(
            "ip",
            &strings(["link", "add", &veth, "type", "veth", "peer", "name", &peer]),
        )?;
        run_formatted("ip", &strings(["link", "set", &peer, "netns", &name]))?;
        run_formatted(
            "ip",
            &strings(["addr", "add", &format!("{subnet}.1/30"), "dev", &veth]),
        )?;
        run_formatted("ip", &strings(["link", "set", &veth, "up"]))?;
        run_formatted(
            "ip",
            &strings([
                "netns",
                "exec",
                &name,
                "ip",
                "addr",
                "add",
                &format!("{subnet}.2/30"),
                "dev",
                &peer,
            ]),
        )?;
        run_formatted(
            "ip",
            &strings(["netns", "exec", &name, "ip", "link", "set", &peer, "up"]),
        )?;

        let ns_dir = Path::new("/etc/netns").join(&name);
        let mut directory = fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o755);
        }
        directory
            .create(&ns_dir)
            .with_context(|| format!("创建 {} 失败", ns_dir.display()))?;
        write_file(ns_dir.join("resolv.conf"), NETNS_RESOLV_CONF, 0o644)
            .context("写 resolv.conf 失败")?;

        // Do not add a default route here. If OpenVPN dies, only the endpoint
        // and DNS /32s remain, so client traffic cannot fall back to the host.
        let mut ips = direct_ips.to_vec();
        ips.push("8.8.8.8".into());
        let pins = netns_direct_cmds(NetnsDirect {
            gw: self.gateway(),
            dev: peer,
            ips,
        });
        for pin in pins {
            let mut args = vec!["netns".into(), "exec".into(), name.clone()];
            args.extend(pin);
            run_formatted("ip", &args)?;
        }

        let cidr = self.subnet_cidr();
        ensure_rule("nat", "POSTROUTING", &["-s", &cidr, "-j", "MASQUERADE"])?;
        ensure_rule_insert("filter", "FORWARD", &["-s", &cidr, "-j", "ACCEPT"])?;
        ensure_rule_insert("filter", "FORWARD", &["-d", &cidr, "-j", "ACCEPT"])?;
        Ok(())
    }

    /// Best-effort cleanup. Individual resources may already be absent.
    pub fn teardown(&self) {
        #[cfg(target_os = "linux")]
        {
            let name = self.name();
            let veth = self.veth();
            let cidr = self.subnet_cidr();
            run_quiet("ip", &strings(["netns", "del", &name]));
            run_quiet("ip", &strings(["link", "del", &veth]));
            run_quiet(
                "iptables",
                &strings([
                    "-w",
                    "5",
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-s",
                    &cidr,
                    "-j",
                    "MASQUERADE",
                ]),
            );
            run_quiet(
                "iptables",
                &strings(["-w", "5", "-D", "FORWARD", "-s", &cidr, "-j", "ACCEPT"]),
            );
            run_quiet(
                "iptables",
                &strings(["-w", "5", "-D", "FORWARD", "-d", &cidr, "-j", "ACCEPT"]),
            );
        }
    }
}

fn strings<'a>(parts: impl AsRef<[&'a str]>) -> Vec<String> {
    parts
        .as_ref()
        .iter()
        .map(|part| (*part).to_string())
        .collect()
}

fn ensure_rule(table: &str, chain: &str, spec: &[&str]) -> Result<()> {
    ensure_rule_impl(table, chain, None, spec)
}

fn ensure_rule_insert(table: &str, chain: &str, spec: &[&str]) -> Result<()> {
    ensure_rule_impl(table, chain, Some("1"), spec)
}

fn ensure_rule_impl(
    table: &str,
    chain: &str,
    insert_at: Option<&str>,
    spec: &[&str],
) -> Result<()> {
    let mut last_error = None;
    for attempt in 0..6 {
        let mut check = strings(&["-w", "5", "-t", table, "-C", chain]);
        check.extend(spec.iter().map(|part| (*part).to_string()));
        if run_formatted("iptables", &check).is_ok() {
            return Ok(());
        }

        let mut args = strings(&["-w", "5", "-t", table]);
        if let Some(position) = insert_at {
            args.extend(strings(&["-I", chain, position]));
        } else {
            args.extend(strings(&["-A", chain]));
        }
        args.extend(spec.iter().map(|part| (*part).to_string()));
        match run_formatted("iptables", &args) {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                if attempt + 1 < 6 {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("iptables 规则写入失败")))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    Tcp,
    Udp,
}

impl Network {
    pub fn parse(network: &str) -> Result<Self> {
        match force_ipv4_network(network) {
            "tcp4" => Ok(Self::Tcp),
            "udp4" => Ok(Self::Udp),
            other => bail!("netns 拨号只支持 IPv4 TCP/UDP，拒绝 {other}"),
        }
    }
}

#[derive(Debug)]
pub enum NetnsConnection {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

impl NetnsConnection {
    pub fn as_tcp(&self) -> Option<&TcpStream> {
        match self {
            Self::Tcp(stream) => Some(stream),
            Self::Udp(_) => None,
        }
    }

    pub fn as_udp(&self) -> Option<&UdpSocket> {
        match self {
            Self::Tcp(_) => None,
            Self::Udp(socket) => Some(socket),
        }
    }

    pub fn into_tcp(self) -> Option<TcpStream> {
        match self {
            Self::Tcp(stream) => Some(stream),
            Self::Udp(_) => None,
        }
    }

    pub fn into_udp(self) -> Option<UdpSocket> {
        match self {
            Self::Tcp(_) => None,
            Self::Udp(socket) => Some(socket),
        }
    }
}

/// An IPv4-only dialer that creates each socket inside `namespace`.
///
/// Every dial runs on a new std OS thread. That thread enters the target with
/// `setns`, creates/connects the socket, and restores its original namespace
/// before exiting. It is never a Tokio worker or a reusable blocking-pool
/// thread, so neither cancellation nor a failed restore can poison other work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetnsDialer {
    namespace: String,
    timeout: Duration,
}

impl NetnsDialer {
    pub fn new(namespace: impl Into<String>) -> Self {
        Self::with_timeout(namespace, SOCKS_DIAL_TIMEOUT)
    }

    pub fn with_timeout(namespace: impl Into<String>, timeout: Duration) -> Self {
        Self {
            namespace: namespace.into(),
            timeout,
        }
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub async fn dial<A>(&self, network: &str, address: A) -> Result<NetnsConnection>
    where
        A: ToSocketAddrs + Send + 'static,
    {
        match Network::parse(network)? {
            Network::Tcp => self.dial_tcp(address).await.map(NetnsConnection::Tcp),
            Network::Udp => self.dial_udp(address).await.map(NetnsConnection::Udp),
        }
    }

    pub async fn dial_tcp_host(&self, host: impl Into<String>, port: u16) -> Result<TcpStream> {
        self.dial_tcp((host.into(), port)).await
    }

    pub async fn dial_tcp<A>(&self, address: A) -> Result<TcpStream>
    where
        A: ToSocketAddrs + Send + 'static,
    {
        let budget = self.timeout;
        let namespace = self.namespace.clone();
        let mut receiver = self.spawn_in_netns(move || connect_tcp(address, budget))?;
        let stream = timeout(budget, &mut receiver)
            .await
            .map_err(|_| anyhow!("在 netns {namespace} 内 TCP 拨号超时"))?
            .context("netns 拨号线程异常退出")?;
        let stream =
            stream.map_err(|error| anyhow!("在 netns {namespace} 内 TCP 连接失败: {error}"))?;
        TcpStream::from_std(stream)
            .with_context(|| format!("在 netns {namespace} 内创建 Tokio TCP socket 失败"))
    }

    pub async fn dial_udp_host(&self, host: impl Into<String>, port: u16) -> Result<UdpSocket> {
        self.dial_udp((host.into(), port)).await
    }

    pub async fn dial_udp<A>(&self, address: A) -> Result<UdpSocket>
    where
        A: ToSocketAddrs + Send + 'static,
    {
        let budget = self.timeout;
        let namespace = self.namespace.clone();
        let mut receiver = self.spawn_in_netns(move || connect_udp(address, budget))?;
        let socket = timeout(budget, &mut receiver)
            .await
            .map_err(|_| anyhow!("在 netns {namespace} 内 UDP 拨号超时"))?
            .context("netns 拨号线程异常退出")?;
        let socket =
            socket.map_err(|error| anyhow!("在 netns {namespace} 内 UDP 连接失败: {error}"))?;
        UdpSocket::from_std(socket)
            .with_context(|| format!("在 netns {namespace} 内创建 Tokio UDP socket 失败"))
    }

    fn spawn_in_netns<T, F>(&self, operation: F) -> Result<oneshot::Receiver<io::Result<T>>>
    where
        T: Send + 'static,
        F: FnOnce() -> io::Result<T> + Send + 'static,
    {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, operation);
            bail!("Linux network namespaces are not available on this platform");
        }

        #[cfg(target_os = "linux")]
        {
            let target_path = Path::new(NETNS_ROOT).join(&self.namespace);
            let namespace = self.namespace.clone();
            let (sender, receiver) = oneshot::channel();
            thread::Builder::new()
                .name("fanout-netns-dial".into())
                .spawn(move || {
                    let origin = match File::open("/proc/thread-self/ns/net") {
                        Ok(file) => file,
                        Err(error) => {
                            let error = io::Error::new(
                                error.kind(),
                                format!("记录拨号线程原网络命名空间失败: {error}"),
                            );
                            let _ = sender.send(Err(error));
                            return;
                        }
                    };
                    let target = match File::open(&target_path) {
                        Ok(file) => file,
                        Err(error) => {
                            let error = io::Error::new(
                                error.kind(),
                                format!("打开 netns {namespace} 失败: {error}"),
                            );
                            let _ = sender.send(Err(error));
                            return;
                        }
                    };

                    let mut restore = RestoreOnDrop::new(origin);
                    if let Err(error) = enter_netns(&target) {
                        let error = io::Error::new(
                            error.kind(),
                            format!("切入 netns {namespace} 失败: {error}"),
                        );
                        let _ = sender.send(Err(error));
                        return;
                    }
                    restore.armed = true;
                    if sender.is_closed() {
                        return;
                    }

                    let result = operation();
                    if let Err(error) = enter_netns(&restore.origin) {
                        // The socket, if any, is dropped by `result`. This thread
                        // is never reused; Drop makes one best-effort restore retry.
                        let error = io::Error::new(
                            error.kind(),
                            format!("恢复原网络命名空间失败: {error}"),
                        );
                        let _ = sender.send(Err(error));
                        return;
                    }
                    restore.armed = false;
                    let _ = sender.send(result);
                })
                .context("启动 netns 拨号线程失败")?;
            Ok(receiver)
        }
    }
}

#[cfg(target_os = "linux")]
struct RestoreOnDrop {
    origin: File,
    armed: bool,
}

#[cfg(target_os = "linux")]
impl RestoreOnDrop {
    fn new(origin: File) -> Self {
        Self {
            origin,
            armed: false,
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for RestoreOnDrop {
    fn drop(&mut self) {
        if self.armed {
            // Panic unwinding still restores the namespace. This dedicated
            // thread terminates immediately afterwards either way.
            let _ = enter_netns(&self.origin);
        }
    }
}

fn resolve_ipv4<A: ToSocketAddrs + Send + 'static>(
    address: A,
    budget: Duration,
) -> io::Result<Vec<SocketAddr>> {
    if budget.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "DNS 解析超时"));
    }

    // std's resolver has no cancellation API. Run it on a disposable thread
    // and bound the wait, so the setns thread can still restore the host even
    // when getaddrinfo stalls. The resolver inherits the target namespace and
    // is never returned to a worker pool.
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("fanout-netns-dns".into())
        .spawn(move || {
            let _ = sender.send(resolve_ipv4_now(address));
        })
        .map_err(io::Error::other)?;
    receiver.recv_timeout(budget).unwrap_or_else(|error| {
        let kind = match error {
            mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
            mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::Other,
        };
        Err(io::Error::new(kind, format!("DNS 解析失败: {error}")))
    })
}

fn resolve_ipv4_now<A: ToSocketAddrs>(address: A) -> io::Result<Vec<SocketAddr>> {
    let addresses: Vec<SocketAddr> = address
        .to_socket_addrs()?
        .filter(|address| matches!(address, SocketAddr::V4(_)))
        .collect();
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "目标没有 IPv4 地址",
        ));
    }
    Ok(addresses)
}

fn connect_tcp<A: ToSocketAddrs + Send + 'static>(
    address: A,
    budget: Duration,
) -> io::Result<StdTcpStream> {
    let deadline = Instant::now() + budget;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let addresses = resolve_ipv4(address, remaining)?;
    let mut last_error = None;
    for address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "TCP 拨号超时"));
        }
        match StdTcpStream::connect_timeout(&address, remaining) {
            Ok(stream) => {
                stream.set_nonblocking(true)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "目标没有 IPv4 地址")))
}

fn connect_udp<A: ToSocketAddrs + Send + 'static>(
    address: A,
    budget: Duration,
) -> io::Result<StdUdpSocket> {
    let deadline = Instant::now() + budget;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let addresses = resolve_ipv4(address, remaining)?;
    if deadline.saturating_duration_since(Instant::now()).is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "UDP 拨号超时"));
    }
    let address = addresses
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "目标没有 IPv4 地址"))?;
    let socket = StdUdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(&address)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Whether tun0 currently has an IPv4 address in this namespace.
pub fn tun0_up(namespace: &str) -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = namespace;
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        let args = strings([
            "netns", "exec", namespace, "ip", "-4", "addr", "show", "tun0",
        ]);
        output_command("ip", &args)
            .map(|output| String::from_utf8_lossy(&output.stdout).contains("inet "))
            .unwrap_or(false)
    }
}

/// Whether the namespace has a default route (normally pushed by OpenVPN).
pub fn netns_has_default(namespace: &str) -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = namespace;
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        let args = strings([
            "netns", "exec", namespace, "ip", "-o", "route", "show", "default",
        ]);
        combined_output_command("ip", &args)
            .map(|output| route_has_default(&String::from_utf8_lossy(&output.stdout)))
            .unwrap_or(false)
    }
}

fn tun_timeout(budget: Duration) -> anyhow::Error {
    anyhow!("等待 tun0 就绪超时（预算 {:.0} 秒）", budget.as_secs_f64())
}

/// Wait for tun0's IPv4 address, returning immediately if OpenVPN exits.
pub async fn wait_tun_up(process: &OvpnProc, namespace: &str, budget: Duration) -> Result<()> {
    let deadline = Instant::now() + budget;
    let mut ticker = tokio::time::interval(Duration::from_millis(400));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("{}", tun_timeout(budget));
        }

        tokio::select! {
            result = process.wait_for_exit() => {
                match result {
                    Err(error) => bail!("openvpn 退出: {error}"),
                    Ok(()) => bail!("openvpn 意外结束"),
                };
            }
            _ = ticker.tick() => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    bail!("{}", tun_timeout(budget));
                }
                let namespace = namespace.to_string();
                let check = tokio::task::spawn_blocking(move || tun0_up(&namespace));
                match timeout(remaining, check).await {
                    Ok(Ok(true)) => return Ok(()),
                    Ok(Ok(false)) => {}
                    Ok(Err(error)) => bail!("检查 tun0 失败: {error}"),
                    Err(_) => bail!("{}", tun_timeout(budget)),
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "netns_test.rs"]
mod tests;
