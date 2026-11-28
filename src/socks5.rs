use crate::{models::SocksCred, observability::TrafficCounters};
use anyhow::Error as AnyhowError;
use async_trait::async_trait;
use futures::FutureExt;
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::Mutex,
    task::JoinSet,
    time::{timeout, timeout_at, Duration, Instant},
};

pub const SOCKS_VERSION: u8 = 0x05;
pub const AUTH_NONE: u8 = 0x00;
pub const AUTH_USER_PASS: u8 = 0x02;
pub const AUTH_NO_ACCEPT: u8 = 0xff;
pub const AUTH_SUB_VERSION: u8 = 0x01;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;

pub const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(30);
pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const RELAY_BUFFER_SIZE: usize = 32 * 1024;
const UDP_MAX_SESSIONS: usize = 256;

/// Errors whose text is part of the original Go implementation.
#[derive(Debug)]
pub enum SocksError {
    Io(io::Error),
    Dial(AnyhowError),
    NotSocks5,
    AuthNotOffered,
    InvalidAuthVersion,
    InvalidCredentials,
    CommandNotSupported,
    IPv6NotSupported,
    UnsupportedAddressType(u8),
    WrongSocketType(&'static str),
}

impl fmt::Display for SocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => err.fmt(f),
            Self::Dial(err) => err.fmt(f),
            Self::NotSocks5 => f.write_str("不是 socks5"),
            Self::AuthNotOffered => f.write_str("客户端不支持用户名口令认证"),
            Self::InvalidAuthVersion => f.write_str("认证子协议版本不对"),
            Self::InvalidCredentials => f.write_str("用户名或口令不对"),
            Self::CommandNotSupported => f.write_str("仅支持 CONNECT 与 UDP ASSOCIATE"),
            Self::IPv6NotSupported => f.write_str("隧道内不支持 IPv6"),
            Self::UnsupportedAddressType(atyp) => write!(f, "不支持的地址类型 {atyp}"),
            Self::WrongSocketType(expected) => write!(f, "拨号返回的 socket 类型不是 {expected}"),
        }
    }
}

impl Error for SocksError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Dial(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}

impl From<io::Error> for SocksError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<AnyhowError> for SocksError {
    fn from(err: AnyhowError) -> Self {
        Self::Dial(err)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialNetwork {
    Tcp,
    Udp,
}

impl DialNetwork {
    /// The network name used by the Go SOCKS5 dial callback.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// Implementations must use this form so AAAA records cannot bypass the tunnel.
    pub const fn ipv4_as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp4",
            Self::Udp => "udp4",
        }
    }
}

#[derive(Debug)]
pub enum DialSocket {
    Tcp(TcpStream),
    Udp(UdpSocket),
}

pub type DialError = AnyhowError;

pub struct DialGuard(Option<Box<dyn FnOnce() + Send + Sync>>);

impl DialGuard {
    pub fn new(release: impl FnOnce() + Send + Sync + 'static) -> Self {
        Self(Some(Box::new(release)))
    }

    pub fn none() -> Self {
        Self(None)
    }
}

impl Drop for DialGuard {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            release();
        }
    }
}

/// Supplies already-created sockets to the SOCKS5 server.
///
/// Implementations are responsible for creating both socket types on a
/// namespace-affine thread and for restoring that thread's original network
/// namespace before returning. Use [`DialNetwork::ipv4_as_str`] for resolution
/// and dialing inside the selected namespace. A UDP result must be connected
/// to the requested destination, and returned Tokio sockets must be in
/// nonblocking mode (for example, via `TcpStream::from_std` or
/// `UdpSocket::from_std`).
#[async_trait]
pub trait SocksDialer: Send + Sync {
    async fn dial(&self, network: DialNetwork, addr: &str) -> Result<DialSocket, DialError>;

    async fn dial_guarded(
        &self,
        network: DialNetwork,
        addr: &str,
    ) -> Result<(DialSocket, DialGuard), DialError> {
        self.dial(network, addr)
            .await
            .map(|socket| (socket, DialGuard::none()))
    }
}

/// Handles one accepted SOCKS5 TCP connection, including authentication,
/// request negotiation, and CONNECT or UDP ASSOCIATE relay setup.
pub async fn serve_socks<D>(
    client: TcpStream,
    cred: Option<&SocksCred>,
    dial: &D,
) -> Result<(), SocksError>
where
    D: SocksDialer + ?Sized,
{
    serve_socks_inner(client, cred, dial, None).await
}

pub async fn serve_socks_counted<D>(
    client: TcpStream,
    cred: Option<&SocksCred>,
    dial: &D,
    traffic: Arc<TrafficCounters>,
) -> Result<(), SocksError>
where
    D: SocksDialer + ?Sized,
{
    serve_socks_inner(client, cred, dial, Some(traffic)).await
}

async fn serve_socks_inner<D>(
    mut client: TcpStream,
    cred: Option<&SocksCred>,
    dial: &D,
    traffic: Option<Arc<TrafficCounters>>,
) -> Result<(), SocksError>
where
    D: SocksDialer + ?Sized,
{
    let deadline = Instant::now() + NEGOTIATION_TIMEOUT;
    let _ = client.set_nodelay(true);

    match timeout_at(deadline, socks_handshake(&mut client, cred)).await {
        Ok(result) => result?,
        Err(_) => return Err(timeout_error()),
    }

    let request = match timeout_at(deadline, read_socks_request_with_cmd(&mut client)).await {
        Ok(result) => result,
        Err(_) => Err(timeout_error()),
    };
    let (cmd, addr) = match request {
        Ok(request) => request,
        Err(err) => {
            let code = if matches!(err, SocksError::CommandNotSupported) {
                REP_COMMAND_NOT_SUPPORTED
            } else {
                REP_GENERAL_FAILURE
            };
            let _ = timeout_at(deadline, socks_reply(&mut client, code)).await;
            return Err(err);
        }
    };

    if cmd == CMD_UDP_ASSOCIATE {
        // Unlike CONNECT, UDP ASSOCIATE has no overall control-connection timeout.
        return serve_udp_associate_inner(client, dial, &addr, traffic).await;
    }

    let (remote, _guard) =
        match timeout_at(deadline, dial.dial_guarded(DialNetwork::Tcp, &addr)).await {
            Ok(Ok((DialSocket::Tcp(stream), guard))) => (stream, guard),
            Ok(Ok((DialSocket::Udp(_), _))) => {
                let _ = timeout_at(deadline, socks_reply(&mut client, REP_HOST_UNREACHABLE)).await;
                return Err(SocksError::WrongSocketType("TcpStream"));
            }
            Ok(Err(err)) => {
                let _ = timeout_at(deadline, socks_reply(&mut client, REP_HOST_UNREACHABLE)).await;
                return Err(err.into());
            }
            Err(_) => {
                let _ = timeout_at(deadline, socks_reply(&mut client, REP_HOST_UNREACHABLE)).await;
                return Err(timeout_error());
            }
        };

    let _ = remote.set_nodelay(true);
    match timeout_at(deadline, socks_reply(&mut client, REP_SUCCESS)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => return Err(timeout_error()),
    }

    match traffic {
        Some(traffic) => relay_counted(client, remote, traffic)
            .await
            .map_err(SocksError::from),
        None => relay(client, remote).await.map_err(SocksError::from),
    }
}

/// Negotiates RFC1928 methods and, when required, RFC1929 credentials.
pub async fn socks_handshake<S>(stream: &mut S, cred: Option<&SocksCred>) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    read_full(stream, &mut head).await?;
    if head[0] != SOCKS_VERSION {
        return Err(SocksError::NotSocks5);
    }

    let mut methods = vec![0u8; head[1] as usize];
    read_full(stream, &mut methods).await?;

    if cred.map_or(true, |cred| cred.user.is_empty()) {
        stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await?;
        return Ok(());
    }

    // Never fall back to unauthenticated access when credentials are required.
    if !methods.contains(&AUTH_USER_PASS) {
        let _ = stream.write_all(&[SOCKS_VERSION, AUTH_NO_ACCEPT]).await;
        return Err(SocksError::AuthNotOffered);
    }
    stream.write_all(&[SOCKS_VERSION, AUTH_USER_PASS]).await?;
    socks_auth(stream, cred.expect("credentials checked above")).await
}

/// Runs the RFC1929 username/password sub-negotiation.
pub async fn socks_auth<S>(stream: &mut S, cred: &SocksCred) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut version = [0u8; 1];
    read_full(stream, &mut version).await?;
    if version[0] != AUTH_SUB_VERSION {
        return Err(SocksError::InvalidAuthVersion);
    }

    let user = read_len_prefixed(stream).await?;
    let pass = read_len_prefixed(stream).await?;
    let user_ok = user.as_slice().ct_eq(cred.user.as_bytes());
    let pass_ok = pass.as_slice().ct_eq(cred.pass.as_bytes());
    if !bool::from(user_ok & pass_ok) {
        let _ = stream.write_all(&[AUTH_SUB_VERSION, 0x01]).await;
        return Err(SocksError::InvalidCredentials);
    }
    stream.write_all(&[AUTH_SUB_VERSION, 0x00]).await?;
    Ok(())
}

async fn read_len_prefixed<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 1];
    read_full(stream, &mut len).await?;
    let mut value = vec![0u8; len[0] as usize];
    read_full(stream, &mut value).await?;
    Ok(value)
}

/// Reads a CONNECT-only request and rejects UDP ASSOCIATE.
pub async fn read_socks_request<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<String, SocksError> {
    let (cmd, addr) = read_socks_request_with_cmd(stream).await?;
    if cmd != CMD_CONNECT {
        return Err(SocksError::CommandNotSupported);
    }
    Ok(addr)
}

/// Reads an RFC1928 CONNECT or UDP ASSOCIATE request.
///
/// Request VER and RSV are intentionally left unchecked, matching the Go
/// implementation. IPv6 targets are consumed and then rejected before dialing.
pub async fn read_socks_request_with_cmd<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<(u8, String), SocksError> {
    let mut head = [0u8; 4];
    read_full(stream, &mut head).await?;
    if head[1] != CMD_CONNECT && head[1] != CMD_UDP_ASSOCIATE {
        return Err(SocksError::CommandNotSupported);
    }

    let host = match head[3] {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            read_full(stream, &mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            read_full(stream, &mut octets).await?;
            return Err(SocksError::IPv6NotSupported);
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_full(stream, &mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            read_full(stream, &mut domain).await?;
            String::from_utf8_lossy(&domain).into_owned()
        }
        atyp => return Err(SocksError::UnsupportedAddressType(atyp)),
    };

    let mut port = [0u8; 2];
    read_full(stream, &mut port).await?;
    Ok((head[1], join_host_port(&host, u16::from_be_bytes(port))))
}

/// Sends an IPv4 wildcard-bound reply, as the Go server does for CONNECT.
pub async fn socks_reply<S: AsyncWrite + Unpin>(stream: &mut S, code: u8) -> io::Result<()> {
    stream
        .write_all(&[SOCKS_VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
}

/// Sends a reply containing the relay's IPv4 address and port.
pub async fn socks_reply_with<S: AsyncWrite + Unpin>(
    stream: &mut S,
    code: u8,
    ip: IpAddr,
    port: u16,
) -> io::Result<()> {
    let ip = match ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(ip) => ip.to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED),
    };
    let mut reply = [0u8; 10];
    reply[..4].copy_from_slice(&[SOCKS_VERSION, code, 0x00, ATYP_IPV4]);
    reply[4..8].copy_from_slice(&ip.octets());
    reply[8..].copy_from_slice(&port.to_be_bytes());
    stream.write_all(&reply).await
}

/// Copies in both directions and returns when the first copy finishes.
///
/// The owned streams are then dropped, closing both sides. This deliberately
/// differs from `copy_bidirectional`, which waits for both directions.
pub async fn relay<A, B>(a: A, b: B) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    relay_inner(a, b, None).await
}

async fn relay_counted<A, B>(a: A, b: B, traffic: Arc<TrafficCounters>) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    relay_inner(a, b, Some(traffic)).await
}

async fn relay_inner<A, B>(a: A, b: B, traffic: Option<Arc<TrafficCounters>>) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut a_read, mut a_write) = io::split(a);
    let (mut b_read, mut b_write) = io::split(b);
    let mut client_buffer = vec![0_u8; RELAY_BUFFER_SIZE];
    let mut remote_buffer = vec![0_u8; RELAY_BUFFER_SIZE];
    let traffic = traffic.as_deref();
    tokio::select! {
        result = copy_relay_direction(&mut a_read, &mut b_write, &mut client_buffer, traffic, true) => result,
        result = copy_relay_direction(&mut b_read, &mut a_write, &mut remote_buffer, traffic, false) => result,
    }
}

async fn copy_relay_direction<R, W>(
    mut reader: R,
    mut writer: W,
    buffer: &mut [u8],
    traffic: Option<&TrafficCounters>,
    up: bool,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let count = reader.read(buffer).await?;
        if count == 0 {
            return Ok(());
        }
        writer.write_all(&buffer[..count]).await?;
        if let Some(traffic) = traffic {
            if up {
                traffic.add_up(count);
            } else {
                traffic.add_down(count);
            }
        }
    }
}

#[derive(Debug)]
pub struct UdpRequest {
    pub atyp: u8,
    pub addr: Vec<u8>,
    pub host: String,
    pub port: u16,
    pub payload: Vec<u8>,
}

impl UdpRequest {
    pub fn destination(&self) -> String {
        join_host_port(&self.host, self.port)
    }
}

/// Parses RSV FRAG ATYP ADDR PORT DATA. Nonzero RSV/FRAG, IPv6, unknown
/// address types, and truncated headers are rejected without an error reply.
pub fn parse_udp_req_header(buf: &[u8]) -> Option<UdpRequest> {
    if buf.len() < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
        return None;
    }

    let atyp = buf[3];
    let mut pos = 4usize;
    let (addr, host) = match atyp {
        ATYP_IPV4 => {
            if buf.len() < pos + 4 + 2 {
                return None;
            }
            let addr = buf[pos..pos + 4].to_vec();
            let host = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string();
            pos += 4;
            (addr, host)
        }
        ATYP_DOMAIN => {
            if buf.len() < pos + 1 {
                return None;
            }
            let len = buf[pos] as usize;
            pos += 1;
            if buf.len() < pos + len + 2 {
                return None;
            }
            let addr = buf[pos..pos + len].to_vec();
            let host = String::from_utf8_lossy(&addr).into_owned();
            pos += len;
            (addr, host)
        }
        _ => return None,
    };

    if buf.len() < pos + 2 {
        return None;
    }
    let port = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    Some(UdpRequest {
        atyp,
        addr,
        host,
        port,
        payload: buf[pos..].to_vec(),
    })
}

/// Builds an RFC1928 UDP response header and appends the payload.
pub fn build_udp_resp_header(atyp: u8, addr: &[u8], port: u16, data: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + addr.len() + 2 + data.len());
    packet.extend_from_slice(&[0, 0, 0, atyp]);
    packet.extend_from_slice(addr);
    packet.extend_from_slice(&port.to_be_bytes());
    packet.extend_from_slice(data);
    packet
}

struct UdpSession {
    socket: UdpSocket,
    client: SocketAddr,
    atyp: u8,
    addr: Vec<u8>,
    port: u16,
    _guard: DialGuard,
}

type SessionMap = Arc<Mutex<HashMap<String, Arc<UdpSession>>>>;

fn normalize_udp_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

fn udp_source_allowed(source: SocketAddr, allowed_ip: IpAddr) -> bool {
    normalize_udp_ip(source.ip()) == normalize_udp_ip(allowed_ip)
}

fn udp_requested_ip(requested: &str, peer_ip: IpAddr) -> IpAddr {
    requested
        .parse::<SocketAddr>()
        .ok()
        .map(|address| address.ip())
        .filter(|ip| !ip.is_unspecified())
        .unwrap_or(peer_ip)
}

/// Serves one UDP ASSOCIATE until its TCP control connection closes or the
/// relay has no client datagrams for 60 seconds.
pub async fn serve_udp_associate<D>(
    client: TcpStream,
    dial: &D,
    requested_endpoint: &str,
) -> Result<(), SocksError>
where
    D: SocksDialer + ?Sized,
{
    serve_udp_associate_inner(client, dial, requested_endpoint, None).await
}

async fn serve_udp_associate_inner<D>(
    mut client: TcpStream,
    dial: &D,
    requested_endpoint: &str,
    traffic: Option<Arc<TrafficCounters>>,
) -> Result<(), SocksError>
where
    D: SocksDialer + ?Sized,
{
    let local = match client.local_addr() {
        Ok(local) => local,
        Err(err) => {
            let _ = socks_reply(&mut client, REP_GENERAL_FAILURE).await;
            return Err(err.into());
        }
    };
    let peer_ip = match client.peer_addr() {
        Ok(peer) => peer.ip(),
        Err(err) => {
            let _ = socks_reply(&mut client, REP_GENERAL_FAILURE).await;
            return Err(err.into());
        }
    };
    let allowed_ip = udp_requested_ip(requested_endpoint, peer_ip);
    let bind_ip = match local {
        SocketAddr::V4(local) => IpAddr::V4(*local.ip()),
        SocketAddr::V6(local) => local
            .ip()
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(*local.ip())),
    };
    let relay = match UdpSocket::bind((bind_ip, 0)).await {
        Ok(relay) => Arc::new(relay),
        Err(err) => {
            let _ = socks_reply(&mut client, REP_GENERAL_FAILURE).await;
            return Err(err.into());
        }
    };
    let bnd_ip = match local {
        SocketAddr::V4(local) if !local.ip().is_unspecified() => *local.ip(),
        SocketAddr::V6(local) => local
            .ip()
            .to_ipv4_mapped()
            .filter(|ip| !ip.is_unspecified())
            .unwrap_or(Ipv4Addr::UNSPECIFIED),
        _ => Ipv4Addr::UNSPECIFIED,
    };
    let bnd_port = match relay.local_addr() {
        Ok(local) => local.port(),
        Err(err) => {
            let _ = socks_reply(&mut client, REP_GENERAL_FAILURE).await;
            return Err(err.into());
        }
    };
    socks_reply_with(&mut client, REP_SUCCESS, IpAddr::V4(bnd_ip), bnd_port).await?;

    // Keep the write half alive while waiting for any control-connection data,
    // EOF, or error. All three terminate the association, matching Go.
    let (mut control_read, _control_write) = io::split(client);
    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));
    let mut workers = JoinSet::new();
    let mut buf = vec![0u8; 65_535];
    let mut control_buf = [0u8; 1];

    let result = loop {
        let received = tokio::select! {
            control = control_read.read(&mut control_buf) => {
                match control {
                    Ok(0) => break Ok(()),
                    Ok(_) => continue,
                    Err(err) => break Err(err),
                }
            }
            received = timeout(UDP_IDLE_TIMEOUT, relay.recv_from(&mut buf)) => {
                match received {
                    Ok(Ok(packet)) => packet,
                    Ok(Err(err)) => break Err(err),
                    Err(_) => break Ok(()),
                }
            }
        };
        let (len, src) = received;
        if !udp_source_allowed(src, allowed_ip) {
            continue;
        }
        let Some(request) = parse_udp_req_header(&buf[..len]) else {
            continue;
        };
        let dest = request.destination();
        let key = format!("{src}|{dest}");

        let existing = sessions.lock().await.get(&key).cloned();
        let session = if let Some(session) = existing {
            session
        } else {
            let full = { sessions.lock().await.len() >= UDP_MAX_SESSIONS };
            if full {
                continue;
            }
            let (socket, guard) = match dial.dial_guarded(DialNetwork::Udp, &dest).await {
                Ok((DialSocket::Udp(socket), guard)) => (socket, guard),
                _ => continue,
            };
            let candidate = Arc::new(UdpSession {
                socket,
                client: src,
                atyp: request.atyp,
                addr: request.addr,
                port: request.port,
                _guard: guard,
            });
            let mut guard = sessions.lock().await;
            if let Some(session) = guard.get(&key) {
                Arc::clone(session)
            } else if guard.len() >= UDP_MAX_SESSIONS {
                continue;
            } else {
                guard.insert(key.clone(), Arc::clone(&candidate));
                drop(guard);
                workers.spawn(relay_udp(
                    Arc::clone(&candidate),
                    Arc::clone(&relay),
                    Arc::clone(&sessions),
                    key,
                    traffic.clone(),
                ));
                candidate
            }
        };

        // A failed send is left to the per-session reader's idle cleanup.
        if session.socket.send(&request.payload).await.is_ok() {
            if let Some(traffic) = traffic.as_ref() {
                traffic.add_up(request.payload.len());
            }
        }
    };

    workers.abort_all();
    while workers.join_next().await.is_some() {}
    sessions.lock().await.clear();
    result.map_err(SocksError::from)
}

async fn relay_udp(
    session: Arc<UdpSession>,
    relay: Arc<UdpSocket>,
    sessions: SessionMap,
    key: String,
    traffic: Option<Arc<TrafficCounters>>,
) {
    let mut buf = vec![0u8; 65_535];
    loop {
        let read = timeout(UDP_IDLE_TIMEOUT, session.socket.recv(&mut buf)).await;
        let len = match read {
            Ok(Ok(len)) => len,
            _ => break,
        };
        let packet = build_udp_resp_header(session.atyp, &session.addr, session.port, &buf[..len]);
        if relay.send_to(&packet, session.client).await.is_err() {
            break;
        }
        if let Some(traffic) = traffic.as_ref() {
            traffic.add_down(len);
        }
    }

    let mut sessions = sessions.lock().await;
    if sessions
        .get(&key)
        .is_some_and(|current| Arc::ptr_eq(current, &session))
    {
        sessions.remove(&key);
    }
}

fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn timeout_error() -> SocksError {
    SocksError::Io(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout"))
}

/// Matches io.ReadFull's distinction between EOF and unexpected EOF.
async fn read_full<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) -> io::Result<()> {
    let mut read = 0usize;
    while read < buf.len() {
        match stream.read(&mut buf[read..]).await {
            Ok(0) => {
                let message = if read == 0 { "EOF" } else { "unexpected EOF" };
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, message));
            }
            Ok(len) => read += len,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "socks5_test.rs"]
mod tests;
