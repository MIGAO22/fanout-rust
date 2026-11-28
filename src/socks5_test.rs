use super::*;
use anyhow::anyhow;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex as StdMutex,
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

fn auth_request(user: &str, pass: &str) -> Vec<u8> {
    let mut request = vec![AUTH_SUB_VERSION, user.len() as u8];
    request.extend_from_slice(user.as_bytes());
    request.push(pass.len() as u8);
    request.extend_from_slice(pass.as_bytes());
    request
}

async fn handshake(request: &[u8], cred: Option<SocksCred>) -> (Vec<u8>, Result<(), SocksError>) {
    let (mut client, mut server) = io::duplex(1024);
    let server = tokio::spawn(async move { socks_handshake(&mut server, cred.as_ref()).await });
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    (response, server.await.unwrap())
}

#[tokio::test]
async fn counted_relay_direction_tracks_payload_bytes() {
    for up in [true, false] {
        let (mut writer, reader) = io::duplex(64);
        let traffic = Arc::new(TrafficCounters::default());
        writer.write_all(b"hello").await.unwrap();
        drop(writer);
        let mut buffer = [0_u8; 16];
        copy_relay_direction(reader, io::sink(), &mut buffer, Some(&traffic), up)
            .await
            .unwrap();
        let (uploaded, downloaded) = traffic.snapshot();
        assert_eq!((uploaded, downloaded), if up { (5, 0) } else { (0, 5) });
    }
}

#[tokio::test]
async fn parses_ipv4_connect_request() {
    let bytes = [5, CMD_CONNECT, 0, ATYP_IPV4, 8, 8, 8, 8, 0x01, 0xbb];
    let mut input = bytes.as_slice();
    let (cmd, addr) = read_socks_request_with_cmd(&mut input).await.unwrap();
    assert_eq!(cmd, CMD_CONNECT);
    assert_eq!(addr, "8.8.8.8:443");
    assert!(input.is_empty());
}

#[tokio::test]
async fn parses_domain_udp_associate_request() {
    let bytes = [
        5,
        CMD_UDP_ASSOCIATE,
        0,
        ATYP_DOMAIN,
        11,
        b'e',
        b'x',
        b'a',
        b'm',
        b'p',
        b'l',
        b'e',
        b'.',
        b'c',
        b'o',
        b'm',
        0,
        53,
    ];
    let mut input = bytes.as_slice();
    let (cmd, addr) = read_socks_request_with_cmd(&mut input).await.unwrap();
    assert_eq!(cmd, CMD_UDP_ASSOCIATE);
    assert_eq!(addr, "example.com:53");
    assert!(input.is_empty());
}

#[tokio::test]
async fn request_errors_match_go_text() {
    let mut ipv6 = vec![5, CMD_CONNECT, 0, ATYP_IPV6];
    ipv6.extend_from_slice(&[0u8; 16]);
    ipv6.extend_from_slice(&[0, 53]);
    let cases: &[(&[u8], &str)] = &[
        (&[5, 2, 0, ATYP_IPV4], "仅支持 CONNECT 与 UDP ASSOCIATE"),
        (&ipv6, "隧道内不支持 IPv6"),
        (&[5, 1, 0, 9], "不支持的地址类型 9"),
    ];
    for (bytes, expected) in cases {
        let mut input = *bytes;
        let err = read_socks_request_with_cmd(&mut input).await.unwrap_err();
        assert_eq!(err.to_string(), *expected);
    }
}

#[tokio::test]
async fn truncated_request_fields_match_go_io_errors() {
    let cases: &[(&[u8], &str)] = &[
        (&[], "EOF"),
        (&[5, 1], "unexpected EOF"),
        (&[5, 1, 0, ATYP_IPV4, 1], "unexpected EOF"),
        (&[5, 1, 0, ATYP_IPV4, 1, 2, 3, 4], "EOF"),
    ];
    for (bytes, expected) in cases {
        let mut input = *bytes;
        let err = read_socks_request_with_cmd(&mut input).await.unwrap_err();
        assert_eq!(err.to_string(), *expected);
    }

    let mut input = [3u8, b'a', b'b'].as_slice();
    let err = read_len_prefixed(&mut input).await.unwrap_err();
    assert_eq!(err.to_string(), "unexpected EOF");
}

#[tokio::test]
async fn connect_only_reader_rejects_udp_associate() {
    let bytes = [5, CMD_UDP_ASSOCIATE, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    let mut input = bytes.as_slice();
    let err = read_socks_request(&mut input).await.unwrap_err();
    assert!(matches!(err, SocksError::CommandNotSupported));
}

#[tokio::test]
async fn handshake_selects_no_auth_without_credentials() {
    let (response, result) = handshake(&[5, 1, AUTH_NONE], None).await;
    assert_eq!(response, [5, AUTH_NONE]);
    result.unwrap();

    let (response, result) = handshake(
        &[5, 1, AUTH_NONE],
        Some(SocksCred {
            user: String::new(),
            pass: "ignored".into(),
        }),
    )
    .await;
    assert_eq!(response, [5, AUTH_NONE]);
    result.unwrap();
}

#[tokio::test]
async fn handshake_accepts_correct_credentials() {
    let mut request = vec![5, 1, AUTH_USER_PASS];
    request.extend_from_slice(&auth_request("alice", "s3cret"));
    let (response, result) = handshake(
        &request,
        Some(SocksCred {
            user: "alice".into(),
            pass: "s3cret".into(),
        }),
    )
    .await;
    assert_eq!(response, [5, AUTH_USER_PASS, AUTH_SUB_VERSION, 0]);
    result.unwrap();
}

#[tokio::test]
async fn handshake_rejects_wrong_credentials() {
    let mut request = vec![5, 1, AUTH_USER_PASS];
    request.extend_from_slice(&auth_request("alice", "wrong"));
    let (response, result) = handshake(
        &request,
        Some(SocksCred {
            user: "alice".into(),
            pass: "s3cret".into(),
        }),
    )
    .await;
    assert_eq!(response, [5, AUTH_USER_PASS, AUTH_SUB_VERSION, 1]);
    assert_eq!(result.unwrap_err().to_string(), "用户名或口令不对");
}

#[tokio::test]
async fn handshake_rejects_missing_auth_offer() {
    let (response, result) = handshake(
        &[5, 1, AUTH_NONE],
        Some(SocksCred {
            user: "alice".into(),
            pass: "s3cret".into(),
        }),
    )
    .await;
    assert_eq!(response, [5, AUTH_NO_ACCEPT]);
    assert_eq!(
        result.unwrap_err().to_string(),
        "客户端不支持用户名口令认证"
    );
}

#[tokio::test]
async fn handshake_rejects_wrong_versions() {
    let (response, result) = handshake(&[4, 1, AUTH_NONE], None).await;
    assert!(response.is_empty());
    assert_eq!(result.unwrap_err().to_string(), "不是 socks5");

    let mut request = vec![5, 1, AUTH_USER_PASS];
    request.extend_from_slice(&[2, 0, 0]);
    let (response, result) = handshake(
        &request,
        Some(SocksCred {
            user: "alice".into(),
            pass: "s3cret".into(),
        }),
    )
    .await;
    assert_eq!(response, [5, AUTH_USER_PASS]);
    assert_eq!(result.unwrap_err().to_string(), "认证子协议版本不对");
}

#[tokio::test]
async fn replies_match_rfc1928_wire_format() {
    let (mut client, mut server) = io::duplex(64);
    let write = socks_reply(&mut server, REP_GENERAL_FAILURE);
    let read = async {
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await?;
        Ok::<_, io::Error>(reply)
    };
    let (written, read) = tokio::join!(write, read);
    written.unwrap();
    assert_eq!(
        read.unwrap(),
        [5, REP_GENERAL_FAILURE, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
    );

    let cases = [
        (IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), [1, 2, 3, 4]),
        (IpAddr::V6("::ffff:1.2.3.4".parse().unwrap()), [1, 2, 3, 4]),
        (IpAddr::V6("::1".parse().unwrap()), [0, 0, 0, 0]),
    ];
    for (ip, expected_ip) in cases {
        let (mut client, mut server) = io::duplex(64);
        let write = socks_reply_with(&mut server, REP_SUCCESS, ip, 5555);
        let read = async {
            let mut reply = [0u8; 10];
            client.read_exact(&mut reply).await?;
            Ok::<_, io::Error>(reply)
        };
        let (written, read) = tokio::join!(write, read);
        written.unwrap();
        let reply = read.unwrap();
        assert_eq!(&reply[..4], &[5, REP_SUCCESS, 0, ATYP_IPV4]);
        assert_eq!(&reply[4..8], &expected_ip);
        assert_eq!(&reply[8..], &[0x15, 0xb3]);
    }
}

#[test]
fn udp_relay_only_accepts_the_tcp_peers_address() {
    let peer = "127.0.0.1".parse::<IpAddr>().unwrap();
    assert!(udp_source_allowed("127.0.0.1:53000".parse().unwrap(), peer));
    assert!(!udp_source_allowed(
        "127.0.0.2:53000".parse().unwrap(),
        peer
    ));
    assert!(udp_source_allowed(
        "[::ffff:127.0.0.1]:53000".parse().unwrap(),
        peer
    ));
    assert_eq!(udp_requested_ip("0.0.0.0:0", peer), peer);
    assert_eq!(
        udp_requested_ip("127.0.0.2:53000", peer),
        "127.0.0.2".parse::<IpAddr>().unwrap()
    );
    assert_eq!(udp_requested_ip("client.example:53000", peer), peer);
}

#[test]
fn parses_ipv4_udp_request() {
    let bytes = [0, 0, 0, ATYP_IPV4, 8, 8, 8, 8, 0, 53, 1, 2, 3];
    let request = parse_udp_req_header(&bytes).unwrap();
    assert_eq!(request.atyp, ATYP_IPV4);
    assert_eq!(request.addr, [8, 8, 8, 8]);
    assert_eq!(request.host, "8.8.8.8");
    assert_eq!(request.port, 53);
    assert_eq!(request.payload, [1, 2, 3]);
    assert_eq!(request.destination(), "8.8.8.8:53");
}

#[test]
fn parses_domain_udp_request() {
    let bytes = [0, 0, 0, ATYP_DOMAIN, 3, b'd', b'n', b's', 0, 35, 9, 9];
    let request = parse_udp_req_header(&bytes).unwrap();
    assert_eq!(request.atyp, ATYP_DOMAIN);
    assert_eq!(request.addr, b"dns");
    assert_eq!(request.host, "dns");
    assert_eq!(request.port, 35);
    assert_eq!(request.payload, [9, 9]);
    assert_eq!(request.destination(), "dns:35");
}

#[test]
fn rejects_malformed_udp_requests() {
    let ipv4 = [0, 0, 0, ATYP_IPV4, 1, 2, 3, 4, 0, 53];
    for index in 0..3 {
        let mut bytes = ipv4;
        bytes[index] = 1;
        assert!(parse_udp_req_header(&bytes).is_none());
    }

    let mut ipv6 = vec![0, 0, 0, ATYP_IPV6];
    ipv6.extend_from_slice(&[0u8; 16]);
    ipv6.extend_from_slice(&[0, 53]);
    assert!(parse_udp_req_header(&ipv6).is_none());
    assert!(parse_udp_req_header(&[0, 0, 0, 9, 1, 2, 3, 4, 0, 53]).is_none());

    for len in 0..ipv4.len() {
        assert!(parse_udp_req_header(&ipv4[..len]).is_none());
    }
    assert!(parse_udp_req_header(&ipv4).is_some());

    let domain = [0, 0, 0, ATYP_DOMAIN, 3, b'd', b'n', b's', 0, 35];
    for len in 0..domain.len() {
        assert!(parse_udp_req_header(&domain[..len]).is_none());
    }
    assert!(parse_udp_req_header(&domain).is_some());
}

#[test]
fn builds_udp_response_header() {
    let packet = build_udp_resp_header(ATYP_IPV4, &[8, 8, 8, 8], 53, &[1, 2]);
    assert_eq!(packet, [0, 0, 0, ATYP_IPV4, 8, 8, 8, 8, 0, 53, 1, 2]);

    let packet = build_udp_resp_header(ATYP_DOMAIN, &[3, b'd', b'n', b's'], 35, &[9]);
    assert_eq!(
        packet,
        [0, 0, 0, ATYP_DOMAIN, 3, b'd', b'n', b's', 0, 35, 9]
    );
}

#[tokio::test]
async fn relay_copies_both_directions_and_stops_after_first_eof() {
    let (mut client_a, server_a) = io::duplex(64);
    let (mut client_b, server_b) = io::duplex(64);
    let relay = tokio::spawn(relay(server_a, server_b));

    client_a.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    client_b.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    client_b.write_all(b"pong").await.unwrap();
    client_a.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");

    client_a.shutdown().await.unwrap();
    timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(client_b.read(&mut buf).await.unwrap(), 0);
}

struct GuardedTcpDialer {
    socket: StdMutex<Option<TcpStream>>,
    released: Arc<AtomicBool>,
}

#[async_trait]
impl SocksDialer for GuardedTcpDialer {
    async fn dial(&self, network: DialNetwork, addr: &str) -> Result<DialSocket, DialError> {
        let (socket, guard) = self.dial_guarded(network, addr).await?;
        drop(guard);
        Ok(socket)
    }

    async fn dial_guarded(
        &self,
        network: DialNetwork,
        _addr: &str,
    ) -> Result<(DialSocket, DialGuard), DialError> {
        assert_eq!(network, DialNetwork::Tcp);
        let socket = self.socket.lock().unwrap().take().unwrap();
        let released = Arc::clone(&self.released);
        Ok((
            DialSocket::Tcp(socket),
            DialGuard::new(move || released.store(true, Ordering::SeqCst)),
        ))
    }
}

#[tokio::test]
async fn tcp_route_guard_lives_until_the_relay_finishes() {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let (remote, mut peer) = tokio::join!(TcpStream::connect(upstream_addr), upstream.accept());
    let remote = remote.unwrap();
    let (mut peer, _) = peer.unwrap();
    let released = Arc::new(AtomicBool::new(false));
    let dialer = GuardedTcpDialer {
        socket: StdMutex::new(Some(remote)),
        released: Arc::clone(&released),
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        serve_socks(client, None, &dialer).await
    });
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&[5, 1, AUTH_NONE]).await.unwrap();
    let mut selected = [0u8; 2];
    client.read_exact(&mut selected).await.unwrap();
    client
        .write_all(&[5, CMD_CONNECT, 0, ATYP_IPV4, 1, 1, 1, 1, 0, 53])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, REP_SUCCESS, 0, ATYP_IPV4]);
    assert!(!released.load(Ordering::SeqCst));

    client.write_all(b"ping").await.unwrap();
    let mut payload = [0u8; 4];
    peer.read_exact(&mut payload).await.unwrap();
    peer.write_all(b"pong").await.unwrap();
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"pong");
    client.shutdown().await.unwrap();
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(released.load(Ordering::SeqCst));
}

struct RejectDialer;

#[async_trait]
impl SocksDialer for RejectDialer {
    async fn dial(&self, _network: DialNetwork, _addr: &str) -> Result<DialSocket, DialError> {
        Err(anyhow!("拒绝拨号"))
    }
}

async fn serve_exchange(
    request: Vec<u8>,
    response_len: usize,
) -> (Vec<u8>, Result<(), SocksError>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        serve_socks(client, None, &RejectDialer).await
    });
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(&request).await.unwrap();
    let mut response = vec![0u8; response_len];
    client.read_exact(&mut response).await.unwrap();
    (response, server.await.unwrap())
}

#[tokio::test]
async fn request_failures_use_expected_reply_codes() {
    let mut ipv6 = vec![5, 1, 0];
    ipv6.extend_from_slice(&[5, CMD_CONNECT, 0, ATYP_IPV6]);
    ipv6.extend_from_slice(&[0u8; 16]);
    ipv6.extend_from_slice(&[0, 53]);
    let cases = [
        (
            vec![5, 1, 0, 5, CMD_CONNECT, 0, ATYP_IPV4, 8, 8, 8, 8, 0, 53],
            REP_HOST_UNREACHABLE,
            "拒绝拨号",
        ),
        (
            vec![5, 1, 0, 5, 2, 0, ATYP_IPV4, 8, 8, 8, 8, 0, 53],
            REP_COMMAND_NOT_SUPPORTED,
            "仅支持 CONNECT 与 UDP ASSOCIATE",
        ),
        (ipv6, REP_GENERAL_FAILURE, "隧道内不支持 IPv6"),
        (
            vec![5, 1, 0, 5, CMD_CONNECT, 0, 9],
            REP_GENERAL_FAILURE,
            "不支持的地址类型 9",
        ),
    ];
    for (request, code, error) in cases {
        let (response, result) = serve_exchange(request, 12).await;
        assert_eq!(&response[..2], &[5, AUTH_NONE]);
        assert_eq!(response[2], 5);
        assert_eq!(response[3], code);
        assert_eq!(&response[4..], &[0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]);
        assert_eq!(result.unwrap_err().to_string(), error);
    }
}

struct EchoDialer {
    target: SocketAddr,
    released: Arc<AtomicBool>,
}

#[async_trait]
impl SocksDialer for EchoDialer {
    async fn dial(&self, network: DialNetwork, addr: &str) -> Result<DialSocket, DialError> {
        let (socket, guard) = self.dial_guarded(network, addr).await?;
        drop(guard);
        Ok(socket)
    }

    async fn dial_guarded(
        &self,
        network: DialNetwork,
        addr: &str,
    ) -> Result<(DialSocket, DialGuard), DialError> {
        assert_eq!(network, DialNetwork::Udp);
        assert_eq!(addr, self.target.to_string());
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        socket.connect(self.target).await?;
        let released = Arc::clone(&self.released);
        Ok((
            DialSocket::Udp(socket),
            DialGuard::new(move || released.store(true, Ordering::SeqCst)),
        ))
    }
}

#[tokio::test]
async fn udp_associate_relays_payload_and_reports_bound_address() {
    let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let (len, src) = echo.recv_from(&mut buf).await.unwrap();
        echo.send_to(&buf[..len], src).await.unwrap();
    });

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let released = Arc::new(AtomicBool::new(false));
    let dialer_released = Arc::clone(&released);
    let server = tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        serve_socks(
            client,
            None,
            &EchoDialer {
                target: echo_addr,
                released: dialer_released,
            },
        )
        .await
    });

    let mut control = TcpStream::connect(addr).await.unwrap();
    control.write_all(&[5, 1, AUTH_NONE]).await.unwrap();
    let mut selected = [0u8; 2];
    control.read_exact(&mut selected).await.unwrap();
    assert_eq!(selected, [5, AUTH_NONE]);

    control
        .write_all(&[5, CMD_UDP_ASSOCIATE, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, REP_SUCCESS, 0, ATYP_IPV4]);
    assert_eq!(&reply[4..8], &Ipv4Addr::LOCALHOST.octets());
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    assert_ne!(relay_port, 0);
    let relay_addr = format!("127.0.0.1:{relay_port}")
        .parse::<SocketAddr>()
        .unwrap();

    let mut udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    udp.connect(relay_addr).await.unwrap();
    let mut packet = vec![0, 0, 0, ATYP_IPV4, 127, 0, 0, 1];
    packet.extend_from_slice(&echo_addr.port().to_be_bytes());
    packet.extend_from_slice(b"ping");
    udp.send(&packet).await.unwrap();

    let mut response = vec![0u8; packet.len()];
    timeout(Duration::from_secs(2), udp.recv(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, packet);
    assert!(!released.load(Ordering::SeqCst));

    drop(control);
    timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(released.load(Ordering::SeqCst));
    echo.await.unwrap();
}
