use super::*;
use crate::{
    config::WebSettings,
    factory::UnavailableFactory,
    jobs::JobStore,
    pools_logic::{POOL_MODE_CONCURRENT, POOL_MODE_RACE, POOL_MODE_ROUND_ROBIN},
};
use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, Utc};
use std::{
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::RwLock,
    task::yield_now,
    time::{sleep, timeout},
};

fn test_manager(dir: &Path) -> Arc<Manager> {
    Manager::new(
        dir.to_path_buf(),
        4,
        Arc::new(RwLock::new(WebSettings::default())),
        JobStore::new(),
        Arc::new(UnavailableFactory),
        Arc::new(crate::observability::ObservabilityStore::default()),
    )
}

fn test_pool() -> Pool {
    Pool {
        id: "p1".into(),
        name: "测试组".into(),
        mode: POOL_MODE_SINGLE.into(),
        hosts: vec!["missing-a".into(), "missing-b".into()],
        rr_step: 5,
        cred: SocksCred {
            user: "original-user".into(),
            pass: "original-pass".into(),
        },
        ..Pool::default()
    }
}

async fn connect(addr: SocketAddr) -> TcpStream {
    timeout(Duration::from_secs(2), TcpStream::connect(addr))
        .await
        .expect("connect timed out")
        .expect("connect failed")
}

fn up_member(host: &str) -> PoolMember {
    PoolMember {
        host: host.into(),
        namespace: format!("tunnel-{host}"),
        status: "up".into(),
        up: true,
        ..PoolMember::default()
    }
}

fn first_host(choice: &crate::pools_logic::PoolChoice) -> &str {
    choice
        .order
        .first()
        .map(|member| member.host.as_str())
        .unwrap_or("")
}

#[tokio::test]
async fn crud_preserves_listener_port_and_credentials_and_persists_changes() {
    let dir = tempfile::tempdir().unwrap();
    let manager = test_manager(dir.path());
    let service = PoolService::load(
        dir.path(),
        manager,
        PoolStore {
            next: 2,
            pools: vec![test_pool()],
        },
    )
    .await
    .unwrap();

    let initial = service.views().await;
    assert_eq!(initial.len(), 1);
    assert!(initial[0].running);
    assert_ne!(initial[0].port, 0);
    assert_eq!(initial[0].identity, "pool-p1");
    assert_eq!((initial[0].up, initial[0].total), (0, 2));
    assert!(initial[0]
        .members
        .iter()
        .all(|member| member.status == "missing"));
    assert!(pool_ports().contains(&initial[0].port));

    let addr = SocketAddr::from((LOOPBACK, initial[0].port));
    drop(connect(addr).await);
    let stored = crate::pools_logic::load_pool_store(dir.path()).unwrap();
    assert_eq!(stored.pools[0].port, initial[0].port);

    let updated = service
        .set_pool(Pool {
            id: "p1".into(),
            name: "改名组".into(),
            mode: POOL_MODE_ROUND_ROBIN.into(),
            hosts: vec![" missing-b ".into(), "missing-b".into(), "".into()],
            rr_step: 0,
            port: 1,
            cred: SocksCred {
                user: "must-not-replace".into(),
                pass: "must-not-replace".into(),
            },
            ..Pool::default()
        })
        .await
        .unwrap();
    assert_eq!(updated.port, initial[0].port);
    assert_eq!(updated.cred, test_pool().cred);
    assert_eq!(updated.hosts, ["missing-b"]);
    assert_eq!(updated.rr_step, crate::models::POOL_DEFAULT_RR_STEP);

    let generated = service.set_cred("p1", SocksCred::default()).await.unwrap();
    assert!(generated.user.starts_with("fo"));
    assert_eq!(generated.pass.len(), 14);
    assert!(service
        .set_cred(
            "p1",
            SocksCred {
                user: "bad user".into(),
                pass: "bad-pass".into(),
            },
        )
        .await
        .is_err());
    assert_eq!(service.pool("p1").unwrap().cred, generated);

    assert!(service.rename_host("missing-b", "renamed").await.unwrap());
    assert!(!service.rename_host("missing-b", "again").await.unwrap());
    let view = service.views().await.remove(0);
    assert_eq!(view.name, "改名组");
    assert_eq!(view.mode, POOL_MODE_ROUND_ROBIN);
    assert_eq!(view.members[0].host, "renamed");
    assert_eq!(view.cred, generated);

    let egress = service.egress("pool-p1").await.unwrap();
    assert_eq!(egress.port, initial[0].port);
    assert_eq!(egress.tag, "fanout-pool-p1");
    assert_eq!(egress.up, 0);

    service.delete_pool("p1").await.unwrap();
    assert!(service.pools().is_empty());
    assert!(service.views().await.is_empty());
    assert!(service.egresses().await.is_empty());
    assert!(service.delete_pool("p1").await.is_err());
    let mut closed = false;
    for _ in 0..20 {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_err() {
            closed = true;
            break;
        }
        sleep(Duration::from_millis(25)).await;
    }
    assert!(closed, "删除出口组后监听应关闭");
    assert!(crate::pools_logic::load_pool_store(dir.path())
        .unwrap()
        .pools
        .is_empty());

    service.close().await;
    service.close().await;
}

#[tokio::test]
async fn new_pools_get_monotonic_ids_generated_credentials_and_validation() {
    let dir = tempfile::tempdir().unwrap();
    let manager = test_manager(dir.path());
    let service = PoolService::load(dir.path(), manager, PoolStore::new())
        .await
        .unwrap();

    let first = service
        .set_pool(Pool {
            id: "caller-id-is-ignored".into(),
            name: "第一组".into(),
            mode: "unknown".into(),
            hosts: vec![" a ".into(), "a".into(), "".into(), "b".into()],
            ..Pool::default()
        })
        .await
        .unwrap();
    assert_eq!(first.id, "p1");
    assert_eq!(first.mode, POOL_MODE_SINGLE);
    assert_eq!(first.hosts, ["a", "b"]);
    assert!(!first.cred.user.is_empty() && !first.cred.pass.is_empty());
    assert_ne!(first.port, 0);

    let second = service
        .set_pool(Pool {
            name: "第二组".into(),
            mode: POOL_MODE_ROUND_ROBIN.into(),
            hosts: vec!["c".into()],
            ..Pool::default()
        })
        .await
        .unwrap();
    assert_eq!(second.id, "p2");
    assert_eq!(service.pools().len(), 2);

    assert!(service
        .set_pool(Pool {
            name: "空组".into(),
            hosts: Vec::new(),
            ..Pool::default()
        })
        .await
        .is_err());
    assert_eq!(service.pools().len(), 2);
    assert_eq!(service.pool("p1").unwrap().port, first.port);

    let mut unknown = Pool {
        hosts: vec![" absent ".into(), "absent".into()],
        ..Pool::default()
    };
    assert!(service.check_pool_hosts(&mut unknown).await.is_err());
    service.close().await;
}

#[tokio::test]
async fn runtime_selection_covers_affinity_cooldown_latency_and_udp_fallback() {
    let listener = TcpListener::bind(SocketAddr::from((LOOPBACK, 0)))
        .await
        .unwrap();
    let run = PoolRun::new(
        listener,
        &Pool {
            mode: POOL_MODE_ROUND_ROBIN.into(),
            rr_step: 1,
            ..Pool::default()
        },
    );
    let mut members = vec![
        up_member("a"),
        up_member("b"),
        up_member("c"),
        PoolMember {
            host: "down".into(),
            namespace: "tunnel-down".into(),
            status: "failed".into(),
            ..PoolMember::default()
        },
    ];

    assert_eq!(first_host(&run.choose("site", &members, true)), "a");
    assert_eq!(first_host(&run.choose("other", &members, true)), "b");
    assert_eq!(first_host(&run.choose("site", &members, true)), "a");

    let now = Utc::now();
    run.note_failure("a");
    assert!(run
        .runtime
        .lock()
        .unwrap()
        .stats
        .get("a")
        .unwrap()
        .is_cooling(now));
    run.apply_state(&mut members);
    let degraded = run.choose("new-target", &members, true);
    assert_eq!(first_host(&degraded), "b");
    assert_eq!(degraded.order.last().unwrap().host, "a");

    run.note_success("probe", "a", Duration::from_millis(10));
    run.note_success("probe", "b", Duration::from_millis(200));
    run.note_success("probe", "c", Duration::from_millis(300));
    run.apply_state(&mut members);
    assert!(!members[0].cooling);
    run.reconfigure(POOL_MODE_BALANCE, 5);
    assert_eq!(
        first_host(&run.choose("latency-target", &members, true)),
        "a"
    );
    assert_eq!(
        lock_unpoisoned(&run.runtime).stats["a"].latency,
        Duration::from_millis(10)
    );

    for (mode, expected) in [(POOL_MODE_CONCURRENT, "a"), (POOL_MODE_RACE, "b")] {
        run.reconfigure(mode, 5);
        let tcp = run.choose("race-target", &members, true);
        assert!(tcp.concurrent);
        assert_eq!(tcp.order.len(), 3);
        let udp = run.choose("race-target", &members, false);
        assert!(!udp.concurrent);
        assert_eq!(first_host(&udp), expected);
    }

    // A successful sample ages out after the configured stale interval.
    let future = Utc::now() + ChronoDuration::seconds(121);
    assert!(lock_unpoisoned(&run.runtime).stats["a"].is_stale(future));
}

#[tokio::test]
async fn concurrent_dial_returns_the_winner_and_closes_late_sockets() {
    struct DelayedTcpDialer {
        delay: Duration,
        socket: StdMutex<Option<TcpStream>>,
    }

    #[async_trait]
    impl SocksDialer for DelayedTcpDialer {
        async fn dial(&self, _network: DialNetwork, _addr: &str) -> Result<DialSocket> {
            sleep(self.delay).await;
            let socket = self.socket.lock().unwrap().take().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotConnected, "socket already used")
            })?;
            Ok(DialSocket::Tcp(socket))
        }
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(SocketAddr::from((LOOPBACK, 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let client = connect(addr).await;
        let (server, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        (client, server)
    }

    let listener = TcpListener::bind(SocketAddr::from((LOOPBACK, 0)))
        .await
        .unwrap();
    let run = PoolRun::new(
        listener,
        &Pool {
            mode: POOL_MODE_CONCURRENT.into(),
            rr_step: 5,
            ..Pool::default()
        },
    );
    let (fast_socket, mut fast_peer) = tcp_pair().await;
    let (slow_socket, mut slow_peer) = tcp_pair().await;
    let candidates = vec![
        ResolvedMember {
            member: up_member("slow"),
            dialer: Some(Arc::new(DelayedTcpDialer {
                delay: Duration::from_millis(60),
                socket: StdMutex::new(Some(slow_socket)),
            })),
        },
        ResolvedMember {
            member: up_member("fast"),
            dialer: Some(Arc::new(DelayedTcpDialer {
                delay: Duration::from_millis(1),
                socket: StdMutex::new(Some(fast_socket)),
            })),
        },
    ];

    let (socket, host) = timeout(
        Duration::from_secs(2),
        PoolService::race_dial(
            &run,
            candidates,
            DialNetwork::Tcp,
            "example.com:443",
            "example.com",
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(host, "fast");
    let DialSocket::Tcp(mut winner) = socket else {
        panic!("TCP race returned a UDP socket");
    };
    winner.write_all(b"fast").await.unwrap();
    let mut payload = [0u8; 4];
    fast_peer.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"fast");

    let mut one = [0u8; 1];
    let closed = timeout(Duration::from_millis(500), slow_peer.read(&mut one))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(closed, 0, "the losing socket was not closed");
    timeout(Duration::from_millis(500), async {
        loop {
            if lock_unpoisoned(&run.runtime).stats.len() == 2 {
                break;
            }
            yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(lock_unpoisoned(&run.runtime).stats.contains_key("fast"));
    assert!(lock_unpoisoned(&run.runtime).stats.contains_key("slow"));
}

#[tokio::test]
async fn dialing_with_no_resolved_tunnel_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let manager = test_manager(dir.path());
    let service = PoolService::load(
        dir.path(),
        manager,
        PoolStore {
            next: 2,
            pools: vec![test_pool()],
        },
    )
    .await
    .unwrap();

    let error = service
        .dialer_for("p1")
        .dial(DialNetwork::Tcp, "example.com:443")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("没有可用出口"));
    assert!(service
        .resolve_members("p1")
        .await
        .iter()
        .all(|member| { member.namespace.is_empty() && !member.up }));
    service.close().await;
}

#[tokio::test]
async fn listener_reads_updated_credentials_for_each_new_connection() {
    let dir = tempfile::tempdir().unwrap();
    let manager = test_manager(dir.path());
    let service = PoolService::load(
        dir.path(),
        manager,
        PoolStore {
            next: 2,
            pools: vec![test_pool()],
        },
    )
    .await
    .unwrap();
    let addr = SocketAddr::from((LOOPBACK, service.pool("p1").unwrap().port));

    async fn negotiate(addr: SocketAddr, methods: &[u8]) -> [u8; 2] {
        let mut client = connect(addr).await;
        client.write_all(&[5, methods.len() as u8]).await.unwrap();
        client.write_all(methods).await.unwrap();
        let mut reply = [0u8; 2];
        timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        reply
    }

    assert_eq!(
        negotiate(addr, &[crate::socks5::AUTH_NONE]).await,
        [5, 0xff]
    );
    assert_eq!(
        negotiate(addr, &[crate::socks5::AUTH_USER_PASS]).await,
        [5, 2]
    );

    let mut client = connect(addr).await;
    client
        .write_all(&[5, 1, crate::socks5::AUTH_USER_PASS])
        .await
        .unwrap();
    let mut method = [0u8; 2];
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    client.write_all(&[1, 1, b'x', 1, b'y']).await.unwrap();
    let mut denied = [0u8; 2];
    client.read_exact(&mut denied).await.unwrap();
    assert_eq!(denied, [1, 1]);
    drop(client);

    let next = service
        .set_cred(
            "p1",
            SocksCred {
                user: "next-user".into(),
                pass: "next-pass".into(),
            },
        )
        .await
        .unwrap();
    let mut client = connect(addr).await;
    client
        .write_all(&[5, 1, crate::socks5::AUTH_USER_PASS])
        .await
        .unwrap();
    client.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 2]);
    let mut auth = Vec::with_capacity(3 + next.user.len() + next.pass.len());
    auth.push(1);
    auth.push(next.user.len() as u8);
    auth.extend_from_slice(next.user.as_bytes());
    auth.push(next.pass.len() as u8);
    auth.extend_from_slice(next.pass.as_bytes());
    client.write_all(&auth).await.unwrap();
    let mut accepted = [0u8; 2];
    timeout(Duration::from_secs(2), client.read_exact(&mut accepted))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted, [1, 0]);
    drop(client);

    service.close().await;
}
