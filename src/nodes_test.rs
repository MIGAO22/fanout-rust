use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

const CSV_HEADER: &str = "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64";

fn sample_node_csv(host: &str) -> String {
    let cfg = STANDARD.encode(b"client\nremote 1.2.3.4 443\n");
    format!(
        "*vpn_servers\n{CSV_HEADER}\n{host},1.2.3.4,100,20,10000000,Japan,JP,3,1,1,1,2,op,,{cfg}\n*\n"
    )
}

struct TestServer {
    url: String,
    hit: Arc<AtomicBool>,
    key: Arc<Mutex<String>>,
    task: JoinHandle<()>,
}

impl TestServer {
    async fn new(status: &str, body: String) -> Self {
        let status = status.to_string();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hit = Arc::new(AtomicBool::new(false));
        let key = Arc::new(Mutex::new(String::new()));
        let server_hit = Arc::clone(&hit);
        let server_key = Arc::clone(&key);
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buf = [0u8; 2048];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            server_hit.store(true, Ordering::SeqCst);
            let request = String::from_utf8_lossy(&request);
            for line in request.lines().skip(1) {
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("x-fanout-key") {
                        *server_key.lock().unwrap() = value.trim().to_owned();
                    }
                }
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/csv; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        Self {
            url,
            hit,
            key,
            task,
        }
    }

    fn key(&self) -> String {
        self.key.lock().unwrap().clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn fetch_nodes_uses_direct_when_healthy() {
    let direct = TestServer::new("200 OK", sample_node_csv("direct-node")).await;
    let mirror = TestServer::new("200 OK", sample_node_csv("mirror-node")).await;

    let nodes = fetch_nodes_with(
        &direct.url,
        &mirror.url,
        "test-key",
        Duration::from_secs(5),
        "balanced",
    )
    .await
    .unwrap();

    assert_eq!(nodes[0].hostname, "direct-node");
    assert!(direct.hit.load(Ordering::SeqCst));
    assert!(!mirror.hit.load(Ordering::SeqCst));
    assert_eq!(direct.key(), "");
}

#[tokio::test]
async fn fetch_nodes_falls_back_to_mirror_with_key() {
    let direct = TestServer::new("403 Forbidden", "blocked".into()).await;
    let mirror = TestServer::new("200 OK", sample_node_csv("mirror-node")).await;

    let nodes = fetch_nodes_with(
        &direct.url,
        &mirror.url,
        " test-key ",
        Duration::from_secs(5),
        "balanced",
    )
    .await
    .unwrap();

    assert_eq!(nodes[0].hostname, "mirror-node");
    assert_eq!(mirror.key(), "test-key");
}

#[tokio::test]
async fn fetch_nodes_falls_back_on_garbage_body() {
    let direct = TestServer::new("200 OK", "<html><body>请先登录网络</body></html>".into()).await;
    let mirror = TestServer::new("200 OK", sample_node_csv("mirror-node")).await;

    let nodes = fetch_nodes_with(
        &direct.url,
        &mirror.url,
        "",
        Duration::from_secs(5),
        "balanced",
    )
    .await
    .unwrap();

    assert_eq!(nodes[0].hostname, "mirror-node");
}

#[tokio::test]
async fn fetch_nodes_reports_direct_error_when_mirror_disabled() {
    let direct = TestServer::new("403 Forbidden", "blocked".into()).await;
    let err = fetch_nodes_with(&direct.url, "  ", "", Duration::from_secs(5), "balanced")
        .await
        .unwrap_err();

    assert!(err.to_string().contains("HTTP 403"));
}

#[tokio::test]
async fn fetch_nodes_reports_both_failures() {
    let direct = TestServer::new("403 Forbidden", "blocked".into()).await;
    let mirror = TestServer::new("500 Internal Server Error", "broken".into()).await;
    let err = fetch_nodes_with(
        &direct.url,
        &mirror.url,
        "",
        Duration::from_secs(5),
        "balanced",
    )
    .await
    .unwrap_err();

    let message = err.to_string();
    assert!(message.contains("直连失败"));
    assert!(message.contains("反代也失败"));
    assert!(message.contains("HTTP 403"));
    assert!(message.contains("HTTP 500"));
}

#[test]
fn parse_node_csv_preserves_gate_fields_and_config() {
    let body = sample_node_csv("vpn829571948").replace('\n', "\r\n");
    let nodes = parse_node_csv(&body, "balanced").unwrap();

    assert_eq!(nodes.len(), 1);
    let node = &nodes[0];
    assert_eq!(node.hostname, "vpn829571948");
    assert_eq!(node.ip, "1.2.3.4");
    assert_eq!(node.country, "Japan");
    assert_eq!(node.country_code, "JP");
    assert_eq!(node.ping, 20);
    assert_eq!(node.sessions, 3);
    assert!((node.speed_mbps - 10.0).abs() < f64::EPSILON);
    assert!(node.residential);
    assert_eq!(node.config, "client\nremote 1.2.3.4 443\n");

    let nodes = parse_node_csv(&sample_node_csv("public-vpn-200"), "balanced").unwrap();
    assert!(!nodes[0].residential);
}

#[test]
fn parse_node_csv_uses_header_names_and_handles_csv_quotes() {
    let cfg = STANDARD.encode(b"client\n");
    let body = format!(
        "*vpn_servers\n#HostName,IP,CountryShort,CountryLong,Ping,Speed,NumVpnSessions,OpenVPN_ConfigData_Base64\nquoted,1.2.3.4,JP,\"Japan, Republic of\",7,4000000,2,{cfg}\n*\n"
    );
    let nodes = parse_node_csv(&body, "balanced").unwrap();
    assert_eq!(nodes[0].country, "Japan, Republic of");
    assert_eq!(nodes[0].country_code, "JP");
    assert!((nodes[0].speed_mbps - 4.0).abs() < f64::EPSILON);
}

#[test]
fn parse_node_csv_skips_unusable_rows_and_defaults_bad_numbers() {
    let cfg = STANDARD.encode(b"client\n");
    let body = format!(
        "*vpn_servers\n{CSV_HEADER}\n\
         missing-config,1.2.3.4,100,20,10000000,Japan,JP,3,1,1,1,2,op,,\n\
         bad-base64,1.2.3.4,100,20,10000000,Japan,JP,3,1,1,1,2,op,,%%%\n\
         short\n\
         ,1.2.3.4,100,20,10000000,Japan,JP,3,1,1,1,2,op,,{cfg}\n\
         good,1.2.3.4,100,bad,bad,Japan,JP,bad,1,1,1,2,op,,{cfg}\n\
         *\n"
    );
    let nodes = parse_node_csv(&body, "balanced").unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].hostname, "good");
    assert_eq!(nodes[0].ping, 0);
    assert_eq!(nodes[0].sessions, 0);
    assert_eq!(nodes[0].speed_mbps, 0.0);
}

#[test]
fn parse_node_csv_rejects_bad_lists() {
    assert!(parse_node_csv("<html>login</html>", "balanced").is_err());
    assert!(parse_node_csv(&format!("*vpn_servers\n{CSV_HEADER}\n*\n"), "balanced").is_err());

    let missing = CSV_HEADER.replace("CountryShort,", "");
    let csv = sample_node_csv("vpn1");
    let row = csv.lines().nth(2).unwrap().to_string();
    let err =
        parse_node_csv(&format!("*vpn_servers\n{missing}\n{row}\n*\n"), "balanced").unwrap_err();
    assert!(err.to_string().contains("CountryShort"));
    assert!(parse_node_csv("#\n#\n", "balanced").is_err());
}

#[test]
fn residential_filter_matches_hostname_and_network() {
    let cases = [
        ("public-vpn-123", "1.2.3.4", false),
        ("PUBLIC-VPN-9", "1.2.3.4", false),
        (" PUBLIC-VPN-9 ", "1.2.3.4", false),
        ("vpn829571948", "219.100.37.117", false),
        ("vpn123", "219.100.37.0", false),
        ("vpn123", "219.100.37.255", false),
        ("vpn123", "::ffff:219.100.37.117", false),
        ("vpn829571948", "60.101.169.14", true),
        ("vpn123", "219.100.38.1", true),
        ("vpn123", "219.100.36.255", true),
        ("vpn123", "", true),
        ("vpn123", "不是IP", true),
    ];
    for (host, ip, want) in cases {
        assert_eq!(is_residential(host, ip), want, "{host} / {ip}");
    }
}

#[test]
fn selectable_nodes_can_exclude_hosting() {
    let nodes = vec![
        Node {
            hostname: "public-vpn-1".into(),
            speed_mbps: 900.0,
            residential: false,
            ..Node::default()
        },
        Node {
            hostname: "jp-home".into(),
            speed_mbps: 300.0,
            residential: true,
            ..Node::default()
        },
        Node {
            hostname: "kr-dc".into(),
            speed_mbps: 500.0,
            residential: false,
            ..Node::default()
        },
    ];
    let selected = selectable_nodes(&nodes, true);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].hostname, "jp-home");
    assert_eq!(selectable_nodes(&nodes, false), nodes);
}

fn scored(host: &str, speed: f64, sessions: i64, ping: i64) -> Node {
    Node {
        hostname: host.into(),
        speed_mbps: speed,
        sessions,
        ping,
        ..Node::default()
    }
}

#[test]
fn node_score_weights_and_defaults_match_go() {
    let unknown = scored("unknown", 0.0, 0, 0);
    let fast_busy_slow = scored("fast", 40.0, 50, 600);
    let expected = [
        ("balanced", 0.5375, 0.225),
        ("speed", 0.35, 0.40),
        ("idle", 0.75, 0.05),
        ("ping", 0.575, 0.05),
        ("unrecognized", 0.5375, 0.225),
    ];
    for (mode, unknown_want, fast_want) in expected {
        assert!((node_score(&unknown, mode) - unknown_want).abs() < 1e-12);
        assert!((node_score(&fast_busy_slow, mode) - fast_want).abs() < 1e-12);
    }

    let negative = scored("negative", -1.0, -1, -1);
    assert_eq!(
        node_score(&negative, "balanced"),
        node_score(&unknown, "balanced")
    );
}

#[test]
fn node_score_clamps_load_and_ping() {
    let at_limit = scored("at-limit", 80.0, 50, 600);
    let over_limit = scored("over-limit", 80.0, 100, 1200);
    for mode in ["balanced", "speed", "idle", "ping"] {
        assert!((node_score(&at_limit, mode) - node_score(&over_limit, mode)).abs() < 1e-12);
    }
}

#[test]
fn score_nodes_is_descending_and_stable() {
    let mut nodes = vec![
        scored("first", 10.0, 10, 10),
        scored("second", 100.0, 10, 10),
        scored("third", 100.0, 10, 10),
        scored("last", 1.0, 100, 600),
    ];
    score_nodes(&mut nodes, "balanced");
    let names: Vec<_> = nodes.iter().map(|node| node.hostname.as_str()).collect();
    assert_eq!(names, ["second", "third", "first", "last"]);
}

fn nodes_of(specs: &[&str]) -> Vec<Node> {
    specs
        .iter()
        .map(|spec| {
            let (name, region) = spec.split_once(':').unwrap_or((spec, ""));
            Node {
                hostname: name.into(),
                country_code: region.into(),
                ..Node::default()
            }
        })
        .collect()
}

fn names_of(nodes: &[Node]) -> Vec<&str> {
    nodes.iter().map(|node| node.hostname.as_str()).collect()
}

fn marks(names: &[&str]) -> HashMap<String, bool> {
    names
        .iter()
        .map(|name| ((*name).to_owned(), true))
        .collect()
}

#[test]
fn order_candidates_first_round_stays_in_region() {
    let pool = nodes_of(&["jp2:JP", "jp3:JP", "us1:US", "de1:DE"]);
    let current = nodes_of(&["jp1:JP"]).remove(0);
    let got = order_candidates(
        &current,
        "JP",
        true,
        6,
        &pool,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert_eq!(names_of(&got), ["jp1", "jp2", "jp3"]);
}

#[test]
fn order_candidates_widens_after_failed_round() {
    let current = nodes_of(&["gone.example:JP"]).remove(0);
    let pool = nodes_of(&["us1:US", "de1:DE", "gone.example:JP"]);
    let got = order_candidates(
        &current,
        "JP",
        false,
        6,
        &pool,
        &marks(&["gone.example"]),
        &HashMap::new(),
    );
    assert_eq!(names_of(&got), ["us1", "de1", "gone.example"]);
}

#[test]
fn order_candidates_prefers_region_over_widening() {
    let current = nodes_of(&["jp1:JP"]).remove(0);
    let pool = nodes_of(&["us1:US", "jp2:JP", "de1:DE", "jp3:JP"]);
    let got = order_candidates(
        &current,
        "JP",
        false,
        6,
        &pool,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert_eq!(names_of(&got), ["jp2", "jp3", "us1", "de1", "jp1"]);
}

#[test]
fn order_candidates_respects_max_tries() {
    let current = nodes_of(&["jp1:JP"]).remove(0);
    let pool = nodes_of(&["jp2:JP", "jp3:JP", "us1:US"]);
    let got = order_candidates(
        &current,
        "JP",
        false,
        2,
        &pool,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert_eq!(names_of(&got), ["jp2", "jp3"]);

    let first = order_candidates(
        &current,
        "JP",
        true,
        0,
        &pool,
        &HashMap::new(),
        &HashMap::new(),
    );
    let widened = order_candidates(
        &current,
        "JP",
        false,
        0,
        &pool,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert_eq!(names_of(&first), ["jp1"]);
    assert!(widened.is_empty());
}

#[test]
fn order_candidates_widening_still_filters() {
    let current = nodes_of(&["jp1:JP"]).remove(0);
    let pool = nodes_of(&["us1:US", "us2:US", "de1:DE"]);
    let got = order_candidates(
        &current,
        "JP",
        false,
        6,
        &pool,
        &marks(&["us1"]),
        &marks(&["us2"]),
    );
    assert_eq!(names_of(&got), ["de1", "jp1"]);
}

#[test]
fn order_candidates_unknown_region_uses_whole_pool() {
    let current = nodes_of(&["vpn9:"]).remove(0);
    let pool = nodes_of(&["us1:US", "jp1:JP"]);
    let got = order_candidates(
        &current,
        "",
        true,
        6,
        &pool,
        &HashMap::new(),
        &HashMap::new(),
    );
    assert_eq!(names_of(&got), ["vpn9", "us1", "jp1"]);
}

#[test]
fn order_candidates_always_returns_current_as_fallback() {
    let current = nodes_of(&["jp1:JP"]).remove(0);
    let pool = nodes_of(&["jp2:JP", "us1:US"]);
    let used = marks(&["jp2", "us1"]);
    for prefer in [true, false] {
        let got = order_candidates(&current, "JP", prefer, 6, &pool, &used, &HashMap::new());
        assert_eq!(names_of(&got), ["jp1"]);
    }
}

#[test]
fn scored_candidates_preserve_region_tiers_and_skip_quarantine() {
    let current = nodes_of(&["jp1:JP"]).remove(0);
    let pool = nodes_of(&["jp2:JP", "jp3:JP", "us1:US", "us2:US"]);
    let got = order_candidates_scored(
        &current,
        "JP",
        false,
        6,
        &pool,
        &HashMap::new(),
        &HashMap::new(),
        |node| match node.hostname.as_str() {
            "jp3" => 0.9,
            "jp2" => 0.5,
            "us2" => 0.8,
            _ => 0.2,
        },
        |host| host == "us2",
    );
    assert_eq!(names_of(&got), ["jp3", "jp2", "us1", "jp1"]);
}

#[test]
fn swap_note_mentions_cross_region_only_when_known() {
    assert_eq!(swap_note(1, "JP", "JP"), "已换到第 2 个候选节点");
    assert_eq!(
        swap_note(1, "JP", "DE"),
        "同区没有空闲节点，已跨区换到 DE（第 2 个候选）"
    );
    assert_eq!(swap_note(0, "", "DE"), "已换到第 1 个候选节点");
    assert_eq!(swap_note(0, "JP", ""), "已换到第 1 个候选节点");
}

#[test]
fn flag_of_matches_go_cases() {
    let cases = [
        ("JP", "🇯🇵"),
        ("jp", "🇯🇵"),
        ("US", "🇺🇸"),
        ("HK", "🇭🇰"),
        (" kr ", "🇰🇷"),
        ("", ""),
        ("J", ""),
        ("JPN", ""),
        ("J1", ""),
    ];
    for (input, want) in cases {
        assert_eq!(flag_of(input), want);
    }
}

#[test]
fn country_label_uses_chinese_then_english_then_code() {
    let cases = [
        ("JP", "Japan", "🇯🇵 日本"),
        ("jp", "Japan", "🇯🇵 日本"),
        ("KR", "Korea Republic of", "🇰🇷 韩国"),
        ("TW", "Taiwan", "🇹🇼 台湾"),
        ("XK", "Kosovo", "🇽🇰 Kosovo"),
        ("XK", "", "🇽🇰 XK"),
        ("", "Japan", "Japan"),
        ("JPN", "Japan", "Japan"),
        ("", "", ""),
    ];
    for (code, fallback, want) in cases {
        assert_eq!(country_label(code, fallback), want);
    }
    let node = Node {
        country_code: "JP".into(),
        country: "Japan".into(),
        ..Node::default()
    };
    assert_eq!(node_label(&node), "🇯🇵 日本");
}

#[test]
fn country_table_is_sane() {
    for &(code, name) in COUNTRY_CN {
        assert_eq!(code.len(), 2);
        assert!(!flag_of(code).is_empty());
        assert!(!name.is_empty());
    }
}

#[test]
fn generated_labels_and_unique_remarks_match_go() {
    for remark in ["🇯🇵 日本 54", "🇺🇸 美国 1", " 🇰🇷 韩国 15"] {
        assert!(is_generated_label(remark));
    }
    for remark in ["", "线路A", "JP-244", "fanout-JP-243", "日本 54"] {
        assert!(!is_generated_label(remark));
    }

    let mut taken = HashMap::new();
    let want = "🇯🇵 日本 54";
    assert_eq!(unique_remark(want, &taken), want);
    taken.insert(want.to_owned(), true);
    assert_eq!(unique_remark(want, &taken), "🇯🇵 日本 54 2");
    taken.insert("🇯🇵 日本 54 2".to_owned(), true);
    assert_eq!(unique_remark(want, &taken), "🇯🇵 日本 54 3");
    assert_eq!(unique_remark("", &taken), "");
}

#[test]
fn parse_version_parts_matches_go_cases() {
    let cases = [
        ("2.6.8", Some((2, 6))),
        ("2.4.11", Some((2, 4))),
        ("2.5.8-0ubuntu1", Some((2, 5))),
        ("2.6", Some((2, 6))),
        ("3.0.1", Some((3, 0))),
        (" 2.7.9 ", Some((2, 7))),
        ("", None),
        ("2", None),
        ("v2.6.0", None),
        ("openvpn", None),
        ("2.", None),
    ];
    for (input, want) in cases {
        assert_eq!(parse_version_parts(input), want, "{input}");
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn data_cipher_args_are_version_specific() {
    let cases = [
        ("2.6.8", "--data-ciphers"),
        ("2.5.8", "--data-ciphers"),
        ("3.1.0", "--data-ciphers"),
        ("2.4.11", "--ncp-ciphers"),
    ];
    for (version, flag) in cases {
        let args = data_cipher_args(version, false);
        assert_eq!(args[0], flag);
        assert!(args.join(" ").contains("AES-256-CBC"));
    }
    assert_eq!(
        data_cipher_args("2.6.8", false),
        strings(&[
            "--data-ciphers",
            "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC",
            "--data-ciphers-fallback",
            "AES-256-CBC",
        ])
    );
    assert_eq!(
        data_cipher_args("2.4.11", false),
        strings(&[
            "--ncp-ciphers",
            "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC",
        ])
    );
    for version in ["2.3.20", "", "junk"] {
        assert!(data_cipher_args(version, false).is_empty());
    }
}

#[test]
fn aead_only_and_compression_args_respect_version_limits() {
    let aead = data_cipher_args("2.7.9", true);
    assert_eq!(
        aead,
        strings(&[
            "--data-ciphers",
            "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
        ])
    );
    assert!(!aead.join(" ").contains("CBC"));
    assert!(!aead.join(" ").contains("fallback"));
    assert_eq!(
        data_cipher_args("2.4.11", true),
        data_cipher_args("2.4.11", false)
    );
    assert!(data_cipher_args("2.3.20", true).is_empty());
    assert!(compression_off_args("2.4.11").is_empty());
    assert_eq!(
        compression_off_args("2.6.8"),
        strings(&["--allow-compression", "no"])
    );
    assert_eq!(
        compression_off_args("3.0.0"),
        strings(&["--allow-compression", "no"])
    );
}

#[test]
fn ovpn_compression_detection_matches_go() {
    let cases = [
        ("dev tun\nproto tcp\nremote a 443\n", false),
        ("dev tun\ncomp-lzo yes\n", true),
        ("dev tun\ncomp-lzo no\n", false),
        ("dev tun\nallow-compression no\n", false),
        ("dev tun\ncomp-lzo\n", true),
        ("dev tun\n  COMP-LZ4 yes\n", true),
        ("dev tun\n--comp-noadapt\n", true),
        ("dev tun\nallow-compression asym\n", true),
        ("dev tun\n; comp-lzo yes\n", false),
        ("dev tun\ncompress lz4-v2\n", true),
        ("dev tun\n--compress lz4\n", true),
    ];
    for (cfg, want) in cases {
        assert_eq!(ovpn_config_enables_compression(cfg), want, "{cfg:?}");
    }
}

#[test]
fn ovpn_aead_detection_matches_go() {
    let gate_sample = "dev tun\r\nproto tcp\r\nremote 126.187.75.122 1262\r\n\
        #  cipher: [NULL-CIPHER] NULL AES-128-CBC AES-256-CBC BF-CBC\r\n\
        #  data-ciphers: same as cipher\r\n\
        cipher AES-128-CBC\r\ndata-ciphers AES-128-CBC\r\nauth SHA1\r\n\
        resolv-retry infinite\r\nnobind\r\npersist-key\r\npersist-tun\r\nclient\r\n";
    let cases = [
        (gate_sample, false),
        ("data-ciphers AES-256-GCM:AES-128-CBC\n", true),
        ("data-ciphers CHACHA20-POLY1305\n", true),
        ("--cipher AES-128-GCM\n", true),
        (
            "data-ciphers AES-256-GCM\ndata-ciphers AES-128-CBC\n",
            false,
        ),
        ("# data-ciphers AES-256-GCM\n", false),
        ("dev tun\nproto udp\nremote a 1194\n", false),
        ("", false),
        ("ncp-ciphers AES-256-GCM,AES-128-CBC\n", true),
    ];
    for (cfg, want) in cases {
        assert_eq!(ovpn_config_offers_aead(cfg), want, "{cfg:?}");
    }
}

#[test]
fn node_supports_aead_requires_aead_without_compression() {
    let cases = [
        ("cipher AES-128-CBC\r\ndata-ciphers AES-128-CBC\r\n", false),
        ("data-ciphers AES-256-GCM:AES-128-CBC\ncomp-lzo no\n", true),
        ("data-ciphers AES-256-GCM\ncomp-lzo yes\n", false),
        ("data-ciphers AES-256-GCM\nallow-compression no\n", true),
        ("", false),
    ];
    for (cfg, want) in cases {
        assert_eq!(node_supports_aead(cfg), want, "{cfg:?}");
    }
}

#[test]
fn generated_credentials_match_shape_and_alphabet() {
    for _ in 0..32 {
        let cred = new_socks_cred();
        assert!(cred.user.starts_with("fo"));
        assert_eq!(cred.user.len(), 8);
        assert_eq!(cred.pass.len(), 14);
        for field in [cred.user.strip_prefix("fo").unwrap(), &cred.pass] {
            assert!(field.bytes().all(|byte| CRED_ALPHABET.contains(&byte)));
        }
        validate_cred(&cred).unwrap();
    }
    assert_eq!(random_cred_string(0), "");
}

#[test]
fn validate_cred_matches_go_rules_and_byte_limit() {
    for cred in [
        SocksCred {
            user: "fo123".into(),
            pass: "abcDEF234".into(),
        },
        SocksCred {
            user: "u".into(),
            pass: "p".into(),
        },
        SocksCred {
            user: "a".repeat(CRED_MAX_LEN),
            pass: "b".repeat(CRED_MAX_LEN),
        },
    ] {
        validate_cred(&cred).unwrap();
    }

    let bad = [
        SocksCred {
            user: "".into(),
            pass: "x".into(),
        },
        SocksCred {
            user: "x".into(),
            pass: "".into(),
        },
        SocksCred {
            user: "a:b".into(),
            pass: "x".into(),
        },
        SocksCred {
            user: "a b".into(),
            pass: "x".into(),
        },
        SocksCred {
            user: "x".into(),
            pass: "a@b".into(),
        },
        SocksCred {
            user: "x".into(),
            pass: "a/b".into(),
        },
        SocksCred {
            user: "a\tb".into(),
            pass: "x".into(),
        },
        SocksCred {
            user: "x".into(),
            pass: "a\rb".into(),
        },
        SocksCred {
            user: "x".into(),
            pass: "a\nb".into(),
        },
        SocksCred {
            user: "é".repeat(128),
            pass: "x".into(),
        },
    ];
    for cred in bad {
        assert!(validate_cred(&cred).is_err(), "{cred:?}");
    }
}

#[test]
fn socks_server_json_and_url_match_go() {
    let cred = SocksCred {
        user: "u".into(),
        pass: "p".into(),
    };
    assert_eq!(
        socks_server_port_cred(20000, &cred),
        json!({
            "address": "127.0.0.1",
            "port": 20000,
            "users": [{"user": "u", "pass": "p"}],
        })
    );
    assert_eq!(
        socks_server_port_cred(20000, &SocksCred::default()),
        json!({"address": "127.0.0.1", "port": 20000})
    );
    assert_eq!(
        socks_url("1.2.3.4", 20000, &cred),
        "socks5://u:p@1.2.3.4:20000"
    );
    assert_eq!(
        socks_url("1.2.3.4", 20000, &SocksCred::default()),
        "socks5://1.2.3.4:20000"
    );
}
