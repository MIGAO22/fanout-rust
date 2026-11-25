use super::*;
use serde_json::json;
use std::collections::HashSet;

fn client() -> NativeClient {
    NativeClient {
        email: "e".into(),
        id: "uuid-1".into(),
        password: "pw-1".into(),
        enable: true,
        flow: String::new(),
    }
}

fn inbound(port: u16) -> NativeInbound {
    NativeInbound {
        id: 1,
        port,
        protocol: "vless".into(),
        enable: true,
        remark: "r".into(),
        clients: vec![client()],
        ..NativeInbound::default()
    }
}

fn tunnel(host: &str, status: &str, port: u16) -> TunnelState {
    TunnelState {
        node: crate::models::Node {
            hostname: host.into(),
            ..Default::default()
        },
        status: status.into(),
        port,
        cred: SocksCred {
            user: "fo-user".into(),
            pass: "secret".into(),
        },
        ..TunnelState::default()
    }
}

fn regional_flag(code: &str) -> String {
    code.bytes()
        .map(|b| char::from_u32(0x1f1e6 + u32::from(b - b'A')).unwrap())
        .collect()
}

#[test]
fn native_tags_match_xui_format() {
    let mut ib = inbound(443);
    assert_eq!(ib.tag(), "in-443-tcp");
    ib.network = "ws".into();
    ib.port = 8080;
    assert_eq!(ib.tag(), "in-8080-ws");
    assert_eq!(sanitize_tag("jp/a b"), "jp-a-b");
    assert_eq!(sanitize_tag("日本"), "--");
    assert_eq!(sanitize_tag(""), "unknown");
    assert_eq!(egress_tag("pool-main"), "fanout-pool-main");
}

#[test]
fn native_json_schema_round_trips_without_losing_security() {
    let store = NativeStore {
        next_id: 7,
        inbounds: vec![NativeInbound {
            tls: Some(TlsConfig {
                server_name: "demo.local".into(),
                cert_file: "/tmp/demo.crt".into(),
                key_file: "/tmp/demo.key".into(),
                self_signed: true,
                cert_sha256: "AABB".into(),
            }),
            security: "tls".into(),
            bound_to: "jp1".into(),
            ..inbound(443)
        }],
    };
    let value = serde_json::to_value(&store).unwrap();
    assert_eq!(value["next_id"], 7);
    assert_eq!(value["inbounds"][0]["bound_to"], "jp1");
    assert_eq!(value["inbounds"][0]["tls"]["self_signed"], true);
    assert_eq!(value["inbounds"][0]["tls"]["cert_sha256"], "AABB");
    assert!(value["inbounds"][0]["clients"][0].get("flow").is_none());
    assert!(value["inbounds"][0].get("reality").is_none());
    let decoded: NativeStore = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.next_id, 7);
    assert_eq!(
        decoded.inbounds[0].tls.as_ref().unwrap().cert_file,
        "/tmp/demo.crt"
    );
    assert_eq!(decoded.inbounds[0].clients[0].id, "uuid-1");
}

#[test]
fn store_sorting_is_by_port() {
    let store = NativeStore {
        next_id: 3,
        inbounds: vec![inbound(300), inbound(100), inbound(200)],
    };
    let ports: Vec<_> = store.sorted().iter().map(|ib| ib.port).collect();
    assert_eq!(ports, vec![100, 200, 300]);
}

#[test]
fn normalize_spec_defaults_and_generates_paths() {
    let used = HashSet::new();
    let normalized = normalize_inbound_spec(
        &NewInboundSpec {
            port: 12345,
            ..Default::default()
        },
        &used,
    )
    .unwrap();
    assert_eq!(normalized.protocol, "vless");
    assert_eq!(normalized.network, "tcp");
    assert_eq!(normalized.security, "none");
    assert_eq!(normalized.remark, "vless-12345");
    assert!(normalized.path.is_empty());

    for network in ["ws", "httpupgrade", "xhttp", "grpc"] {
        let normalized = normalize_inbound_spec(
            &NewInboundSpec {
                network: network.into(),
                port: 1234,
                ..Default::default()
            },
            &used,
        )
        .unwrap();
        assert!(!normalized.path.is_empty(), "{network} should get a path");
        if network == "grpc" {
            assert!(!normalized.path.starts_with('/'));
        } else {
            assert!(normalized.path.starts_with('/'));
        }
    }
}

#[test]
fn normalize_spec_rejects_invalid_combinations() {
    let cases = [
        NewInboundSpec {
            protocol: "ss".into(),
            port: 1,
            ..Default::default()
        },
        NewInboundSpec {
            network: "quic".into(),
            port: 1,
            ..Default::default()
        },
        NewInboundSpec {
            security: "xtls".into(),
            port: 1,
            ..Default::default()
        },
        NewInboundSpec {
            network: "ws".into(),
            security: "reality".into(),
            port: 1,
            ..Default::default()
        },
        NewInboundSpec {
            network: "ws".into(),
            security: "tls".into(),
            vision: true,
            port: 1,
            ..Default::default()
        },
    ];
    for spec in cases {
        assert!(normalize_inbound_spec(&spec, &HashSet::new()).is_err());
    }
    assert!(normalize_inbound_spec(
        &NewInboundSpec {
            port: 443,
            ..Default::default()
        },
        &HashSet::from([443]),
    )
    .is_err());
}

#[test]
fn vision_requires_vless_tcp_with_tls_or_reality() {
    assert!(vision_capable("vless", "tcp", "reality"));
    assert!(vision_capable("vless", "tcp", "tls"));
    assert!(!vision_capable("vless", "ws", "tls"));
    assert!(!vision_capable("vless", "tcp", "none"));
    assert!(!vision_capable("trojan", "tcp", "tls"));
    let normalized = normalize_inbound_spec(
        &NewInboundSpec {
            security: "reality".into(),
            vision: true,
            port: 1234,
            ..Default::default()
        },
        &HashSet::new(),
    )
    .unwrap();
    assert_eq!(normalized.flow, "xtls-rprx-vision");
}

#[test]
fn spec_value_accepts_frontend_aliases() {
    let spec = NewInboundSpec::from_value(&json!({
        "port": "443",
        "vision": "1",
        "sni": "example.test",
        "cert": "/tmp/cert",
        "key": "/tmp/key",
        "serverNames": "example.test, www.example.test",
        "sid": "abcd1234",
        "fp": "chrome"
    }))
    .unwrap();
    assert_eq!(spec.port, 443);
    assert!(spec.vision);
    assert_eq!(spec.server_name, "example.test");
    assert_eq!(spec.cert_file, "/tmp/cert");
    assert_eq!(spec.short_id, "abcd1234");
}

#[test]
fn stream_settings_cover_all_native_networks() {
    let cases = [
        ("ws", "/p", "wsSettings", "path", json!("/p")),
        (
            "httpupgrade",
            "/h",
            "httpupgradeSettings",
            "path",
            json!("/h"),
        ),
        ("xhttp", "/x", "xhttpSettings", "path", json!("/x")),
        ("grpc", "/svc", "grpcSettings", "serviceName", json!("svc")),
    ];
    for (network, path, settings_key, value_key, expected) in cases {
        let mut ib = inbound(1234);
        ib.network = network.into();
        ib.path = path.into();
        ib.host = "cdn.example".into();
        let stream = stream_settings_json(&ib);
        assert_eq!(stream["network"], network);
        assert_eq!(stream[settings_key][value_key], expected);
        if network != "grpc" {
            assert_eq!(stream[settings_key]["host"], "cdn.example");
        }
    }
}

#[test]
fn reality_server_settings_never_leak_public_key() {
    let mut ib = inbound(1234);
    ib.security = "reality".into();
    ib.reality = Some(RealityConfig {
        dest: "www.cloudflare.com:443".into(),
        server_names: vec!["www.cloudflare.com".into()],
        private_key: "priv".into(),
        public_key: "pub".into(),
        short_ids: vec!["abcd1234".into()],
        fingerprint: "chrome".into(),
    });
    let stream = stream_settings_json(&ib);
    assert_eq!(stream["security"], "reality");
    assert_eq!(stream["realitySettings"]["privateKey"], "priv");
    assert_eq!(stream["realitySettings"]["shortIds"], json!(["abcd1234"]));
    assert!(stream["realitySettings"].get("publicKey").is_none());
    assert!(stream["realitySettings"].get("fingerprint").is_none());
}

#[test]
fn xray_config_binds_only_live_tunnels_and_keeps_pool_fail_closed() {
    let mut first = inbound(100);
    first.bound_to = "jp1".into();
    let mut second = inbound(200);
    second.bound_to = "jp2".into();
    let mut pooled = inbound(300);
    pooled.bound_to = "pool-main".into();
    let mut disabled = inbound(400);
    disabled.bound_to = "jp1".into();
    disabled.enable = false;

    let config = build_xray_config(
        &[first, second, pooled, disabled],
        &[tunnel("jp1", "up", 1080), tunnel("jp2", "failed", 1081)],
        &[PoolView {
            id: "main".into(),
            port: 1090,
            up: 0,
            running: true,
            ..Default::default()
        }],
    );
    let tags: HashSet<_> = config["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|out| out["tag"].as_str().unwrap())
        .collect();
    assert!(tags.contains("fanout-jp1"));
    assert!(!tags.contains("fanout-jp2"));
    assert!(tags.contains("fanout-pool-main"));
    assert_eq!(
        config["outbounds"][0]["settings"]["domainStrategy"],
        "UseIPv4"
    );
    assert_eq!(config["inbounds"].as_array().unwrap().len(), 3);

    let rules = config["routing"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["outboundTag"], "fanout-jp1");
    assert_eq!(rules[1]["outboundTag"], "fanout-pool-main");
    let server = &config["outbounds"][2]["settings"]["servers"][0];
    assert_eq!(server["address"], "127.0.0.1");
    assert_eq!(server["port"], 1080);
    assert_eq!(server["users"][0]["user"], "fo-user");
}

#[test]
fn share_links_use_protocol_credentials_and_transport_parameters() {
    let vless = share_link(&inbound(100), &client(), "1.2.3.4");
    assert_eq!(
        vless,
        "vless://uuid-1@1.2.3.4:100?encryption=none&security=none&type=tcp#r"
    );

    let mut trojan = inbound(200);
    trojan.protocol = "trojan".into();
    trojan.network = "ws".into();
    trojan.path = "/p".into();
    let link = share_link(&trojan, &client(), "h");
    assert!(link.starts_with("trojan://pw-1@h:200?"));
    assert!(link.contains("path=%2Fp"));
    assert!(link.contains("security=none"));
    assert!(link.contains("type=ws"));

    let mut vmess = inbound(300);
    vmess.protocol = "vmess".into();
    let link = share_link(&vmess, &client(), "h");
    assert!(link.starts_with("vmess://uuid-1@h:300?"));
    assert!(link.contains("encryption=auto"));
}

#[test]
fn share_links_carry_reality_and_self_signed_tls_pins() {
    let mut client = client();
    client.flow = "xtls-rprx-vision".into();
    let mut ib = inbound(100);
    ib.security = "reality".into();
    ib.reality = Some(RealityConfig {
        dest: "www.cloudflare.com:443".into(),
        server_names: vec!["www.cloudflare.com".into()],
        public_key: "PBK".into(),
        short_ids: vec!["sid1".into()],
        fingerprint: "chrome".into(),
        ..Default::default()
    });
    let link = share_link(&ib, &client, "h");
    for expected in [
        "pbk=PBK",
        "sid=sid1",
        "fp=chrome",
        "sni=www.cloudflare.com",
        "flow=xtls-rprx-vision",
    ] {
        assert!(link.contains(expected), "missing {expected} in {link}");
    }

    let mut ib = inbound(200);
    ib.security = "tls".into();
    ib.tls = Some(TlsConfig {
        server_name: "demo.local".into(),
        self_signed: true,
        cert_sha256: "AABB".into(),
        ..Default::default()
    });
    let link = share_link(&ib, &client(), "h");
    assert!(link.contains("sni=demo.local"));
    assert!(link.contains("pinSHA256=AABB"));
    assert!(!link.contains("allowInsecure"));
}

#[test]
fn generated_labels_are_unique_and_only_auto_names_are_renamed() {
    let label = format!("{} 日本 54", regional_flag("JP"));
    let mut taken = HashSet::new();
    assert_eq!(unique_remark(&label, &taken), label);
    taken.insert(label.clone());
    assert_eq!(unique_remark(&label, &taken), format!("{label} 2"));
    taken.insert(format!("{label} 2"));
    assert_eq!(unique_remark(&label, &taken), format!("{label} 3"));
    assert!(is_generated_label(&format!(" {}", label)));
    assert!(!is_generated_label("线路A"));
    assert!(!is_generated_label("日本 54"));
    assert_eq!(rename_exit_label(&label, "new"), "new");
    assert_eq!(rename_exit_label("线路A", "new"), "线路A");
    assert_eq!(rename_exit_label(&label, ""), label);

    let exit = Exit {
        host: "jp-host".into(),
        country_code: "JP".into(),
        country: "Japan".into(),
        exit_ip: "203.0.113.54".into(),
        ..Default::default()
    };
    assert_eq!(
        exit_label(&exit),
        format!("{} 日本 54", regional_flag("JP"))
    );
}

#[test]
fn credential_validation_and_socks_json_match_protocol_limits() {
    let valid = SocksCred {
        user: "fo123".into(),
        pass: "abcDEF234".into(),
    };
    validate_cred(&valid).unwrap();
    for invalid in [
        SocksCred {
            user: String::new(),
            pass: "x".into(),
        },
        SocksCred {
            user: "x".into(),
            pass: String::new(),
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
            user: "x".repeat(256),
            pass: "p".into(),
        },
    ] {
        assert!(validate_cred(&invalid).is_err());
    }
    assert_eq!(
        socks_url("1.2.3.4", 20000, &valid),
        "socks5://fo123:abcDEF234@1.2.3.4:20000"
    );
    assert_eq!(
        socks_url("1.2.3.4", 20000, &SocksCred::default()),
        "socks5://1.2.3.4:20000"
    );
    let anonymous = socks_server_json(1080, &SocksCred::default());
    assert_eq!(anonymous, json!({"address": "127.0.0.1", "port": 1080}));
    let authenticated = socks_server_json(1080, &valid);
    assert_eq!(
        authenticated["users"],
        json!([{"user": "fo123", "pass": "abcDEF234"}])
    );
}

#[test]
fn external_port_parser_is_lenient_per_inbound() {
    let ports = xray_config_ports(
        br#"{
        "inbounds": [
            {"port": 15331},
            {"port": 8080},
            {"port": "1000-2000"},
            {"protocol": "no-port"},
            {"port": 0},
            {"port": 65536},
            {"port": -1},
            {"port": 80.5}
        ]
    }"#,
    );
    assert_eq!(ports, HashSet::from([15331, 8080]));
    assert!(xray_config_ports(b"not json").is_empty());
    assert!(xray_config_ports(br#"{"inbounds": {}}"#).is_empty());
}

#[test]
fn restart_backoff_is_bounded() {
    assert_eq!(restart_delay(0), None);
    assert_eq!(restart_delay(1), Some(Duration::from_secs(2)));
    assert_eq!(restart_delay(2), Some(Duration::from_secs(4)));
    assert_eq!(restart_delay(3), Some(Duration::from_secs(8)));
    assert_eq!(restart_delay(4), Some(Duration::from_secs(16)));
    assert_eq!(restart_delay(5), None);
}

#[test]
fn output_trimming_respects_utf8_boundaries() {
    assert_eq!(trim_output("short"), "short");
    assert_eq!(
        trim_output(&"é".repeat(250)),
        format!("{}...", "é".repeat(200))
    );
}
