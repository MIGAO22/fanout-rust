use super::*;
use crate::models::{Node, SocksCred};
use serde_json::json;

fn tunnel(host: &str, status: &str, port: u16) -> TunnelState {
    TunnelState {
        slot: 1,
        port,
        node: Node {
            hostname: host.into(),
            country_code: "JP".into(),
            country: "Japan".into(),
            ..Node::default()
        },
        status: status.into(),
        exit_ip: "203.0.113.248".into(),
        cred: SocksCred {
            user: "foUser".into(),
            pass: "secret".into(),
        },
        ..TunnelState::default()
    }
}

fn pool(id: &str, port: u16, up: usize) -> PoolView {
    PoolView {
        id: id.into(),
        port,
        up,
        total: 2,
        socks_user: "poolUser".into(),
        socks_pass: "poolPass".into(),
        ..PoolView::default()
    }
}

#[test]
fn settings_fields_stay_on_their_own_lines() {
    let text = "current panel settings as follows:\nWarning: Panel is not secure with SSL\nport: 37285\nwebBasePath: /abc123/\n";
    let parsed = parse_panel_settings(text).unwrap();
    assert_eq!(parsed.port, 37_285);
    assert_eq!(parsed.base_path, "/abc123");
    assert!(parse_panel_settings("webBasePath:\nport: 1\n").is_err());
    assert!(parse_panel_settings("port:\nwebBasePath: /x\n").is_err());
}

#[test]
fn ssl_detection_excludes_the_warning_substring() {
    let off = "Warning: Panel is not secure with SSL\nport: 1\n";
    let on = "Panel is secure with SSL\nport: 1\n";
    let silent = "port: 1\nwebBasePath: /x\n";
    assert_eq!(xui_ssl_from_settings(off), (false, true));
    assert_eq!(xui_ssl_from_settings(on), (true, true));
    assert_eq!(xui_ssl_from_settings(silent), (false, false));
}

#[test]
fn certificate_detection_does_not_cross_a_blank_line() {
    assert!(!xui_cert_configured("cert:\nkey:\n"));
    assert!(!xui_cert_configured("cert: \nkey: \n"));
    assert!(xui_cert_configured(
        "cert: /root/cert.crt\nkey: /root/private.key\n"
    ));
}

#[test]
fn token_and_access_url_parsing_strip_ansi_and_ignore_prose() {
    assert_eq!(
        parse_api_token("apiToken: AbC123\n").as_deref(),
        Some("AbC123")
    );
    assert_eq!(parse_api_token("hint: apiToken: nope\n"), None);
    assert_eq!(
        parse_access_url(&strip_ansi(
            "\x1b[32mAccess URL: https://panel.example.com:2053/secret/\x1b[0m\n"
        )),
        Some(("https".into(), "panel.example.com".into()))
    );
}

#[test]
fn inbound_tag_prefers_api_and_decodes_string_stream_settings() {
    assert_eq!(
        resolved_inbound_tag("in-12080-tcp", 12_080, &json!({"network": "ws"})),
        "in-12080-tcp"
    );
    assert_eq!(
        resolved_inbound_tag("", 12_080, &json!({"network": "ws"})),
        "in-12080-ws"
    );
    assert_eq!(
        resolved_inbound_tag("", 12_080, &json!("{\"network\":\"grpc\"}")),
        "in-12080-grpc"
    );
    assert_eq!(inbound_tag(8080, &Value::Null), "in-8080-tcp");
}

#[test]
fn xray_config_is_decoded_twice() {
    let inner = json!({
        "outboundTestUrl": "https://example.test/",
        "xraySetting": {"routing": {"rules": []}, "outbounds": []},
    })
    .to_string();
    let (setting, test_url) = parse_xray_config(&json!(inner)).unwrap();
    assert_eq!(test_url, "https://example.test/");
    assert_eq!(setting["outbounds"], json!([]));
    assert!(parse_xray_config(&json!({"xraySetting": {}})).is_err());
}

#[test]
fn binding_parser_ignores_legacy_numeric_tags_and_accepts_string_or_array() {
    let setting = json!({
        "routing": {
            "rules": [
                {"outboundTag": "fanout-node.example", "inboundTag": "in-1-tcp"},
                {"outboundTag": "fanout-pool-a", "inboundTag": ["in-2-ws", 3]},
                {"outboundTag": "fanout-12", "inboundTag": ["legacy"]},
                {"outboundTag": "direct", "inboundTag": ["manual"]},
            ]
        }
    });
    let bound = bound_from_setting(&setting);
    assert_eq!(
        bound.get("in-1-tcp").map(String::as_str),
        Some("node.example")
    );
    assert_eq!(bound.get("in-2-ws").map(String::as_str), Some("pool-a"));
    assert!(!bound.contains_key("legacy"));
    assert!(!bound.contains_key("manual"));
    assert!(!is_all_digits(""));
    assert!(is_all_digits("001"));
}

#[test]
fn outbound_sync_replaces_only_fanout_entries_and_forces_direct_ipv4() {
    let mut setting = json!({
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "fanout-old", "protocol": "socks", "settings": {}},
            {"tag": "custom", "protocol": "socks", "settings": {"servers": []}},
        ]
    });
    let runtime = Runtime {
        tunnels: vec![
            tunnel("node/a", "up", 30_001),
            tunnel("down", "starting", 30_002),
        ],
        pools: vec![pool("a", 40_001, 0)],
    };
    sync_outbounds_with_runtime(&mut setting, &runtime);
    let outbounds = setting["outbounds"].as_array().unwrap();
    assert_eq!(outbounds.len(), 4);
    assert_eq!(outbounds[0]["settings"]["domainStrategy"], "UseIPv4");
    assert_eq!(outbounds[1]["tag"], "custom");
    assert_eq!(outbounds[2]["tag"], "fanout-node-a");
    assert_eq!(
        outbounds[2]["settings"]["servers"][0],
        json!({
            "address": "127.0.0.1",
            "port": 30_001,
            "users": [{"user": "foUser", "pass": "secret"}],
        })
    );
    assert_eq!(outbounds[3]["tag"], "fanout-pool-a");
    assert_eq!(outbounds[3]["settings"]["servers"][0]["port"], 40_001);
}

#[test]
fn inbound_payload_preserves_encoded_fields_and_resets_expiry() {
    let raw = Map::from_iter([
        ("enable".into(), json!(true)),
        ("remark".into(), json!("线路 A")),
        ("listen".into(), Value::Null),
        ("port".into(), json!(443)),
        ("protocol".into(), json!("vless")),
        ("settings".into(), json!("{\"clients\":[]}")),
        ("streamSettings".into(), json!({"network": "tcp"})),
        ("sniffing".into(), json!({"enabled": true})),
    ]);
    let payload = inbound_payload(&raw);
    assert_eq!(payload["settings"], json!("{\"clients\":[]}"));
    assert_eq!(payload["streamSettings"], json!("{\"network\":\"tcp\"}"));
    assert_eq!(payload["sniffing"], json!("{\"enabled\":true}"));
    assert_eq!(payload["allocate"], json!("{}"));
    assert_eq!(payload["expiryTime"], json!(0));
    assert_eq!(payload["total"], json!(0));
    assert_eq!(payload["listen"], json!(""));
}

#[test]
fn clone_payload_clears_clients_and_keeps_panel_string_fields() {
    let template = Map::from_iter([
        ("settings".into(), json!({"clients": [{"email": "a@b"}]})),
        ("streamSettings".into(), json!("{\"network\":\"ws\"}")),
        (
            "sniffing".into(),
            json!({"enabled": true, "destOverride": ["http"]}),
        ),
        ("listen".into(), json!("0.0.0.0")),
        ("protocol".into(), json!("vless")),
    ]);
    let payload = clone_inbound_payload(&template, 31_001, &tunnel("n", "up", 1)).unwrap();
    assert_eq!(payload["enable"], json!(true));
    assert_eq!(payload["port"], json!(31_001));
    assert_eq!(payload["listen"], json!("0.0.0.0"));
    assert_eq!(payload["allocate"], json!("{}"));
    let settings: Value = serde_json::from_str(payload["settings"].as_str().unwrap()).unwrap();
    assert_eq!(settings["clients"], json!([]));
    assert_eq!(payload["streamSettings"], json!("{\"network\":\"ws\"}"));
}

#[test]
fn client_entry_uses_panel_field_types() {
    let vless = new_client_entry("vless", "vless-443");
    assert_eq!(vless["tgId"], json!(0));
    assert_eq!(vless["totalGB"], json!(0));
    assert_eq!(vless["limitIp"], json!(0));
    assert_eq!(vless["reset"], json!(0));
    assert_eq!(vless["flow"], json!(""));
    Uuid::parse_str(vless["id"].as_str().unwrap()).unwrap();

    let trojan = new_client_entry("trojan", "trojan-443");
    assert_eq!(trojan["password"].as_str().unwrap().len(), 16);
    assert!(!trojan.contains_key("id"));
    assert!(!trojan.contains_key("flow"));
}

#[test]
fn vmess_links_are_decoded_filtered_and_reencoded() {
    let config = json!({
        "v": "2",
        "ps": "t-ws",
        "add": "localhost",
        "port": 40_978,
        "id": "06a30cf8-2c06-4aeb-82fe-b4c7f1ab0159",
        "net": "ws",
        "path": "/abc",
    });
    let link = format!("vmess://{}", BASE64_STANDARD.encode(config.to_string()));
    let (fixed, ok) = link_for_port(&link, 40_978, "1.2.3.4").unwrap();
    assert!(ok);
    let decoded = BASE64_STANDARD
        .decode(fixed.strip_prefix("vmess://").unwrap())
        .unwrap();
    let fixed: Value = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(fixed["add"], json!("1.2.3.4"));
    assert_eq!(fixed["port"], json!(40_978));
    assert_eq!(fixed["path"], json!("/abc"));
    assert!(link_for_port(&link, 12_345, "1.2.3.4").is_none());
}

#[test]
fn uri_links_match_query_or_fragment_and_replace_only_localhost() {
    let link = "vless://uuid@localhost:26387?security=none&type=tcp#t-tcp";
    let (fixed, ok) = link_for_port(link, 26_387, "1.2.3.4").unwrap();
    assert!(ok);
    assert_eq!(
        fixed,
        "vless://uuid@1.2.3.4:26387?security=none&type=tcp#t-tcp"
    );
    assert!(link_for_port(link, 0, "1.2.3.4").is_none());

    let fragment = "trojan://pass@localhost:443#name";
    assert!(link_for_port(fragment, 443, "host.test")
        .unwrap()
        .0
        .contains("@host.test:443"));
}

#[test]
fn malformed_vmess_falls_back_to_uri_port_matching() {
    assert_eq!(
        link_for_port("vmess://not-base64:1234?x", 1234, "host"),
        Some((String::new(), true))
    );
    assert_eq!(
        link_for_port("vmess://not-base64:9999?x", 1234, "host"),
        Some((String::new(), false))
    );
    let invalid_json = format!("vmess://{}", BASE64_STANDARD.encode(b"not-json"));
    assert!(link_for_port(&invalid_json, 1234, "host").is_none());
    for valid_non_object in ["[]", "42", "null"] {
        let link = format!("vmess://{}", BASE64_STANDARD.encode(valid_non_object));
        assert!(link_for_port(&link, 1234, "host").is_none());
    }
}

#[test]
fn rebind_renames_only_fanout_generated_labels() {
    let generated = "🇰🇷 韩国 248";
    assert_eq!(rename_exit_label(generated, "🇯🇵 日本 132"), "🇯🇵 日本 132");
    assert_eq!(rename_exit_label("🇰🇷 韩国 248 2", "new"), "new");
    for manual in [
        "线路A",
        "线路A-KR-248",
        "fanout-JP-243-VN-165",
        "无格式",
        "",
    ] {
        assert_eq!(rename_exit_label(manual, "new"), manual);
    }
    assert_eq!(rename_exit_label(generated, ""), generated);
}

#[test]
fn tag_sanitizing_and_unique_remarks_are_stable() {
    assert_eq!(sanitize_tag("node.example/path"), "node-example-path");
    assert_eq!(sanitize_tag("节点"), "--");
    assert_eq!(sanitize_tag(""), "unknown");
    assert_eq!(sanitize_tag("a_b-9"), "a_b-9");
    let taken = HashSet::from_iter(["same".to_string(), "same 2".to_string()]);
    assert_eq!(unique_remark("same", &taken), "same 3");
    assert_eq!(unique_remark("", &taken), "");
}

#[tokio::test]
async fn inbound_spec_defaults_and_validation_match_native_rules() {
    let spec = json!({
        "protocol": " VLESS ",
        "network": " WS ",
        "port": 12_345,
        "security": " TLS ",
        "path": "/fixed",
        "remark": " 测试 ",
        "sni": "panel.example.com",
    });
    let normalized = normalize_inbound_spec(&spec, &HashSet::new())
        .await
        .unwrap();
    assert_eq!(normalized.protocol, "vless");
    assert_eq!(normalized.network, "ws");
    assert_eq!(normalized.security, "tls");
    assert_eq!(normalized.port, 12_345);
    assert_eq!(normalized.path, "/fixed");
    assert_eq!(normalized.remark, "测试");
    assert_eq!(normalized.server_name, "panel.example.com");
    assert!(normalized.flow.is_empty());

    let vision = normalize_inbound_spec(
        &json!({
            "protocol": "vless",
            "network": "tcp",
            "security": "reality",
            "vision": true,
            "port": 12_346,
        }),
        &HashSet::new(),
    )
    .await
    .unwrap();
    assert_eq!(vision.flow, "xtls-rprx-vision");

    assert!(
        normalize_inbound_spec(&json!({"protocol": "ss", "port": 1}), &HashSet::new())
            .await
            .is_err()
    );
    assert!(
        normalize_inbound_spec(&json!({"network": "quic", "port": 1}), &HashSet::new())
            .await
            .is_err()
    );
    assert!(
        normalize_inbound_spec(&json!({"security": "xtls", "port": 1}), &HashSet::new())
            .await
            .is_err()
    );
    assert!(normalize_inbound_spec(
        &json!({"network": "ws", "security": "reality", "port": 1}),
        &HashSet::new()
    )
    .await
    .is_err());
    assert!(normalize_inbound_spec(
        &json!({"network": "ws", "security": "tls", "vision": true, "port": 1}),
        &HashSet::new()
    )
    .await
    .is_err());
    assert!(
        normalize_inbound_spec(&json!({"port": 443}), &HashSet::from([443]))
            .await
            .is_err()
    );
}

#[test]
fn stream_settings_match_xray_and_include_panel_reality_link_fields() {
    let spec = NormalizedSpec {
        protocol: "vless".into(),
        network: "ws".into(),
        security: "reality".into(),
        port: 443,
        path: "/socket".into(),
        host: "cdn.example.com".into(),
        remark: "r".into(),
        flow: String::new(),
        server_name: String::new(),
        cert_file: String::new(),
        key_file: String::new(),
        dest: String::new(),
        server_names: String::new(),
        short_id: String::new(),
        fingerprint: String::new(),
    };
    let reality = RealityConfig {
        dest: "www.tesla.com:443".into(),
        server_names: vec!["www.tesla.com".into()],
        private_key: "private".into(),
        public_key: "public".into(),
        short_ids: vec!["0123abcd".into()],
        fingerprint: "chrome".into(),
    };
    let stream = xui_stream_settings(&spec, None, Some(&reality));
    assert_eq!(stream["network"], json!("ws"));
    assert_eq!(stream["security"], json!("reality"));
    assert_eq!(stream["wsSettings"]["path"], json!("/socket"));
    assert_eq!(stream["wsSettings"]["host"], json!("cdn.example.com"));
    assert_eq!(stream["realitySettings"]["show"], json!(false));
    assert_eq!(stream["realitySettings"]["xver"], json!(0));
    assert_eq!(
        stream["realitySettings"]["settings"],
        json!({"publicKey": "public", "fingerprint": "chrome", "spiderX": "/"})
    );
}

#[test]
fn envelope_defaults_missing_obj_to_null() {
    let envelope: Envelope = serde_json::from_value(json!({"success": true})).unwrap();
    assert!(envelope.success);
    assert_eq!(envelope.obj, Value::Null);
}
