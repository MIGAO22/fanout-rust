use super::*;
use crate::{models::Node, panel::InboundPatch};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};
use tempfile::TempDir;

#[derive(Clone, Default)]
struct StaticRuntime {
    tunnels: Vec<TunnelState>,
    pools: Vec<PoolView>,
}

impl XCLRuntime for StaticRuntime {
    fn tunnels(&self) -> Vec<TunnelState> {
        self.tunnels.clone()
    }

    fn pools(&self) -> Vec<PoolView> {
        self.pools.clone()
    }
}

fn fixture_cfg() -> Value {
    json!({
        "inbounds": [
            {"tag": "vless-ws", "port": 10001, "protocol": "vless"},
            {"tag": "trojan-ws", "port": 10002, "protocol": "trojan"},
            {"tag": "vmess-ws", "port": 10003, "protocol": "vmess"}
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {"type": "field", "outboundTag": "block", "protocol": ["bittorrent"]}
            ]
        }
    })
}

fn fixture_with_runtime(runtime: StaticRuntime) -> (TempDir, XCL) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    fs::write(&path, serde_json::to_vec(&fixture_cfg()).unwrap()).unwrap();
    let xcl = XCL::new(path, runtime)
        .with_init_system("systemd")
        .with_service_name("xray")
        .with_restart(|| Ok(()))
        .with_restart_debounce(Duration::ZERO);
    (dir, xcl)
}

fn fixture() -> (TempDir, XCL) {
    fixture_with_runtime(StaticRuntime::default())
}

fn tunnel(host: &str, port: u16) -> TunnelState {
    TunnelState {
        port,
        node: Node {
            hostname: host.into(),
            ..Node::default()
        },
        status: "up".into(),
        cred: SocksCred {
            user: "fo-user".into(),
            pass: "secret".into(),
        },
        ..TunnelState::default()
    }
}

fn pool(identity: &str, port: u16, running: bool, up: usize) -> PoolView {
    PoolView {
        identity: identity.into(),
        port,
        running,
        ready: running && up > 0,
        up,
        total: up,
        cred: SocksCred {
            user: "fo-pool".into(),
            pass: "pool-secret".into(),
        },
        ..PoolView::default()
    }
}

fn read_cfg(xcl: &XCL) -> Value {
    xcl.load_cfg().unwrap()
}

fn outbound_tags(cfg: &Value) -> Vec<String> {
    cfg["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|outbound| outbound.get("tag"))
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn routing_rules(cfg: &Value) -> &Vec<Value> {
    cfg["routing"]["rules"].as_array().unwrap()
}

#[test]
fn detection_requires_state_and_valid_object_config() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let path = dir.path().join("config.json");

    let error = XCL::detect_at(&state, &path, ()).err().unwrap();
    assert!(error.to_string().contains("状态目录"));

    fs::create_dir(&state).unwrap();
    let error = XCL::detect_at(&state, &path, ()).err().unwrap();
    assert!(error.to_string().contains("Xray 配置"));

    fs::write(&path, b"[]").unwrap();
    let error = XCL::detect_at(&state, &path, ()).err().unwrap();
    assert!(error.to_string().contains("JSON 对象"));

    fs::write(&path, b"{not-json").unwrap();
    assert!(XCL::detect_at(&state, &path, ()).is_err());

    fs::write(&path, serde_json::to_vec(&fixture_cfg()).unwrap()).unwrap();
    let xcl = XCL::detect_at(&state, &path, ()).unwrap();
    assert_eq!(xcl.config_path(), path.as_path());
    assert_eq!(xcl.kind(), "xray-cf-lite");
    assert!(xcl.describe().contains("config.json"));
}

#[test]
fn inbounds_sort_fall_back_and_ignore_legacy_numeric_tags() {
    let (_dir, xcl) = fixture();
    let mut cfg = fixture_cfg();
    cfg["inbounds"] = json!([
        {"tag": "vmess-ws", "port": 10003, "protocol": "vmess"},
        42,
        {"tag": "", "port": 10001.9, "protocol": "vless"},
        {"tag": "trojan-ws", "port": 10002, "protocol": "trojan"}
    ]);
    cfg["routing"]["rules"] = json!([
        {"outboundTag": "fanout-jp-01", "inboundTag": "in-vless-10001"},
        {"outboundTag": "fanout-12", "inboundTag": "trojan-ws"},
        {"outboundTag": "direct", "inboundTag": "trojan-ws"},
        {"outboundTag": "fanout-us-02", "inboundTag": ["vmess-ws", 7]}
    ]);
    fs::write(xcl.config_path(), serde_json::to_vec(&cfg).unwrap()).unwrap();

    let live = HashMap::from([("jp-01".into(), true), ("us-02".into(), false)]);
    let inbounds = xcl.inbounds_with_live(&live).unwrap();
    assert_eq!(inbounds.len(), 3);
    assert_eq!(inbounds[0].id, "10001");
    assert_eq!(inbounds[0].port, 10001);
    assert_eq!(inbounds[0].tag, "in-vless-10001");
    assert_eq!(inbounds[0].remark, "in-vless-10001");
    assert_eq!(inbounds[0].bound_to, "jp-01");
    assert!(inbounds[0].bound_up);
    assert!(inbounds[0].enable);
    assert_eq!(inbounds[1].tag, "trojan-ws");
    assert!(inbounds[1].bound_to.is_empty());
    assert_eq!(inbounds[2].tag, "vmess-ws");
    assert_eq!(inbounds[2].bound_to, "us-02");
    assert!(!inbounds[2].bound_up);
}

#[test]
fn bind_adds_authenticated_socks_outbound_and_preserves_foreign_config() {
    let (_dir, xcl) = fixture();
    let tunnels = vec![tunnel("jp-01", 20001)];
    xcl.bind_with_state("vless-ws", "jp-01", &tunnels, &[])
        .unwrap();

    let cfg = read_cfg(&xcl);
    assert_eq!(outbound_tags(&cfg), ["direct", "block", "fanout-jp-01"]);
    assert_eq!(cfg["outbounds"][0]["settings"]["domainStrategy"], "UseIPv4");
    assert_eq!(cfg["outbounds"][2]["protocol"], "socks");
    assert_eq!(
        cfg["outbounds"][2]["settings"]["servers"][0],
        json!({
            "address": "127.0.0.1",
            "port": 20001,
            "users": [{"user": "fo-user", "pass": "secret"}]
        })
    );
    assert_eq!(routing_rules(&cfg).len(), 2);
    assert_eq!(routing_rules(&cfg)[0]["outboundTag"], "block");
    assert_eq!(routing_rules(&cfg)[0]["protocol"], json!(["bittorrent"]));
    assert_eq!(routing_rules(&cfg)[1]["outboundTag"], "fanout-jp-01");
    assert_eq!(routing_rules(&cfg)[1]["inboundTag"], json!(["vless-ws"]));
    assert_eq!(cfg["routing"]["domainStrategy"], "AsIs");
    assert_eq!(xcl.bound_inbounds(&cfg)["vless-ws"], "jp-01");

    let inbounds = xcl.inbounds_with_live(&live_map(&tunnels, &[])).unwrap();
    assert!(inbounds[0].bound_up);
    assert!(inbounds[1].bound_to.is_empty());
    assert!(inbounds[2].bound_to.is_empty());
    assert!(!xcl.config_path().with_extension("json.fanout.tmp").exists());
}

#[test]
fn rebind_and_unbind_replace_rules_instead_of_duplicating() {
    let (_dir, xcl) = fixture();
    let tunnels = vec![tunnel("jp-01", 20001), tunnel("us-02", 20002)];
    xcl.bind_with_state("vless-ws", "jp-01", &tunnels, &[])
        .unwrap();
    xcl.bind_with_state("trojan-ws", "us-02", &tunnels, &[])
        .unwrap();
    xcl.bind_with_state("vless-ws", "us-02", &tunnels, &[])
        .unwrap();

    let cfg = read_cfg(&xcl);
    assert_eq!(routing_rules(&cfg).len(), 3);
    let bound = xcl.bound_inbounds(&cfg);
    assert_eq!(bound["vless-ws"], "us-02");
    assert_eq!(bound["trojan-ws"], "us-02");

    xcl.bind_with_state("vless-ws", "", &tunnels, &[]).unwrap();
    let cfg = read_cfg(&xcl);
    assert_eq!(routing_rules(&cfg).len(), 2);
    assert_eq!(routing_rules(&cfg)[0]["outboundTag"], "block");
    assert!(!xcl.bound_inbounds(&cfg).contains_key("vless-ws"));
    assert_eq!(xcl.bound_inbounds(&cfg)["trojan-ws"], "us-02");
}

#[test]
fn bind_cleans_stale_tags_and_rejects_unknown_inbounds_without_writing() {
    let (_dir, xcl) = fixture();
    let mut cfg = fixture_cfg();
    cfg["routing"]["rules"].as_array_mut().unwrap().push(json!({
        "type": "field",
        "inboundTag": ["vless-ws", "stale-tag"],
        "outboundTag": "fanout-jp-01"
    }));
    cfg["routing"]["rules"].as_array_mut().unwrap().push(json!({
        "type": "field",
        "inboundTag": "trojan-ws",
        "outboundTag": "fanout-us-02",
        "custom": true
    }));
    fs::write(xcl.config_path(), serde_json::to_vec(&cfg).unwrap()).unwrap();

    let tunnels = vec![tunnel("jp-01", 20001), tunnel("us-02", 20002)];
    let before = fs::read(xcl.config_path()).unwrap();
    let error = xcl
        .bind_with_state("missing", "jp-01", &tunnels, &[])
        .err()
        .unwrap();
    assert!(error.to_string().contains("入站 missing 不存在"));
    assert_eq!(fs::read(xcl.config_path()).unwrap(), before);

    xcl.bind_with_state("vless-ws", "jp-01", &tunnels, &[])
        .unwrap();
    let cfg = read_cfg(&xcl);
    let rules = routing_rules(&cfg);
    assert_eq!(rules.len(), 3);
    assert!(!rules
        .iter()
        .any(|rule| rule.to_string().contains("stale-tag")));
    assert_eq!(rules[1]["outboundTag"], "fanout-us-02");
    assert_eq!(rules[1]["inboundTag"], json!(["trojan-ws"]));
    assert_eq!(rules[1]["custom"], true);
    assert_eq!(rules[2]["outboundTag"], "fanout-jp-01");
    assert_eq!(rules[2]["inboundTag"], json!(["vless-ws"]));
}

#[test]
fn bind_validates_tunnel_and_pool_state() {
    let (_dir, xcl) = fixture();
    let mut down = tunnel("jp-down", 20001);
    down.status = "down".into();

    let error = xcl
        .bind_with_state("vless-ws", "missing", &[], &[])
        .err()
        .unwrap();
    assert!(error.to_string().contains("没有运行中的隧道"));
    let error = xcl
        .bind_with_state("vless-ws", "jp-down", &[down], &[])
        .err()
        .unwrap();
    assert!(error.to_string().contains("当前 down"));
    let error = xcl
        .bind_with_state("vless-ws", "pool-1", &[], &[])
        .err()
        .unwrap();
    assert!(error.to_string().contains("出口组 pool-1"));
    let error = xcl
        .bind_with_state(
            "vless-ws",
            "pool-1",
            &[],
            &[pool("pool-1", 21001, false, 1)],
        )
        .err()
        .unwrap();
    assert!(error.to_string().contains("监听没起来"));
}

#[test]
fn rebind_moves_all_matching_inbounds_and_reports_no_matches() {
    let (_dir, xcl) = fixture();
    let tunnels = vec![tunnel("jp-01", 20001), tunnel("us-02", 20002)];
    xcl.bind_with_state("vless-ws", "jp-01", &tunnels, &[])
        .unwrap();
    xcl.bind_with_state("trojan-ws", "jp-01", &tunnels, &[])
        .unwrap();
    xcl.rebind_with_state("jp-01", "us-02", &tunnels, &[])
        .unwrap();

    let cfg = read_cfg(&xcl);
    let bound = xcl.bound_inbounds(&cfg);
    assert_eq!(bound.len(), 2);
    assert_eq!(bound["vless-ws"], "us-02");
    assert_eq!(bound["trojan-ws"], "us-02");
    let error = xcl
        .rebind_with_state("missing", "us-02", &tunnels, &[])
        .err()
        .unwrap();
    assert!(error.to_string().contains("没有入站绑在 missing"));
    let error = xcl
        .rebind_with_state("jp-01", "", &tunnels, &[])
        .err()
        .unwrap();
    assert!(error.to_string().contains("目标节点为空"));
}

#[test]
fn resync_drops_dead_outbounds_but_keeps_running_empty_pools() {
    let (_dir, xcl) = fixture();
    let up = tunnel("jp-01", 20001);
    let mut down = tunnel("us-02", 20002);
    down.status = "down".into();
    xcl.bind_with_state("vless-ws", "jp-01", &[up.clone()], &[])
        .unwrap();

    let pools = vec![
        pool("pool-1", 21001, true, 0),
        pool("pool-2", 21002, false, 2),
    ];
    xcl.resync_outbound_with_state("ignored", &[up, down], &pools)
        .unwrap();
    let cfg = read_cfg(&xcl);
    assert_eq!(
        outbound_tags(&cfg),
        ["direct", "block", "fanout-jp-01", "fanout-pool-1"]
    );
    assert_eq!(cfg["outbounds"][3]["settings"]["servers"][0]["port"], 21001);
    assert_eq!(xcl.bound_inbounds(&cfg)["vless-ws"], "jp-01");

    xcl.on_tunnels_changed_with_state(&[], &[]).unwrap();
    let cfg = read_cfg(&xcl);
    assert_eq!(outbound_tags(&cfg), ["direct", "block"]);
    // Tunnel loss does not silently delete a binding and expose the host's direct IP.
    assert_eq!(xcl.bound_inbounds(&cfg)["vless-ws"], "jp-01");
}

#[tokio::test]
async fn panel_uses_runtime_snapshots_for_live_status_and_binding() {
    let runtime = StaticRuntime {
        tunnels: vec![tunnel("jp-01", 20001)],
        pools: vec![pool("pool-1", 21001, true, 1)],
    };
    let (_dir, xcl) = fixture_with_runtime(runtime);
    xcl.bind("vless-ws", "jp-01").await.unwrap();
    xcl.bind("trojan-ws", "pool-1").await.unwrap();

    let inbounds = xcl.inbounds().await.unwrap();
    assert_eq!(inbounds[0].bound_to, "jp-01");
    assert!(inbounds[0].bound_up);
    assert_eq!(inbounds[1].bound_to, "pool-1");
    assert!(inbounds[1].bound_up);

    xcl.resync_outbound("jp-01").await.unwrap();
    assert_eq!(
        outbound_tags(&read_cfg(&xcl)),
        ["direct", "block", "fanout-jp-01", "fanout-pool-1"]
    );
}

#[tokio::test]
async fn panel_detail_links_close_and_node_mutations_match_go_policy() {
    let (_dir, xcl) = fixture();
    let before = fs::read(xcl.config_path()).unwrap();
    let detail = xcl.inbound_detail("10001", "ignored").await.unwrap();
    assert_eq!(detail.id, "10001");
    assert_eq!(detail.tag, "vless-ws");
    assert_eq!(
        xcl.inbound_detail("010001", "ignored").await.unwrap().id,
        "10001"
    );
    assert!(xcl.inbound_detail("not-a-port", "").await.is_err());
    assert!(detail.clients.is_empty());
    assert!(detail.links.is_empty());
    assert!(xcl
        .inbound_links(&["10001".into()], "ignored")
        .await
        .unwrap()
        .is_empty());
    assert!(xcl.inbound_detail("99999", "").await.is_err());

    let create_error = xcl.create_inbound(&json!({})).await.err().unwrap();
    assert_eq!(create_error.to_string(), XCL_READ_ONLY_ERROR);
    let clone_error = xcl
        .clone_to_tunnels("10001", &["jp-01".into()])
        .await
        .err()
        .unwrap();
    assert_eq!(clone_error.to_string(), XCL_READ_ONLY_ERROR);
    let delete_error = xcl.delete_inbounds(&["10001".into()]).await.err().unwrap();
    assert_eq!(delete_error.to_string(), XCL_READ_ONLY_ERROR);
    let update_error = xcl
        .update_inbound("10001", &InboundPatch::default())
        .await
        .err()
        .unwrap();
    assert_eq!(update_error.to_string(), XCL_READ_ONLY_ERROR);
    let add_error = xcl.add_client("10001", "a@b").await.err().unwrap();
    assert_eq!(add_error.to_string(), XCL_READ_ONLY_ERROR);
    let delete_client_error = xcl.delete_client("10001", "a@b").await.err().unwrap();
    assert_eq!(delete_client_error.to_string(), XCL_READ_ONLY_ERROR);
    let reset_error = xcl.reset_client("10001", "a@b").await.err().unwrap();
    assert_eq!(reset_error.to_string(), XCL_READ_ONLY_ERROR);
    xcl.close().await.unwrap();
    assert_eq!(fs::read(xcl.config_path()).unwrap(), before);
}

#[test]
fn restart_command_selects_systemd_or_openrc() {
    let (_dir, xcl) = fixture();
    assert_eq!(
        xcl.restart_command(),
        ("systemctl", vec!["restart".into(), "xray".into()])
    );
    let xcl = xcl
        .with_init_system("openrc")
        .with_service_name("custom-xray");
    assert_eq!(
        xcl.restart_command(),
        ("rc-service", vec!["custom-xray".into(), "restart".into()])
    );
}

#[test]
fn save_cfg_calls_injected_restart_and_propagates_terminal_failure() {
    let (_dir, xcl) = fixture();
    let restarts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&restarts);
    let xcl = xcl.with_restart(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    xcl.save_cfg(&json!({"inbounds": []})).unwrap();
    assert_eq!(restarts.load(Ordering::SeqCst), 1);
    assert_eq!(read_cfg(&xcl), json!({"inbounds": []}));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(xcl.config_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    let mut xcl = xcl.with_restart(|| Err(anyhow!("restart boom")));
    xcl.restart_gate = Arc::new(RestartGate::new(0));
    let error = xcl
        .save_cfg(&json!({"inbounds": [], "saved": true}))
        .err()
        .unwrap();
    assert!(error.to_string().contains("restart boom"));
    assert_eq!(read_cfg(&xcl)["saved"], true);
}

#[test]
fn delayed_restarts_are_coalesced() {
    let (_dir, xcl) = fixture();
    let restarts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&restarts);
    let xcl = xcl
        .with_restart(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .with_restart_debounce(Duration::from_millis(100));
    xcl.save_cfg(&json!({"write": 1})).unwrap();
    xcl.save_cfg(&json!({"write": 2})).unwrap();
    assert_eq!(restarts.load(Ordering::SeqCst), 0);

    let deadline = Instant::now() + Duration::from_secs(2);
    while restarts.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(restarts.load(Ordering::SeqCst), 1);
    thread::sleep(Duration::from_millis(150));
    assert_eq!(restarts.load(Ordering::SeqCst), 1);
    assert_eq!(read_cfg(&xcl)["write"], 2);
}

#[test]
fn pool_view_socks_fields_supply_credentials_when_cred_is_empty() {
    let mut ui_pool = pool("pool-1", 21001, true, 1);
    ui_pool.cred = SocksCred::default();
    ui_pool.socks_user = "fo-ui-user".into();
    ui_pool.socks_pass = "ui-secret".into();
    let mut cfg = fixture_cfg();
    let (_dir, xcl) = fixture();
    xcl.sync_outbounds(&mut cfg, &[], &[ui_pool]);
    assert_eq!(
        cfg["outbounds"][2]["settings"]["servers"][0]["users"],
        json!([{"user": "fo-ui-user", "pass": "ui-secret"}])
    );
}

#[test]
fn tag_and_pool_helpers_preserve_identity_rules() {
    assert_eq!(sanitize_tag("jp-01_example.com"), "jp-01_example-com");
    assert_eq!(sanitize_tag(""), "unknown");
    assert_eq!(egress_tag("jp-01"), "fanout-jp-01");
    assert_eq!(pool_identity_to_id("pool-7"), ("7".into(), true));
    assert_eq!(pool_identity_to_id("pool-"), ("".into(), false));
    assert_eq!(pool_identity_to_id("jp-01"), ("".into(), false));
    assert!(is_all_digits("123"));
    assert!(!is_all_digits(""));
    assert!(!is_all_digits("12a"));
}
