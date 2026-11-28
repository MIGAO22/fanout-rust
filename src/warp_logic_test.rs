use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{TimeZone, Utc};
use std::{collections::HashSet, time::Duration};
use x25519_dalek::StaticSecret;

const WARP_REG_FIXTURE: &str = r#"{
  "id": "3f2c1e0a-9b7d-4c6e-8a1f-2d5b7c9e0f13",
  "key": "hB3U4kK6UZ0O2mQvVa1nYyt3Ld9FbR7iXsZ0oCjPq1M=",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fixture",
  "type": "a",
  "name": "fanout",
  "account": {"id": "acct-1", "account_type": "free", "warp_plus": true, "role": "child"},
  "config": {
    "client_id": "0f9d0000-1111-2222-3333-444455556666",
    "peers": [
      {
        "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "endpoint": {
          "v4": "162.159.192.6:0",
          "v6": "[2606:4700:d0::a29f:c006]:0",
          "host": "engage.cloudflareclient.com:2408",
          "ports": [2408, 500, 1701, 4500]
        },
        "allowed_ips": ["0.0.0.0/0", "::/0"]
      }
    ],
    "interface": {
      "addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8c91:320c:fcfc:fd0e:ba60"},
      "dns": {"servers": "1.1.1.1"}
    },
    "services": {"http_proxy": "172.16.0.1:2480"}
  },
  "warp_enabled": false,
  "enabled": true,
  "place": 0,
  "locale": "en-US",
  "policy": {"tunnel_protocol": "masque", "post_quantum": "enabled_with_downgrades"}
}"#;

fn joined(command: &[String]) -> String {
    command.join(" ")
}

fn registration() -> WarpRegResponse {
    parse_warp_reg(WARP_REG_FIXTURE.as_bytes()).unwrap()
}

fn have_all_tools(_: &str) -> bool {
    true
}

#[test]
fn warp_parses_real_registration() {
    let response = registration();
    let public_key = response.key.clone();
    let now = Utc
        .with_ymd_and_hms(2026, 11, 24, 3, 4, 5)
        .single()
        .unwrap();
    let account = warp_account_of(
        12,
        &response,
        "priv-bytes",
        &public_key,
        WARP_CLIENT_VERSION,
        now,
    )
    .unwrap();

    assert_eq!(account.endpoint, "162.159.192.6");
    assert_eq!(account.port, WARP_PORT);
    assert_eq!(account.peer_key, WARP_PEER_PUB);
    assert_eq!(account.tun_ip, "172.16.0.2");
    assert_eq!(account.id, "3f2c1e0a-9b7d-4c6e-8a1f-2d5b7c9e0f13");
    assert!(!account.token.is_empty());
    assert_eq!(account.created_at, "2026-11-24T03:04:05Z");
    assert_eq!(account.dev_name(""), warp_dev_name("", 12));
}

#[test]
fn warp_account_rejects_key_mismatch() {
    let response = registration();
    let now = Utc::now();
    let error =
        warp_account_of(3, &response, "p", "OTHERKEY=", WARP_CLIENT_VERSION, now).unwrap_err();
    assert!(error.to_string().contains("公钥"));
}

#[test]
fn warp_registration_response_requires_usable_fields() {
    let cases = [
        (
            "缺 id",
            r#"{"token":"t","config":{"peers":[{"public_key":"k","endpoint":{"v4":"1.2.3.4:0"}}]}}"#,
        ),
        (
            "缺 token",
            r#"{"id":"i","config":{"peers":[{"public_key":"k","endpoint":{"v4":"1.2.3.4:0"}}]}}"#,
        ),
        ("没 peer", r#"{"id":"i","token":"t","config":{"peers":[]}}"#),
        ("门户页", "<html><body>captive portal</body></html>"),
    ];
    for (name, body) in cases {
        assert!(parse_warp_reg(body.as_bytes()).is_err(), "{name} 本该报错");
    }
}

#[test]
fn warp_endpoint_port_preference() {
    let (ip, port) = warp_endpoint(
        "162.159.192.6:0",
        "engage.cloudflareclient.com:2408",
        &[2408, 500],
    )
    .unwrap();
    assert_eq!((ip.as_str(), port), ("162.159.192.6", 2408));

    let (ip, port) = warp_endpoint(
        "162.159.192.7:2409",
        "engage.cloudflareclient.com:2408",
        &[500],
    )
    .unwrap();
    assert_eq!((ip.as_str(), port), ("162.159.192.7", 2409));

    let (_, port) = warp_endpoint(
        "162.159.192.7:0",
        "engage.cloudflareclient.com",
        &[1701, 4500],
    )
    .unwrap();
    assert_eq!(port, 1701);

    let (_, port) = warp_endpoint("162.159.192.7", "", &[]).unwrap();
    assert_eq!(port, WARP_PORT);

    assert!(warp_endpoint("", "[2606:4700:d0::a29f:c006]:0", &[2408]).is_err());
    assert!(warp_endpoint("engage.cloudflareclient.com:2408", "", &[]).is_err());
}

#[test]
fn warp_key_pair_is_wireguard_compatible() {
    let (private, public) = new_warp_keys().unwrap();
    let raw_private = STANDARD.decode(&private).unwrap();
    let raw_public = STANDARD.decode(&public).unwrap();
    assert_eq!(raw_private.len(), 32);
    assert_eq!(raw_public.len(), 32);

    let raw_private: [u8; 32] = raw_private.try_into().unwrap();
    let secret = StaticSecret::from(raw_private);
    assert_eq!(STANDARD.encode(PublicKey::from(&secret).as_bytes()), public);
}

#[test]
fn warp_registration_request_body() {
    let request = new_warp_reg_request("PUBKEY=", "").unwrap();
    let value = serde_json::to_value(&request).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), 5);
    assert_eq!(object["key"], "PUBKEY=");
    assert_eq!(object["version"], WARP_CLIENT_VERSION);
    assert_eq!(object["os"], "linux");
    assert_eq!(object["type"], "WireGuard");

    let install_id = object["install_id"].as_str().unwrap();
    assert_eq!(install_id.len(), 16);
    assert!(install_id
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_ne!(warp_install_id().unwrap(), install_id);
    assert_eq!(warp_version_parts(&request.version).unwrap().len(), 4);

    let supplied = new_warp_reg_request("PUBKEY=", " 2026.9.1.0 ").unwrap();
    assert_eq!(supplied.version, " 2026.9.1.0 ");
}

#[test]
fn warp_setup_commands_order() {
    let input = WarpSetupInput {
        dev: "fow12".to_string(),
        peer_key: WARP_PEER_PUB.to_string(),
        endpoint: "162.159.192.6".to_string(),
        port: 2408,
        tun_ip: "172.16.0.2".to_string(),
        mtu: 1420,
        veth_gw: "10.99.12.1".to_string(),
        veth: "fop12".to_string(),
        direct_ips: vec!["8.8.8.8".to_string()],
    };
    let commands = warp_setup_cmds(&input);
    assert_eq!(commands.len(), 7);
    assert_eq!(
        joined(&commands[0]),
        "ip route replace 162.159.192.6/32 via 10.99.12.1 dev fop12"
    );
    assert_eq!(
        joined(&commands[1]),
        "ip route replace 8.8.8.8/32 via 10.99.12.1 dev fop12"
    );
    assert_eq!(
        joined(&commands[2]),
        "ip link add dev fow12 mtu 1420 type wireguard"
    );
    assert_eq!(joined(&commands[3]), "ip addr add 172.16.0.2/32 dev fow12");
    let wg_set = joined(&commands[4]);
    for wanted in [
        "private-key /proc/self/fd/0".to_string(),
        format!("peer {WARP_PEER_PUB}"),
        "endpoint 162.159.192.6:2408".to_string(),
        "allowed-ips 0.0.0.0/0".to_string(),
        format!("persistent-keepalive {WARP_KEEPALIVE}"),
    ] {
        assert!(wg_set.contains(&wanted), "wg set 缺 {wanted}: {wg_set}");
    }
    for command in &commands {
        let command = joined(command);
        assert!(!command.contains(".wgkey"));
        assert!(!command.contains("/var/lib/fanout"));
    }
    assert_eq!(joined(&commands[5]), "ip link set dev fow12 up");
    assert_eq!(joined(&commands[6]), "ip route replace default dev fow12");
}

#[test]
fn generic_options_never_follow_type() {
    let input = WarpSetupInput {
        dev: "fow3".to_string(),
        peer_key: WARP_PEER_PUB.to_string(),
        endpoint: "162.159.192.6".to_string(),
        port: 2408,
        tun_ip: "172.16.0.2".to_string(),
        mtu: 1390,
        veth_gw: "10.99.3.1".to_string(),
        veth: "fop3".to_string(),
        direct_ips: vec!["8.8.8.8".to_string()],
    };
    let mut commands = warp_setup_cmds(&input);
    commands.extend(warp_split_cmds(
        "fow3",
        "tun0",
        &["61.215.116.134".to_string()],
    ));
    let generic = [
        "mtu",
        "address",
        "name",
        "numtxqueues",
        "numrxqueues",
        "txqueuelen",
    ];
    let mut typed_commands = 0;
    for command in &commands {
        let text = joined(command);
        if command.first().map(String::as_str) != Some("ip") || !text.contains(" type ") {
            continue;
        }
        typed_commands += 1;
        let type_at = command.iter().position(|token| token == "type").unwrap();
        for token in &command[type_at + 2..] {
            assert!(
                !generic.contains(&token.as_str()),
                "通用选项排到了 type 之后: {text}"
            );
        }
    }
    assert_eq!(typed_commands, 1);
    assert!(joined(&commands[2]).contains("mtu 1390 type wireguard"));
}

#[test]
fn warp_setup_keeps_non_ip_direct_out_of_routes() {
    let input = WarpSetupInput {
        dev: "fow1".to_string(),
        peer_key: WARP_PEER_PUB.to_string(),
        endpoint: "162.159.192.6".to_string(),
        port: 2408,
        tun_ip: "172.16.0.2".to_string(),
        mtu: 1420,
        veth_gw: "10.1.1.1".to_string(),
        veth: "fop1".to_string(),
        direct_ips: vec![
            "fd00::1".to_string(),
            "not-an-ip".to_string(),
            "1.1.1.1".to_string(),
        ],
    };
    let routes: Vec<_> = warp_setup_cmds(&input)
        .iter()
        .filter(|command| {
            command.len() > 3
                && command[1] == "route"
                && command[2] == "replace"
                && command[3] != "default"
        })
        .map(|command| joined(command))
        .collect();
    assert_eq!(routes.len(), 2);
    for route in routes {
        assert!(!route.contains("not-an-ip"));
        assert!(!route.contains("fd00"));
    }
}

#[test]
fn warp_probe_commands_touch_nothing_but_the_device() {
    let (setup, cleanup) = warp_probe_cmds(WARP_PEER_PUB, "162.159.193.2", 2408, 1420);
    assert_eq!(setup.len(), 2);
    assert_eq!(
        joined(&setup[0]),
        "ip link add dev foarpprobe mtu 1420 type wireguard"
    );
    assert!(WARP_PROBE_DEV.len() <= 15);
    let wg_set = joined(&setup[1]);
    for wanted in [
        "private-key /proc/self/fd/0".to_string(),
        format!("peer {WARP_PEER_PUB}"),
        "endpoint 162.159.193.2:2408".to_string(),
        "allowed-ips 0.0.0.0/0".to_string(),
        format!("persistent-keepalive {WARP_KEEPALIVE}"),
    ] {
        assert!(wg_set.contains(&wanted), "自检 wg set 缺 {wanted}");
    }
    for command in setup
        .iter()
        .cloned()
        .chain(std::iter::once(cleanup.clone()))
    {
        let text = joined(&command);
        for forbidden in [" route ", "addr add", "link set", "sysctl", "iptables"] {
            assert!(!text.contains(forbidden), "自检命令改变了转发状态: {text}");
        }
    }
    assert_eq!(joined(&cleanup), "ip link del foarpprobe");
}

#[test]
fn warp_argv_never_doubles_the_program() {
    let link_command = vec![
        "ip",
        "link",
        "add",
        "dev",
        WARP_PROBE_DEV,
        "mtu",
        "1420",
        "type",
        "wireguard",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    let wg_command = vec![
        "wg",
        "set",
        WARP_PROBE_DEV,
        "private-key",
        "/var/lib/fanout/fow1.wgkey",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();

    for command in [&link_command, &wg_command] {
        let (program, argv) = warp_argv("", command);
        let mut full = vec![program];
        full.extend(argv);
        assert_eq!(joined(&full), joined(command));
    }
    let (program, argv) = warp_argv("fo1", &link_command);
    let mut full = vec![program];
    full.extend(argv);
    assert_eq!(
        joined(&full),
        format!("ip netns exec fo1 {}", joined(&link_command))
    );

    for namespace in ["", "fo1"] {
        for command in [&link_command, &wg_command] {
            let (program, argv) = warp_argv(namespace, command);
            let mut full = vec![program];
            full.extend(argv);
            let full = format!("{} ", joined(&full));
            for bad in ["ip ip ", "wg wg ", "ip netns exec  "] {
                assert!(!full.contains(bad), "命令拼重了: {full}");
            }
        }
    }

    let mut wg_command = wg_command;
    wg_command.extend(["peer".to_string(), WARP_PEER_PUB.to_string()]);
    assert_eq!(warp_cmd_tag("fo1", &wg_command), "fo1：wg set foarpprobe");
    assert_eq!(warp_cmd_tag("", &link_command), "ip link add");
}

#[test]
fn warp_key_only_goes_to_wg() {
    let private_key = "yA7EpL6HvcV6Y2s4Yz3Q4rBp7W8p3BpB9p8v2nB1F3U=";
    assert_eq!(
        warp_key_for(&command(&["wg", "set", "fow1"]), private_key),
        format!("{private_key}\n")
    );
    for command in [
        command(&[
            "ip",
            "link",
            "add",
            "dev",
            "fow1",
            "mtu",
            "1420",
            "type",
            "wireguard",
        ]),
        command(&["ip", "addr", "add", "172.16.0.2/32", "dev", "fow1"]),
        command(&["ip", "route", "replace", "default", "dev", "fow1"]),
    ] {
        assert_eq!(warp_key_for(&command, private_key), "");
    }
    assert_eq!(warp_key_for(&[], private_key), "");
}

#[test]
fn wireguard_error_hint_names_the_actionable_cause() {
    let cases = [
        (
            r#"ip link add dev foarpprobe mtu 1420 type wireguard: Garbage instead of arguments "mtu ..."."#,
            "升级",
        ),
        (
            "Unable to read key from file /var/lib/fanout/fow1.wgkey",
            "私钥",
        ),
        ("RTNETLINK answers: Operation not supported", "内核"),
        ("Cannot find device \"fow1\"", "设备"),
        ("SIOCSIFADDR: Permission denied", "权限"),
        (
            "Error sending 'set device' message: Protocol error",
            "wireguard-tools",
        ),
        ("Bad peer public key", "公钥"),
        ("", ""),
        ("Some unrelated failure from ip route", ""),
    ];
    for (raw, wanted) in cases {
        let hint = wireguard_error_hint(raw);
        if wanted.is_empty() {
            assert!(hint.is_empty(), "认不出的原话不该编原因: {raw} -> {hint}");
        } else {
            assert!(
                hint.contains(wanted),
                "{raw} 的提示该含 {wanted}, 实际 {hint}"
            );
        }
    }
}

#[test]
fn warp_split_pins_gate_onto_warp() {
    let commands = warp_split_cmds(
        "fow7",
        "tun0",
        &["61.215.116.134".to_string(), "210.167.4.5".to_string()],
    );
    assert_eq!(commands.len(), 4);
    assert_eq!(
        joined(&commands[0]),
        "ip route replace 61.215.116.134/32 dev fow7"
    );
    assert_eq!(joined(&commands[2]), "ip route replace 0.0.0.0/1 dev tun0");
    assert_eq!(
        joined(&commands[3]),
        "ip route replace 128.0.0.0/1 dev tun0"
    );
    for command in &commands[..2] {
        assert!(joined(command).contains("/32"));
    }
    assert_eq!(
        warp_split_cmds(
            "fow7",
            "tun0",
            &["bogus".to_string(), "1.2.3.4".to_string()]
        )
        .len(),
        3
    );
    assert_eq!(warp_split_cmds("fow7", "tun0", &[]).len(), 2);
}

#[test]
fn warp_gate_addresses() {
    let config = [
        "client-config-sample by vpngate",
        "remote 61.215.116.134 1194 udp",
        "remote 61.215.116.134 443 tcp",
        "remote-entry gate.example.net 1194 udp",
        "# remote 203.0.113.9 1194 udp",
        "server 198.18.0.7",
        "dev tun",
    ]
    .join("\n");
    assert_eq!(
        warp_gate_hosts(&config)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["61.215.116.134", "gate.example.net", "198.18.0.7"]
    );

    let commands = warp_split_cmds("fow1", "tun0", &warp_gate_ips(&config, "203.0.113.10"));
    let pinned: Vec<_> = commands
        .iter()
        .filter(|command| command.len() > 3 && command[1] == "route" && command[3].ends_with("/32"))
        .map(|command| command[3].as_str())
        .collect();
    assert_eq!(
        pinned,
        vec!["198.18.0.7/32", "203.0.113.10/32", "61.215.116.134/32"]
    );
    assert_eq!(
        warp_gate_names(&config)
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["gate.example.net"]
    );
    assert!(warp_gate_names("remote 1.2.3.4 1194 udp\n").is_empty());
    assert_eq!(
        warp_gate_ips("", "203.0.113.9"),
        vec!["203.0.113.9".to_string()]
    );
    assert!(warp_gate_ips("remote 2001:db8::1 1194 udp\n", "").is_empty());
}

#[test]
fn warp_nameservers_from_resolv_conf() {
    let nameservers = warp_nameservers(
        "# generated\nnameserver 8.8.8.8\nnameserver 8.8.8.8\nsearch lan\nnameserver 1.1.1.1\n",
    );
    assert_eq!(
        nameservers,
        vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]
    );
    assert!(warp_nameservers("nameserver fe80::1\n").is_empty());
}

#[test]
fn warp_off_changes_nothing() {
    assert_eq!(warp_path_mtu(false, 1500), (0, 0, 1380));
    assert!(warp_openvpn_args(false, 0).is_empty());
    assert_eq!(
        warp_budget(Duration::from_secs(45), false),
        Duration::from_secs(45)
    );

    let (wg, tun, mssfix) = warp_path_mtu(true, 1500);
    assert_eq!((wg, tun, mssfix), (1420, 1380, 1340));
    assert!(mssfix < tun && tun < wg);
    let args = warp_openvpn_args(true, tun);
    assert!(args.contains(&"--route-nopull".to_string()));
    assert!(args
        .windows(2)
        .any(|pair| pair[0] == "--tun-mtu" && pair[1] == "1380"));
    assert_eq!(
        warp_budget(Duration::from_secs(45), true),
        Duration::from_secs(45) + WARP_EXTRA_BUDGET
    );
}

#[test]
fn warp_split_routes_are_idempotent() {
    let commands = warp_split_cmds(
        "fow1",
        "tun0",
        &["180.59.230.60".to_string(), "8.8.8.8".to_string()],
    );
    assert_eq!(commands.len(), 4);
    for command in &commands {
        let text = joined(command);
        assert!(text.starts_with("ip route replace "));
        assert!(!text.starts_with("ip route add "));
    }
    assert_eq!(
        joined(commands.last().unwrap()),
        "ip route replace 128.0.0.0/1 dev tun0"
    );
}

#[test]
fn parse_warp_routes_reads_the_field_output() {
    let good = r#"0.0.0.0/1 dev tun0 scope link 
default dev fow1 scope link 
8.8.8.8 via 10.99.1.1 dev fop1 
10.99.1.0/30 dev fop1 proto kernel scope link src 10.99.1.2 
10.211.1.14 dev tun0 proto kernel scope link src 10.211.1.13 
128.0.0.0/1 dev tun0 scope link 
162.159.192.3 via 10.99.1.1 dev fop1 
180.59.230.60 dev fow1 scope link "#;
    let split_gone = r#"default dev fow13 scope link 
8.8.8.8 via 10.99.13.1 dev fop13 
10.99.13.0/30 dev fop13 proto kernel scope link src 10.99.13.2 
10.211.1.2 dev tun0 proto kernel scope link src 10.211.1.1 
162.159.192.2 via 10.99.13.1 dev fop13 
182.20.60.214 dev fow13 scope link "#;
    let no_tun = r#"default dev fow12 scope link 
8.8.8.8 via 10.99.12.1 dev fop12 
10.99.12.0/30 dev fop12 proto kernel scope link src 10.99.12.2 
162.159.192.4 via 10.99.12.1 dev fop12 "#;

    let cases = [
        (
            "正常",
            good,
            "fow1",
            WarpRouteState {
                tun_up: true,
                split_ok: true,
                def_on_dev: true,
            },
            false,
        ),
        (
            "重连后分流没了",
            split_gone,
            "fow13",
            WarpRouteState {
                tun_up: true,
                split_ok: false,
                def_on_dev: true,
            },
            true,
        ),
        (
            "隧道没连着",
            no_tun,
            "fow12",
            WarpRouteState {
                tun_up: false,
                split_ok: false,
                def_on_dev: true,
            },
            true,
        ),
        ("全都没有", "", "fow9", WarpRouteState::default(), false),
    ];
    for (name, blob, dev, wanted, need_guard) in cases {
        let state = parse_warp_routes(blob, dev);
        assert_eq!(state, wanted, "{name}");
        assert_eq!(warp_guard_needed(&state), need_guard, "{name}");
    }
}

#[test]
fn warp_gate_pins_are_separate_and_ipv4_only() {
    let pins = warp_gate_pin_cmds(
        "fow1",
        &[
            "182.20.60.214".to_string(),
            "fd00::1".to_string(),
            "bogus".to_string(),
            "61.215.116.134".to_string(),
        ],
    );
    assert_eq!(pins.len(), 2);
    assert_eq!(
        joined(&pins[0]),
        "ip route replace 182.20.60.214/32 dev fow1"
    );
    assert!(!joined(&pins[1]).contains("tun0"));
    let split = warp_split_cmds("fow1", "tun0", &["182.20.60.214".to_string()]);
    assert_eq!(
        joined(&split[0]),
        "ip route replace 182.20.60.214/32 dev fow1"
    );
    assert!(warp_gate_pin_cmds("fow1", &[]).is_empty());
}

#[test]
fn warp_guard_commands_differ_by_tunnel_state() {
    let open = warp_guard_cmds("fow1", "tun0", &["180.59.230.60".to_string()], true);
    assert_eq!(joined(&open[0]), "ip route replace default dev fow1");
    let tail = format!(
        "{} | {}",
        joined(&open[open.len() - 2]),
        joined(&open[open.len() - 1])
    );
    assert!(tail.contains("0.0.0.0/1 dev tun0"));
    assert!(tail.contains("128.0.0.0/1 dev tun0"));

    let closed = warp_guard_cmds("fow1", "tun0", &["180.59.230.60".to_string()], false);
    assert_eq!(closed.len(), 1);
    assert_eq!(joined(&closed[0]), "ip route del default");
    assert!(!joined(&closed[0]).contains("/1"));
    assert!(!joined(&closed[0]).contains("tun0"));
}

#[test]
fn warp_exit_is_cloudflare_transit_only() {
    for ip in [
        "104.28.247.68",
        "104.28.215.69",
        "162.159.192.3",
        "172.64.10.1",
        "198.41.128.9",
    ] {
        assert!(warp_exit_is_transit_only(ip), "{ip} 该判成只走了中转");
    }
    for ip in [
        "42.146.135.174",
        "113.145.249.52",
        "180.59.230.60",
        "202.224.30.208",
        "104.32.0.1",
        "",
        "读不出来",
        "104.28.247.68,104.28.247.69",
    ] {
        assert!(!warp_exit_is_transit_only(ip), "{ip} 不该被判成中转出口");
    }
}

#[test]
fn warp_pull_filters_match_openvpn_syntax_and_version() {
    assert!(warp_pull_filters(false, "2.6.8").is_empty());
    let filters = warp_pull_filters(true, "2.6.8");
    let wanted = [
        "--pull-filter",
        "ignore",
        "tun-mtu",
        "--pull-filter",
        "ignore",
        "link-mtu",
        "--pull-filter",
        "ignore",
        "mssfix",
    ];
    assert_eq!(
        filters.iter().map(String::as_str).collect::<Vec<_>>(),
        wanted
    );
    for (index, argument) in filters.iter().enumerate() {
        assert!(argument != "--pull" && argument != "pull");
        if argument == "--pull-filter" {
            assert!(index + 2 < filters.len());
            assert_eq!(filters[index + 1], "ignore");
        }
    }
    for version in ["2.3.20", "2.2.1", "", "读不出来"] {
        assert!(
            warp_pull_filters(true, version).is_empty(),
            "openvpn {version}"
        );
    }
    for version in [
        "2.4.0",
        "2.4.9-1ubuntu5",
        "2.5.8",
        "2.6.20-1ubuntu1",
        "2.7.9",
        "3.0.0",
    ] {
        assert!(
            !warp_pull_filters(true, version).is_empty(),
            "openvpn {version}"
        );
    }
}

#[test]
fn warp_mtu_follows_under_link() {
    let cases = [
        (1500, 1420, 1380, 1340),
        (1492, 1420, 1380, 1340),
        (1450, 1390, 1350, 1310),
        (1400, 1340, 1300, 1260),
        (1300, 1280, 1240, 1200),
        (0, 1420, 1380, 1340),
        (-5, 1420, 1380, 1340),
        (9000, 1420, 1380, 1340),
    ];
    for (under, wanted_wg, wanted_tun, wanted_mssfix) in cases {
        let (wg, tun, mssfix) = warp_path_mtu(true, under);
        assert_eq!(
            (wg, tun, mssfix),
            (wanted_wg, wanted_tun, wanted_mssfix),
            "under={under}"
        );
        assert!(wg >= 1280);
        assert!(mssfix < tun && tun < wg);
    }
}

#[test]
fn warp_default_dev_reads_default_route() {
    let blob = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
        eth0\t00000000\t010251C0\t0003\t0\t0\t100\t00000000\t1500\t0\t0\n\
        eth0\t000251C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t1500\t0\t0\n\
        docker0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t1500\t0\t0\n";
    assert_eq!(warp_default_dev(blob), "eth0");
    assert_eq!(warp_default_dev("Iface\tDestination\n"), "");
    assert_eq!(warp_default_dev(""), "");
    assert_eq!(warp_default_dev("Iface\tDestination\neth0\t000251C0\n"), "");
}

#[test]
fn warp_dev_names_fit_and_differ() {
    let mut seen = HashSet::new();
    for tag in ["", "a1", "zz9zz9"] {
        for slot in 1..=24 {
            let dev = warp_dev_name(tag, slot);
            assert!(dev.len() <= 15, "设备名 {dev} 超过 15 字符");
            assert!(dev.starts_with("fow"));
            assert!(seen.insert(dev.clone()), "设备名 {dev} 撞了");
        }
    }
    assert_eq!(warp_key_file_name("fow12"), "fow12.wgkey");
}

#[test]
fn warp_live_from_wg_dump() {
    let public_key = WARP_PEER_PUB;
    let fresh =
        format!("{public_key}\t(none)\t162.159.193.5:2408\t0.0.0.0/0\t3521\t45210\t38991\t25");
    let stale =
        format!("{public_key}\t(none)\t162.159.192.6:2408\t0.0.0.0/0,::/0\t120\t45210\t38991\toff");
    let never = format!("{public_key}\t(none)\t(none)\t0.0.0.0/0\t0\t0\t0\t25");

    let peers = parse_wg_dump(&fresh);
    assert_eq!(peers.len(), 1);
    let peer = &peers[0];
    assert_eq!(peer.pub_key, public_key);
    assert_eq!(peer.handshake, 3521);
    assert_eq!(peer.endpoint, "162.159.193.5:2408");
    assert_eq!((peer.rx, peer.tx, peer.keepalive), (45210, 38991, 25));
    assert!(warp_live(peer, 3600, 1_777_000_000));

    let epoch_peer = WarpPeer {
        pub_key: public_key.to_string(),
        endpoint: "162.159.193.5:2408".to_string(),
        handshake: 1_777_000_000 - 30,
        ..WarpPeer::default()
    };
    assert!(warp_live(&epoch_peer, 3600, 1_777_000_000));
    assert!(!warp_live(
        &WarpPeer {
            endpoint: "1.2.3.4:2408".to_string(),
            handshake: 1_777_000_100,
            ..WarpPeer::default()
        },
        4000,
        1_777_000_000,
    ));
    assert!(!warp_live(
        peer,
        3600 + WARP_FRESH_AFTER.as_secs() as i64,
        1_777_000_000,
    ));

    let (endpoint, live) = warp_live_endpoint(&parse_wg_dump(&fresh), 3600, 1_777_000_000);
    assert!(live);
    assert_eq!(endpoint, "162.159.193.5:2408");

    let stale_peers = parse_wg_dump(&stale);
    assert_eq!(stale_peers.len(), 1);
    let (endpoint, live) = warp_live_endpoint(&stale_peers, 100_000, 1_777_000_000);
    assert!(!live);
    assert_eq!(endpoint, "162.159.192.6:2408");
    assert_eq!(stale_peers[0].keepalive, 0);

    let (endpoint, live) = warp_live_endpoint(&parse_wg_dump(&never), 100_000, 1_777_000_000);
    assert!(!live);
    assert!(endpoint.is_empty());
    let (endpoint, live) = warp_live_endpoint(&[], 100_000, 1_777_000_000);
    assert!(!live);
    assert!(endpoint.is_empty());

    let noise = format!(
        "\n\n(none)\t{public_key}\t51820\toff\nwg: Permission denied\nnot\tenough\n{public_key}\tshort\n"
    );
    assert!(parse_wg_dump(&noise).is_empty());
}

#[test]
fn warp_handshake_age_handles_both_rulers() {
    let wall = 1_777_000_000_i64;
    let uptime = 40_000_i64;
    let cases = [
        ("开机秒", uptime - 90, 90, true),
        ("epoch 秒", wall - 45, 45, true),
        ("从没握手", 0, 0, false),
        ("负数", -5, 0, false),
        ("在未来", wall + 60, 0, false),
    ];
    for (name, handshake, wanted_age, wanted_ok) in cases {
        let (age, ok) = warp_handshake_age(handshake, uptime, wall);
        assert_eq!(ok, wanted_ok, "{name}");
        if ok {
            assert_eq!(age, wanted_age, "{name}");
        }
    }
    assert!(warp_handshake_age(wall - 5, uptime, wall).1);
}

#[test]
fn warp_version_compare() {
    let cases = [
        ("2026.8.2115.0", "2026.8.2115.0", false),
        ("2026.3.846.0", "2026.8.2115.0", true),
        ("2025.6.1335.0", "2026.3.846.0", true),
        ("2026.8.2115.0", "2026.8.2116.0", true),
        ("2026.8.2115.1", "2026.8.2115.0", false),
        ("2026.8.2115", "2026.8.2115.0", false),
        ("2026.8.2115.0-1", "2026.8.2115.0", false),
        ("v2026.8.2115.0", "2026.8.2115.0", false),
        ("2024.4.133-1", "2026.8.2115.0", true),
        ("latest", "2026.8.2115.0", true),
    ];
    for (a, b, wanted) in cases {
        assert_eq!(
            warp_version_less(a, b),
            wanted,
            "warp_version_less({a}, {b})"
        );
    }
    assert!(warp_version_parts(WARP_CLIENT_VERSION).is_some());
    for version in ["", "latest", "2026.x.1"] {
        assert!(warp_version_parts(version).is_none(), "{version}");
    }
}

#[test]
fn warp_pkg_index_parsing() {
    let body = [
        "Package: cloudflared",
        "Version: 2026.10.2",
        "Architecture: amd64",
        "",
        "Package: cloudflare-warp",
        "Version: 2026.8.2115.0",
        "Architecture: amd64",
        "",
    ]
    .join("\r\n");
    assert_eq!(parse_warp_pkg_version(&body), "2026.8.2115.0");
    assert_eq!(
        parse_warp_pkg_version("Package: nginx\nVersion: 1.2.3\n"),
        ""
    );
    assert_eq!(parse_warp_pkg_version("<html>502 bad gateway</html>"), "");

    let codenames = parse_warp_codenames(WARP_CODENAMES);
    assert!(codenames.len() >= 2);
    assert_ne!(codenames[0], "bullseye");
    assert_ne!(codenames[0], "focal");
    assert_eq!(
        parse_warp_codenames("noble,, jammy ,"),
        vec!["noble".to_string(), "jammy".to_string()]
    );
}

fn store_accounts() -> Vec<WarpAccount> {
    vec![
        WarpAccount {
            slot: 1,
            id: "id1".to_string(),
            token: "t1".to_string(),
            priv_key: "p1".to_string(),
            pub_key: "q1".to_string(),
            peer_key: WARP_PEER_PUB.to_string(),
            endpoint: "162.159.192.6".to_string(),
            port: 2408,
            tun_ip: "172.16.0.2".to_string(),
            version: WARP_CLIENT_VERSION.to_string(),
            created_at: "2026-11-24T03:04:05Z".to_string(),
            ..WarpAccount::default()
        },
        WarpAccount {
            slot: 2,
            id: "id2".to_string(),
            token: "t2".to_string(),
            priv_key: "p2".to_string(),
            pub_key: "q2".to_string(),
            peer_key: WARP_PEER_PUB.to_string(),
            endpoint: "162.159.193.5".to_string(),
            port: 2408,
            tun_ip: "172.16.0.2".to_string(),
            version: "2026.3.846.0".to_string(),
            ..WarpAccount::default()
        },
    ]
}

#[test]
fn warp_store_round_trip() {
    let blob = render_warp_store(&store_accounts()).unwrap();
    let accounts = parse_warp_store(&blob).unwrap();
    assert_eq!(accounts.len(), 2);
    assert_eq!(accounts[0].id, "id1");
    assert_eq!(accounts[1].version, "2026.3.846.0");
    let value: serde_json::Value = serde_json::from_slice(&blob).unwrap();
    assert_eq!(value["version"].as_u64(), Some(WARP_STORE_VERSION as u64));
    assert!(value["accounts"].is_array());
    let text = String::from_utf8(blob).unwrap();
    assert!(text.contains("\"priv_key\": \"p1\""));
}

#[test]
fn warp_store_v2_preserves_pool_state_and_audit() {
    let mut accounts = store_accounts();
    accounts[0].pool_id = "pool-id1".into();
    accounts[0].state = WarpAccountState::Leased;
    accounts[0].lease_generation = 7;
    accounts[1].slot = 0;
    accounts[1].pool_id = "pool-id2".into();
    accounts[1].state = WarpAccountState::Ready;
    let audit = vec![WarpAuditEvent {
        at: "2026-11-28T00:00:00Z".into(),
        account_id: "pool-id1".into(),
        cloud_id: "id1".into(),
        slot: 1,
        lease_generation: 7,
        action: "lease".into(),
        result: "ok".into(),
        message: "assigned".into(),
    }];
    let blob = render_warp_store_with_audit(&accounts, &audit).unwrap();
    let (parsed, parsed_audit) = parse_warp_store_full(&blob).unwrap();
    assert_eq!(parsed[0].state, WarpAccountState::Leased);
    assert_eq!(parsed[0].lease_generation, 7);
    assert_eq!(parsed[1].state, WarpAccountState::Ready);
    assert_eq!(parsed_audit, audit);
}

#[test]
fn legacy_warp_store_migrates_slot_accounts_to_leased() {
    let blob = br#"{"version":1,"accounts":[{"slot":3,"id":"id","token":"t","priv_key":"p","pub_key":"q","peer_key":"k","endpoint":"1.2.3.4","port":2408,"tun_ip":"172.16.0.2","version":"v","created_at":"2026-11-28T00:00:00Z"}]}"#;
    let accounts = parse_warp_store(blob).unwrap();
    assert_eq!(accounts[0].state, WarpAccountState::Leased);
    assert!(!accounts[0].pool_id.is_empty());
}

#[test]
fn warp_store_drops_unusable_records() {
    let bad = r#"{"version":1,"accounts":[
      {"slot":1,"id":"id1","token":"t","priv_key":"","peer_key":"k","endpoint":"1.2.3.4"},
      {"slot":2,"id":"id2","token":"t","priv_key":"p","peer_key":"","endpoint":"1.2.3.4"},
      {"slot":3,"id":"id3","token":"t","priv_key":"p","peer_key":"k","endpoint":""},
      {"slot":4,"id":"id4","token":"t","priv_key":"p","peer_key":"k","endpoint":"1.2.3.4","port":0,"tun_ip":""}
    ]}"#;
    let accounts = parse_warp_store(bad.as_bytes()).unwrap();
    assert_eq!(accounts.len(), 1);
    assert_eq!(accounts[0].slot, 4);
    assert_eq!(accounts[0].port, WARP_PORT);
    assert_eq!(accounts[0].tun_ip, WARP_TUN_IP);
    assert!(parse_warp_store(b"{oops").is_err());
    assert!(render_warp_store(&[]).is_ok());
}

#[test]
fn warp_account_endpoint_is_ip_only() {
    let response = registration();
    let public_key = response.key.clone();
    let account = warp_account_of(
        2,
        &response,
        "p",
        &public_key,
        WARP_CLIENT_VERSION,
        Utc::now(),
    )
    .unwrap();
    assert!(!account.endpoint.contains(':'));
    assert!(account.endpoint.parse::<Ipv4Addr>().is_ok());
    assert!((1..=65535).contains(&account.port));
}

#[test]
fn wireguard_install_plan_per_distro() {
    type Have = fn(&str) -> bool;
    let cases: &[(&str, &str, &str, &str, Have)] = &[
        (
            "debian",
            "ID=debian\n",
            "deb",
            "apt-get install -y wireguard-tools",
            have_all_tools,
        ),
        (
            "ubuntu",
            "ID=ubuntu\nID_LIKE=debian\n",
            "deb",
            "apt-get install -y wireguard-tools",
            have_all_tools,
        ),
        (
            "centos7",
            "ID=centos\nID_LIKE=\"rhel centos fedora\"\n",
            "rpm",
            "yum -y install wireguard-tools",
            |name| name == "yum",
        ),
        (
            "rocky",
            "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n",
            "rpm",
            "dnf -y install wireguard-tools",
            have_all_tools,
        ),
        (
            "alpine",
            "ID=alpine\n",
            "alpine",
            "apk add --no-cache wireguard-tools",
            have_all_tools,
        ),
        (
            "arch",
            "ID=arch\n",
            "arch",
            "pacman -Sy --noconfirm --needed wireguard-tools",
            have_all_tools,
        ),
        (
            "suse",
            "ID=opensuse-leap\n",
            "suse",
            "zypper --non-interactive install -y wireguard-tools",
            have_all_tools,
        ),
    ];
    for &(name, os_release, wanted_family, wanted_last, have) in cases {
        let (steps, family) = wireguard_install_plan(os_release, have).unwrap();
        assert_eq!(family, wanted_family, "{name}");
        assert!(!steps.is_empty(), "{name}");
        assert_eq!(joined(steps.last().unwrap()), wanted_last, "{name}");
    }
}

#[test]
fn wireguard_install_plan_does_not_upgrade_everything() {
    for os_release in ["ID=debian\n", "ID=fedora\n", "ID=arch\n", "ID=alpine\n"] {
        let (steps, _) = wireguard_install_plan(os_release, have_all_tools).unwrap();
        for step in steps {
            let text = joined(&step);
            assert!(!text.contains(" upgrade "), "{os_release}: {text}");
            assert!(!text.contains(" full-upgrade"), "{os_release}: {text}");
            assert!(!text.ends_with(" update"), "{os_release}: {text}");
            assert!(!text.ends_with(" -Sy"), "{os_release}: {text}");
        }
    }
}

#[test]
fn wireguard_install_plan_missing_package_manager() {
    let error = wireguard_install_plan("ID=debian\n", |name| name == "curl").unwrap_err();
    assert_eq!(error.family, "deb");
    let message = error.to_string();
    assert!(message.contains("apt-get"));
    assert!(message.contains(WIREGUARD_PKG));
}

#[test]
fn wireguard_install_plan_unknown_distro() {
    let error =
        wireguard_install_plan("ID=openwrt\nNAME=\"OpenWrt\"\n", have_all_tools).unwrap_err();
    assert!(error.family.is_empty());
    assert!(error.to_string().contains("手动安装"));
}

#[test]
fn wireguard_install_hint_cases() {
    let cases = [
        (
            "rpm",
            "Error: Unable to find a match: wireguard-tools",
            "epel",
            "apt-get",
        ),
        (
            "deb",
            "E: Unable to locate package wireguard-tools",
            "apt-get update",
            "epel",
        ),
        (
            "deb",
            "E: Package 'wireguard-tools' has no installation candidate",
            "apt-get update",
            "",
        ),
        (
            "deb",
            "dpkg: error processing archive /var/cache/apt/archives/x.deb",
            "",
            "",
        ),
        ("rpm", "Segmentation fault (core dumped)", "", ""),
    ];
    for (family, output, wanted, denied) in cases {
        let hint = wireguard_install_hint(family, output);
        if wanted.is_empty() {
            assert!(hint.is_empty(), "{family}/{output} 不该提示");
        } else {
            assert!(
                hint.to_lowercase().contains(wanted),
                "{family}/{output}: {hint}"
            );
        }
        if !denied.is_empty() {
            assert!(!hint.contains(denied), "{family}/{output}: {hint}");
        }
    }
}

#[test]
fn wireguard_plan_uses_the_same_package_name() {
    for os_release in ["ID=debian\n", "ID=fedora\n", "ID=alpine\n"] {
        let (steps, _) = wireguard_install_plan(os_release, have_all_tools).unwrap();
        assert!(joined(steps.last().unwrap()).contains(WIREGUARD_PKG));
    }
}
