use std::{collections::BTreeSet, fs, path::Path, time::Duration};

use crate::{
    instance::{
        load_or_pick_net_base_with_used, lock_work_dir, parse_host_used_net_bases,
        pick_net_base_with_used, Instance, DEFAULT_NET_BASE, NET_BASE_MAX, NET_BASE_MIN,
    },
    netns::{
        force_ipv4_network, netns_direct_cmds, route_has_default, Netns, NetnsDirect, Network,
    },
    process::{openvpn_argv, ovpn_error_line, ovpn_tuning},
    util::{fnv1a32, path_string, short_hash},
};

fn flat(commands: Vec<Vec<String>>) -> String {
    commands
        .into_iter()
        .map(|command| command.join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(unix)]
#[test]
fn init_default_directory_keeps_legacy_identity() {
    for path in ["/var/lib/fanout", "/var/lib/fanout/"] {
        let instance = Instance::init(path).unwrap();
        assert_eq!(instance, Instance::legacy());
    }
}

#[test]
fn default_instance_keeps_legacy_names_and_subnet() {
    let instance = Instance::legacy();
    assert_eq!(instance.tag, "");
    assert_eq!(instance.net_base, DEFAULT_NET_BASE);

    let tunnel = Netns::new(instance, 3);
    assert_eq!(tunnel.name(), "fo3");
    assert_eq!(tunnel.subnet(), "10.99.3");
    assert_eq!(tunnel.subnet_cidr(), "10.99.3.0/30");
    assert_eq!(tunnel.gateway(), "10.99.3.1");
    assert_eq!(tunnel.veth(), "fov3");
    assert_eq!(tunnel.peer(), "fop3");
}

#[test]
fn custom_instance_names_include_the_workdir_identity() {
    let instance = Instance {
        tag: "a1b2".into(),
        net_base: 137,
    };
    for slot in [1, 3, 99] {
        let tunnel = Netns::new(instance.clone(), slot);
        assert_eq!(tunnel.name(), format!("foa1b2{slot}"));
        assert_eq!(tunnel.subnet(), format!("10.137.{slot}"));
        assert_eq!(tunnel.veth(), format!("fova1b2{slot}"));
        assert_eq!(tunnel.peer(), format!("fopa1b2{slot}"));
        assert!(tunnel.veth().len() <= 15);
        assert!(tunnel.peer().len() <= 15);
    }
}

#[test]
fn short_hash_is_four_stable_hex_characters() {
    let tag = short_hash("/opt/fanout-demo");
    assert_eq!(tag.len(), 4);
    assert_eq!(tag, short_hash("/opt/fanout-demo"));
    assert_ne!(tag, short_hash("/opt/fanout-other"));
    assert_eq!(tag, format!("{:04x}", fnv1a32("/opt/fanout-demo") & 0xffff));
}

#[test]
fn net_base_is_persisted_and_reused_even_if_host_later_uses_it() {
    let dir = tempfile::tempdir().unwrap();
    let abs = dir.path().join("instance");
    let used = BTreeSet::from([DEFAULT_NET_BASE]);

    let first = load_or_pick_net_base_with_used(dir.path(), &abs, used.clone()).unwrap();
    assert!((NET_BASE_MIN..=NET_BASE_MAX).contains(&first));
    assert_eq!(
        fs::read_to_string(dir.path().join("netbase")).unwrap(),
        format!("{first}\n")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(dir.path().join("netbase"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    let mut later_used = used;
    later_used.insert(first);
    let second = load_or_pick_net_base_with_used(dir.path(), &abs, later_used).unwrap();
    assert_eq!(second, first, "重启必须沿用已经落盘的网段");
}

#[test]
fn corrupt_netbase_is_replaced_with_a_free_base() {
    let dir = tempfile::tempdir().unwrap();
    let abs = Path::new("/opt/fanout-corrupt-netbase");
    let mut used: BTreeSet<u8> = (NET_BASE_MIN..=NET_BASE_MAX).collect();
    used.remove(&137);

    for junk in ["", "  ", "abc", "42", "999", "-1"] {
        fs::write(dir.path().join("netbase"), junk).unwrap();
        let picked = load_or_pick_net_base_with_used(dir.path(), abs, used.clone()).unwrap();
        assert_eq!(picked, 137);
        assert_eq!(
            fs::read_to_string(dir.path().join("netbase")).unwrap(),
            "137\n"
        );
    }
}

#[test]
fn net_base_picker_uses_hash_start_then_advances_and_reports_exhaustion() {
    let abs = Path::new("/opt/fanout-demo");
    let start = NET_BASE_MIN + (fnv1a32(&path_string(abs)) % 156) as u8;
    assert_eq!(
        pick_net_base_with_used(abs, &BTreeSet::from([DEFAULT_NET_BASE])).unwrap(),
        start
    );
    let next = if start == NET_BASE_MAX {
        NET_BASE_MIN
    } else {
        start + 1
    };
    assert_eq!(
        pick_net_base_with_used(abs, &BTreeSet::from([DEFAULT_NET_BASE, start])).unwrap(),
        next
    );

    let all_used: BTreeSet<u8> = (NET_BASE_MIN..=NET_BASE_MAX).collect();
    let error = pick_net_base_with_used(abs, &all_used).err().unwrap();
    assert!(error.to_string().contains("都被占用了"));
}

#[test]
fn two_workdirs_can_be_assigned_distinct_identities() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let abs_a = Path::new("/opt/fanout-instance-a");
    let abs_b = Path::new("/opt/fanout-instance-b");
    let mut used = BTreeSet::from([DEFAULT_NET_BASE]);

    let base_a = load_or_pick_net_base_with_used(a.path(), &abs_a, used.clone()).unwrap();
    used.insert(base_a);
    let base_b = load_or_pick_net_base_with_used(b.path(), &abs_b, used).unwrap();
    assert_ne!(base_a, base_b);

    let instance_a = Instance {
        tag: short_hash(&path_string(&abs_a)),
        net_base: base_a,
    };
    let instance_b = Instance {
        tag: short_hash(&path_string(&abs_b)),
        net_base: base_b,
    };
    assert_ne!(instance_a.ns_name(3), instance_b.ns_name(3));
    assert_ne!(instance_a.subnet(3), instance_b.subnet(3));
}

#[test]
fn host_used_base_parser_keeps_only_10_x_second_octets() {
    let output = "2: eth0    inet 10.8.0.2/24 brd 10.8.0.255 scope global eth0\n\
                      3: docker0 inet 10.255.1.1/16 scope global docker0\n\
                      4: eth1    inet 192.168.1.2/24 scope global eth1\n\
                      5: vpn0    inet fd00::1/128 scope global vpn0\n";
    assert_eq!(parse_host_used_net_bases(output), BTreeSet::from([8, 255]));
}

#[cfg(unix)]
#[test]
fn workdir_lock_rejects_a_second_owner_and_releases_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let first = lock_work_dir(dir.path()).unwrap();
    let error = lock_work_dir(dir.path()).err().unwrap();
    assert!(error.to_string().contains("另一个 fanout"));
    assert!(error.to_string().contains("-dir"));
    drop(first);
    let _again = lock_work_dir(dir.path()).unwrap();
}

#[test]
fn direct_routes_are_exact_ipv4_pins_without_a_default() {
    let commands = netns_direct_cmds(NetnsDirect {
        gw: "10.99.12.1".into(),
        dev: "fop12".into(),
        ips: vec![
            "61.215.116.134".into(),
            "8.8.8.8".into(),
            "219.100.37.198".into(),
        ],
    });
    assert_eq!(commands.len(), 3);
    for command in &commands {
        assert_eq!(command[0], "ip");
        assert_eq!(command[1], "route");
        assert_eq!(command[2], "replace");
        assert!(command[3].ends_with("/32"));
        assert_eq!(command[4], "via");
        assert_eq!(command[5], "10.99.12.1");
        assert_eq!(command[6], "dev");
        assert_eq!(command[7], "fop12");
        assert!(!command.join(" ").contains("default"));
        assert!(!command
            .join(" ")
            .chars()
            .any(|ch| matches!(ch, '&' | '|' | ';' | '$' | '`')));
    }
}

#[test]
fn direct_route_shape_and_order_are_stable() {
    let command = netns_direct_cmds(NetnsDirect {
        gw: "10.0.0.1".into(),
        dev: "fop1".into(),
        ips: vec!["1.2.3.4".into()],
    });
    assert_eq!(
        flat(command),
        "ip route replace 1.2.3.4/32 via 10.0.0.1 dev fop1"
    );

    let first = flat(netns_direct_cmds(NetnsDirect {
        gw: "10.0.0.1".into(),
        dev: "fop1".into(),
        ips: vec!["9.9.9.9".into(), "1.1.1.1".into(), "9.9.9.9".into()],
    }));
    let second = flat(netns_direct_cmds(NetnsDirect {
        gw: "10.0.0.1".into(),
        dev: "fop1".into(),
        ips: vec!["1.1.1.1".into(), "9.9.9.9".into()],
    }));
    assert_eq!(first, second);
    assert!(first.starts_with("ip route replace 1.1.1.1/32"));

    let mapped = flat(netns_direct_cmds(NetnsDirect {
        gw: "10.0.0.1".into(),
        dev: "fop1".into(),
        ips: vec!["::ffff:8.8.8.8".into()],
    }));
    assert_eq!(mapped, "ip route replace 8.8.8.8/32 via 10.0.0.1 dev fop1");
}

#[test]
fn direct_routes_reject_v6_hostnames_and_missing_link_data() {
    let cases = [
        (
            NetnsDirect {
                gw: "10.0.0.1".into(),
                dev: "fop1".into(),
                ips: vec!["fd00::1".into()],
            },
            0,
        ),
        (
            NetnsDirect {
                gw: "10.0.0.1".into(),
                dev: "fop1".into(),
                ips: vec!["vpn.example.com".into()],
            },
            0,
        ),
        (
            NetnsDirect {
                gw: "10.0.0.1".into(),
                dev: "fop1".into(),
                ips: vec!["".into(), "  ".into()],
            },
            0,
        ),
        (
            NetnsDirect {
                gw: "10.0.0.1".into(),
                dev: "fop1".into(),
                ips: vec!["8.8.8.8".into(), "fd00::1".into(), "1.1.1.1".into()],
            },
            2,
        ),
        (
            NetnsDirect {
                gw: "10.0.0.1".into(),
                dev: "fop1".into(),
                ips: vec!["::ffff:8.8.8.8".into()],
            },
            1,
        ),
        (
            NetnsDirect {
                gw: String::new(),
                dev: "fop1".into(),
                ips: vec!["8.8.8.8".into()],
            },
            0,
        ),
        (
            NetnsDirect {
                gw: "10.0.0.1".into(),
                dev: String::new(),
                ips: vec!["8.8.8.8".into()],
            },
            0,
        ),
        (
            NetnsDirect {
                gw: "10.0.0.1".into(),
                dev: "fop1".into(),
                ips: vec![],
            },
            0,
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(netns_direct_cmds(input).len(), expected);
    }
}

#[test]
fn default_route_detection_requires_a_route_line() {
    for output in [
        "default via 10.99.12.1 dev fop1 \n",
        "default dev tun0 table main proto kernel scope link src 10.8.0.6 \n",
        "default via 10.0.0.1 dev eth0 metric 100\ndefault via 10.0.0.2 dev eth1\n",
        "  default   dev   fow1  \n",
    ] {
        assert!(route_has_default(output), "漏掉默认路由: {output:?}");
    }
    for output in [
        "",
        "\n\n",
        "10.8.0.0/24 dev tun0 proto kernel scope link src 10.8.0.6 \n",
        "Error: can't open route for source fd00::1.\n",
        "default",
        "notdefault via 1.1.1.1 dev eth0\n",
    ] {
        assert!(!route_has_default(output), "误判默认路由: {output:?}");
    }
}

#[test]
fn generic_network_names_are_forced_to_ipv4() {
    assert_eq!(force_ipv4_network("tcp"), "tcp4");
    assert_eq!(force_ipv4_network("udp"), "udp4");
    assert_eq!(force_ipv4_network("tcp4"), "tcp4");
    assert_eq!(force_ipv4_network("udp6"), "udp6");
    assert_eq!(Network::parse("tcp").unwrap(), Network::Tcp);
    assert_eq!(Network::parse("udp4").unwrap(), Network::Udp);
    assert!(Network::parse("tcp6").is_err());
    assert!(Network::parse("udp6").is_err());
}

#[test]
fn openvpn_process_helpers_keep_command_and_failure_shape() {
    let args = vec!["--config".into(), "/tmp/fo1.ovpn".into()];
    assert_eq!(
        openvpn_argv("fo1", "/usr/sbin/openvpn", &args),
        [
            "ip",
            "netns",
            "exec",
            "fo1",
            "/usr/sbin/openvpn",
            "--config",
            "/tmp/fo1.ovpn"
        ]
        .into_iter()
        .map(String::from)
        .collect::<Vec<_>>()
    );

    let short = ovpn_tuning(Duration::from_secs(3), 1360);
    assert!(short
        .windows(2)
        .any(|pair| pair[0] == "--hand-window" && pair[1] == "5"));
    let clamped = ovpn_tuning(Duration::from_secs(300), 1320);
    assert!(clamped
        .windows(2)
        .any(|pair| pair[0] == "--hand-window" && pair[1] == "20"));
    assert!(clamped
        .windows(2)
        .any(|pair| pair[0] == "--mssfix" && pair[1] == "1320"));

    let hint = ovpn_error_line(
        "Connection timed out with 1.1.1.1:1194\nAUTH_FAILED: [none] with 2.2.2.2:443\n",
    );
    assert!(hint.starts_with("节点拒绝了用户名/密码："));
    assert!(!hint.contains("1.1.1.1"));
    let own_fault = ovpn_error_line(
        "write UDP: message too long\nConnection timed out: retrying with next remote\n",
    );
    assert!(own_fault.starts_with("外层包超过链路 MTU："));
}
