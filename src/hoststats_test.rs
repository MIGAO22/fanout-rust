use super::*;
use crate::models::HostStats;
use crate::publicip::{
    is_ipv4_or_mapped, probe_sources, resolve_public_ip, PublicIPState, IP_ORACLES,
    PUBLIC_IP_SOURCES, PUBLIC_IP_TTL,
};
use std::time::Duration;

fn close(got: f64, want: f64) -> bool {
    (got - want).abs() <= 0.01
}

fn devs(entries: &[(&str, u64, u64)]) -> NetDevMap {
    entries
        .iter()
        .map(|(name, rx, tx)| ((*name).to_string(), [*rx, *tx]))
        .collect()
}

#[test]
fn parse_cpu_times_and_pct() {
    let prev = parse_cpu_times(b"cpu  100 10 50 800 40 0 10 0 5 5\nintr 1\n").unwrap();
    assert_eq!(prev.total, 1010, "guest columns must not be counted twice");
    assert_eq!(prev.idle, 840, "idle must include iowait");

    let cur = parse_cpu_times(b"cpu  200 10 100 880 60 0 10 0 5 5\n").unwrap();
    assert!(close(cpu_pct(prev, cur), 60.0));
}

#[test]
fn parse_cpu_times_rejects_junk() {
    for bad in ["", "intr 1\ntxt 2\n", "cpu 1 2 3\n", "cpu a b c d e\n"] {
        assert!(parse_cpu_times(bad.as_bytes()).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn cpu_pct_clamps_and_handles_zero_window() {
    let same = CpuTimes {
        idle: 10,
        total: 10,
    };
    assert_eq!(cpu_pct(same, same), 0.0);
    assert_eq!(
        cpu_pct(
            CpuTimes {
                idle: 500,
                total: 900
            },
            CpuTimes {
                idle: 100,
                total: 400
            },
        ),
        0.0
    );
    assert_eq!(
        cpu_pct(
            CpuTimes { idle: 0, total: 10 },
            CpuTimes { idle: 0, total: 20 },
        ),
        100.0
    );
}

#[test]
fn parse_meminfo_uses_available() {
    let blob = b"MemTotal:       16384000 kB\nMemFree:          204800 kB\nMemAvailable:    8192000 kB\nBuffers:          100000 kB\nSwapTotal:       4096000 kB\nSwapFree:        3072000 kB\n";
    let (total, avail, swap_total, swap_free) = parse_meminfo(blob);
    assert_eq!((total, avail), (16_384_000, 8_192_000));
    assert_eq!((swap_total, swap_free), (4_096_000, 3_072_000));
    assert!(close(pct_of(total - avail, total), 50.0));
}

#[test]
fn parse_meminfo_falls_back_to_mem_free() {
    let (total, avail, swap_total, _) =
        parse_meminfo(b"MemTotal: 1000 kB\nMemFree: 250 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n");
    assert_eq!((total, avail, swap_total), (1000, 250, 0));
}

#[test]
fn parse_sockstat_kernel_and_legacy_spellings() {
    let current = b"sockets: used 512\nTCP: inuse 20 orphan 0 tw 128 alloc 150 mem 34\nUDP: inuse 9 memory 4\nUDPLITE: inuse 0\nRAW: inuse 0\nFRAG: inuse 0 memory 0\n";
    assert_eq!(parse_sockstat(current), (148, 9));
    assert_eq!(
        parse_sockstat(b"TCP: in use 37 orphaned 0 tw 128\nUDP: in use 9\n"),
        (165, 9)
    );
    assert_eq!(parse_sockstat(b"TCP: inuse 4\n"), (4, 0));
}

#[test]
fn parse_sockstat_ipv6_and_sum_both_tables() {
    let v4 = b"TCP: inuse 37 orphan 0 tw 128 mem 5\nUDP: inuse 2 mem 2\n";
    let v6 = b"TCP6: inuse 8\nUDP6: inuse 6\nUDPLITE6: inuse 0\nRAW6: inuse 0\nFRAG6: inuse 0 memory 0\n";
    let (tcp4, udp4) = parse_sockstat(v4);
    let (tcp6, udp6) = parse_sockstat(v6);
    assert_eq!((tcp4, udp4, tcp6, udp6), (165, 2, 8, 6));
    assert_eq!(tcp4 + tcp6, 173);
    assert_eq!(udp4 + udp6, 8);
}

#[test]
fn parse_loadavg_fixture_and_short_input() {
    let (l1, l5, l15) = parse_loadavg(b"0.52 0.41 0.30 3/214 8891\n").unwrap();
    assert_eq!((l1, l5, l15), (0.52, 0.41, 0.30));
    assert!(parse_loadavg(b"0.52 0.41\n").is_err());
}

#[test]
fn parse_port_range_fixture_and_bad_ranges() {
    assert_eq!(parse_port_range(b"32768\t60999\n"), 28_232);
    for bad in ["", "32768", "b a\n", "60999 32768\n"] {
        assert_eq!(parse_port_range(bad.as_bytes()), 0, "accepted {bad:?}");
    }
}

#[test]
fn percentages_guard_zero_and_clamp() {
    assert_eq!(pct_of(5, 0), 0.0);
    assert_eq!(pct_of_counts(5, 0), 0.0);
    assert!(close(pct_of(3, 4), 75.0));
    assert!(close(pct_of_counts(3, 4), 75.0));
    assert_eq!(clamp_pct(-1.0), 0.0);
    assert_eq!(clamp_pct(140.0), 100.0);
    assert_eq!(rate_pct(12345.0, 0.0), 0.0);
    assert!(close(rate_pct(100.0 * 1000.0 * 1000.0, 1000.0), 80.0));
}

#[test]
fn parse_net_dev_fixture() {
    let blob = b"Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n    lo: 1048576    9012    0    0    0     0          0         0  1048576    9012    0    0    0     0       0          0\n  eth0: 524288000  400000    0    0    0     0          0         0 262144000  300000    0    0    0     0       0          0\n";
    let got = parse_net_dev(blob);
    assert_eq!(got.len(), 2);
    assert_eq!(got["eth0"], [524_288_000, 262_144_000]);
    assert_eq!(got["lo"], [1_048_576, 1_048_576]);
}

#[test]
fn parse_net_dev_skips_malformed_lines() {
    let got = parse_net_dev(b"eth0: 1 2\neth1: nope 0 0 0 0 0 0 0 10\neth2: 7 0 0 0 0 0 0 0 9\n");
    assert_eq!(got.len(), 1);
    assert_eq!(got["eth2"], [7, 9]);
}

#[test]
fn parse_default_ifaces_sorts_and_deduplicates() {
    let blob = b"Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\neth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\nwg0\t00000000\tFEA9B60A\t0003\t0\t0\t50\t00000000\t0\t0\t0\neth0\t00000000\tFEA9B60A\t0003\t0\t0\t50\t00000000\t0\t0\t0\n";
    assert_eq!(parse_default_ifaces(blob), ["eth0", "wg0"]);
    assert!(parse_default_ifaces(b"").is_empty());
}

#[test]
fn fallback_ifaces_skips_virtual_interfaces() {
    let got = fallback_ifaces(&devs(&[
        ("lo", 0, 0),
        ("eth0", 0, 0),
        ("docker0", 0, 0),
        ("veth1a2b3c", 0, 0),
        ("br-9f8e7d", 0, 0),
        ("virbr0", 0, 0),
        ("tun0", 0, 0),
    ]));
    assert_eq!(got, ["eth0", "tun0"]);
}

#[test]
fn link_speed_fixture_and_missing_speed() {
    let ifaces = ["eth0".to_string(), "eth1".to_string(), "tun0".to_string()];
    let total = link_mbps_from(&ifaces, |name| match name {
        "eth0" => Some(b"1000\n".to_vec()),
        "eth1" => Some(b"-1\n".to_vec()),
        "tun0" => Some(b"0\n".to_vec()),
        _ => None,
    });
    assert_eq!(total, 1000.0);
    assert_eq!(
        link_mbps(&["iface-that-does-not-exist-xyz".to_string()]),
        0.0
    );
    assert_eq!(parse_link_speed(b"not a speed\n"), 0);
}

#[test]
fn net_rates_first_window_is_not_ready() {
    let now = Instant::now();
    let mut sample = NetCounters::default();
    let (up, down, ready) = net_rates_at(
        devs(&[("eth0", 100, 40)]),
        &["eth0".into()],
        now,
        &mut sample,
    );
    assert_eq!((up, down, ready), (0.0, 0.0, false));
}

#[test]
fn net_rates_uses_byte_deltas_and_skips_new_or_reset_interfaces() {
    let now = Instant::now();
    let mut sample = NetCounters {
        at: Some(now),
        devs: devs(&[("eth0", 0, 0)]),
        has: true,
        ..NetCounters::default()
    };
    let names = ["eth0".to_string(), "wg0".to_string()];
    let (up, down, ready) = net_rates_at(
        devs(&[("eth0", 500, 250), ("wg0", 9_000_000_000, 9_000_000_000)]),
        &names,
        now + Duration::from_secs(1),
        &mut sample,
    );
    assert!(ready);
    assert_eq!(up, 250.0);
    assert_eq!(down, 500.0);

    sample.at = Some(now);
    sample.devs = devs(&[("eth0", 1_000_000, 1_000_000)]);
    let (up, down, ready) = net_rates_at(
        devs(&[("eth0", 10, 10)]),
        &["eth0".into()],
        now + Duration::from_secs(1),
        &mut sample,
    );
    assert!(ready);
    assert_eq!((up, down), (0.0, 0.0));
}

#[test]
fn net_rates_short_window_keeps_previous_values() {
    let now = Instant::now();
    let mut sample = NetCounters {
        at: Some(now),
        devs: devs(&[("eth0", 0, 0)]),
        has: true,
        up: 111.0,
        down: 222.0,
        ready: true,
    };
    let got = net_rates_at(
        devs(&[("eth0", 1 << 30, 1 << 30)]),
        &["eth0".into()],
        now + Duration::from_millis(5),
        &mut sample,
    );
    assert_eq!(got, (111.0, 222.0, true));
    assert_eq!(sample.devs["eth0"], [1 << 30, 1 << 30]);
}

#[test]
fn disk_stat_matches_df_semantics() {
    const FRSIZE: i64 = 4096;
    let blocks = |gib: i64| gib * 1024 * 1024 * 1024 / FRSIZE;
    let (used, total, pct) = disk_stat(blocks(100), blocks(40), blocks(35), FRSIZE);
    assert_eq!(used, 60 * 1024 * 1024 * 1024);
    assert_eq!(total, 100 * 1024 * 1024 * 1024);
    assert!(close(pct, 100.0 * 60.0 / 95.0));
}

#[test]
fn disk_stat_guards_bad_counts() {
    assert_eq!(disk_stat(0, 0, 0, 4096), (0, 0, 0.0));
    assert_eq!(disk_stat(100, 40, 40, 0), (0, 0, 0.0));
    assert_eq!(disk_stat(100, 120, 100, 1024), (0, 102_400, 0.0));
    assert_eq!(disk_stat(100, 0, 0, 4096).2, 100.0);
}

#[cfg(unix)]
#[test]
fn read_disk_usage_falls_back_to_root() {
    let (used, total, pct, mount) =
        read_disk_usage(&[Path::new("/definitely-not-a-mount-point"), Path::new("/")]).unwrap();
    assert_eq!(mount, "/");
    assert!(total > 0 && used <= total);
    assert!((0.0..=100.0).contains(&pct));
    assert!(read_disk_usage(&[Path::new("")]).is_err());
}

#[cfg(not(unix))]
#[test]
fn read_disk_usage_has_a_compiling_windows_fallback() {
    assert!(read_disk_usage(&[Path::new(".")]).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn host_stats_reads_real_proc_and_serializes_exact_shape() {
    let dir = tempfile::tempdir().unwrap();
    let st = read_host_stats(dir.path()).unwrap();
    assert!(st.mem_total > 0);
    assert!(st.mem_used <= st.mem_total);
    assert!(st.cores > 0);
    assert!(!st.disk_mount.is_empty());
    for pct in [
        st.cpu,
        st.mem_pct,
        st.swap_pct,
        st.disk_pct,
        st.load_pct,
        st.tcp_pct,
        st.udp_pct,
        st.up_pct,
        st.down_pct,
    ] {
        assert!(pct.is_finite() && (0.0..=100.0).contains(&pct), "{pct}");
    }

    let value = serde_json::to_value(HostStats::default()).unwrap();
    let expected = [
        "cpu",
        "mem_pct",
        "mem_used",
        "mem_total",
        "swap_pct",
        "swap_used",
        "swap_total",
        "disk_pct",
        "disk_used",
        "disk_total",
        "disk_mount",
        "load1",
        "load5",
        "load15",
        "cores",
        "load_pct",
        "tcp",
        "tcp_pct",
        "udp",
        "udp_pct",
        "tcp6",
        "udp6",
        "sock_cap",
        "up_bps",
        "down_bps",
        "up_pct",
        "down_pct",
        "net_ready",
        "net_if",
        "link_mbps",
    ];
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), expected.len());
    for key in expected {
        assert!(object.contains_key(key), "missing JSON field {key}");
    }
}

#[test]
fn public_ip_source_lists_match_go() {
    assert_eq!(
        PUBLIC_IP_SOURCES,
        [
            "https://api.ipify.org",
            "https://ipv4.icanhazip.com",
            "https://ifconfig.me/ip"
        ]
    );
    assert_eq!(
        IP_ORACLES,
        [
            "http://api.ipify.org",
            "http://ipv4.icanhazip.com",
            "http://4.ident.me",
            "http://ifconfig.me/ip",
            "http://ipecho.net/plain",
        ]
    );
}

#[test]
fn public_ip_validation_matches_parse_ip_to4() {
    assert!(is_ipv4_or_mapped("203.0.113.9"));
    assert!(is_ipv4_or_mapped("::ffff:203.0.113.9"));
    for bad in [
        "",
        "not-an-ip",
        "203.0.113.999",
        "2001:db8::1",
        "127.0.0.1 extra",
    ] {
        assert!(!is_ipv4_or_mapped(bad), "accepted {bad:?}");
    }
}

#[test]
fn public_ip_probe_uses_first_valid_source() {
    let sources = ["one", "two", "three"].map(str::to_string);
    let mut seen = Vec::new();
    let got = probe_sources(sources, |source| {
        seen.push(source.to_string());
        match source {
            "one" => Some("server error\n".to_string()),
            "two" => Some("  198.51.100.4\n".to_string()),
            _ => panic!("must stop after the first valid IPv4"),
        }
    });
    assert_eq!(got, "198.51.100.4");
    assert_eq!(seen, ["one", "two"]);
}

#[test]
fn public_ip_override_beats_cache_and_probe() {
    let now = Instant::now();
    let mutex = Mutex::new(PublicIPState {
        override_ip: "198.51.100.1".to_string(),
        cache: "198.51.100.2".to_string(),
        at: Some(now),
    });
    let got = resolve_public_ip(&mutex, || panic!("override must not probe"), now);
    assert_eq!(got, "198.51.100.1");

    let mut state = PublicIPState::default();
    state.set_override("  198.51.100.3\n");
    assert_eq!(state.override_ip, "198.51.100.3");
    state.set_override(" \t");
    assert!(state.override_ip.is_empty());
}

#[test]
fn public_ip_fresh_cache_avoids_probe() {
    let now = Instant::now();
    let mutex = Mutex::new(PublicIPState {
        cache: "198.51.100.2".to_string(),
        at: Some(now - Duration::from_secs(60)),
        ..PublicIPState::default()
    });
    let got = resolve_public_ip(&mutex, || panic!("fresh cache must not probe"), now);
    assert_eq!(got, "198.51.100.2");
}

#[test]
fn public_ip_expired_cache_refreshes_or_falls_back_to_stale() {
    let now = Instant::now();
    let mutex = Mutex::new(PublicIPState {
        cache: "198.51.100.2".to_string(),
        at: Some(now - PUBLIC_IP_TTL - Duration::from_secs(1)),
        ..PublicIPState::default()
    });
    let got = resolve_public_ip(&mutex, || "198.51.100.5".to_string(), now);
    assert_eq!(got, "198.51.100.5");
    assert_eq!(lock_unpoisoned(&mutex).cache, "198.51.100.5");

    let mutex = Mutex::new(PublicIPState {
        cache: "198.51.100.2".to_string(),
        at: Some(now - PUBLIC_IP_TTL - Duration::from_secs(1)),
        ..PublicIPState::default()
    });
    let got = resolve_public_ip(&mutex, String::new, now);
    assert_eq!(got, "198.51.100.2");
}

#[test]
fn public_ip_failed_probe_without_cache_is_empty() {
    let mutex = Mutex::new(PublicIPState::default());
    assert_eq!(resolve_public_ip(&mutex, String::new, Instant::now()), "");
}
