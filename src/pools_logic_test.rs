use super::*;
use crate::models::{Node, SocksCred};
use chrono::TimeZone;
use std::fs;
use std::time::Duration;

fn test_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 23, 10, 0, 0)
        .single()
        .unwrap()
}

fn up_member(host: &str, latency: Duration) -> PoolMember {
    PoolMember {
        host: host.to_string(),
        namespace: format!("fo-{host}"),
        up: true,
        status: "up".to_string(),
        latency,
        ..PoolMember::default()
    }
}

fn first_host(choice: &PoolChoice) -> &str {
    assert!(!choice.order.is_empty(), "选路结果为空");
    choice.order[0].host.as_str()
}

fn hosts(members: &[PoolMember]) -> Vec<String> {
    members.iter().map(|member| member.host.clone()).collect()
}

fn autofill_pool(size: usize, hosts: &[&str]) -> Pool {
    Pool {
        id: "p1".to_string(),
        name: "补位组".to_string(),
        mode: POOL_MODE_SINGLE.to_string(),
        hosts: hosts.iter().map(|host| host.to_string()).collect(),
        rr_step: 5,
        auto_fill: true,
        size,
        ..Pool::default()
    }
}

fn tunnel(host: &str, status: &str) -> TunnelState {
    TunnelState {
        slot: 3,
        node: Node {
            hostname: host.to_string(),
            ..Node::default()
        },
        status: status.to_string(),
        ..TunnelState::default()
    }
}

#[test]
fn single_is_sticky_and_degrades_in_order() {
    let mut policy = PoolPolicy::new(POOL_MODE_SINGLE, 5);
    let members = [
        up_member("a", Duration::ZERO),
        up_member("b", Duration::ZERO),
        up_member("c", Duration::ZERO),
    ];
    for index in 0..4 {
        let choice = policy.pick(&format!("t{index}"), &members);
        assert_eq!(first_host(&choice), "a");
        assert!(!choice.concurrent);
        assert_eq!(hosts(&choice.order), ["a", "b", "c"]);
    }

    let mut down = members;
    down[0].up = false;
    assert_eq!(first_host(&policy.pick("t9", &down)), "b");
    assert_eq!(first_host(&policy.pick("t10", &down)), "b");
}

#[test]
fn round_robin_uses_steps_and_wraps() {
    let mut policy = PoolPolicy::new(POOL_MODE_ROUND_ROBIN, 5);
    let members = [
        up_member("a", Duration::ZERO),
        up_member("b", Duration::ZERO),
        up_member("c", Duration::ZERO),
    ];
    for index in 0..5 {
        assert_eq!(
            first_host(&policy.pick(&format!("site-{index}"), &members)),
            "a"
        );
    }
    for index in 5..10 {
        assert_eq!(
            first_host(&policy.pick(&format!("site-{index}"), &members)),
            "b"
        );
    }
    assert_eq!(first_host(&policy.pick("site-10", &members)), "c");
    for index in 11..15 {
        policy.pick(&format!("site-{index}"), &members);
    }
    assert_eq!(first_host(&policy.pick("site-15", &members)), "a");
}

#[test]
fn affinity_keeps_targets_stable_for_round_robin_and_balance() {
    for mode in [POOL_MODE_ROUND_ROBIN, POOL_MODE_BALANCE, POOL_MODE_LATENCY] {
        let mut policy = PoolPolicy::new(mode, 1);
        let members = [
            up_member("a", Duration::ZERO),
            up_member("b", Duration::ZERO),
        ];
        let first = first_host(&policy.pick("example.com", &members)).to_string();
        for _ in 0..6 {
            policy.pick("other.com", &members);
            assert_eq!(first_host(&policy.pick("example.com", &members)), first);
        }
    }
}

#[test]
fn balance_switches_only_when_the_sticky_exit_is_much_slower() {
    let mut policy = PoolPolicy::new(POOL_MODE_BALANCE, 1);
    let slow = up_member("slow", Duration::from_secs(2));
    let fast = up_member("fast", Duration::from_millis(50));
    assert_eq!(
        first_host(&policy.pick("t0", std::slice::from_ref(&slow))),
        "slow"
    );
    assert_eq!(first_host(&policy.pick("t0", &[slow, fast])), "fast");

    let mut policy = PoolPolicy::new(POOL_MODE_BALANCE, 1);
    let a = up_member("a", Duration::from_millis(100));
    let b = up_member("b", Duration::from_millis(40));
    assert_eq!(
        first_host(&policy.pick("t0", std::slice::from_ref(&a))),
        "a"
    );
    assert_eq!(first_host(&policy.pick("t0", &[a, b])), "a");
}

#[test]
fn balance_probes_unknown_samples_first() {
    let mut policy = PoolPolicy::new(POOL_MODE_BALANCE, 1);
    let known = up_member("known", Duration::from_millis(80));
    let fresh = up_member("fresh", Duration::ZERO);
    assert_eq!(first_host(&policy.pick("t0", &[known, fresh])), "fresh");
}

#[test]
fn concurrent_races_all_healthy_members() {
    for mode in [POOL_MODE_CONCURRENT, POOL_MODE_RACE] {
        let mut policy = PoolPolicy::new(mode, 5);
        let members = [
            up_member("a", Duration::ZERO),
            up_member("b", Duration::ZERO),
            PoolMember {
                host: "c".to_string(),
                ..PoolMember::default()
            },
        ];
        let choice = policy.pick("t0", &members);
        assert!(choice.concurrent);
        assert_eq!(hosts(&choice.order), ["a", "b"]);
    }
}

#[test]
fn cooling_members_are_last_but_never_permanently_excluded() {
    let mut policy = PoolPolicy::new(POOL_MODE_SINGLE, 5);
    let cooling = PoolMember {
        cooling: true,
        ..up_member("a", Duration::ZERO)
    };
    let fresh = up_member("b", Duration::ZERO);
    let choice = policy.pick("t0", &[cooling.clone(), fresh]);
    assert_eq!(first_host(&choice), "b");
    assert_eq!(hosts(&choice.order), ["b", "a"]);
    assert_eq!(
        first_host(&policy.pick("t1", std::slice::from_ref(&cooling))),
        "a"
    );
}

#[test]
fn no_up_member_returns_an_empty_choice() {
    let mut policy = PoolPolicy::new(POOL_MODE_SINGLE, 5);
    let choice = policy.pick(
        "t0",
        &[
            PoolMember {
                host: "a".to_string(),
                ..PoolMember::default()
            },
            PoolMember {
                host: "b".to_string(),
                ..PoolMember::default()
            },
        ],
    );
    assert!(choice.order.is_empty());
    assert!(!choice.concurrent);
}

#[test]
fn forgetting_a_member_clears_only_its_affinity() {
    let mut policy = PoolPolicy::new(POOL_MODE_ROUND_ROBIN, 1);
    let members = [
        up_member("a", Duration::ZERO),
        up_member("b", Duration::ZERO),
    ];
    policy.pick("t0", &members);
    policy.pick("t1", &members);
    policy.forget_member("a");
    assert!(!policy.affinity().values().any(|host| host == "a"));
    assert_eq!(policy.affinity().get("t1").map(String::as_str), Some("b"));
    assert!(policy
        .affinity_order()
        .iter()
        .all(|target| policy.affinity().contains_key(target)));
}

#[test]
fn affinity_is_fifo_capped() {
    let mut policy = PoolPolicy::new(POOL_MODE_ROUND_ROBIN, 1);
    let members = [
        up_member("a", Duration::ZERO),
        up_member("b", Duration::ZERO),
    ];
    for index in 0..POOL_AFFINITY_MAX + 500 {
        policy.pick(&format!("t{index}"), &members);
    }
    assert!(policy.affinity().len() <= POOL_AFFINITY_MAX);
    assert_eq!(policy.affinity_order().len(), policy.affinity().len());
    assert!(policy
        .affinity()
        .contains_key(&format!("t{}", POOL_AFFINITY_MAX + 499)));
    assert!(!policy.affinity().contains_key("t0"));
}

#[test]
fn policy_reconfiguration_keeps_affinity_but_resets_other_state() {
    let mut policy = PoolPolicy::new(POOL_MODE_ROUND_ROBIN, 1);
    let members = [
        up_member("a", Duration::ZERO),
        up_member("b", Duration::ZERO),
    ];
    policy.pick("t0", &members);
    assert_eq!(policy.affinity().get("t0").map(String::as_str), Some("a"));
    policy.reconfigure(POOL_MODE_SINGLE, 0);
    assert_eq!(policy.step, POOL_DEFAULT_RR_STEP);
    assert!(policy.current_host().is_empty());
    assert_eq!(policy.affinity().get("t0").map(String::as_str), Some("a"));
    assert_eq!(first_host(&policy.pick("new-target", &members)), "a");
    assert_eq!(policy.current_host(), "a");
}

#[test]
fn target_key_handles_hosts_ports_and_ipv6_without_resolution() {
    for (input, expected) in [
        ("93.184.216.34:443", "93.184.216.34"),
        ("example.com:8080", "example.com"),
        ("no-port", "no-port"),
        ("[::1]:443", "::1"),
        ("::1", "::1"),
        ("[::1]", "[::1]"),
        ("host:not-a-port", "host"),
        (":443", ""),
    ] {
        assert_eq!(target_key(input), expected, "target_key({input})");
    }
}

#[test]
fn identity_round_trip_and_sequence_parsing() {
    let pool = Pool {
        id: "p7".to_string(),
        ..Pool::default()
    };
    assert_eq!(pool.identity(), "pool-p7");
    assert_eq!(pool_identity_to_id(&pool.identity()).as_deref(), Some("p7"));
    assert_eq!(pool_identity_to_id("vpn-gate.example.jp"), None);
    assert_eq!(pool_identity_to_id("pool-"), None);
    for (id, sequence) in [("p12", 12), ("p001", 1), ("p", 0), ("x12", 0), ("p-1", 0)] {
        assert_eq!(parse_pool_seq(id), sequence);
    }
}

#[test]
fn pool_normalization_and_validation_match_go() {
    let mut pool = Pool {
        id: "p1".to_string(),
        mode: "nonsense".to_string(),
        rr_step: 0,
        hosts: vec!["a".into(), " a ".into(), "".into(), "b".into(), "a".into()],
        ..Pool::default()
    };
    pool.normalize();
    assert_eq!(pool.mode, POOL_MODE_SINGLE);
    assert_eq!(pool.rr_step, POOL_DEFAULT_RR_STEP);
    assert_eq!(pool.hosts, ["a", "b"]);
    assert_eq!(pool.name, "出口组 p1");
    assert!(Pool {
        id: "p2".to_string(),
        ..Pool::default()
    }
    .validate()
    .is_err());

    let mut too_many = Pool {
        hosts: (0..33).map(|index| format!("h{index}")).collect(),
        ..Pool::default()
    };
    too_many.normalize();
    assert!(too_many.validate().is_err());

    let mut long_name = Pool {
        name: "名".repeat(22),
        hosts: vec!["a".into()],
        ..Pool::default()
    };
    long_name.normalize();
    assert!(long_name.validate().is_err());
}

#[test]
fn pool_normalization_clamps_steps_size_and_pins_autofill_target() {
    let mut pool = Pool {
        id: "p1".to_string(),
        mode: POOL_MODE_LATENCY.to_string(),
        rr_step: POOL_MAX_RR_STEP + 1,
        hosts: vec![" a ".into(), "b".into()],
        auto_fill: true,
        size: 0,
        ..Pool::default()
    };
    pool.normalize();
    assert_eq!(pool.mode, POOL_MODE_LATENCY);
    assert_eq!(pool.rr_step, POOL_MAX_RR_STEP);
    assert_eq!(pool.size, 2);

    pool.size = POOL_MAX_SIZE + 10;
    pool.normalize();
    assert_eq!(pool.size, POOL_MAX_SIZE);
}

#[test]
fn pool_store_round_trip_preserves_json_and_sequences() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = PoolStore::new();
    store.pools.push(Pool {
        id: "p1".to_string(),
        name: "日本组".to_string(),
        mode: POOL_MODE_BALANCE.to_string(),
        rr_step: 5,
        hosts: vec!["a".into(), "b".into()],
        cred: SocksCred {
            user: "u".into(),
            pass: "p".into(),
        },
        ..Pool::default()
    });
    store.save(dir.path()).unwrap();

    let raw: serde_json::Value =
        serde_json::from_slice(&fs::read(pool_state_path(dir.path())).unwrap()).unwrap();
    assert_eq!(raw["next"], 1);
    assert_eq!(raw["pools"][0]["rr_step"], 5);
    assert_eq!(raw["pools"][0]["auto_fill"], false);
    assert_eq!(raw["pools"][0]["cred"]["user"], "u");

    let loaded = load_pool_store(dir.path()).unwrap();
    assert_eq!(loaded.pools[0].name, "日本组");
    assert_eq!(loaded.pools[0].mode, POOL_MODE_BALANCE);
    assert!(loaded.next >= 2);

    fs::write(
        pool_state_path(dir.path()),
        r#"{"next":1,"pools":[{"id":"p9","name":"x","mode":"single","rr_step":5,"hosts":["a"]}]}"#,
    )
    .unwrap();
    let loaded = load_pool_store(dir.path()).unwrap();
    assert!(loaded.next > 9);
}

#[test]
fn pool_store_missing_file_is_empty_and_garbage_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = load_pool_store(dir.path()).unwrap();
    assert_eq!(store.next, 1);
    assert!(store.pools.is_empty());
    fs::write(pool_state_path(dir.path()), b"{not json").unwrap();
    assert!(load_pool_store(dir.path()).is_err());
}

#[test]
fn pool_store_loader_accepts_legacy_zero_values_and_normalizes() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        pool_state_path(dir.path()),
        r#"{"next":-4,"pools":[{"id":"p4","mode":"latency","hosts":[" a ","a",""],"rr_step":-2,"auto_fill":true,"size":-3,"cred":{}}]}"#,
    )
    .unwrap();
    let mut store = load_pool_store(dir.path()).unwrap();
    assert_eq!(store.next, 5);
    assert_eq!(store.pools[0].mode, POOL_MODE_LATENCY);
    assert_eq!(store.pools[0].rr_step, POOL_DEFAULT_RR_STEP);
    assert_eq!(store.pools[0].hosts, ["a"]);
    assert_eq!(store.pools[0].size, 1);
    assert_eq!(store.pools[0].name, "出口组 p4");
    assert_eq!(store.pools[0].cred.user, "");

    assert!(store.swap_member("p4", "a", "new").unwrap());
    assert_eq!(store.pools[0].hosts, ["new"]);
    assert!(!store.swap_member("p4", "missing", "new").unwrap());
    assert_eq!(store.pools[0].hosts, ["new"]);
    assert!(store.swap_member("p4", "missing", "extra").unwrap());
    assert_eq!(store.pools[0].hosts, ["new", "extra"]);
    assert!(store.swap_member("absent", "", "x").is_err());
}

#[test]
fn pool_store_get_and_sorted_do_not_mutate_member_order() {
    let mut store = PoolStore::new();
    for (id, name) in [("p10", "same"), ("p2", "same"), ("p1", "first")] {
        store.pools.push(Pool {
            id: id.to_string(),
            name: name.to_string(),
            ..Pool::default()
        });
    }
    let sorted: Vec<&str> = store.sorted().iter().map(|pool| pool.id.as_str()).collect();
    assert_eq!(sorted, ["p1", "p2", "p10"]);
    assert_eq!(store.get("p10").unwrap().name, "same");
    assert!(store.get("absent").is_none());
    store.get_mut("p10").unwrap().name = "changed".into();
    assert_eq!(store.pools[0].name, "changed");
}

#[test]
fn gone_hosts_wait_for_the_full_reconnect_window() {
    let now = test_now();
    let mut first_dead = HashMap::new();
    let members = [
        up_member("a.example", Duration::ZERO),
        PoolMember {
            host: "b.example".to_string(),
            namespace: "fo1".to_string(),
            status: "starting".to_string(),
            ..PoolMember::default()
        },
    ];
    let (live, gone) = pool_gone_hosts(&members, &mut first_dead, Duration::from_secs(300), now);
    assert_eq!(live, 1);
    assert!(gone.is_empty());
    assert_eq!(first_dead.get("b.example"), Some(&now));

    let (_, gone) = pool_gone_hosts(
        &members,
        &mut first_dead,
        Duration::from_secs(300),
        now + ChronoDuration::seconds(299),
    );
    assert!(gone.is_empty());
    let late = now + ChronoDuration::seconds(301);
    let (_, gone) = pool_gone_hosts(&members, &mut first_dead, Duration::from_secs(300), late);
    assert_eq!(gone, ["b.example"]);
    let (_, gone) = pool_gone_hosts(&members, &mut first_dead, Duration::from_secs(300), late);
    assert_eq!(gone, ["b.example"]);
}

#[test]
fn gone_hosts_recovers_clears_ledger_and_keeps_order() {
    let now = test_now();
    let dead = now - ChronoDuration::minutes(10);
    let mut first_dead = HashMap::from([
        ("b.example".to_string(), dead),
        ("c.example".to_string(), dead),
    ]);
    let members = [
        PoolMember {
            host: "a.example".to_string(),
            namespace: "fo0".to_string(),
            status: "starting".to_string(),
            ..PoolMember::default()
        },
        PoolMember {
            host: "b.example".to_string(),
            namespace: "fo1".to_string(),
            status: "starting".to_string(),
            ..PoolMember::default()
        },
        up_member("c.example", Duration::ZERO),
    ];
    let (live, gone) = pool_gone_hosts(&members, &mut first_dead, Duration::from_secs(300), now);
    assert_eq!(live, 1);
    assert_eq!(gone, ["b.example"]);
    assert!(!first_dead.contains_key("c.example"));
    assert_eq!(first_dead.get("a.example"), Some(&now));
}

#[test]
fn gone_hosts_treats_missing_or_finished_tunnels_as_immediately_dead() {
    let now = test_now();
    let mut first_dead = HashMap::new();
    let members = [
        PoolMember {
            host: "missing.example".to_string(),
            ..PoolMember::default()
        },
        PoolMember {
            host: "failed.example".to_string(),
            namespace: "fo1".to_string(),
            status: "failed".to_string(),
            ..PoolMember::default()
        },
        PoolMember {
            host: "stopped.example".to_string(),
            namespace: "fo2".to_string(),
            status: "stopped".to_string(),
            ..PoolMember::default()
        },
        PoolMember {
            host: "trying.example".to_string(),
            namespace: "fo3".to_string(),
            status: "starting".to_string(),
            ..PoolMember::default()
        },
    ];
    let (live, gone) = pool_gone_hosts(&members, &mut first_dead, POOL_FILL_DEAD_AFTER, now);
    assert_eq!(live, 0);
    assert_eq!(
        gone,
        ["missing.example", "failed.example", "stopped.example"]
    );
    for host in ["missing.example", "failed.example", "stopped.example"] {
        assert!(!first_dead.contains_key(host));
    }
    assert!(first_dead.contains_key("trying.example"));

    let (live, gone) = pool_gone_hosts(&[], &mut first_dead, POOL_FILL_DEAD_AFTER, now);
    assert_eq!(live, 0);
    assert!(gone.is_empty());
}

#[test]
fn reuse_pick_prefers_spares_then_shared_and_skips_offline() {
    let candidates = [
        PoolFillCand {
            host: "busy1".into(),
            online: true,
            shared: true,
        },
        PoolFillCand {
            host: "spare1".into(),
            online: true,
            shared: false,
        },
        PoolFillCand {
            host: "down1".into(),
            online: false,
            shared: false,
        },
        PoolFillCand {
            host: "spare2".into(),
            online: true,
            shared: false,
        },
        PoolFillCand {
            host: "busy2".into(),
            online: true,
            shared: true,
        },
        PoolFillCand {
            host: "down2".into(),
            online: false,
            shared: true,
        },
    ];
    assert_eq!(
        pool_reuse_pick(&candidates, 3),
        ["spare1", "spare2", "busy1"]
    );
    assert_eq!(pool_reuse_pick(&candidates, 1), ["spare1"]);
    assert_eq!(pool_reuse_pick(&candidates, 9).len(), 4);
    assert!(pool_reuse_pick(&candidates, 0).is_empty());
    assert!(pool_reuse_pick(
        &[PoolFillCand {
            host: "x".into(),
            ..PoolFillCand::default()
        }],
        2
    )
    .is_empty());
}

#[test]
fn fill_candidates_exclude_own_members_and_active_penalties() {
    let now = test_now();
    let pool = autofill_pool(2, &["gate-dead", "gate-ok"]);
    let other = Pool {
        id: "p2".to_string(),
        hosts: vec!["gate-shared".into()],
        ..Pool::default()
    };
    let tunnels = [
        tunnel("gate-dead", "failed"),
        tunnel("gate-ok", "up"),
        tunnel("gate-free", "up"),
        tunnel("down-gate", "failed"),
        tunnel("gate-shared", "up"),
        tunnel("gate-cool", "up"),
    ];
    let bad_until = HashMap::from([("gate-cool".to_string(), now + ChronoDuration::minutes(1))]);
    let candidates = fill_candidates(&[pool, other], "p1", &tunnels, &bad_until, now);
    assert!(!candidates
        .iter()
        .any(|candidate| candidate.host == "gate-ok"));
    assert!(!candidates
        .iter()
        .any(|candidate| candidate.host == "gate-cool"));
    let free = candidates
        .iter()
        .find(|candidate| candidate.host == "gate-free")
        .unwrap();
    assert!(free.online && !free.shared);
    let shared = candidates
        .iter()
        .find(|candidate| candidate.host == "gate-shared")
        .unwrap();
    assert!(shared.online && shared.shared);
    let down = candidates
        .iter()
        .find(|candidate| candidate.host == "down-gate")
        .unwrap();
    assert!(!down.online);

    let expired = HashMap::from([("gate-cool".to_string(), now)]);
    assert!(fill_candidates(&[], "p1", &tunnels, &expired, now)
        .iter()
        .any(|candidate| candidate.host == "gate-cool"));
}

#[test]
fn fill_assessment_prefers_online_replacement_and_keeps_size() {
    let now = test_now();
    let pool = autofill_pool(2, &["gate-dead", "gate-ok"]);
    let members = [
        PoolMember {
            host: "gate-dead".to_string(),
            namespace: "fo0".to_string(),
            status: "failed".to_string(),
            ..PoolMember::default()
        },
        up_member("gate-ok", Duration::ZERO),
    ];
    let mut ledger = HashMap::new();
    let assessment = assess_pool_fill(&pool, &members, &mut ledger, now);
    assert_eq!(assessment.live, 1);
    assert_eq!(assessment.short, 1);
    assert_eq!(assessment.need, 1);
    assert_eq!(assessment.gone, ["gate-dead"]);

    let candidates = [PoolFillCand {
        host: "gate-free".to_string(),
        online: true,
        shared: false,
    }];
    let picks = pool_reuse_pick(&candidates, assessment.need);
    let mut store = PoolStore {
        next: 2,
        pools: vec![pool.clone()],
    };
    for (index, host) in picks.iter().enumerate() {
        assert!(store
            .swap_member("p1", fill_slot(&assessment.gone, index).unwrap_or(""), host)
            .unwrap());
    }
    assert_eq!(store.pools[0].hosts, ["gate-free", "gate-ok"]);
    assert_eq!(store.pools[0].size, 2);
    assert_eq!(
        fill_completion_note(&pool, &assessment, picks.len(), 0, None),
        None
    );
}

#[test]
fn fill_assessment_allows_growth_without_replacing_live_members() {
    let now = test_now();
    let pool = autofill_pool(3, &["gate-a", "gate-b"]);
    let members = [
        up_member("gate-a", Duration::ZERO),
        up_member("gate-b", Duration::ZERO),
    ];
    let assessment = assess_pool_fill(&pool, &members, &mut HashMap::new(), now);
    assert_eq!(assessment.need, 1);
    assert!(assessment.gone.is_empty());
    assert_eq!(fill_slot(&assessment.gone, 0), None);

    let mut store = PoolStore {
        next: 2,
        pools: vec![pool.clone()],
    };
    assert!(store.swap_member("p1", "", "gate-c").unwrap());
    assert_eq!(store.pools[0].hosts, ["gate-a", "gate-b", "gate-c"]);
    assert_eq!(store.pools[0].size, 3);
}

#[test]
fn fill_assessment_waits_for_reconnecting_members() {
    let now = test_now();
    let pool = autofill_pool(3, &["gate-a", "gate-b", "gate-c"]);
    let members: Vec<PoolMember> = ["gate-a", "gate-b", "gate-c"]
        .into_iter()
        .map(|host| PoolMember {
            host: host.to_string(),
            namespace: format!("fo-{host}"),
            status: "starting".to_string(),
            ..PoolMember::default()
        })
        .collect();
    let assessment = assess_pool_fill(&pool, &members, &mut HashMap::new(), now);
    assert_eq!(assessment.live, 0);
    assert_eq!(assessment.need, 0);
    assert!(assessment.gone.is_empty());
    assert!(assessment.note.unwrap().contains("正在自动重连"));
}

#[test]
fn fill_completion_reports_shortfall_without_shrinking_target() {
    let now = test_now();
    let pool = autofill_pool(3, &["gate-dead", "gate-ok"]);
    let members = [
        PoolMember {
            host: "gate-dead".to_string(),
            status: "failed".to_string(),
            ..PoolMember::default()
        },
        up_member("gate-ok", Duration::ZERO),
    ];
    let assessment = assess_pool_fill(&pool, &members, &mut HashMap::new(), now);
    assert_eq!(assessment.need, 2);
    let note = fill_completion_note(&pool, &assessment, 1, 0, Some("没有可用节点".into())).unwrap();
    assert!(note.contains("还差 1 条"));
    assert_eq!(pool.size, 3);
}

#[test]
fn autofill_preserves_slot_floor_and_penalizes_failed_nodes() {
    assert_eq!(creation_room(0), 0);
    assert_eq!(creation_room(POOL_FILL_SLOT_FLOOR), 0);
    assert_eq!(creation_room(POOL_FILL_SLOT_FLOOR + 3), 3);
    assert!(fill_failure_reason("dead").contains("冷却 10 分钟"));
    let pool = autofill_pool(1, &["dead"]);
    let assessment = FillAssessment {
        live: 0,
        short: 1,
        need: 1,
        gone: vec!["dead".into()],
        note: None,
    };
    assert!(fill_completion_note(&pool, &assessment, 0, 0, None)
        .unwrap()
        .contains("要留 2 个余量"));

    let now = test_now();
    let mut state = PoolFillState::default();
    assert!(state.begin_fill());
    assert!(!state.begin_fill());
    state.finish_fill();
    state.mark_bad("dead", now);
    assert_eq!(
        state.bad_until.get("dead"),
        Some(&(now + ChronoDuration::minutes(10)))
    );
    state.prune_bad(now + ChronoDuration::minutes(10));
    assert!(state.bad_until.contains_key("dead"));
    state.prune_bad(now + ChronoDuration::minutes(10) + ChronoDuration::nanoseconds(1));
    assert!(!state.bad_until.contains_key("dead"));
}

#[test]
fn fill_ledger_snapshots_merge_replace_and_drop() {
    let now = test_now();
    let mut state = PoolFillState::default();
    let mut store = PoolStore {
        next: 2,
        pools: vec![autofill_pool(1, &["a"])],
    };
    state.merge_dead("p1", HashMap::from([("a".to_string(), now)]), &store);
    assert_eq!(state.dead_snapshot("p1").get("a"), Some(&now));
    state.forget_dead("p1", "a");
    assert!(!state.dead_snapshot("p1").contains_key("a"));
    state.set_note("p1", Some("waiting".into()));
    assert_eq!(state.notes().get("p1").map(String::as_str), Some("waiting"));
    state.merge_dead("p1", HashMap::new(), &store);
    store.pools.clear();
    state.merge_dead("p1", HashMap::from([("stale".to_string(), now)]), &store);
    assert!(!state.first_dead.contains_key("p1"));
    state.drop_ledger("p1");
    assert!(!state.notes.contains_key("p1"));
}

#[test]
fn fill_avoid_contains_members_and_only_active_penalties() {
    let now = test_now();
    let members = [up_member("member", Duration::ZERO)];
    let bad_until = HashMap::from([
        ("active".to_string(), now + ChronoDuration::seconds(1)),
        ("expired".to_string(), now),
    ]);
    let avoid = fill_avoid(&members, &bad_until, now);
    assert!(avoid.contains("member"));
    assert!(avoid.contains("active"));
    assert!(!avoid.contains("expired"));
}

#[test]
fn retirement_keeps_recovered_shared_bound_and_unknown_tunnels() {
    let dead = tunnel("vpn-gate-dead", "failed");
    assert_eq!(
        retire_slot("vpn-gate-dead", Some(&dead), false, Some(false)),
        Some(3)
    );
    assert_eq!(
        retire_slot("vpn-gate-dead", Some(&dead), true, Some(false)),
        None
    );
    assert_eq!(
        retire_slot("vpn-gate-dead", Some(&dead), false, Some(true)),
        None
    );
    assert_eq!(retire_slot("vpn-gate-dead", Some(&dead), false, None), None);
    assert_eq!(retire_slot("vpn-gate-dead", None, false, Some(false)), None);
    assert_eq!(retire_slot("", Some(&dead), false, Some(false)), None);
    let recovered = tunnel("vpn-gate-dead", "up");
    assert_eq!(
        retire_slot("vpn-gate-dead", Some(&recovered), false, Some(false)),
        None
    );

    let pools = vec![Pool {
        hosts: vec!["vpn-gate-dead".into()],
        ..Pool::default()
    }];
    assert!(host_in_pool(&pools, "vpn-gate-dead"));
    assert!(!host_in_pool(&pools, "other"));
}

#[test]
fn latency_ewma_and_cooldown_state_match_go() {
    assert_eq!(
        ewma_latency(Duration::ZERO, Duration::from_millis(100)),
        Duration::from_millis(100)
    );
    assert_eq!(
        ewma_latency(Duration::from_millis(100), Duration::from_millis(200)),
        Duration::from_millis(130)
    );
    assert_eq!(cooldown_for_failures(1), Duration::from_secs(20));
    assert_eq!(cooldown_for_failures(4), Duration::from_secs(160));
    assert_eq!(cooldown_for_failures(5), POOL_COOL_MAX);
    assert_eq!(cooldown_for_failures(6), POOL_COOL_MAX);

    let now = test_now();
    let mut stat = MemberStat::default();
    stat.note_fail(now);
    assert!(stat.is_cooling(now + ChronoDuration::seconds(19)));
    assert!(!stat.is_cooling(now + ChronoDuration::seconds(20)));
    stat.note_ok(Duration::from_millis(80), now + ChronoDuration::seconds(21));
    assert_eq!(stat.failures, 0);
    assert_eq!(stat.cooling_until, None);
    assert_eq!(stat.latency, Duration::from_millis(80));
}

#[test]
fn runtime_state_applies_samples_and_forgets_failed_affinity() {
    let now = test_now();
    let mut runtime = PoolRuntimeState::new(POOL_MODE_ROUND_ROBIN, 1);
    let members = [
        up_member("a", Duration::ZERO),
        up_member("b", Duration::ZERO),
    ];
    runtime.policy.pick("t0", &members);
    runtime.note_success("a", Duration::from_millis(90), now);
    runtime.note_failure("b", now);
    assert!(!runtime.policy.affinity().values().any(|host| host == "b"));

    let mut resolved = members;
    runtime.apply_state(&mut resolved, now);
    assert_eq!(resolved[0].latency, Duration::from_millis(90));
    assert!(!resolved[0].cooling);
    assert!(resolved[1].cooling);
    assert!(runtime.needs_probe(
        POOL_MODE_BALANCE,
        &resolved[0],
        now + ChronoDuration::seconds(121)
    ));
    assert!(!runtime.needs_probe(POOL_MODE_ROUND_ROBIN, &resolved[0], now));
}

#[test]
fn pool_view_projects_runtime_state_and_mode_aliases() {
    let pool = Pool {
        id: "p1".to_string(),
        name: "组".into(),
        mode: POOL_MODE_LATENCY.to_string(),
        rr_step: 5,
        port: 1081,
        cred: SocksCred {
            user: "u".into(),
            pass: "p".into(),
        },
        auto_fill: true,
        size: 2,
        ..Pool::default()
    };
    let members = [
        PoolMember {
            latency: Duration::from_millis(42),
            cooling: true,
            ..up_member("a", Duration::ZERO)
        },
        PoolMember {
            host: "missing".to_string(),
            ..PoolMember::default()
        },
    ];
    let view = pool_view(
        &pool,
        &members,
        true,
        Some("waiting"),
        &HashSet::from(["a".to_string()]),
    );
    assert_eq!(view.identity, "pool-p1");
    assert_eq!(view.mode, POOL_MODE_LATENCY);
    assert!(!view.mode_label.is_empty());
    assert!(view.running);
    assert_eq!((view.up, view.total), (1, 2));
    assert_eq!(view.members[0].latency_ms, 42);
    assert!(view.members[0].cooling && view.members[0].aead);
    assert_eq!(view.members[1].status, "missing");
    assert_eq!(view.fill_note, "waiting");
    assert_eq!(view.socks_user, "u");
}
