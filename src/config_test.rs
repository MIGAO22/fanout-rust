use super::*;

#[test]
fn listen_formats_ipv4_and_ipv6() {
    let mut settings = WebSettings {
        listen_addr: "127.0.0.1".into(),
        port: 8899,
        ..WebSettings::default()
    };
    assert_eq!(settings.listen(), "127.0.0.1:8899");
    settings.listen_addr = "::1".into();
    assert_eq!(settings.listen(), "[::1]:8899");
}

#[test]
fn corrupt_settings_are_rejected_instead_of_reset() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(temporary.path().join("settings.json"), "{bad json").unwrap();
    assert!(load_settings(temporary.path(), 8899, false).is_err());
}

#[test]
fn optimization_defaults_are_backward_compatible() {
    let settings = WebSettings::default().normalized();
    assert!(settings.conn.smart_selection);
    assert_eq!(settings.conn.min_dwell_secs, 60);
    assert_eq!(settings.conn.switch_cooldown_secs, 30);
    assert_eq!(settings.conn.node_quarantine_secs, 120);
    let pool = settings.warp().pool;
    assert!(!pool.enabled);
    assert_eq!(pool.size, 4);
    assert_eq!(pool.prewarm_ttl_secs, 1800);
    assert_eq!(pool.rotate_after_failures, 3);
}
