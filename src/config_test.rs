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
