use super::*;
use crate::config::{save_settings, ConnSettings, WebSettings};

#[test]
fn concurrent_subscription_token_creation_preserves_settings() {
    let temporary = tempfile::tempdir().unwrap();
    let settings = WebSettings {
        port: 12_345,
        listen_addr: "127.0.0.1".into(),
        conn: ConnSettings::defaults(),
        ..WebSettings::default()
    };
    save_settings(temporary.path(), &settings).unwrap();
    let threads = (0..8)
        .map(|_| {
            let dir = temporary.path().to_path_buf();
            std::thread::spawn(move || sub_token(&dir).unwrap())
        })
        .collect::<Vec<_>>();
    let tokens = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert!(tokens.windows(2).all(|pair| pair[0] == pair[1]));
    let saved = load_settings(temporary.path(), 8899, false).unwrap();
    assert_eq!(saved.port, 12_345);
    assert_eq!(saved.listen_addr, "127.0.0.1");
    assert_eq!(saved.sub_token.as_deref(), Some(tokens[0].as_str()));
}
