use super::*;
use crate::config::WebSettings;
use tokio::sync::RwLock;

#[tokio::test]
async fn warp_store_read_errors_are_not_treated_as_empty() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(temporary.path().join("warp.json"), "{bad json").unwrap();
    let result = WarpService::load(
        temporary.path(),
        Instance::default(),
        Arc::new(RwLock::new(WebSettings::default())),
    );
    assert!(result.await.is_err());
}

#[tokio::test]
async fn missing_warp_store_is_empty() {
    let temporary = tempfile::tempdir().unwrap();
    let service = WarpService::load(
        temporary.path(),
        Instance::default(),
        Arc::new(RwLock::new(WebSettings::default())),
    )
    .await
    .unwrap();
    assert!(service.all().await.is_empty());
}
