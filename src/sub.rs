use crate::{
    config::{load_settings, save_settings, WebSettings},
    util::{atomic_write, read_trim},
};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;
use std::path::Path;

pub fn sub_token(dir: &Path) -> Result<String> {
    let _guard = crate::config::settings_file_lock()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut s = load_settings(dir, crate::config::DEFAULT_PORT, false)?;
    if let Some(t) = s.sub_token.as_ref().filter(|t| !t.is_empty()) {
        return Ok(t.clone());
    }
    let t = sub_token_value();
    s.sub_token = Some(t.clone());
    save_settings(dir, &s)?;
    Ok(t)
}

pub fn reset_sub_token(dir: &Path) -> Result<String> {
    let _guard = crate::config::settings_file_lock()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut s = load_settings(dir, crate::config::DEFAULT_PORT, false)?;
    let t = sub_token_value();
    s.sub_token = Some(t.clone());
    save_settings(dir, &s)?;
    Ok(t)
}

fn sub_token_value() -> String {
    let mut bytes = [0_u8; 20];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

pub fn sub_path(token: &str) -> String {
    format!("/sub?token={token}")
}

pub fn sub_path_with_base(base_path: &str, token: &str) -> String {
    let base = base_path.trim_matches('/');
    if base.is_empty() {
        sub_path(token)
    } else {
        format!("/{base}/sub?token={token}")
    }
}

pub fn sub_full_url(req_host: &str, token: &str) -> String {
    format!("http://{req_host}{}", sub_path(token))
}

pub fn encode_sub(links: &[String], target: &str) -> Result<String> {
    let plain = links.join("\n");
    match target {
        "" | "base64" | "b64" | "v2ray" => Ok(STANDARD.encode(plain.as_bytes())),
        "links" | "plain" | "text" => Ok(plain),
        _ => anyhow::bail!("target 只支持 base64 或 links"),
    }
}

pub fn write_token_file(dir: &Path, token: &str) -> Result<()> {
    atomic_write(dir.join("sub-token"), token.as_bytes(), 0o600)
}

pub fn read_token_file(dir: &Path) -> Option<String> {
    read_trim(dir.join("sub-token"))
}

pub fn settings_with_token(mut s: WebSettings, token: String) -> WebSettings {
    s.sub_token = Some(token);
    s
}
