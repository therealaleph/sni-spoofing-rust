use std::net::SocketAddr;

use serde::Deserialize;

fn default_conn_timeout_sec() -> u64 {
    5
}

fn default_handshake_timeout_sec() -> u64 {
    2
}

fn default_keepalive_time_sec() -> u64 {
    11
}

fn default_keepalive_interval_sec() -> u64 {
    2
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listeners: Vec<ListenerConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ListenerConfig {
    pub listen: SocketAddr,
    pub connect: SocketAddr,
    pub fake_sni: String,
    #[serde(default = "default_conn_timeout_sec")]
    pub conn_timeout_sec: u64,
    #[serde(default = "default_handshake_timeout_sec")]
    pub handshake_timeout_sec: u64,
    #[serde(default = "default_keepalive_time_sec")]
    pub keepalive_time_sec: u64,
    #[serde(default = "default_keepalive_interval_sec")]
    pub keepalive_interval_sec: u64,
}

pub fn load(path: &str) -> Result<Config, crate::error::ConfigError> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| crate::error::ConfigError::Io(path.to_string(), e))?;
    let cfg: Config = serde_json::from_str(&data)
        .map_err(|e| crate::error::ConfigError::Parse(path.to_string(), e))?;
    if cfg.listeners.is_empty() {
        return Err(crate::error::ConfigError::Empty);
    }
    for lc in &cfg.listeners {
        if lc.fake_sni.len() > 219 {
            return Err(crate::error::ConfigError::SniTooLong(lc.fake_sni.clone()));
        }
    }
    Ok(cfg)
}
