use std::net::SocketAddr;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub idle_timeout: u64,
    pub buffer_size: usize,
    pub listeners: Vec<ListenerConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ListenerConfig {
    pub listen: SocketAddr,
    pub connect: SocketAddr,
    pub fake_sni: String,
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
