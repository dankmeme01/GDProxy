use std::path::Path;

use serde::{Deserialize, Serialize};

fn default_secret_key() -> String {
    // generate a random 32-byte key
    let secret_key = rand::random::<[u8; 32]>();
    hex::encode(secret_key)
}

fn default_port() -> u16 {
    3000
}

fn default_cache_ttl() -> u64 {
    3600 // 1 hour
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_secret_key")]
    pub secret_key: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub revoked_tokens: Vec<u64>,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
}

impl Config {
    pub fn load_from_path(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::load_from_content(&content)
    }

    pub fn load_from_content(content: &str) -> anyhow::Result<Self> {
        let config: Self = toml::de::from_str(content)?;
        Ok(config)
    }

    pub fn save_to_path(&self, path: &Path) -> anyhow::Result<()> {
        let content = toml::ser::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            secret_key: default_secret_key(),
            port: default_port(),
            revoked_tokens: Vec::new(),
            cache_ttl: default_cache_ttl(),
        }
    }
}
