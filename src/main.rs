use std::{collections::HashSet, sync::Arc, time::Duration};

use axum::{Router, body::Bytes, routing::post};
use blake3::Hasher;
use hyper::StatusCode;
use moka::future::{Cache, CacheBuilder};
use tokio::net::TcpListener;
use tracing::info;

use crate::{
    config::Config,
    token_issuer::{TokenData, TokenIssuer, TokenValidationError},
};

mod config;
mod routes;
mod token_issuer;

#[derive(Clone)]
pub struct AppState {
    issuer: TokenIssuer,
    revoked: HashSet<u64>,
    cache: Option<Cache<u64, (StatusCode, String)>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let issuer = TokenIssuer::new(&config.secret_key).unwrap();
        let cache = if config.cache_ttl > 0 {
            Some(
                CacheBuilder::new(512)
                    .time_to_live(Duration::from_secs(config.cache_ttl))
                    .build(),
            )
        } else {
            None
        };

        Self {
            issuer,
            revoked: config.revoked_tokens.into_iter().collect(),
            cache,
        }
    }

    pub fn validate_token(&self, token: &str) -> Result<TokenData, TokenValidationError> {
        let data = self.issuer.validate(token)?;

        // check if revoked
        if self.revoked.contains(&data.id) {
            return Err(TokenValidationError::Revoked);
        }

        Ok(data)
    }

    pub fn generate_token(&self) -> (String, u64) {
        let num = rand::random::<u64>();
        (self.issuer.generate(num), num)
    }

    pub fn compute_cache_key(&self, path: &str, body: &Bytes) -> u64 {
        let mut hasher = Hasher::new();
        hasher.update(path.as_bytes());
        hasher.update(body);
        let hash = hasher.finalize();
        hash.as_bytes()[..8]
            .try_into()
            .map(u64::from_le_bytes)
            .unwrap()
    }

    pub async fn get_cached_response(&self, key: u64) -> Option<(StatusCode, String)> {
        self.cache.as_ref()?.get(&key).await
    }

    pub async fn cache_response(&self, key: u64, response: (StatusCode, String)) {
        self.cache.as_ref().map(|c| c.insert(key, response));
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config_path = std::path::Path::new("config.toml");
    let config = if config_path.exists() {
        Config::load_from_path(config_path).expect("Failed to load config")
    } else {
        let config = Config::default();
        config
            .save_to_path(config_path)
            .expect("Failed to save config");
        config
    };
    let c_port = config.port;

    let state = Arc::new(AppState::new(config));

    // if 'generate-token' is passed, generate a token and exit

    let mut args = std::env::args().skip(1);
    let cmd = args.next();

    match cmd.as_deref() {
        Some("generate-token") => {
            let (token, id) = state.generate_token();
            info!("Generated token with ID {id}: {token}");
            return;
        }

        Some("check-token") => {
            let token = args.next().expect("Token argument missing");
            match state.validate_token(&token) {
                Ok(data) => {
                    info!("Token valid, ID: {}", data.id);
                }

                Err(e) => {
                    info!("Token invalid: {}", e);
                }
            }

            return;
        }

        _ => {}
    }

    info!("Starting GD proxy server...");

    let port = std::env::var("GD_PROXY_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(c_port);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();

    let app = Router::new()
        .route("/database/{*key}", post(routes::proxy_handler))
        .with_state(state);

    axum::serve(listener, app).await.unwrap();
}
