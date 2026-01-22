use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use axum::{Router, body::Bytes, routing::post};
use blake3::Hasher;
use bytes::BytesMut;
use http_body_util::Full;
use hyper::StatusCode;
use hyper_rustls::{ConfigBuilderExt, HttpsConnector};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use moka::future::{Cache, CacheBuilder};
use tokio::{net::TcpListener, sync::Mutex};
use tracing::info;

use crate::{
    config::Config,
    rate_limiter::RateLimiter,
    token_issuer::{TokenData, TokenIssuer, TokenValidationError},
};

mod config;
pub mod extractors;
mod rate_limiter;
mod routes;
mod token_issuer;

pub struct AppState {
    issuer: TokenIssuer,
    revoked: HashSet<u64>,
    cache: Option<Cache<u64, (StatusCode, Bytes)>>,
    rate_limiters: Mutex<HashMap<u64, RateLimiter>>,
    tokens_per_sec: u32,
    pub http_client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
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

        let rate_limiters = Mutex::new(HashMap::new());

        let tls = rustls::ClientConfig::builder()
            .with_native_roots()
            .unwrap()
            .with_no_client_auth();

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .build();

        let client = Client::builder(TokioExecutor::new()).build(https);

        Self {
            issuer,
            revoked: config.revoked_tokens.into_iter().collect(),
            cache,
            rate_limiters,
            tokens_per_sec: config.max_requests_per_second,
            http_client: client,
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

    pub async fn get_cached_response(&self, key: u64) -> Option<(StatusCode, Bytes)> {
        self.cache.as_ref()?.get(&key).await
    }

    pub async fn cache_response(
        &self,
        key: u64,
        response: (StatusCode, BytesMut),
    ) -> (StatusCode, Bytes) {
        let data = response.1.freeze();

        if let Some(cache) = self.cache.as_ref() {
            cache.insert(key, (response.0, data.clone())).await;
        }
        (response.0, data)
    }

    pub async fn check_rate_limit(&self, id: u64) -> bool {
        // TODO: in the future, periodically clean up old rate limiters

        let mut map = self.rate_limiters.lock().await;
        let entry = map.entry(id).or_insert_with(|| self.new_limiter());

        entry.consume()
    }

    fn new_limiter(&self) -> RateLimiter {
        if self.tokens_per_sec == 0 {
            RateLimiter::new_unlimited()
        } else {
            RateLimiter::new(self.tokens_per_sec, self.tokens_per_sec)
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // do one-time initialization of TLS stuff
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

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
