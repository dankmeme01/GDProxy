use std::sync::Arc;

use axum::{extract::FromRequestParts, http::request::Parts};
use hyper::StatusCode;
use tracing::{debug, warn};

use crate::AppState;

#[derive(Debug, Clone, Copy, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct Auth(pub u64);

impl FromRequestParts<Arc<AppState>> for Auth {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        if let Some(auth) = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
        {
            match state.validate_token(auth) {
                Ok(data) => Ok(Auth(data.id)),
                Err(e) => {
                    debug!("Token validation error: {e}");
                    Err((StatusCode::UNAUTHORIZED, "unauthorized"))
                }
            }
        } else {
            Err((StatusCode::UNAUTHORIZED, "unauthorized"))
        }
    }
}

pub struct Limit(pub Auth);

impl FromRequestParts<Arc<AppState>> for Limit {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth = Auth::from_request_parts(parts, state).await?;

        if state.check_rate_limit(auth.0).await {
            Ok(Limit(auth))
        } else {
            warn!("Rate limit exceeded for user {}", auth.0);
            Err((StatusCode::TOO_MANY_REQUESTS, "too many requests"))
        }
    }
}
