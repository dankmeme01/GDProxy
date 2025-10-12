use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{FromRequestParts, Path, RawForm, State},
    http::request::Parts,
    response::IntoResponse,
};
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode};
use tracing::{debug, info, warn};

use crate::AppState;

#[derive(Debug)]
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
                    Err((StatusCode::UNAUTHORIZED, "Unauthorized"))
                }
            }
        } else {
            Err((StatusCode::UNAUTHORIZED, "Unauthorized"))
        }
    }
}

#[axum::debug_handler]
pub async fn proxy_handler(
    Path(path): Path<String>,
    Auth(id): Auth,
    State(state): State<Arc<AppState>>,
    RawForm(form): RawForm,
) -> impl IntoResponse {
    // path will be "blah.php" n stuff
    info!("Forwarding request to {path} (ID {id})");
    debug!("Body: {:?}", form);

    // see if we have a cached response
    let should_cache = should_cache_endpoint(&path);
    let ckey = state.compute_cache_key(&path, &form);

    if should_cache && let Some(cached) = state.get_cached_response(ckey).await {
        debug!("Cache hit, returning cached response");
        return cached;
    }

    match forward_request(&path, form, &state).await {
        Ok(resp) => {
            if should_cache {
                state.cache_response(ckey, resp.clone()).await;
            }

            resp
        }

        Err(e) => {
            warn!("Error forwarding request: {}", e);

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_owned(),
            )
        }
    }
}

async fn forward_request(
    path: &str,
    form: Bytes,
    state: &AppState,
) -> anyhow::Result<(StatusCode, String)> {
    let url = format!("https://www.boomlings.com/database/{}", path).parse::<hyper::Uri>()?;

    let authority = url.authority().unwrap().clone();
    let req = Request::builder()
        .uri(url)
        .header(hyper::header::HOST, authority.as_str())
        .header(
            hyper::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(hyper::header::USER_AGENT, "")
        .method(hyper::Method::POST)
        .body(Full::new(form))?;

    let mut res = state.http_client.request(req).await?;
    let mut body = Vec::new();

    while let Some(next) = res.frame().await {
        let frame = next?;
        if let Some(chunk) = frame.data_ref() {
            body.extend_from_slice(chunk);
        }
    }

    let status = res.status();

    Ok((status, String::from_utf8(body)?))
}

fn should_cache_endpoint(path: &str) -> bool {
    // only cache endpoints that are read-only and are expected to not change often
    matches!(
        path,
        // Users
        "getGJScores20.php" |
        "getGJUserInfo20.php" |
        "getGJUsers20.php" |

        // Levels
        "getGJGauntlets21.php" |
        "getGJLevels21.php" |
        "getGJLevelScores211.php" |
        "getGJMapPacks21.php" |

        // Lists
        "getGJLevelLists.php" |

        // // Comments
        // "getGJAccountComments20.php" |
        // "getGJCommentHistory.php" |
        // "getGJComments21.php" |

        // Socials
        "getGJUserList20.php" |

        // Rewards
        "getGJChallenges.php" |
        "getGJRewards.php" |

        // Songs
        "getGJSongInfo.php"
    )
}
