use std::sync::Arc;

use axum::{
    extract::{Path, Query, RawForm, State},
    response::IntoResponse,
};
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::{
    AppState,
    extractors::{Auth, Limit},
};

#[derive(Debug, Deserialize)]
pub struct RequestParams {
    #[serde(default)]
    pub no_cache: bool,
}

#[axum::debug_handler]
pub async fn proxy_handler(
    Path(path): Path<String>,
    Auth(id): Auth,
    State(state): State<Arc<AppState>>,
    Query(query): Query<RequestParams>,
    _: Limit,
    RawForm(form): RawForm,
) -> impl IntoResponse {
    // compute cache key and check if cachable
    let should_cache = !query.no_cache && should_cache_endpoint(&path);
    let ckey = state.compute_cache_key(&path, &form);

    // path will be "blah.php" n stuff
    info!("[{id}] request to {path}");
    debug!("Cacheable: {should_cache}, key: {ckey}");
    debug!("Body: {:?}", form);

    if should_cache && let Some(cached) = state.get_cached_response(ckey).await {
        debug!("Cache hit, returning cached response");
        return cached;
    }

    match forward_request(&path, form, &state).await {
        Ok(resp) => {
            if should_cache {
                state.cache_response(ckey, resp).await
            } else {
                (resp.0, resp.1.freeze())
            }
        }

        Err(e) => {
            warn!("Error forwarding request: {}", e);

            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string().into_bytes().into(),
            )
        }
    }
}

async fn forward_request(
    path: &str,
    form: Bytes,
    state: &AppState,
) -> anyhow::Result<(StatusCode, BytesMut)> {
    let url = format!("https://www.boomlings.com/database/{}", path).parse::<hyper::Uri>()?;

    info!("Forwarding request to {}", url);

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
    let mut body = BytesMut::new();

    while let Some(next) = res.frame().await {
        let frame = next?;
        if let Some(chunk) = frame.data_ref() {
            body.extend_from_slice(chunk);
        }
    }

    let status = res.status();

    Ok((status, body))
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
