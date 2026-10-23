use crate::state::AppState as SharedState;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use std::collections::HashSet;

/// Returns the router for the `/api` prefix.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/list", get(api_list))
        .route("/get/{key}", get(api_get))
        .route("/transition", post(api_transition))
        .route("/verified/{key}", put(api_set_verified))
}

/// Middleware to authenticate API requests using a Bearer token.
pub async fn api_auth(
    State(state): State<SharedState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if !check_token(request.headers(), &state.config.api_tokens) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(request).await
}

/// Response type when calling /api/list.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiListResponse {
    state: &'static str,
    pub_key: String,
}

/// GET /api/list - Lists all authentication requests with their states.
pub async fn api_list(State(state): State<SharedState>) -> impl IntoResponse {
    match state.storage.get_all_requests().await {
        Ok(requests) => {
            let resp: Vec<ApiListResponse> = requests
                .into_iter()
                .map(|(pub_key, s)| ApiListResponse {
                    state: s.as_str(),
                    pub_key,
                })
                .collect();
            Json(resp).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to get requests: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Response type when calling /api/get/{key}.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiGetResponse {
    state: &'static str,
    pub_key: String,
    data: serde_json::Value,
}

/// GET /api/get/{key} - Retrieves full data for a specific request.
pub async fn api_get(
    State(state): State<SharedState>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_request(&key).await {
        Ok(Some((s, data))) => Json(ApiGetResponse {
            state: s.as_str(),
            pub_key: key,
            data,
        })
        .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("Failed to get request: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Payload when calling /api/transition.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransitionRequest {
    pub pub_key: String,
    pub old_state: String,
    pub new_state: String,
}

/// POST /api/transition - Performs a state transition.
pub async fn api_transition(
    State(state): State<SharedState>,
    Json(payload): Json<TransitionRequest>,
) -> impl IntoResponse {
    let from = match payload.old_state.parse::<crate::storage::State>() {
        Ok(s) => s,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let to = match payload.new_state.parse::<crate::storage::State>() {
        Ok(s) => s,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    match state
        .storage
        .transition_request(&payload.pub_key, from, to)
        .await
    {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => {
            tracing::error!("Failed to transition request: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Checks the inputs of `PUT /api/verified/{key}` before storage is touched.
fn check_verified_input(
    key: &str,
    body: &serde_json::Value,
) -> Result<(), StatusCode> {
    if crate::routes_client::validate_pubkey(key).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !body.is_object() {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

/// PUT /api/verified/{key} - Replaces the record's `verified` object.
///
/// Works in any state, including `authorized`, so a key that joins again
/// gets its verified claims refreshed. Only this route writes `verified`;
/// the `payload` written by `PUT /request-auth/{key}` is caller-supplied
/// and never trusted.
pub async fn api_set_verified(
    State(state): State<SharedState>,
    Path(key): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Err(status) = check_verified_input(&key, &body) {
        return status.into_response();
    }
    match state.storage.set_verified(&key, &body).await {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!("Failed to set verified: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Returns the bearer token from the `Authorization` header, if any.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

/// Whether the headers carry a bearer token that is in `tokens`.
///
/// Every token in the set is compared in constant time, so the response
/// time does not tell a caller how much of a token it guessed right.
pub(crate) fn check_token(
    headers: &HeaderMap,
    tokens: &HashSet<String>,
) -> bool {
    use subtle::ConstantTimeEq;

    let Some(token) = bearer_token(headers) else {
        return false;
    };
    let mut found = subtle::Choice::from(0);
    for candidate in tokens {
        found |= candidate.as_bytes().ct_eq(token.as_bytes());
    }
    found.into()
}

#[cfg(test)]
mod tests {
    use super::{check_token, check_verified_input};
    use axum::http::{HeaderMap, StatusCode};
    use serde_json::json;
    use std::collections::HashSet;

    fn headers(auth: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = auth {
            h.insert("authorization", v.parse().unwrap());
        }
        h
    }

    fn tokens() -> HashSet<String> {
        ["t1", "t2"].iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn accepts_a_bearer_token_in_the_set() {
        assert!(check_token(&headers(Some("Bearer t1")), &tokens()));
        assert!(check_token(&headers(Some("Bearer t2")), &tokens()));
    }

    #[test]
    fn refuses_a_token_outside_the_set() {
        assert!(!check_token(&headers(Some("Bearer t3")), &tokens()));
        assert!(!check_token(&headers(Some("Bearer t")), &tokens()));
        assert!(!check_token(&headers(Some("Bearer t1x")), &tokens()));
        assert!(!check_token(&headers(Some("Bearer ")), &tokens()));
    }

    #[test]
    fn refuses_a_missing_header_or_another_scheme() {
        assert!(!check_token(&headers(None), &tokens()));
        assert!(!check_token(&headers(Some("Basic t1")), &tokens()));
        assert!(!check_token(&headers(Some("t1")), &tokens()));
    }

    #[test]
    fn refuses_everything_when_the_set_is_empty() {
        assert!(!check_token(&headers(Some("Bearer t1")), &HashSet::new()));
    }

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn accepts_a_valid_key_and_an_object_body() {
        assert_eq!(
            check_verified_input(KEY, &json!({ "email": "a@b.c" })),
            Ok(())
        );
        assert_eq!(check_verified_input(KEY, &json!({})), Ok(()));
    }

    #[test]
    fn refuses_a_malformed_key() {
        assert_eq!(
            check_verified_input("not-a-key", &json!({})),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn refuses_a_body_that_is_not_an_object() {
        for body in [json!("x"), json!(1), json!(null), json!(["a"])] {
            assert_eq!(
                check_verified_input(KEY, &body),
                Err(StatusCode::BAD_REQUEST)
            );
        }
    }
}
