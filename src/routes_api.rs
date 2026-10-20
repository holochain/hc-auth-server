use crate::state::AppState as SharedState;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post, put},
};

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
    if !check_api_token(request.headers(), &state) {
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

/// Validates if the provided headers contain a valid API token.
fn check_api_token(headers: &HeaderMap, state: &SharedState) -> bool {
    if let Some(auth_value) = headers.get(header::AUTHORIZATION)
        && let Ok(auth_str) = auth_value.to_str()
        && auth_str.starts_with("Bearer ")
    {
        let token = &auth_str[7..];
        return state.config.api_tokens.contains(token);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::check_verified_input;
    use axum::http::StatusCode;
    use serde_json::json;

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
