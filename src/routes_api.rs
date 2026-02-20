use crate::state::AppState as SharedState;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/list", get(api_list_pending))
        .route("/get/{key}", get(api_get_pending))
        .route("/approve/{key}", post(api_approve_pending))
        .route("/reject/{key}", post(api_reject_pending))
}

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

pub async fn api_list_pending(
    State(state): State<SharedState>,
) -> impl IntoResponse {
    match state.storage.get_pending_requests().await {
        Ok(pending) => {
            let keys: Vec<String> =
                pending.keys().cloned().collect::<Vec<String>>();
            Json(keys).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to get pending requests: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn api_get_pending(
    State(state): State<SharedState>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    match state.storage.get_pending_requests().await {
        Ok(pending) => {
            if let Some(data) = pending.get(&key) {
                Json(data.clone()).into_response()
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }
        Err(e) => {
            tracing::error!("Failed to get pending requests: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn api_approve_pending(
    State(state): State<SharedState>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    match state.storage.approve_request(&key).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => {
            tracing::error!("Failed to approve request: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn api_reject_pending(
    State(state): State<SharedState>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    match state.storage.delete_request(&key).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(e) => {
            tracing::error!("Failed to reject request: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

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
