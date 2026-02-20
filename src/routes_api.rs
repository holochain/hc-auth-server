use crate::state::AppState as SharedState;
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};

pub async fn api_list_pending(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !check_api_token(&headers, &state) {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }

    match state.storage.get_pending_requests() {
        Ok(pending) => {
            let keys: Vec<String> = pending.keys().cloned().collect();
            Json(keys).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to get pending requests: {}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn api_get_pending(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if !check_api_token(&headers, &state) {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }

    match state.storage.get_pending_requests() {
        Ok(pending) => {
            if let Some(data) = pending.get(&key) {
                Json(data).into_response()
            } else {
                axum::http::StatusCode::NOT_FOUND.into_response()
            }
        }
        Err(e) => {
            tracing::error!("Failed to get pending requests: {}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn api_approve_pending(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if !check_api_token(&headers, &state) {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }

    match state.storage.approve_request(&key) {
        Ok(_) => axum::http::StatusCode::OK.into_response(),
        Err(e) => {
            tracing::error!("Failed to approve request: {}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn api_reject_pending(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    if !check_api_token(&headers, &state) {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }

    match state.storage.delete_request(&key) {
        Ok(_) => axum::http::StatusCode::OK.into_response(),
        Err(e) => {
            tracing::error!("Failed to reject request: {}", e);
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn check_api_token(headers: &HeaderMap, state: &SharedState) -> bool {
    let auth_header = headers.get(axum::http::header::AUTHORIZATION);
    if let Some(auth_value) = auth_header {
        if let Ok(auth_str) = auth_value.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                return state.config.api_tokens.contains(token);
            }
        }
    }
    false
}
